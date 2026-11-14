//! One probe per call: TCP connect, HTTP request or ICMP echo. Every probe
//! is bounded by its timeout and reports what it actually measured.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::tools::http_client::client::{self as http, HttpRequest};
use crate::tools::traceroute::core::Outcome as IcmpOutcome;
use crate::tools::traceroute::probe::{self as icmp, ProbeSpec};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Tcp,
    Http,
    Icmp,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Target {
    /// Chosen by the UI; echoed on every sample.
    pub id: u32,
    pub kind: Kind,
    /// Host for TCP and ICMP; a URL for HTTP.
    pub address: String,
    /// TCP port.
    #[serde(default)]
    pub port: u16,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Sample {
    pub target: u32,
    pub seq: u64,
    /// Unix time in milliseconds when the probe started.
    pub at_ms: i64,
    pub ok: bool,
    /// Measured time; None when nothing answered.
    pub ms: Option<f64>,
    /// Short status: "connected", "200", "echo reply", "refused", ...
    pub status: String,
    pub detail: String,
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or_default()
}

fn elapsed_ms(t: Instant) -> f64 {
    (t.elapsed().as_secs_f64() * 100_000.0).round() / 100.0
}

/// Check a target before monitoring starts.
pub fn validate(t: &Target) -> Result<(), String> {
    let a = t.address.trim();
    if a.is_empty() {
        return Err("a target has no address".into());
    }
    match t.kind {
        Kind::Tcp if t.port == 0 => Err(format!("{a}: TCP needs a port")),
        Kind::Http => crate::tools::http_client::url::parse(a).map(|_| ()),
        Kind::Icmp if a.parse::<IpAddr>().is_ok_and(|ip| ip.is_ipv6()) => {
            Err(format!("{a}: ICMP monitoring supports IPv4 only"))
        }
        _ => Ok(()),
    }
}

fn resolve_v4(host: &str) -> Result<Ipv4Addr, String> {
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        return Ok(ip);
    }
    (host, 0)
        .to_socket_addrs()
        .map_err(|e| format!("could not resolve {host}: {e}"))?
        .find_map(|a| match a.ip() {
            IpAddr::V4(v4) => Some(v4),
            IpAddr::V6(_) => None,
        })
        .ok_or_else(|| format!("{host} has no IPv4 address"))
}

/// Blocking connect with a timeout that reports a refusal at once on every
/// OS (Windows otherwise retries the SYN for about two seconds after a RST).
fn connect(addr: &SocketAddr, timeout: Duration) -> std::io::Result<TcpStream> {
    use socket2::{Domain, Protocol, Socket, Type};
    let sock = Socket::new(
        Domain::for_address(*addr),
        Type::STREAM,
        Some(Protocol::TCP),
    )?;
    #[cfg(windows)]
    crate::tools::port_scanner::commands::fast_refusal(&sock);
    sock.connect_timeout(&(*addr).into(), timeout)?;
    Ok(sock.into())
}

fn tcp(t: &Target, timeout: Duration) -> (bool, Option<f64>, String, String) {
    let addr: SocketAddr = match (t.address.trim(), t.port)
        .to_socket_addrs()
        .map(|mut a| a.next())
    {
        Ok(Some(a)) => a,
        Ok(None) => return (false, None, "no address".into(), String::new()),
        Err(e) => return (false, None, "DNS failed".into(), e.to_string()),
    };
    let start = Instant::now();
    match connect(&addr, timeout) {
        Ok(_) => (
            true,
            Some(elapsed_ms(start)),
            "connected".into(),
            addr.to_string(),
        ),
        Err(e) => {
            use std::io::ErrorKind as K;
            match e.kind() {
                // A reset came back: reachable, nothing listening.
                K::ConnectionRefused => (
                    false,
                    Some(elapsed_ms(start)),
                    "refused".into(),
                    "RST received".into(),
                ),
                K::TimedOut | K::WouldBlock => (
                    false,
                    None,
                    "timed out".into(),
                    "no answer within the timeout".into(),
                ),
                _ => (false, None, "error".into(), e.to_string()),
            }
        }
    }
}

fn http_probe(t: &Target, timeout: Duration) -> (bool, Option<f64>, String, String) {
    let req = HttpRequest {
        url: t.address.trim().to_string(),
        method: "GET".into(),
        headers: vec![],
        body: String::new(),
        connect_ip: String::new(),
        follow_redirects: false,
        max_redirects: 0,
        insecure: false,
        timeout_secs: timeout.as_secs().max(1) as u32,
    };
    let start = Instant::now();
    match http::run(&req) {
        Ok(r) => match r.hops.first() {
            Some(h) => {
                // A response below 400 counts as up; 4xx and 5xx are answers
                // but mean the service is not serving this URL correctly.
                let ok = h.status < 400;
                let total = h.timing.total_ms as f64;
                (ok, Some(total), h.status.to_string(), h.reason.clone())
            }
            None => (
                false,
                Some(elapsed_ms(start)),
                "no response".into(),
                String::new(),
            ),
        },
        Err(e) => (false, None, "failed".into(), e),
    }
}

fn icmp_probe(
    t: &Target,
    timeout: Duration,
    seq: u16,
    ident: u16,
) -> (bool, Option<f64>, String, String) {
    let dst = match resolve_v4(t.address.trim()) {
        Ok(d) => d,
        Err(e) => return (false, None, "DNS failed".into(), e),
    };
    let spec = ProbeSpec {
        dst,
        ttl: 64,
        ident,
        seq,
        size: 64,
        df: false,
        timeout,
    };
    match icmp::probe(&spec) {
        Ok(r) => match r.outcome {
            IcmpOutcome::Reached => (true, r.rtt_ms, "echo reply".into(), icmp::method()),
            IcmpOutcome::Timeout => (false, None, "no reply".into(), "No reply. A device may simply drop ICMP; this alone does not mean the host or its services are down.".into()),
            IcmpOutcome::Unreachable(code) => (false, r.rtt_ms, "unreachable".into(), format!("ICMP unreachable code {code}{}", r.responder.map(|ip| format!(" from {ip}")).unwrap_or_default())),
            IcmpOutcome::Hop => (false, r.rtt_ms, "TTL exceeded".into(), "a router answered instead of the target".into()),
            IcmpOutcome::TooBig(_) => (false, r.rtt_ms, "too big".into(), String::new()),
        },
        Err(e) => (false, None, "cannot probe".into(), e.to_string()),
    }
}

/// Run one probe now. Blocking; call from a blocking thread.
pub fn run(t: &Target, seq: u64, timeout: Duration, ident: u16) -> Sample {
    let at_ms = now_ms();
    let (ok, ms, status, detail) = match t.kind {
        Kind::Tcp => tcp(t, timeout),
        Kind::Http => http_probe(t, timeout),
        Kind::Icmp => icmp_probe(t, timeout, (seq & 0xffff) as u16, ident),
    };
    Sample {
        target: t.id,
        seq,
        at_ms,
        ok,
        ms,
        status,
        detail,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    fn target(kind: Kind, address: &str, port: u16) -> Target {
        Target {
            id: 7,
            kind,
            address: address.into(),
            port,
        }
    }

    #[test]
    fn validation() {
        assert!(validate(&target(Kind::Tcp, "example.com", 443)).is_ok());
        assert!(validate(&target(Kind::Tcp, "example.com", 0)).is_err());
        assert!(validate(&target(Kind::Http, "ftp://x", 0)).is_err());
        assert!(validate(&target(Kind::Http, "https://example.com/health", 0)).is_ok());
        assert!(validate(&target(Kind::Icmp, "2001:db8::1", 0)).is_err());
        assert!(validate(&target(Kind::Icmp, " ", 0)).is_err());
    }

    #[test]
    fn tcp_up_and_refused() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let s = run(
            &target(Kind::Tcp, "127.0.0.1", port),
            1,
            Duration::from_secs(2),
            1,
        );
        assert!(s.ok && s.ms.is_some() && s.status == "connected" && s.target == 7);
        drop(l);
        let s = run(
            &target(Kind::Tcp, "127.0.0.1", port),
            2,
            Duration::from_secs(2),
            1,
        );
        assert!(!s.ok);
        assert_eq!(s.status, "refused");
    }

    #[test]
    fn http_status_decides() {
        for (code, up) in [(200u16, true), (301, true), (503, false)] {
            let l = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = l.local_addr().unwrap().port();
            let h = std::thread::spawn(move || {
                let (mut c, _) = l.accept().unwrap();
                let mut b = [0u8; 1024];
                let _ = c.read(&mut b);
                c.write_all(format!("HTTP/1.1 {code} X\r\nContent-Length: 0\r\n\r\n").as_bytes())
                    .unwrap();
            });
            let s = run(
                &target(Kind::Http, &format!("http://127.0.0.1:{port}/"), 0),
                1,
                Duration::from_secs(2),
                1,
            );
            h.join().unwrap();
            assert_eq!((s.ok, s.status.as_str()), (up, code.to_string().as_str()));
        }
    }
}
