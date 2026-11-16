//! Blocking DNS transports for the benchmark: UDP, TCP, DNS over TLS and DNS
//! over HTTPS. Each keeps its connection open between queries so per-query
//! latency excludes the handshake, which is measured once on connect. Every
//! socket has timeouts and every response is size bounded.

use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, StreamOwned};

use super::core::Transport;
use crate::tools::tls_inspector::live::{ROOTS, provider};

/// Per-query and connect timeout.
pub const TIMEOUT: Duration = Duration::from_secs(2);
/// Largest DNS message accepted (the TCP length prefix limit).
const MAX_MESSAGE: usize = 65_535;

/// One open path to a resolver.
pub enum Conn {
    Udp(UdpSocket),
    Tcp(TcpStream),
    Dot(Box<StreamOwned<ClientConnection, TcpStream>>),
    Doh { agent: ureq::Agent, url: String },
}

/// Open a connection over `t`. Returns it and the handshake time in ms
/// (None for UDP, which has no handshake).
pub fn connect(
    t: Transport,
    ip: IpAddr,
    doh: Option<&str>,
    dot: Option<&str>,
) -> Result<(Conn, Option<f64>), String> {
    let start = Instant::now();
    let ms = |s: Instant| s.elapsed().as_secs_f64() * 1000.0;
    match t {
        Transport::Udp => {
            let bind: SocketAddr = if ip.is_ipv4() {
                "0.0.0.0:0".parse().expect("literal")
            } else {
                "[::]:0".parse().expect("literal")
            };
            let s = UdpSocket::bind(bind).map_err(|e| format!("UDP socket: {e}"))?;
            s.connect(SocketAddr::new(ip, 53))
                .map_err(|e| format!("UDP connect: {e}"))?;
            s.set_read_timeout(Some(TIMEOUT))
                .map_err(|e| e.to_string())?;
            s.set_write_timeout(Some(TIMEOUT))
                .map_err(|e| e.to_string())?;
            Ok((Conn::Udp(s), None))
        }
        Transport::Tcp => {
            let s = tcp(SocketAddr::new(ip, 53))?;
            Ok((Conn::Tcp(s), Some(ms(start))))
        }
        Transport::Dot => {
            let host = dot.ok_or("no DoT host for this resolver")?;
            let sock = tcp(SocketAddr::new(ip, 853))?;
            let name =
                ServerName::try_from(host.to_string()).map_err(|e| format!("DoT host: {e}"))?;
            let conn = ClientConnection::new(Arc::new(tls_config(b"dot")?), name)
                .map_err(|e| format!("TLS: {e}"))?;
            let mut stream = StreamOwned::new(conn, sock);
            // Drive the handshake now so it is timed separately.
            while stream.conn.is_handshaking() {
                stream
                    .conn
                    .complete_io(&mut stream.sock)
                    .map_err(|e| format!("TLS handshake: {e}"))?;
            }
            Ok((Conn::Dot(Box::new(stream)), Some(ms(start))))
        }
        Transport::Doh => {
            let url = doh.ok_or("no DoH URL for this resolver")?.to_string();
            let pinned = SocketAddr::new(ip, 443);
            // Connect to the resolver's address, not whatever the system
            // resolver returns for the URL's host; the certificate is still
            // checked against that host.
            let agent = ureq::AgentBuilder::new()
                .resolver(move |_: &str| Ok(vec![pinned]))
                .timeout_connect(TIMEOUT)
                .timeout(TIMEOUT)
                .max_idle_connections_per_host(1)
                .redirects(0)
                .build();
            Ok((Conn::Doh { agent, url }, None))
        }
    }
}

fn tcp(addr: SocketAddr) -> Result<TcpStream, String> {
    let s =
        TcpStream::connect_timeout(&addr, TIMEOUT).map_err(|e| format!("connect {addr}: {e}"))?;
    s.set_read_timeout(Some(TIMEOUT))
        .map_err(|e| e.to_string())?;
    s.set_write_timeout(Some(TIMEOUT))
        .map_err(|e| e.to_string())?;
    let _ = s.set_nodelay(true);
    Ok(s)
}

fn tls_config(alpn: &[u8]) -> Result<ClientConfig, String> {
    let mut cfg = ClientConfig::builder_with_provider(Arc::new(provider()))
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_root_certificates(ROOTS.clone())
        .with_no_client_auth();
    cfg.alpn_protocols = vec![alpn.to_vec()];
    Ok(cfg)
}

/// Send `query` and return the raw response.
pub fn exchange(conn: &mut Conn, query: &[u8], id: u16) -> Result<Vec<u8>, String> {
    match conn {
        Conn::Udp(s) => {
            s.send(query).map_err(|e| format!("send: {e}"))?;
            let deadline = Instant::now() + TIMEOUT;
            let mut buf = vec![0u8; 4096];
            loop {
                let n = s.recv(&mut buf).map_err(|e| timeout_text(&e))?;
                // Skip late answers to earlier queries.
                if n >= 2 && u16::from_be_bytes([buf[0], buf[1]]) == id {
                    buf.truncate(n);
                    return Ok(buf);
                }
                if Instant::now() >= deadline {
                    return Err("timed out".into());
                }
            }
        }
        Conn::Tcp(s) => framed(s, query),
        Conn::Dot(s) => framed(s.as_mut(), query),
        Conn::Doh { agent, url } => {
            let resp = agent
                .post(url)
                .set("content-type", "application/dns-message")
                .set("accept", "application/dns-message")
                .send_bytes(query)
                .map_err(|e| match e {
                    ureq::Error::Status(505, _) => {
                        "server requires HTTP/2, which this test does not use".to_string()
                    }
                    ureq::Error::Status(code, _) => format!("HTTP {code}"),
                    ureq::Error::Transport(t) => t.to_string(),
                })?;
            let ct = resp
                .header("content-type")
                .unwrap_or("")
                .to_ascii_lowercase();
            if !ct.starts_with("application/dns-message") {
                return Err(format!("unexpected content type {ct:?}"));
            }
            let mut body = Vec::new();
            resp.into_reader()
                .take(MAX_MESSAGE as u64 + 1)
                .read_to_end(&mut body)
                .map_err(|e| format!("read: {e}"))?;
            if body.len() > MAX_MESSAGE {
                return Err("response too large".into());
            }
            Ok(body)
        }
    }
}

/// RFC 1035 TCP framing: a two-byte length, then the message.
fn framed<S: Read + Write>(s: &mut S, query: &[u8]) -> Result<Vec<u8>, String> {
    let len = u16::try_from(query.len()).map_err(|_| "query too large")?;
    let mut out = Vec::with_capacity(query.len() + 2);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(query);
    s.write_all(&out)
        .map_err(|e| format!("send: {}", timeout_text(&e)))?;
    s.flush().map_err(|e| format!("send: {e}"))?;
    let mut lb = [0u8; 2];
    s.read_exact(&mut lb).map_err(|e| timeout_text(&e))?;
    let n = usize::from(u16::from_be_bytes(lb));
    let mut buf = vec![0u8; n];
    s.read_exact(&mut buf).map_err(|e| timeout_text(&e))?;
    Ok(buf)
}

fn timeout_text(e: &std::io::Error) -> String {
    match e.kind() {
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => "timed out".into(),
        std::io::ErrorKind::UnexpectedEof
        | std::io::ErrorKind::ConnectionAborted
        | std::io::ErrorKind::ConnectionReset
        | std::io::ErrorKind::BrokenPipe => "connection closed".into(),
        _ => e.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn tcp_framing_round_trip() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let srv = std::thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            let mut lb = [0u8; 2];
            s.read_exact(&mut lb).unwrap();
            let mut q = vec![0u8; usize::from(u16::from_be_bytes(lb))];
            s.read_exact(&mut q).unwrap();
            q.reverse();
            s.write_all(&(q.len() as u16).to_be_bytes()).unwrap();
            s.write_all(&q).unwrap();
        });
        let mut s = tcp(addr).unwrap();
        assert_eq!(framed(&mut s, b"abc").unwrap(), b"cba");
        srv.join().unwrap();
    }

    #[test]
    fn udp_skips_wrong_ids() {
        let srv = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = srv.local_addr().unwrap();
        let mut c = Conn::Udp({
            let s = UdpSocket::bind("127.0.0.1:0").unwrap();
            s.connect(addr).unwrap();
            s.set_read_timeout(Some(TIMEOUT)).unwrap();
            s
        });
        let t = std::thread::spawn(move || {
            let mut b = [0u8; 64];
            let (_, from) = srv.recv_from(&mut b).unwrap();
            srv.send_to(&[0, 1, 9], from).unwrap();
            srv.send_to(&[0, 2, 7], from).unwrap();
        });
        assert_eq!(exchange(&mut c, &[0, 2], 2).unwrap(), [0, 2, 7]);
        t.join().unwrap();
    }

    #[test]
    fn framed_reports_close() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let srv = std::thread::spawn(move || {
            let (s, _) = l.accept().unwrap();
            drop(s);
        });
        let mut s = tcp(addr).unwrap();
        srv.join().unwrap();
        let e = framed(&mut s, b"abc").unwrap_err();
        assert!(e.contains("connection closed"), "{e}");
    }

    /// Live check against public resolvers; run with `--ignored`.
    #[test]
    #[ignore]
    fn live_public_resolvers() {
        use super::super::core::{build_query, parse_answer, providers};
        use hickory_proto::rr::RecordType;
        for p in providers() {
            let ip: IpAddr = p.ipv4[0].parse().unwrap();
            for t in [
                Transport::Udp,
                Transport::Tcp,
                Transport::Dot,
                Transport::Doh,
            ] {
                let doh = (!p.doh.is_empty()).then_some(p.doh);
                let dot = (!p.dot.is_empty()).then_some(p.dot);
                if (t == Transport::Dot && dot.is_none()) || (t == Transport::Doh && doh.is_none())
                {
                    continue;
                }
                let r = connect(t, ip, doh, dot).and_then(|(mut c, ms)| {
                    let id = if t == Transport::Doh { 0 } else { 0x4242 };
                    let q = build_query(id, "example.com", RecordType::A, true).unwrap();
                    let start = Instant::now();
                    let b = exchange(&mut c, &q, id)?;
                    let a = parse_answer(&b, Some(id)).map_err(|e| e.to_string())?;
                    Ok(format!(
                        "connect {ms:?} query {:.1} ms {:?} ad={}",
                        start.elapsed().as_secs_f64() * 1000.0,
                        a.rcode,
                        a.authentic
                    ))
                });
                println!("{:<24} {:?}: {:?}", p.name, t, r);
            }
        }
    }
}
