//! Run an HTTP/1.1 request, following redirects hop by hop with per-hop
//! timings. Certificate validation is on unless the user turns it off, and
//! that override is carried into every result. HTTP/2 is not used.

use std::io::Write;
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls::{ClientConfig, StreamOwned};
use serde::{Deserialize, Serialize};

use super::observe::{self, Observation};
use super::redirect;
use super::url::{self, Url};
use super::wire::{self, MAX_REQ_BODY};
use crate::tools::tls_inspector::cert;
use crate::tools::tls_inspector::live::{self as tls, Recorder};

/// Body bytes kept for display per hop.
const MAX_BODY: usize = 256 * 1024;
/// Upper bound on redirects followed.
const MAX_REDIRECTS: u8 = 20;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HttpRequest {
    pub url: String,
    pub method: String,
    #[serde(default)]
    pub headers: Vec<(String, String)>,
    #[serde(default)]
    pub body: String,
    /// Send requests for the original host to this IP, keeping Host and SNI.
    #[serde(default)]
    pub connect_ip: String,
    pub follow_redirects: bool,
    pub max_redirects: u8,
    /// Skip certificate validation. Shown on every result when set.
    #[serde(default)]
    pub insecure: bool,
    pub timeout_secs: u32,
}

#[derive(Debug, Clone, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Timing {
    /// None when no lookup happened (IP literal or connect-to IP).
    pub dns_ms: Option<u64>,
    pub connect_ms: u64,
    pub tls_ms: Option<u64>,
    /// From the request being sent to the first response byte.
    pub first_byte_ms: u64,
    pub total_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TlsSummary {
    pub protocol: String,
    pub cipher: String,
    pub alpn: String,
    /// "verified" or "skipped (validation turned off)".
    pub validation: String,
    pub cert_subject: String,
    pub cert_issuer: String,
    pub cert_not_after_ms: i64,
    pub cert_sans: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Hop {
    pub url: String,
    pub method: String,
    /// Headers as sent; credential values masked for display.
    pub request_headers: Vec<(String, String)>,
    pub request_body_len: usize,
    pub address: String,
    pub status: u16,
    pub reason: String,
    pub version: String,
    pub headers: Vec<(String, String)>,
    pub interim: Vec<u16>,
    pub tls: Option<TlsSummary>,
    pub timing: Timing,
    pub content_type: String,
    pub body_len: u64,
    pub body_truncated: bool,
    pub body_text: Option<String>,
    /// First bytes as hex when the body is not text.
    pub body_hex: Option<String>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HttpResult {
    pub hops: Vec<Hop>,
    /// Observations on the final response's headers.
    pub observations: Vec<Observation>,
    /// Set when the chain stopped early (a later hop failed, a loop, or the
    /// redirect limit); the hops that worked are still returned.
    pub error: Option<String>,
    pub insecure: bool,
}

fn ms(d: Duration) -> u64 {
    d.as_millis() as u64
}

fn mask(name: &str, value: &str) -> String {
    let lower = name.to_ascii_lowercase();
    if lower == "authorization" || lower == "proxy-authorization" {
        let scheme = value.split_whitespace().next().unwrap_or("");
        return format!("{scheme} ••••••");
    }
    if lower == "cookie" {
        return value
            .split(';')
            .map(|c| format!("{}=••••", c.split('=').next().unwrap_or("").trim()))
            .collect::<Vec<_>>()
            .join("; ");
    }
    if lower.contains("token")
        || lower.contains("api-key")
        || lower.contains("apikey")
        || lower.contains("secret")
    {
        return "••••••".into();
    }
    value.to_string()
}

fn body_view(body: &[u8]) -> (Option<String>, Option<String>) {
    match std::str::from_utf8(body) {
        Ok(s) if !s.contains('\0') => (Some(s.to_string()), None),
        // A cut in the middle of a multi-byte character is still text.
        Err(e) if e.valid_up_to() + 4 >= body.len() && e.error_len().is_none() => (
            Some(String::from_utf8_lossy(&body[..e.valid_up_to()]).into_owned()),
            None,
        ),
        _ => {
            let hex = body
                .iter()
                .take(512)
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .chunks(16)
                .map(|c| c.join(" "))
                .collect::<Vec<_>>()
                .join("\n");
            (None, Some(hex))
        }
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or_default()
}

struct Sent<'a> {
    url: &'a Url,
    method: &'a str,
    headers: &'a [(String, String)],
    body: &'a [u8],
    /// Connect here instead of resolving (only for the original host).
    connect_ip: Option<IpAddr>,
    insecure: bool,
    timeout: Duration,
}

fn tls_config(insecure: bool) -> Result<ClientConfig, String> {
    let provider = tls::provider();
    let algs = provider.signature_verification_algorithms;
    let builder = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(rustls::ALL_VERSIONS)
        .map_err(|e| e.to_string())?;
    let mut cfg = if insecure {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(Recorder(algs)))
            .with_no_client_auth()
    } else {
        builder
            .with_root_certificates(tls::ROOTS.clone())
            .with_no_client_auth()
    };
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(cfg)
}

/// One request and response on a fresh connection.
fn exchange(s: &Sent) -> Result<Hop, String> {
    let start = Instant::now();
    let mut timing = Timing::default();
    let addrs: Vec<SocketAddr> = if let Some(ip) = s.connect_ip {
        vec![SocketAddr::new(ip, s.url.port)]
    } else if let Ok(ip) = s.url.host.parse::<IpAddr>() {
        vec![SocketAddr::new(ip, s.url.port)]
    } else {
        let t = Instant::now();
        let a: Vec<SocketAddr> = (s.url.host.as_str(), s.url.port)
            .to_socket_addrs()
            .map_err(|e| format!("could not resolve {}: {e}", s.url.host))?
            .take(8)
            .collect();
        timing.dns_ms = Some(ms(t.elapsed()));
        a
    };

    let t = Instant::now();
    let mut last = "no addresses".to_string();
    let mut sock = None;
    for a in &addrs {
        match TcpStream::connect_timeout(a, s.timeout) {
            Ok(sk) => {
                sock = Some((sk, *a));
                break;
            }
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
                last = format!("{a}: connection refused")
            }
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
                last = format!("{a}: no answer within {} s", s.timeout.as_secs())
            }
            Err(e) => last = format!("{a}: {e}"),
        }
    }
    let (mut sock, addr) = sock.ok_or(last)?;
    timing.connect_ms = ms(t.elapsed());
    sock.set_read_timeout(Some(s.timeout)).ok();
    sock.set_write_timeout(Some(s.timeout)).ok();
    sock.set_nodelay(true).ok();

    let request = wire::build_request(
        s.method,
        &s.url.target,
        &s.url.host_header(),
        s.headers,
        s.body,
    );
    let head_only = s.method == "HEAD";
    let (resp, tls_summary, first_byte) = if s.url.https {
        let t = Instant::now();
        let cfg = tls_config(s.insecure)?;
        let conn = tls::handshake(&mut sock, cfg, tls::server_name(&s.url.host)?).map_err(|e| {
            let why = tls::explain(&e);
            if matches!(e, rustls::Error::InvalidCertificate(_)) {
                format!("certificate not accepted: {why}. Turn off certificate validation to see the response anyway (the result will say so).")
            } else {
                format!("TLS handshake failed: {why}")
            }
        })?;
        timing.tls_ms = Some(ms(t.elapsed()));
        let leaf = conn
            .peer_certificates()
            .and_then(|c| c.first())
            .and_then(|d| cert::decode_cert(d.as_ref(), now_ms()).ok());
        let summary = TlsSummary {
            protocol: conn
                .protocol_version()
                .map(|v| format!("{v:?}").replace("TLSv1_", "TLS 1."))
                .unwrap_or_default(),
            cipher: conn
                .negotiated_cipher_suite()
                .map(|c| format!("{:?}", c.suite()))
                .unwrap_or_default(),
            alpn: conn
                .alpn_protocol()
                .map(|a| String::from_utf8_lossy(a).into_owned())
                .unwrap_or_default(),
            validation: if s.insecure {
                "skipped (validation turned off)".into()
            } else {
                "verified".into()
            },
            cert_subject: leaf.as_ref().map(|c| c.subject.clone()).unwrap_or_default(),
            cert_issuer: leaf.as_ref().map(|c| c.issuer.clone()).unwrap_or_default(),
            cert_not_after_ms: leaf.as_ref().map(|c| c.not_after_ms).unwrap_or_default(),
            cert_sans: leaf
                .map(|c| c.sans.dns.into_iter().take(20).collect())
                .unwrap_or_default(),
        };
        let mut stream = StreamOwned::new(conn, sock);
        stream
            .write_all(&request)
            .and_then(|_| stream.flush())
            .map_err(|e| format!("sending the request: {e}"))?;
        let sent = Instant::now();
        let mut timed = wire::Timed::new(stream);
        let resp = wire::read_response(&mut timed, head_only, MAX_BODY)?;
        (
            resp,
            Some(summary),
            timed.first_byte.map(|f| f.duration_since(sent)),
        )
    } else {
        sock.write_all(&request)
            .and_then(|_| sock.flush())
            .map_err(|e| format!("sending the request: {e}"))?;
        let sent = Instant::now();
        let mut timed = wire::Timed::new(&mut sock);
        let resp = wire::read_response(&mut timed, head_only, MAX_BODY)?;
        let fb = timed.first_byte.map(|f| f.duration_since(sent));
        (resp, None, fb)
    };
    timing.first_byte_ms = first_byte.map(ms).unwrap_or_default();
    timing.total_ms = ms(start.elapsed());

    let mut notes = Vec::new();
    if let Some(enc) = resp.header("content-encoding")
        && !enc.eq_ignore_ascii_case("identity")
    {
        notes.push(format!(
            "Body is {enc}-encoded although identity was requested; shown as received, not decoded."
        ));
    }
    let (body_text, body_hex) = body_view(&resp.body);
    Ok(Hop {
        url: s.url.to_string(),
        method: s.method.to_string(),
        request_headers: s
            .headers
            .iter()
            .map(|(n, v)| (n.clone(), mask(n, v)))
            .collect(),
        request_body_len: s.body.len(),
        address: addr.to_string(),
        status: resp.status,
        reason: resp.reason.clone(),
        version: resp.version.clone(),
        content_type: resp.header("content-type").unwrap_or("").to_string(),
        interim: resp.interim.clone(),
        tls: tls_summary,
        timing,
        body_len: resp.body_len,
        body_truncated: resp.truncated,
        body_text,
        body_hex,
        notes,
        headers: resp.headers,
    })
}

/// Validate the request and run it, following redirects when asked.
pub fn run(req: &HttpRequest) -> Result<HttpResult, String> {
    let method = req.method.trim().to_ascii_uppercase();
    if !wire::is_method(&method) {
        return Err(format!("invalid method: {}", req.method));
    }
    let headers: Vec<(String, String)> = req
        .headers
        .iter()
        .filter(|(n, _)| !n.trim().is_empty())
        .map(|(n, v)| (n.trim().to_string(), v.trim().to_string()))
        .collect();
    wire::validate_headers(&headers)?;
    if req.body.len() > MAX_REQ_BODY {
        return Err("request body larger than 1 MB".into());
    }
    let connect_ip = match req.connect_ip.trim() {
        "" => None,
        ip => Some(
            ip.parse::<IpAddr>()
                .map_err(|_| format!("not an IP address: {ip}"))?,
        ),
    };
    let timeout = Duration::from_secs(req.timeout_secs.clamp(1, 120) as u64);
    let max_redirects = if req.follow_redirects {
        req.max_redirects.min(MAX_REDIRECTS)
    } else {
        0
    };

    let first = url::parse(&req.url)?;
    let mut url = first.clone();
    let mut method = method;
    let mut headers = headers;
    let mut body = req.body.clone().into_bytes();
    let mut hops: Vec<Hop> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut error = None;

    loop {
        let sent = Sent {
            url: &url,
            method: &method,
            headers: &headers,
            body: &body,
            connect_ip: connect_ip.filter(|_| url.host == first.host),
            insecure: req.insecure,
            timeout,
        };
        let mut hop = match exchange(&sent) {
            Ok(h) => h,
            Err(e) if hops.is_empty() => return Err(e),
            Err(e) => {
                error = Some(format!("{url}: {e}"));
                break;
            }
        };
        if sent.connect_ip.is_some() {
            hop.notes.push(format!(
                "Connected to {} instead of resolving {}; Host header and SNI kept as {}.",
                hop.address, url.host, url.host
            ));
        }
        let status = hop.status;
        let location = hop
            .headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case("location"))
            .map(|(_, v)| v.clone());
        if !redirect::is_redirect(status) {
            hops.push(hop);
            break;
        }
        let Some(location) = location else {
            hop.notes
                .push("Redirect status without a Location header.".into());
            hops.push(hop);
            break;
        };
        if hops.len() as u8 >= max_redirects {
            if req.follow_redirects {
                error = Some(format!("stopped after {max_redirects} redirects"));
            }
            hops.push(hop);
            break;
        }
        let next = match url::resolve(&url, &location) {
            Ok(n) => n,
            Err(e) => {
                error = Some(format!("cannot follow Location {location:?}: {e}"));
                hops.push(hop);
                break;
            }
        };
        let (next_method, keep_body) = redirect::next_method(status, &method);
        let (next_headers, dropped) = redirect::next_headers(&url, &next, &headers, keep_body);
        if !dropped.is_empty() {
            hop.notes.push(format!(
                "Not forwarded to {} (different origin): {}.",
                next.host_header(),
                dropped.join(", ")
            ));
        }
        if next_method != method {
            hop.notes.push(format!(
                "{status} changes {method} to {next_method} for the next request."
            ));
        }
        if url.https && !next.https {
            hop.notes.push("Redirects from HTTPS to plain HTTP.".into());
        }
        hops.push(hop);
        if !seen.insert(format!("{next_method} {next}")) || next == url && next_method == method {
            error = Some(format!("redirect loop at {next}"));
            break;
        }
        seen.insert(format!("{method} {url}"));
        url = next;
        method = next_method;
        headers = next_headers;
        if !keep_body {
            body.clear();
        }
    }

    let observations = hops
        .last()
        .filter(|h| !redirect::is_redirect(h.status))
        .map(|h| {
            let resp = wire::Response {
                status: h.status,
                headers: h.headers.clone(),
                ..Default::default()
            };
            observe::observe(&resp, h.url.starts_with("https://"))
        })
        .unwrap_or_default();
    Ok(HttpResult {
        hops,
        observations,
        error,
        insecure: req.insecure,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::net::TcpListener;

    /// A one-shot local HTTP server per scripted response.
    fn server(responses: Vec<String>) -> (u16, std::thread::JoinHandle<Vec<String>>) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let h = std::thread::spawn(move || {
            let mut seen = Vec::new();
            for r in responses {
                let (mut s, _) = l.accept().unwrap();
                s.set_read_timeout(Some(Duration::from_secs(2))).ok();
                let mut buf = vec![0u8; 8192];
                let n = s.read(&mut buf).unwrap_or(0);
                seen.push(String::from_utf8_lossy(&buf[..n]).into_owned());
                let r = r.replace("{port}", &port.to_string());
                s.write_all(r.as_bytes()).unwrap();
            }
            seen
        });
        (port, h)
    }

    fn req(url: String) -> HttpRequest {
        HttpRequest {
            url,
            method: "GET".into(),
            headers: vec![],
            body: String::new(),
            connect_ip: String::new(),
            follow_redirects: true,
            max_redirects: 5,
            insecure: false,
            timeout_secs: 3,
        }
    }

    #[test]
    fn follows_redirects_and_strips_credentials() {
        let (port, h) = server(vec![
            "HTTP/1.1 303 See Other\r\nLocation: /next\r\nContent-Length: 0\r\n\r\n".into(),
            "HTTP/1.1 302 Found\r\nLocation: http://localhost:{port}/final\r\nContent-Length: 0\r\n\r\n".into(),
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nok".into(),
        ]);
        let mut r = req(format!("http://127.0.0.1:{port}/start"));
        r.method = "POST".into();
        r.body = "x=1".into();
        r.headers = vec![
            ("Authorization".into(), "Bearer secret".into()),
            ("Content-Type".into(), "text/plain".into()),
        ];
        let out = run(&r).unwrap();
        let seen = h.join().unwrap();
        assert_eq!(out.hops.len(), 3);
        assert_eq!(out.hops[0].status, 303);
        assert_eq!(out.hops[1].method, "GET");
        assert!(
            seen[0].starts_with("POST /start") && seen[0].contains("Authorization: Bearer secret")
        );
        assert!(
            seen[1].starts_with("GET /next")
                && seen[1].contains("Authorization")
                && !seen[1].contains("Content-Type")
        );
        // localhost is a different origin from 127.0.0.1.
        assert!(!seen[2].contains("Authorization"));
        assert!(
            out.hops[1]
                .notes
                .iter()
                .any(|n| n.contains("Not forwarded"))
        );
        assert_eq!(out.hops[2].body_text.as_deref(), Some("ok"));
        assert_eq!(out.hops[0].request_headers[0].1, "Bearer ••••••");
        assert!(out.error.is_none());
        assert!(out.hops[2].timing.dns_ms.is_some());
        assert!(out.hops[0].timing.dns_ms.is_none());
    }

    #[test]
    fn loops_limits_and_no_follow() {
        // The loop is caught before a second request is made.
        let (port, h) = server(vec!["HTTP/1.1 301 Moved\r\nLocation: /a\r\n\r\n".into()]);
        let out = run(&req(format!("http://127.0.0.1:{port}/a"))).unwrap();
        h.join().unwrap();
        assert!(out.error.unwrap().contains("loop"));

        let (port, h) = server(vec!["HTTP/1.1 302 Found\r\nLocation: /b\r\n\r\n".into()]);
        let mut r = req(format!("http://127.0.0.1:{port}/"));
        r.follow_redirects = false;
        let out = run(&r).unwrap();
        h.join().unwrap();
        assert_eq!(out.hops.len(), 1);
        assert!(out.error.is_none());
        assert!(out.observations.is_empty());
    }

    #[test]
    fn connect_ip_keeps_host_header() {
        let (port, h) = server(vec!["HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".into()]);
        let mut r = req(format!("http://www.example.com:{port}/"));
        r.connect_ip = "127.0.0.1".into();
        let out = run(&r).unwrap();
        let seen = h.join().unwrap();
        assert!(seen[0].contains(&format!("Host: www.example.com:{port}")));
        assert!(out.hops[0].notes[0].contains("instead of resolving"));
        assert!(out.hops[0].timing.dns_ms.is_none());
    }

    #[test]
    fn input_validation() {
        let mut r = req("http://127.0.0.1:9/".into());
        r.method = "GE T".into();
        assert!(run(&r).is_err());
        let mut r = req("http://127.0.0.1:9/".into());
        r.headers = vec![("X".into(), "a\r\nB: c".into())];
        assert!(run(&r).unwrap_err().contains("line break"));
        let mut r = req("http://127.0.0.1:9/".into());
        r.connect_ip = "nope".into();
        assert!(run(&r).is_err());
        // Nothing listens on the discard port: a clear connection error.
        assert!(
            run(&req("http://127.0.0.1:9/".into()))
                .unwrap_err()
                .contains("127.0.0.1:9")
        );
    }

    #[test]
    fn masks_and_views() {
        assert_eq!(mask("Cookie", "a=1; b=2"), "a=••••; b=••••");
        assert_eq!(mask("X-Api-Key", "k"), "••••••");
        assert_eq!(mask("Accept", "text/html"), "text/html");
        assert_eq!(body_view(b"hello").0.as_deref(), Some("hello"));
        assert!(body_view(&[0, 1, 2, 255]).1.is_some());
        let cut = "héllo".as_bytes();
        assert_eq!(body_view(&cut[..2]).0.as_deref(), Some("h"));
    }
}
