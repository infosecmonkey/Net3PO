//! HTTP/1.1 on the wire: build a request and parse a response. Responses
//! are untrusted: header count and size, line length, chunk sizes and the
//! body are all bounded. Bodies are never decompressed or rendered.

use std::io::{BufRead, BufReader, Read};
use std::time::Instant;

/// Status line parts plus headers.
type Head = (String, u16, String, Vec<(String, String)>);

/// Most bytes of headers accepted in one response.
const MAX_HEADER_BYTES: usize = 64 * 1024;
/// Most header lines in one response.
const MAX_HEADERS: usize = 200;
/// Most interim (1xx) responses skipped before the final one.
const MAX_INTERIM: usize = 5;
/// Most user headers on a request.
pub const MAX_REQ_HEADERS: usize = 50;
/// Largest request body accepted.
pub const MAX_REQ_BODY: usize = 1024 * 1024;

/// Header names that carry credentials.
pub const CREDENTIAL_HEADERS: &[&str] = &["authorization", "proxy-authorization", "cookie"];

fn is_token(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}

/// Check user headers: valid names, no CR/LF (header injection), limits.
pub fn validate_headers(headers: &[(String, String)]) -> Result<(), String> {
    if headers.len() > MAX_REQ_HEADERS {
        return Err(format!("more than {MAX_REQ_HEADERS} headers"));
    }
    for (n, v) in headers {
        if !is_token(n) {
            return Err(format!("invalid header name: {n:?}"));
        }
        if v.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0) {
            return Err(format!("header {n} contains a line break"));
        }
        if v.len() > 16 * 1024 {
            return Err(format!("header {n} is longer than 16 KB"));
        }
        let lower = n.to_ascii_lowercase();
        if lower == "host"
            || lower == "content-length"
            || lower == "transfer-encoding"
            || lower == "connection"
        {
            return Err(format!("{n} is set by Net3PO; remove it"));
        }
    }
    Ok(())
}

pub fn is_method(m: &str) -> bool {
    is_token(m) && m.len() <= 20
}

/// Serialize a request. Adds Host, User-Agent, Accept, Accept-Encoding
/// identity and Connection: close unless the user set them.
pub fn build_request(
    method: &str,
    target: &str,
    host_header: &str,
    headers: &[(String, String)],
    body: &[u8],
) -> Vec<u8> {
    let has = |name: &str| headers.iter().any(|(n, _)| n.eq_ignore_ascii_case(name));
    let mut out = format!("{method} {target} HTTP/1.1\r\nHost: {host_header}\r\n");
    if !has("user-agent") {
        out.push_str(concat!(
            "User-Agent: Net3PO/",
            env!("CARGO_PKG_VERSION"),
            "\r\n"
        ));
    }
    if !has("accept") {
        out.push_str("Accept: */*\r\n");
    }
    if !has("accept-encoding") {
        out.push_str("Accept-Encoding: identity\r\n");
    }
    for (n, v) in headers {
        out.push_str(&format!("{n}: {v}\r\n"));
    }
    let needs_length = !body.is_empty() || matches!(method, "POST" | "PUT" | "PATCH");
    if needs_length {
        out.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    out.push_str("Connection: close\r\n\r\n");
    let mut bytes = out.into_bytes();
    bytes.extend_from_slice(body);
    bytes
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Response {
    pub version: String,
    pub status: u16,
    pub reason: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// Total body bytes the server sent (or the declared length when we
    /// stopped reading early).
    pub body_len: u64,
    pub truncated: bool,
    /// Interim responses seen first (`100 Continue`, `103 Early Hints`).
    pub interim: Vec<u16>,
}

impl Response {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub fn all(&self, name: &str) -> Vec<&str> {
        self.headers
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
            .collect()
    }
}

/// Records when the first response byte arrived.
pub struct Timed<R> {
    inner: R,
    pub first_byte: Option<Instant>,
}

impl<R> Timed<R> {
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            first_byte: None,
        }
    }
}

impl<R: Read> Read for Timed<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        if n > 0 && self.first_byte.is_none() {
            self.first_byte = Some(Instant::now());
        }
        Ok(n)
    }
}

fn io_err(e: std::io::Error) -> String {
    match e.kind() {
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => {
            "timed out waiting for the server".into()
        }
        std::io::ErrorKind::UnexpectedEof => "the server closed the connection early".into(),
        _ => e.to_string(),
    }
}

/// One header-section line, bounded by the remaining header budget.
fn line<R: BufRead>(r: &mut R, budget: &mut usize) -> Result<String, String> {
    let mut buf = Vec::new();
    let limit = (*budget as u64).saturating_add(1);
    let n = r
        .by_ref()
        .take(limit)
        .read_until(b'\n', &mut buf)
        .map_err(io_err)?;
    if n == 0 {
        return Err("the server closed the connection without a response".into());
    }
    if !buf.ends_with(b"\n") {
        return Err("response headers too large".into());
    }
    *budget -= n.min(*budget);
    while buf.last().is_some_and(|b| *b == b'\n' || *b == b'\r') {
        buf.pop();
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

fn read_head<R: BufRead>(r: &mut R, budget: &mut usize) -> Result<Head, String> {
    let status_line = line(r, budget)?;
    let mut parts = status_line.splitn(3, ' ');
    let version = parts.next().unwrap_or("").to_string();
    if !version.starts_with("HTTP/") {
        return Err(format!(
            "not an HTTP response (got {:?}); wrong port or scheme?",
            status_line.chars().take(40).collect::<String>()
        ));
    }
    let status: u16 = parts
        .next()
        .and_then(|s| s.parse().ok())
        .filter(|s| (100..=999).contains(s))
        .ok_or_else(|| format!("bad status line: {status_line}"))?;
    let reason = parts.next().unwrap_or("").to_string();
    let mut headers = Vec::new();
    loop {
        let l = line(r, budget)?;
        if l.is_empty() {
            break;
        }
        if headers.len() >= MAX_HEADERS {
            return Err(format!("more than {MAX_HEADERS} response headers"));
        }
        // Obsolete line folding: continue the previous value.
        if l.starts_with([' ', '\t']) {
            if let Some((_, v)) = headers.last_mut() {
                let v: &mut String = v;
                v.push(' ');
                v.push_str(l.trim());
            }
            continue;
        }
        match l.split_once(':') {
            Some((n, v)) => headers.push((n.trim().to_string(), v.trim().to_string())),
            None => return Err(format!("malformed header line: {l}")),
        }
    }
    Ok((version, status, reason, headers))
}

/// Read up to `max` bytes into `out`; count everything the server sends
/// until `limit` (None = until close). Returns bytes seen.
fn read_body<R: Read>(
    r: &mut R,
    limit: Option<u64>,
    max: usize,
    out: &mut Vec<u8>,
    truncated: &mut bool,
) -> Result<u64, String> {
    let mut seen: u64 = 0;
    let mut buf = [0u8; 16 * 1024];
    loop {
        let want = match limit {
            Some(l) if seen >= l => break,
            Some(l) => ((l - seen) as usize).min(buf.len()),
            None => buf.len(),
        };
        let n = match r.read(&mut buf[..want]) {
            Ok(0) => {
                if limit.is_some_and(|l| seen < l) {
                    return Err(format!(
                        "the server closed the connection after {seen} of {} body bytes",
                        limit.unwrap_or(0)
                    ));
                }
                break;
            }
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) if limit.is_none() && e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(io_err(e)),
        };
        let room = max.saturating_sub(out.len());
        out.extend_from_slice(&buf[..n.min(room)]);
        seen += n as u64;
        if out.len() >= max {
            // Stop reading: we have the preview; the rest is not needed.
            *truncated = true;
            return Ok(limit.unwrap_or(seen).max(seen));
        }
    }
    Ok(seen)
}

fn read_chunked<R: BufRead>(
    r: &mut R,
    max: usize,
    out: &mut Vec<u8>,
    truncated: &mut bool,
) -> Result<u64, String> {
    let mut total: u64 = 0;
    let mut budget = MAX_HEADER_BYTES;
    loop {
        let size_line = line(r, &mut budget).map_err(|e| format!("chunked body: {e}"))?;
        let hex = size_line.split(';').next().unwrap_or("").trim();
        let size = u64::from_str_radix(hex, 16).map_err(|_| format!("bad chunk size: {hex:?}"))?;
        budget = MAX_HEADER_BYTES; // chunk-size lines are small; reset each time
        if size == 0 {
            // Trailers, then the final blank line.
            loop {
                if line(r, &mut budget)?.is_empty() {
                    break;
                }
            }
            return Ok(total);
        }
        let got = read_body(r, Some(size), max, out, truncated)?;
        total += got;
        if *truncated {
            return Ok(total);
        }
        let mut crlf = [0u8; 2];
        r.read_exact(&mut crlf).map_err(io_err)?;
        if &crlf != b"\r\n" {
            return Err("malformed chunk terminator".into());
        }
    }
}

/// Parse one response from `r`. `head_only` for HEAD requests.
pub fn read_response<R: Read>(r: R, head_only: bool, max_body: usize) -> Result<Response, String> {
    let mut r = BufReader::with_capacity(16 * 1024, r);
    let mut budget = MAX_HEADER_BYTES;
    let mut interim = Vec::new();
    let (version, status, reason, headers) = loop {
        let head = read_head(&mut r, &mut budget)?;
        if (100..200).contains(&head.1) && head.1 != 101 {
            interim.push(head.1);
            if interim.len() > MAX_INTERIM {
                return Err("too many interim responses".into());
            }
            continue;
        }
        break head;
    };
    let mut resp = Response {
        version,
        status,
        reason,
        headers,
        interim,
        ..Default::default()
    };
    let no_body = head_only || status == 204 || status == 304 || status == 101;
    if no_body {
        return Ok(resp);
    }
    let te = resp
        .header("transfer-encoding")
        .unwrap_or("")
        .to_ascii_lowercase();
    let mut body = Vec::new();
    let mut truncated = false;
    let len = if te.split(',').any(|t| t.trim() == "chunked") {
        read_chunked(&mut r, max_body, &mut body, &mut truncated)?
    } else if let Some(cl) = resp.header("content-length") {
        let cl: u64 = cl
            .trim()
            .parse()
            .map_err(|_| format!("bad Content-Length: {cl}"))?;
        read_body(&mut r, Some(cl), max_body, &mut body, &mut truncated)?
    } else {
        read_body(&mut r, None, max_body, &mut body, &mut truncated)?
    };
    resp.body = body;
    resp.body_len = len;
    resp.truncated = truncated;
    Ok(resp)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(raw: &str) -> Result<Response, String> {
        read_response(raw.as_bytes(), false, 1024)
    }

    #[test]
    fn builds_requests() {
        let h = vec![("X-Test".to_string(), "1".to_string())];
        let r = String::from_utf8(build_request("GET", "/a?b", "example.com", &h, b"")).unwrap();
        assert!(r.starts_with("GET /a?b HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Net3PO/"));
        assert!(r.contains("Accept-Encoding: identity\r\nX-Test: 1\r\nConnection: close\r\n\r\n"));
        assert!(!r.contains("Content-Length"));
        let r = String::from_utf8(build_request("POST", "/", "h", &[], b"{}")).unwrap();
        assert!(r.contains("Content-Length: 2\r\n") && r.ends_with("\r\n\r\n{}"));
        let ua = vec![("user-agent".to_string(), "curl/8".to_string())];
        let r = String::from_utf8(build_request("GET", "/", "h", &ua, b"")).unwrap();
        assert!(!r.contains("Net3PO/") && r.contains("user-agent: curl/8"));
    }

    #[test]
    fn rejects_bad_headers() {
        let h = |n: &str, v: &str| vec![(n.to_string(), v.to_string())];
        assert!(validate_headers(&h("X-Ok", "fine")).is_ok());
        assert!(validate_headers(&h("X-Bad", "a\r\nInjected: 1")).is_err());
        assert!(validate_headers(&h("Bad Name", "x")).is_err());
        assert!(validate_headers(&h("Host", "x")).is_err());
        assert!(validate_headers(&h("Content-Length", "1")).is_err());
        assert!(is_method("PROPFIND") && !is_method("GET /x"));
    }

    #[test]
    fn content_length_and_close() {
        let r = parse("HTTP/1.1 200 OK\r\nContent-Length: 5\r\nX-A: 1\r\n\r\nhello").unwrap();
        assert_eq!(
            (r.status, r.reason.as_str(), r.body.as_slice()),
            (200, "OK", b"hello".as_slice())
        );
        assert_eq!(r.header("x-a"), Some("1"));
        let r = parse("HTTP/1.0 200 OK\r\n\r\nuntil close").unwrap();
        assert_eq!(r.body, b"until close");
        assert!(
            parse("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nshort")
                .unwrap_err()
                .contains("closed")
        );
        let r = read_response(
            "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n".as_bytes(),
            true,
            10,
        )
        .unwrap();
        assert!(r.body.is_empty());
        let r = parse("HTTP/1.1 204 No Content\r\n\r\n").unwrap();
        assert_eq!(r.status, 204);
    }

    #[test]
    fn chunked_interim_and_folding() {
        let r = parse("HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nX-Long: a\r\n b\r\n\r\n5;ext=1\r\nhello\r\n6\r\n world\r\n0\r\nTrailer: x\r\n\r\n").unwrap();
        assert_eq!(r.body, b"hello world");
        assert_eq!(r.interim, vec![100]);
        assert_eq!(r.header("x-long"), Some("a b"));
        assert!(parse("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n").is_err());
        assert!(parse("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabcXX").is_err());
    }

    #[test]
    fn bounded() {
        let big = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: 5000\r\n\r\n{}",
            "x".repeat(5000)
        );
        let r = parse(&big).unwrap();
        assert_eq!(r.body.len(), 1024);
        assert!(r.truncated);
        assert_eq!(r.body_len, 5000);
        let many = format!(
            "HTTP/1.1 200 OK\r\n{}\r\n",
            "A: b\r\n".repeat(MAX_HEADERS + 1)
        );
        assert!(parse(&many).unwrap_err().contains("headers"));
        let huge = format!(
            "HTTP/1.1 200 OK\r\nX: {}\r\n\r\n",
            "a".repeat(MAX_HEADER_BYTES + 10)
        );
        assert!(parse(&huge).unwrap_err().contains("too large"));
        assert!(
            parse("SSH-2.0-OpenSSH\r\n")
                .unwrap_err()
                .contains("not an HTTP response")
        );
        assert!(parse("").unwrap_err().contains("without a response"));
        let interim = "HTTP/1.1 103 Early\r\n\r\n".repeat(MAX_INTERIM + 2);
        assert!(parse(&interim).is_err());
        assert!(parse("HTTP/1.1 200 OK\r\nContent-Length: nope\r\n\r\n").is_err());
    }
}
