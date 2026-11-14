//! Pure helpers for the socket tools: payload parsing (text with escapes,
//! or hex), byte previews, connection timing statistics and wording for
//! connection outcomes. No sockets here.

use serde::{Deserialize, Serialize};

/// Largest payload accepted for sending.
pub const MAX_PAYLOAD: usize = 64 * 1024;
/// Bytes shown per received chunk in a preview.
pub const PREVIEW_BYTES: usize = 4096;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PayloadKind {
    Text,
    Hex,
}

/// Turn the user's payload into bytes. Text understands `\r`, `\n`, `\t`,
/// `\0`, `\\` and `\xHH`; hex ignores spaces, colons and `0x` prefixes.
pub fn parse_payload(input: &str, kind: PayloadKind) -> Result<Vec<u8>, String> {
    let out = match kind {
        PayloadKind::Text => unescape(input)?,
        PayloadKind::Hex => parse_hex(input)?,
    };
    if out.len() > MAX_PAYLOAD {
        return Err(format!("payload larger than {} KB", MAX_PAYLOAD / 1024));
    }
    Ok(out)
}

fn unescape(s: &str) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\\' {
            let mut buf = [0u8; 4];
            out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            continue;
        }
        match chars.next() {
            Some('n') => out.push(b'\n'),
            Some('r') => out.push(b'\r'),
            Some('t') => out.push(b'\t'),
            Some('0') => out.push(0),
            Some('\\') => out.push(b'\\'),
            Some('x') => {
                let h: String = chars.by_ref().take(2).collect();
                let b = u8::from_str_radix(&h, 16)
                    .map_err(|_| format!("bad escape \\x{h}: use two hex digits"))?;
                out.push(b);
            }
            Some(other) => {
                return Err(format!(
                    "unknown escape \\{other}; use \\\\ for a backslash"
                ));
            }
            None => return Err("payload ends with a lone backslash".into()),
        }
    }
    Ok(out)
}

fn parse_hex(s: &str) -> Result<Vec<u8>, String> {
    let cleaned: String = s
        .split_whitespace()
        .map(|t| t.trim_start_matches("0x").trim_start_matches("0X"))
        .collect::<String>()
        .replace([':', '-', ','], "");
    if !cleaned.len().is_multiple_of(2) {
        return Err("hex payload has an odd number of digits".into());
    }
    (0..cleaned.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&cleaned[i..i + 2], 16)
                .map_err(|_| format!("not hex: {}", &cleaned[i..i + 2]))
        })
        .collect()
}

/// Printable view of bytes: ASCII as is, CR/LF/tab escaped, others `\xHH`.
pub fn text_view(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len());
    for &b in bytes {
        match b {
            b'\n' => s.push_str("\\n\n"),
            b'\r' => s.push_str("\\r"),
            b'\t' => s.push_str("\\t"),
            0x20..=0x7e => s.push(b as char),
            _ => s.push_str(&format!("\\x{b:02x}")),
        }
    }
    s
}

/// Classic hex dump: offset, 16 bytes in hex, ASCII column.
pub fn hex_view(bytes: &[u8]) -> String {
    bytes
        .chunks(16)
        .enumerate()
        .map(|(i, c)| {
            let hex: Vec<String> = c.iter().map(|b| format!("{b:02x}")).collect();
            let ascii: String = c
                .iter()
                .map(|&b| {
                    if (0x20..=0x7e).contains(&b) {
                        b as char
                    } else {
                        '.'
                    }
                })
                .collect();
            format!("{:08x}  {:<47}  {ascii}", i * 16, hex.join(" "))
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// A received chunk prepared for display.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Chunk {
    pub bytes: usize,
    pub text: String,
    pub hex: String,
    pub truncated: bool,
}

pub fn chunk(bytes: &[u8]) -> Chunk {
    let shown = &bytes[..bytes.len().min(PREVIEW_BYTES)];
    Chunk {
        bytes: bytes.len(),
        text: text_view(shown),
        hex: hex_view(shown),
        truncated: bytes.len() > PREVIEW_BYTES,
    }
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum Outcome {
    /// The TCP handshake completed.
    Connected,
    /// The target answered with a reset: reachable, nothing listening (or a
    /// device rejecting on its behalf).
    Refused,
    /// No answer within the timeout.
    TimedOut,
    /// Anything else (no route, unreachable, local error).
    Error,
}

/// Classify a failed connect.
pub fn classify(e: &std::io::Error) -> (Outcome, String) {
    use std::io::ErrorKind as K;
    match e.kind() {
        K::ConnectionRefused => (Outcome::Refused, "refused (RST received)".into()),
        K::TimedOut | K::WouldBlock => (Outcome::TimedOut, "no answer within the timeout".into()),
        K::HostUnreachable => (Outcome::Error, "host unreachable".into()),
        K::NetworkUnreachable => (Outcome::Error, "network unreachable (no route)".into()),
        K::AddrNotAvailable => (Outcome::Error, "local address not available".into()),
        K::PermissionDenied => (Outcome::Error, "blocked locally (permission denied)".into()),
        _ => (Outcome::Error, e.to_string()),
    }
}

#[derive(Debug, Clone, Default, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Stats {
    pub attempts: u32,
    pub connected: u32,
    pub refused: u32,
    pub timed_out: u32,
    pub errors: u32,
    pub min_ms: Option<f64>,
    pub avg_ms: Option<f64>,
    pub max_ms: Option<f64>,
    pub stddev_ms: Option<f64>,
    pub p95_ms: Option<f64>,
}

/// Statistics over attempts. Durations count only successful connects.
pub fn stats(results: &[(Outcome, f64)]) -> Stats {
    let mut s = Stats {
        attempts: results.len() as u32,
        ..Default::default()
    };
    let mut ok: Vec<f64> = Vec::new();
    for &(o, ms) in results {
        match o {
            Outcome::Connected => {
                s.connected += 1;
                ok.push(ms);
            }
            Outcome::Refused => s.refused += 1,
            Outcome::TimedOut => s.timed_out += 1,
            Outcome::Error => s.errors += 1,
        }
    }
    if !ok.is_empty() {
        ok.sort_by(|a, b| a.total_cmp(b));
        let n = ok.len() as f64;
        let avg = ok.iter().sum::<f64>() / n;
        let var = ok.iter().map(|x| (x - avg).powi(2)).sum::<f64>() / n;
        let idx = ((0.95 * n).ceil() as usize).clamp(1, ok.len()) - 1;
        s.min_ms = ok.first().copied();
        s.max_ms = ok.last().copied();
        s.avg_ms = Some(avg);
        s.stddev_ms = Some(var.sqrt());
        s.p95_ms = Some(ok[idx]);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_payloads() {
        assert_eq!(
            parse_payload("GET / HTTP/1.0\\r\\n\\r\\n", PayloadKind::Text).unwrap(),
            b"GET / HTTP/1.0\r\n\r\n"
        );
        assert_eq!(
            parse_payload("a\\x00\\xffb\\\\", PayloadKind::Text).unwrap(),
            b"a\x00\xffb\\"
        );
        assert_eq!(
            parse_payload("é", PayloadKind::Text).unwrap(),
            "é".as_bytes()
        );
        assert!(parse_payload("\\q", PayloadKind::Text).is_err());
        assert!(parse_payload("\\xZZ", PayloadKind::Text).is_err());
        assert!(parse_payload("end\\", PayloadKind::Text).is_err());
    }

    #[test]
    fn hex_payloads() {
        assert_eq!(
            parse_payload("de ad:be-ef 0x01", PayloadKind::Hex).unwrap(),
            vec![0xde, 0xad, 0xbe, 0xef, 0x01]
        );
        assert!(parse_payload("abc", PayloadKind::Hex).is_err());
        assert!(parse_payload("zz", PayloadKind::Hex).is_err());
        let big = "00".repeat(MAX_PAYLOAD + 1);
        assert!(
            parse_payload(&big, PayloadKind::Hex)
                .unwrap_err()
                .contains("larger")
        );
    }

    #[test]
    fn views() {
        assert_eq!(text_view(b"OK\r\n\x01"), "OK\\r\\n\n\\x01");
        let h = hex_view(b"ABCDEFGHIJKLMNOPQ");
        let lines: Vec<&str> = h.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].starts_with("00000000  41 42"));
        assert!(lines[0].ends_with("ABCDEFGHIJKLMNOP"));
        assert!(lines[1].starts_with("00000010  51"));
        let c = chunk(&vec![b'a'; PREVIEW_BYTES + 10]);
        assert!(c.truncated && c.bytes == PREVIEW_BYTES + 10);
    }

    #[test]
    fn timing_stats() {
        let r = [
            (Outcome::Connected, 10.0),
            (Outcome::Connected, 20.0),
            (Outcome::Connected, 30.0),
            (Outcome::Refused, 1.0),
            (Outcome::TimedOut, 3000.0),
        ];
        let s = stats(&r);
        assert_eq!(
            (s.attempts, s.connected, s.refused, s.timed_out, s.errors),
            (5, 3, 1, 1, 0)
        );
        assert_eq!(s.min_ms, Some(10.0));
        assert_eq!(s.max_ms, Some(30.0));
        assert_eq!(s.avg_ms, Some(20.0));
        assert_eq!(s.p95_ms, Some(30.0));
        assert!((s.stddev_ms.unwrap() - 8.1649).abs() < 0.001);
        let none = stats(&[(Outcome::TimedOut, 1.0)]);
        assert_eq!(none.avg_ms, None);
    }

    #[test]
    fn classification() {
        use std::io::{Error, ErrorKind};
        assert_eq!(
            classify(&Error::from(ErrorKind::ConnectionRefused)).0,
            Outcome::Refused
        );
        assert_eq!(
            classify(&Error::from(ErrorKind::TimedOut)).0,
            Outcome::TimedOut
        );
        assert_eq!(
            classify(&Error::from(ErrorKind::NetworkUnreachable)).0,
            Outcome::Error
        );
    }
}
