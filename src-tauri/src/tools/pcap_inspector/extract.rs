//! Pull files and calls out of a capture: HTTP objects (responses and
//! uploads, with chunked and gzip/deflate bodies decoded), FTP and TFTP
//! transfers, and RTP voice streams in G.711 (saved as WAV). Everything in a
//! capture is hostile: memory is capped per stream and in total, header and
//! body sizes are bounded, decompression is capped, and nothing found here
//! is ever opened or executed. Encrypted traffic (HTTPS, FTPS, SRTP) cannot
//! be extracted.

use std::collections::{BTreeMap, HashMap};
use std::io::Read;
use std::net::IpAddr;

use etherparse::{LaxNetSlice, TransportSlice};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{decode, packets};

/// Most bytes buffered for one TCP direction or one transfer.
const MAX_FLOW: usize = 64 * 1024 * 1024;
/// Most bytes buffered across all streams during the read.
const MAX_BUFFERED: usize = 512 * 1024 * 1024;
/// Most bytes kept across all extracted objects.
const MAX_OUTPUT: usize = 512 * 1024 * 1024;
/// Largest decoded HTTP body.
const MAX_BODY: usize = 64 * 1024 * 1024;
/// Largest HTTP header block.
const MAX_HEADER: usize = 64 * 1024;
/// Most objects listed.
const MAX_OBJECTS: usize = 5000;
/// Most connections and streams tracked.
const MAX_TRACKED: usize = 100_000;
/// RTP streams shorter than this are not reported (avoids false matches).
const MIN_RTP_PACKETS: usize = 20;
/// Longest call decoded, in samples (4 hours at 8 kHz).
const MAX_RTP_SAMPLES: u64 = 8000 * 3600 * 4;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Options {
    pub http: bool,
    pub ftp: bool,
    pub tftp: bool,
    pub voice: bool,
    /// Decode gzip and deflate HTTP bodies.
    pub decompress: bool,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            http: true,
            ftp: true,
            tftp: true,
            voice: true,
            decompress: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Object {
    pub id: u32,
    /// "http", "ftp", "tftp" or "voice".
    pub kind: String,
    /// Suggested file name, already made safe.
    pub name: String,
    pub content_type: String,
    pub size: u64,
    /// `sender > receiver`.
    pub endpoints: String,
    pub detail: String,
    /// 1-based packet number where it starts.
    pub first_packet: u64,
    /// False when bytes are missing (lost packets, capture cut, size cap).
    pub complete: bool,
    pub sha256: String,
}

#[derive(Debug, Default)]
pub struct Extracted {
    pub objects: Vec<Object>,
    pub data: Vec<Vec<u8>>,
    pub warnings: Vec<String>,
    pub cancelled: bool,
}

type Endpoint = (IpAddr, u16);
/// Directional TCP flow: source, destination.
type Flow = (Endpoint, Endpoint);

fn ep(e: &Endpoint) -> String {
    match e.0 {
        IpAddr::V6(a) => format!("[{a}]:{}", e.1),
        IpAddr::V4(a) => format!("{a}:{}", e.1),
    }
}

fn canon(f: &Flow) -> Flow {
    if f.0 <= f.1 { *f } else { (f.1, f.0) }
}

// ------------------------------------------------------------- TCP

#[derive(Default)]
struct Stream {
    base: Option<u32>,
    segs: BTreeMap<u64, Vec<u8>>,
    bytes: usize,
    first_packet: u64,
    over: bool,
}

impl Stream {
    fn add(&mut self, seq: u32, syn: bool, payload: &[u8], budget: &mut usize) {
        if syn {
            self.base = Some(seq.wrapping_add(1));
        }
        if payload.is_empty() {
            return;
        }
        let base = *self.base.get_or_insert(seq);
        let rel = u64::from(seq.wrapping_sub(base));
        if rel > 1 << 31 {
            return; // before the start we know of
        }
        if self
            .segs
            .get(&rel)
            .is_some_and(|s| s.len() >= payload.len())
        {
            return; // retransmission
        }
        if self.bytes + payload.len() > MAX_FLOW || *budget < payload.len() {
            self.over = true;
            return;
        }
        self.bytes += payload.len();
        *budget -= payload.len();
        self.segs.insert(rel, payload.to_vec());
    }

    /// Contiguous bytes from the start; false when a gap or cap cut it.
    fn assemble(&self) -> (Vec<u8>, bool) {
        let mut out = Vec::with_capacity(self.bytes);
        let mut next = 0u64;
        let mut complete = !self.over;
        for (&rel, seg) in &self.segs {
            let end = rel + seg.len() as u64;
            if end <= next {
                continue;
            }
            if rel > next {
                complete = false;
                break;
            }
            out.extend_from_slice(&seg[(next - rel) as usize..]);
            next = end;
        }
        (out, complete)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Interest {
    Http,
    FtpControl,
    FtpData(usize),
    Ignore,
}

struct Conn {
    interest: Interest,
    streams: HashMap<Flow, Stream>,
    /// The direction that sent the first payload.
    first_dir: Option<Flow>,
}

#[derive(Default, Debug)]
struct FtpTransfer {
    /// Command and file name (`RETR x`, `STOR y`, `LIST`).
    command: String,
    name: Option<String>,
}

fn looks_http(p: &[u8]) -> bool {
    const STARTS: [&[u8]; 9] = [
        b"GET ",
        b"POST ",
        b"PUT ",
        b"HEAD ",
        b"DELETE ",
        b"OPTIONS ",
        b"PATCH ",
        b"CONNECT ",
        b"HTTP/1.",
    ];
    STARTS.iter().any(|s| p.starts_with(s))
}

// ------------------------------------------------------------- HTTP

struct Message {
    start: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    complete: bool,
}

impl Message {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Decode a chunked body; returns body, bytes consumed and completeness.
fn dechunk(d: &[u8]) -> (Vec<u8>, usize, bool) {
    let mut out = Vec::new();
    let mut p = 0;
    loop {
        let Some(nl) = find(&d[p..], b"\r\n") else {
            return (out, d.len(), false);
        };
        let line = String::from_utf8_lossy(&d[p..p + nl]);
        let size_text = line.split(';').next().unwrap_or("").trim();
        let Ok(size) = usize::from_str_radix(size_text, 16) else {
            return (out, d.len(), false);
        };
        p += nl + 2;
        if size == 0 {
            // Trailers end with an empty line.
            let end = find(&d[p..], b"\r\n").map(|i| p + i + 2).unwrap_or(d.len());
            return (out, end, true);
        }
        if p + size > d.len() || out.len() + size > MAX_BODY {
            let take = (d.len() - p).min(MAX_BODY.saturating_sub(out.len()));
            out.extend_from_slice(&d[p..p + take]);
            return (out, d.len(), false);
        }
        out.extend_from_slice(&d[p..p + size]);
        p += size + 2;
        if p > d.len() {
            return (out, d.len(), false);
        }
    }
}

/// Parse a run of HTTP messages from one direction of a connection.
/// `head_requests[i]` says the i-th request was HEAD (responses only).
fn messages(d: &[u8], response: bool, head_requests: &[bool]) -> Vec<Message> {
    let mut out = Vec::new();
    let mut p = 0;
    let mut paired = 0;
    while p < d.len() && out.len() < MAX_OBJECTS {
        let rest = &d[p..];
        if !looks_http(rest) {
            break;
        }
        let Some(hend) = find(&rest[..rest.len().min(MAX_HEADER)], b"\r\n\r\n") else {
            break;
        };
        let head = String::from_utf8_lossy(&rest[..hend]);
        let mut lines = head.split("\r\n");
        let start = lines.next().unwrap_or("").to_string();
        let headers: Vec<(String, String)> = lines
            .filter_map(|l| l.split_once(':'))
            .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
            .collect();
        let body_at = hend + 4;
        let body = &rest[body_at..];
        let mut msg = Message {
            start,
            headers,
            body: Vec::new(),
            complete: true,
        };
        let status: u16 = if response {
            msg.start
                .split_whitespace()
                .nth(1)
                .and_then(|s| s.parse().ok())
                .unwrap_or(0)
        } else {
            0
        };
        let informational = response && (100..200).contains(&status);
        let no_body = informational
            || status == 204
            || status == 304
            || (response && head_requests.get(paired).copied().unwrap_or(false));
        let chunked = msg
            .header("transfer-encoding")
            .is_some_and(|v| v.to_ascii_lowercase().contains("chunked"));
        let length: Option<usize> = msg.header("content-length").and_then(|v| v.parse().ok());
        let consumed = if no_body {
            0
        } else if chunked {
            let (b, used, ok) = dechunk(body);
            msg.body = b;
            msg.complete = ok;
            used
        } else if let Some(n) = length {
            let take = n.min(body.len()).min(MAX_BODY);
            msg.body = body[..take].to_vec();
            msg.complete = take == n;
            take
        } else if response {
            // Ends when the connection closes.
            let take = body.len().min(MAX_BODY);
            msg.body = body[..take].to_vec();
            body.len()
        } else {
            0
        };
        if !informational {
            paired += 1;
        }
        let incomplete = !msg.complete;
        out.push(msg);
        p += body_at + consumed;
        if incomplete {
            break;
        }
    }
    out
}

fn decode_body(m: &Message, decompress: bool) -> (Vec<u8>, Option<String>) {
    let enc = m
        .header("content-encoding")
        .unwrap_or("")
        .to_ascii_lowercase();
    if !decompress || enc.is_empty() || enc == "identity" {
        return (m.body.clone(), None);
    }
    let mut out = Vec::new();
    let res = match enc.as_str() {
        "gzip" | "x-gzip" => flate2::read::MultiGzDecoder::new(m.body.as_slice())
            .take(MAX_BODY as u64 + 1)
            .read_to_end(&mut out),
        "deflate" => {
            let r = flate2::read::ZlibDecoder::new(m.body.as_slice())
                .take(MAX_BODY as u64 + 1)
                .read_to_end(&mut out);
            if r.is_err() {
                out.clear();
                flate2::read::DeflateDecoder::new(m.body.as_slice())
                    .take(MAX_BODY as u64 + 1)
                    .read_to_end(&mut out)
            } else {
                r
            }
        }
        other => {
            return (
                m.body.clone(),
                Some(format!("{other} encoding not decoded")),
            );
        }
    };
    match res {
        Ok(_) if out.len() > MAX_BODY => (
            m.body.clone(),
            Some("decoded body over 64 MB; kept encoded".into()),
        ),
        Ok(_) => (out, None),
        Err(_) => (
            m.body.clone(),
            Some(format!("{enc} body could not be decoded; kept as sent")),
        ),
    }
}

fn ext_for(ctype: &str) -> &'static str {
    match ctype {
        "image/png" => "png",
        "image/jpeg" | "image/jpg" => "jpg",
        "image/gif" => "gif",
        "image/webp" => "webp",
        "image/svg+xml" => "svg",
        "image/x-icon" | "image/vnd.microsoft.icon" => "ico",
        "text/html" => "html",
        "text/plain" => "txt",
        "text/css" => "css",
        "text/xml" | "application/xml" => "xml",
        "application/json" => "json",
        "application/javascript" | "text/javascript" => "js",
        "application/pdf" => "pdf",
        "application/zip" => "zip",
        "application/gzip" | "application/x-gzip" => "gz",
        "audio/wav" | "audio/x-wav" => "wav",
        _ => "bin",
    }
}

/// A file name that is safe on every OS: no paths, no control or reserved
/// characters, no Windows device names, not hidden, at most 100 characters.
pub fn safe_name(raw: &str, fallback: &str, ext: &str) -> String {
    let base = raw.rsplit(['/', '\\']).next().unwrap_or("");
    let base = base.split(['?', '#']).next().unwrap_or("");
    let decoded = percent_decode(base);
    let mut s: String = decoded
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || "._-".contains(c) {
                c
            } else {
                '_'
            }
        })
        .collect();
    s = s
        .trim_matches(|c| c == '.' || c == '_' || c == ' ')
        .to_string();
    if s.is_empty() {
        s = fallback.to_string();
    }
    let stem = s.split('.').next().unwrap_or("").to_ascii_uppercase();
    let reserved = ["CON", "PRN", "AUX", "NUL"].contains(&stem.as_str())
        || ((stem.starts_with("COM") || stem.starts_with("LPT"))
            && stem.len() == 4
            && stem.as_bytes()[3].is_ascii_digit());
    if reserved {
        s = format!("_{s}");
    }
    if !s.contains('.') && !ext.is_empty() {
        s = format!("{s}.{ext}");
    }
    if s.len() > 100 {
        let (stem, e) = match s.rsplit_once('.') {
            Some((a, b)) if b.len() <= 10 => (a.to_string(), format!(".{b}")),
            _ => (s.clone(), String::new()),
        };
        s = format!("{}{e}", &stem[..100 - e.len()]);
    }
    s
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%'
            && i + 2 < b.len()
            && let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16)
        {
            out.push(v);
            i += 3;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn disposition_name(v: &str) -> Option<String> {
    let i = v.to_ascii_lowercase().find("filename=")?;
    let rest = &v[i + 9..];
    let name = rest
        .trim_start_matches('"')
        .split(['"', ';'])
        .next()?
        .trim();
    (!name.is_empty()).then(|| name.to_string())
}

// ------------------------------------------------------------- TFTP

struct Tftp {
    name: String,
    write: bool,
    blocks: BTreeMap<u32, Vec<u8>>,
    last: u32,
    blksize: usize,
    bytes: usize,
    done: bool,
    over: bool,
    first_packet: u64,
}

fn tftp_strings(p: &[u8]) -> Vec<String> {
    p.split(|b| *b == 0)
        .take(16)
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect()
}

fn blksize(parts: &[String]) -> Option<usize> {
    parts
        .windows(2)
        .find(|w| w[0].eq_ignore_ascii_case("blksize"))
        .and_then(|w| w[1].parse().ok())
        .filter(|n| (8..=65464).contains(n))
}

// ------------------------------------------------------------- RTP

struct Rtp {
    pt: u8,
    packets: Vec<(u64, u32, Vec<u8>)>,
    last_seq: Option<u16>,
    cycles: u64,
    bytes: usize,
    first_packet: u64,
    over: bool,
}

/// RTP payload of a UDP datagram carrying G.711, with header fields.
fn rtp_parse(p: &[u8]) -> Option<(u8, u16, u32, u32, &[u8])> {
    if p.len() < 13 || p[0] >> 6 != 2 {
        return None;
    }
    let pt = p[1] & 0x7f;
    if pt != 0 && pt != 8 {
        return None;
    }
    let cc = usize::from(p[0] & 0x0f);
    let mut hdr = 12 + 4 * cc;
    if p[0] & 0x10 != 0 {
        let len = usize::from(u16::from_be_bytes([*p.get(hdr + 2)?, *p.get(hdr + 3)?]));
        hdr += 4 + len * 4;
    }
    let mut end = p.len();
    if p[0] & 0x20 != 0 {
        end = end.checked_sub(usize::from(*p.last()?))?;
    }
    if hdr >= end {
        return None;
    }
    let seq = u16::from_be_bytes([p[2], p[3]]);
    let ts = u32::from_be_bytes([p[4], p[5], p[6], p[7]]);
    let ssrc = u32::from_be_bytes([p[8], p[9], p[10], p[11]]);
    Some((pt, seq, ts, ssrc, &p[hdr..end]))
}

/// ITU-T G.711 mu-law to linear PCM.
pub fn ulaw(u: u8) -> i16 {
    let u = !u;
    let t = ((i32::from(u & 0x0f) << 3) + 0x84) << ((u & 0x70) >> 4);
    (if u & 0x80 != 0 { 0x84 - t } else { t - 0x84 }) as i16
}

/// ITU-T G.711 A-law to linear PCM.
pub fn alaw(a: u8) -> i16 {
    let a = a ^ 0x55;
    let mut t = i32::from(a & 0x0f) << 4;
    let seg = (a & 0x70) >> 4;
    match seg {
        0 => t += 8,
        1 => t += 0x108,
        _ => t = (t + 0x108) << (seg - 1),
    }
    (if a & 0x80 != 0 { t } else { -t }) as i16
}

/// 16-bit mono PCM WAV.
pub fn wav(samples: &[i16], rate: u32) -> Vec<u8> {
    let data_len = (samples.len() * 2) as u32;
    let mut o = Vec::with_capacity(44 + samples.len() * 2);
    o.extend_from_slice(b"RIFF");
    o.extend_from_slice(&(36 + data_len).to_le_bytes());
    o.extend_from_slice(b"WAVEfmt ");
    o.extend_from_slice(&16u32.to_le_bytes());
    o.extend_from_slice(&1u16.to_le_bytes());
    o.extend_from_slice(&1u16.to_le_bytes());
    o.extend_from_slice(&rate.to_le_bytes());
    o.extend_from_slice(&(rate * 2).to_le_bytes());
    o.extend_from_slice(&2u16.to_le_bytes());
    o.extend_from_slice(&16u16.to_le_bytes());
    o.extend_from_slice(b"data");
    o.extend_from_slice(&data_len.to_le_bytes());
    for s in samples {
        o.extend_from_slice(&s.to_le_bytes());
    }
    o
}

// ------------------------------------------------------------- driver

struct Extractor {
    opts: Options,
    budget: usize,
    syn: HashMap<Flow, u32>,
    conns: HashMap<Flow, Conn>,
    ftp: Vec<FtpTransfer>,
    /// Data endpoints announced on FTP control connections.
    expected: HashMap<Endpoint, usize>,
    /// Per control connection, the transfer waiting for its command.
    ftp_pending: HashMap<Flow, usize>,
    tftp: HashMap<(IpAddr, u16, IpAddr), Tftp>,
    rtp: HashMap<(Endpoint, Endpoint, u32), Rtp>,
    capped: bool,
}

impl Extractor {
    fn packet(&mut self, n: u64, link: i32, data: &[u8]) {
        let Ok(pkt) = decode::slice(link, data) else {
            return;
        };
        let (src, dst) = match &pkt.net {
            Some(LaxNetSlice::Ipv4(v4)) => {
                if v4.payload().fragmented {
                    return;
                }
                let h = v4.header();
                (
                    IpAddr::V4(h.source_addr()),
                    IpAddr::V4(h.destination_addr()),
                )
            }
            Some(LaxNetSlice::Ipv6(v6)) => {
                if v6.payload().fragmented {
                    return;
                }
                let h = v6.header();
                (
                    IpAddr::V6(h.source_addr()),
                    IpAddr::V6(h.destination_addr()),
                )
            }
            _ => return,
        };
        match &pkt.transport {
            Some(TransportSlice::Tcp(t)) if self.opts.http || self.opts.ftp => {
                let flow = ((src, t.source_port()), (dst, t.destination_port()));
                self.tcp(n, flow, t.sequence_number(), t.syn(), t.payload());
            }
            Some(TransportSlice::Udp(u)) => {
                let flow = ((src, u.source_port()), (dst, u.destination_port()));
                if self.opts.tftp {
                    self.tftp_packet(n, flow, u.payload());
                }
                if self.opts.voice {
                    self.rtp_packet(n, flow, u.payload());
                }
            }
            _ => {}
        }
    }

    fn tcp(&mut self, n: u64, flow: Flow, seq: u32, syn: bool, payload: &[u8]) {
        let key = canon(&flow);
        if syn && self.syn.len() < MAX_TRACKED {
            self.syn.insert(flow, seq);
        }
        if !self.conns.contains_key(&key) {
            let interest = if self.opts.ftp && (flow.0.1 == 21 || flow.1.1 == 21) {
                Some(Interest::FtpControl)
            } else if let Some(i) = self
                .expected
                .get(&flow.0)
                .or_else(|| self.expected.get(&flow.1))
                .copied()
                .filter(|_| self.opts.ftp)
            {
                self.expected.retain(|_, v| *v != i);
                Some(Interest::FtpData(i))
            } else if payload.is_empty() {
                None
            } else if self.opts.http && looks_http(payload) {
                Some(Interest::Http)
            } else {
                Some(Interest::Ignore)
            };
            let Some(interest) = interest else {
                return;
            };
            if self.conns.len() >= MAX_TRACKED {
                self.capped = true;
                return;
            }
            self.conns.insert(
                key,
                Conn {
                    interest,
                    streams: HashMap::new(),
                    first_dir: None,
                },
            );
        }
        let Some(conn) = self.conns.get_mut(&key) else {
            return;
        };
        if conn.interest == Interest::Ignore {
            return;
        }
        if conn.first_dir.is_none() && !payload.is_empty() {
            conn.first_dir = Some(flow);
        }
        let interest = conn.interest;
        let syn_seq = self.syn.get(&flow).copied();
        let stream = conn.streams.entry(flow).or_insert_with(|| Stream {
            base: syn_seq.map(|s| s.wrapping_add(1)),
            first_packet: n,
            ..Default::default()
        });
        let before = stream.over;
        stream.add(seq, syn, payload, &mut self.budget);
        if stream.over && !before {
            self.capped = true;
        }
        if interest == Interest::FtpControl && !payload.is_empty() {
            self.ftp_control(flow, payload);
        }
    }

    /// Follow FTP commands and replies in arrival order.
    fn ftp_control(&mut self, flow: Flow, payload: &[u8]) {
        let text = String::from_utf8_lossy(payload);
        let to_server = flow.1.1 == 21;
        let ctrl = canon(&flow);
        let server_ip = if to_server { flow.1.0 } else { flow.0.0 };
        for line in text.lines() {
            let line = line.trim();
            let upper = line.to_ascii_uppercase();
            let mut endpoint: Option<Endpoint> = None;
            if to_server {
                if let Some(rest) = upper.strip_prefix("PORT ") {
                    endpoint = parse_hostport(rest);
                } else if let Some(rest) = line.get(5..).filter(|_| upper.starts_with("EPRT ")) {
                    let parts: Vec<&str> = rest.split('|').collect();
                    if parts.len() >= 4 {
                        endpoint = parts[2].parse().ok().zip(parts[3].parse().ok());
                    }
                } else {
                    let cmd = upper.split_whitespace().next().unwrap_or("");
                    if matches!(
                        cmd,
                        "RETR" | "STOR" | "STOU" | "APPE" | "LIST" | "NLST" | "MLSD"
                    ) {
                        let name = line
                            .get(cmd.len()..)
                            .map(str::trim)
                            .filter(|s| !s.is_empty());
                        let idx = match self.ftp_pending.remove(&ctrl) {
                            Some(i) => i,
                            None => {
                                self.ftp.push(FtpTransfer::default());
                                self.ftp.len() - 1
                            }
                        };
                        let t = &mut self.ftp[idx];
                        t.command = match name {
                            Some(nm) => format!("{cmd} {nm}"),
                            None => cmd.to_string(),
                        };
                        t.name = name.map(str::to_string).or_else(|| {
                            matches!(cmd, "LIST" | "NLST" | "MLSD").then(|| "listing.txt".into())
                        });
                    }
                }
            } else if upper.starts_with("227") {
                if let (Some(a), Some(b)) = (line.find('('), line.find(')')) {
                    endpoint = parse_hostport(&line[a + 1..b])
                        .map(|(ip, port)| (if ip.is_unspecified() { server_ip } else { ip }, port));
                }
            } else if upper.starts_with("229")
                && let (Some(a), Some(b)) = (line.find("(|||"), line.rfind("|)"))
                && a + 4 <= b
            {
                endpoint = line[a + 4..b].parse().ok().map(|p| (server_ip, p));
            }
            if let Some(e) = endpoint
                && self.ftp.len() < MAX_OBJECTS
            {
                self.ftp.push(FtpTransfer::default());
                let idx = self.ftp.len() - 1;
                self.expected.insert(e, idx);
                self.ftp_pending.insert(ctrl, idx);
            }
        }
    }

    fn tftp_packet(&mut self, n: u64, flow: Flow, p: &[u8]) {
        if p.len() < 4 {
            return;
        }
        let op = u16::from_be_bytes([p[0], p[1]]);
        match op {
            1 | 2 if flow.1.1 == 69 => {
                let parts = tftp_strings(&p[2..]);
                if parts.len() < 2 || self.tftp.len() >= MAX_TRACKED {
                    return;
                }
                self.tftp.insert(
                    (flow.0.0, flow.0.1, flow.1.0),
                    Tftp {
                        name: parts[0].clone(),
                        write: op == 2,
                        blocks: BTreeMap::new(),
                        last: 0,
                        blksize: blksize(&parts[2..]).unwrap_or(512),
                        bytes: 0,
                        done: false,
                        over: false,
                        first_packet: n,
                    },
                );
            }
            3 | 6 => {
                // Server to client (read), or client to server (write).
                let key_read = (flow.1.0, flow.1.1, flow.0.0);
                let key_write = (flow.0.0, flow.0.1, flow.1.0);
                let key = if self.tftp.get(&key_read).is_some_and(|t| !t.write) {
                    key_read
                } else if self.tftp.get(&key_write).is_some_and(|t| t.write) {
                    key_write
                } else if op == 6 && self.tftp.contains_key(&key_read) {
                    key_read
                } else {
                    return;
                };
                let budget = &mut self.budget;
                let Some(t) = self.tftp.get_mut(&key) else {
                    return;
                };
                if op == 6 {
                    if let Some(b) = blksize(&tftp_strings(&p[2..])) {
                        t.blksize = b;
                    }
                    return;
                }
                let block = u32::from(u16::from_be_bytes([p[2], p[3]]));
                // Block numbers wrap after 65535.
                let mut ext = (t.last & !0xffff) | block;
                if ext + 0x8000 < t.last {
                    ext += 0x1_0000;
                }
                let data = &p[4..];
                if !t.blocks.contains_key(&ext) {
                    if t.bytes + data.len() > MAX_FLOW || *budget < data.len() {
                        t.over = true;
                        self.capped = true;
                        return;
                    }
                    t.bytes += data.len();
                    *budget -= data.len();
                    t.blocks.insert(ext, data.to_vec());
                }
                t.last = t.last.max(ext);
                if data.len() < t.blksize {
                    t.done = true;
                }
            }
            _ => {}
        }
    }

    fn rtp_packet(&mut self, n: u64, flow: Flow, p: &[u8]) {
        const SKIP: [u16; 12] = [53, 67, 68, 69, 123, 137, 138, 161, 162, 500, 514, 5353];
        if SKIP.contains(&flow.0.1) || SKIP.contains(&flow.1.1) {
            return;
        }
        let Some((pt, seq, ts, ssrc, payload)) = rtp_parse(p) else {
            return;
        };
        let key = (flow.0, flow.1, ssrc);
        if !self.rtp.contains_key(&key) && self.rtp.len() >= MAX_TRACKED {
            return;
        }
        let s = self.rtp.entry(key).or_insert_with(|| Rtp {
            pt,
            packets: Vec::new(),
            last_seq: None,
            cycles: 0,
            bytes: 0,
            first_packet: n,
            over: false,
        });
        if s.pt != pt || s.over {
            return;
        }
        if let Some(last) = s.last_seq
            && seq < 0x1000
            && last > 0xf000
        {
            s.cycles += 1;
        }
        s.last_seq = Some(seq);
        if s.bytes + payload.len() > MAX_FLOW || self.budget < payload.len() {
            s.over = true;
            self.capped = true;
            return;
        }
        s.bytes += payload.len();
        self.budget -= payload.len();
        s.packets
            .push(((s.cycles << 16) | u64::from(seq), ts, payload.to_vec()));
    }

    fn finish(self, out: &mut Extracted) {
        let mut found: Vec<(Object, Vec<u8>)> = Vec::new();
        let mut kept = 0usize;
        let mut push = |found: &mut Vec<(Object, Vec<u8>)>, o: Object, d: Vec<u8>| {
            if found.len() < MAX_OBJECTS && kept + d.len() <= MAX_OUTPUT {
                kept += d.len();
                found.push((o, d));
                true
            } else {
                false
            }
        };
        let mut dropped = 0usize;

        for conn in self.conns.values() {
            match conn.interest {
                Interest::Http => {
                    let Some(client) = conn.first_dir else {
                        continue;
                    };
                    let server = (client.1, client.0);
                    let (req_bytes, req_ok) = conn
                        .streams
                        .get(&client)
                        .map(Stream::assemble)
                        .unwrap_or_default();
                    let (resp_bytes, resp_ok) = conn
                        .streams
                        .get(&server)
                        .map(Stream::assemble)
                        .unwrap_or_default();
                    let reqs = messages(&req_bytes, false, &[]);
                    let heads: Vec<bool> =
                        reqs.iter().map(|r| r.start.starts_with("HEAD ")).collect();
                    let resps = messages(&resp_bytes, true, &heads);
                    let first_req = conn
                        .streams
                        .get(&client)
                        .map(|s| s.first_packet)
                        .unwrap_or(0);
                    let first_resp = conn
                        .streams
                        .get(&server)
                        .map(|s| s.first_packet)
                        .unwrap_or(0);
                    for r in &reqs {
                        if r.body.is_empty() {
                            continue;
                        }
                        let o = self.http_object(r, r, "upload", &client, first_req, req_ok);
                        if !push(&mut found, o.0, o.1) {
                            dropped += 1;
                        }
                    }
                    let finals = resps.iter().filter(|m| {
                        let st: u16 = m
                            .start
                            .split_whitespace()
                            .nth(1)
                            .and_then(|s| s.parse().ok())
                            .unwrap_or(0);
                        !(100..200).contains(&st)
                    });
                    for (i, m) in finals.enumerate() {
                        if m.body.is_empty() {
                            continue;
                        }
                        let req = reqs.get(i);
                        let o =
                            self.http_object(m, req.unwrap_or(m), "", &server, first_resp, resp_ok);
                        if !push(&mut found, o.0, o.1) {
                            dropped += 1;
                        }
                    }
                }
                Interest::FtpData(idx) => {
                    let t = &self.ftp[idx];
                    // The direction that carried the data.
                    let Some((flow, s)) = conn.streams.iter().max_by_key(|(_, s)| s.bytes) else {
                        continue;
                    };
                    if s.bytes == 0 {
                        continue;
                    }
                    let (bytes, ok) = s.assemble();
                    let name = t.name.clone().unwrap_or_else(|| "ftp-data".into());
                    let o = Object {
                        id: 0,
                        kind: "ftp".into(),
                        name: safe_name(&name, "ftp-data", "bin"),
                        content_type: String::new(),
                        size: bytes.len() as u64,
                        endpoints: format!("{} > {}", ep(&flow.0), ep(&flow.1)),
                        detail: if t.command.is_empty() {
                            "FTP data (command not seen)".into()
                        } else {
                            t.command.clone()
                        },
                        first_packet: s.first_packet,
                        complete: ok,
                        sha256: String::new(),
                    };
                    if !push(&mut found, o, bytes) {
                        dropped += 1;
                    }
                }
                _ => {}
            }
        }

        for ((client, cport, server), t) in &self.tftp {
            if t.blocks.is_empty() {
                continue;
            }
            let mut bytes = Vec::with_capacity(t.bytes);
            let mut complete = t.done && !t.over;
            for (i, (blk, d)) in t.blocks.iter().enumerate() {
                if *blk != i as u32 + 1 {
                    complete = false;
                }
                bytes.extend_from_slice(d);
            }
            let (a, b) = if t.write {
                (ep(&(*client, *cport)), server.to_string())
            } else {
                (server.to_string(), ep(&(*client, *cport)))
            };
            let o = Object {
                id: 0,
                kind: "tftp".into(),
                name: safe_name(&t.name, "tftp-file", "bin"),
                content_type: String::new(),
                size: bytes.len() as u64,
                endpoints: format!("{a} > {b}"),
                detail: format!("{} {}", if t.write { "write" } else { "read" }, t.name),
                first_packet: t.first_packet,
                complete,
                sha256: String::new(),
            };
            if !push(&mut found, o, bytes) {
                dropped += 1;
            }
        }

        for ((src, dst, ssrc), s) in &self.rtp {
            if s.packets.len() < MIN_RTP_PACKETS {
                continue;
            }
            let mut pk: Vec<&(u64, u32, Vec<u8>)> = s.packets.iter().collect();
            pk.sort_by_key(|p| p.0);
            pk.dedup_by_key(|p| p.0);
            let (first_seq, last_seq) = (pk[0].0, pk[pk.len() - 1].0);
            let expected = last_seq - first_seq + 1;
            // Mostly increasing sequence numbers, or this is not a real stream.
            if (pk.len() as u64) * 2 < expected {
                continue;
            }
            let base_ts = pk[0].1;
            let mut samples: Vec<i16> = Vec::new();
            for p in &pk {
                let at = u64::from(p.1.wrapping_sub(base_ts));
                if at > MAX_RTP_SAMPLES {
                    continue;
                }
                let at = at as usize;
                let end = at + p.2.len();
                if samples.len() < end {
                    samples.resize(end, 0);
                }
                for (i, b) in p.2.iter().enumerate() {
                    samples[at + i] = if s.pt == 0 { ulaw(*b) } else { alaw(*b) };
                }
            }
            let lost = expected - pk.len() as u64;
            let secs = samples.len() as f64 / 8000.0;
            let codec = if s.pt == 0 {
                "G.711 mu-law (PCMU)"
            } else {
                "G.711 A-law (PCMA)"
            };
            let host = |a: &IpAddr| a.to_string().replace(['.', ':'], "-");
            let name = format!(
                "call-{}-{}-to-{}-{}-{ssrc:08x}.wav",
                host(&src.0),
                src.1,
                host(&dst.0),
                dst.1
            );
            let o = Object {
                id: 0,
                kind: "voice".into(),
                name: safe_name(&name, "call", "wav"),
                content_type: "audio/wav".into(),
                size: 0,
                endpoints: format!("{} > {}", ep(src), ep(dst)),
                detail: format!(
                    "{codec}, {secs:.1} s, {} packets, {lost} lost ({:.1}%)",
                    pk.len(),
                    lost as f64 * 100.0 / expected as f64
                ),
                first_packet: s.first_packet,
                complete: lost == 0 && !s.over,
                sha256: String::new(),
            };
            let bytes = wav(&samples, 8000);
            if !push(&mut found, o, bytes) {
                dropped += 1;
            }
        }

        found.sort_by_key(|(o, _)| o.first_packet);
        for (i, (mut o, d)) in found.into_iter().enumerate() {
            o.id = i as u32;
            o.size = d.len() as u64;
            o.sha256 = Sha256::digest(&d)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            out.objects.push(o);
            out.data.push(d);
        }
        if self.capped {
            out.warnings.push(
                "Some streams went over the memory limits (64 MB per stream, 512 MB in total); those objects are marked incomplete or left out.".into(),
            );
        }
        if dropped > 0 {
            out.warnings.push(format!(
                "{dropped} more objects were found but not kept (limit 5,000 objects or 512 MB)."
            ));
        }
    }

    fn http_object(
        &self,
        m: &Message,
        req: &Message,
        kind_note: &str,
        sender: &Flow,
        first_packet: u64,
        stream_ok: bool,
    ) -> (Object, Vec<u8>) {
        let (body, note) = decode_body(m, self.opts.decompress);
        let ctype = m
            .header("content-type")
            .unwrap_or("")
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        let mut parts = req.start.split_whitespace();
        let method = parts.next().unwrap_or("");
        let uri = parts.next().unwrap_or("");
        let host = req.header("host").unwrap_or("");
        let status = if std::ptr::eq(m, req) {
            String::new()
        } else {
            m.start.split_whitespace().nth(1).unwrap_or("").to_string()
        };
        let raw_name = m
            .header("content-disposition")
            .and_then(disposition_name)
            .unwrap_or_else(|| uri.to_string());
        let mut detail = format!("{method} {host}{uri}");
        if !status.is_empty() {
            detail.push_str(&format!(" {status}"));
        }
        if !kind_note.is_empty() {
            detail.push_str(&format!(" ({kind_note})"));
        }
        if let Some(n) = note {
            detail.push_str(&format!("; {n}"));
        }
        let o = Object {
            id: 0,
            kind: "http".into(),
            name: safe_name(&raw_name, "object", ext_for(&ctype)),
            content_type: ctype,
            size: 0,
            endpoints: format!("{} > {}", ep(&sender.0), ep(&sender.1)),
            detail,
            first_packet,
            complete: m.complete && stream_ok,
            sha256: String::new(),
        };
        (o, body)
    }
}

/// `h1,h2,h3,h4,p1,p2` from FTP PORT and 227 replies.
fn parse_hostport(s: &str) -> Option<Endpoint> {
    let n: Vec<u8> = s
        .split(',')
        .map(|x| x.trim().parse().ok())
        .collect::<Option<_>>()?;
    if n.len() != 6 {
        return None;
    }
    let ip = IpAddr::from([n[0], n[1], n[2], n[3]]);
    Some((ip, u16::from(n[4]) << 8 | u16::from(n[5])))
}

/// Read a capture and collect every object `opts` asks for.
pub fn extract<R: Read + Send>(
    input: R,
    opts: &Options,
    progress: impl FnMut(u64) -> bool,
) -> Result<Extracted, String> {
    let mut x = Extractor {
        opts: opts.clone(),
        budget: MAX_BUFFERED,
        syn: HashMap::new(),
        conns: HashMap::new(),
        ftp: Vec::new(),
        expected: HashMap::new(),
        ftp_pending: HashMap::new(),
        tftp: HashMap::new(),
        rtp: HashMap::new(),
        capped: false,
    };
    let mut n = 0u64;
    let info = packets::each_packet(
        input,
        |p| {
            n += 1;
            x.packet(n, p.link, p.data);
            true
        },
        progress,
    )?;
    let mut out = Extracted {
        warnings: info.warnings,
        cancelled: info.cancelled,
        ..Default::default()
    };
    x.finish(&mut out);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::super::core::tests::pcap;
    use super::*;
    use etherparse::PacketBuilder;
    use std::io::{Cursor, Write};

    const C: [u8; 4] = [10, 1, 1, 10];
    const S: [u8; 4] = [10, 1, 1, 20];

    fn tcp(
        src: [u8; 4],
        sp: u16,
        dst: [u8; 4],
        dp: u16,
        seq: u32,
        syn: bool,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut b = PacketBuilder::ethernet2([2, 0, 0, 0, 0, 1], [2, 0, 0, 0, 0, 2])
            .ipv4(src, dst, 64)
            .tcp(sp, dp, seq, 64240);
        if syn {
            b = b.syn();
        }
        let mut out = Vec::new();
        b.write(&mut out, payload).unwrap();
        out
    }

    fn udp(src: [u8; 4], sp: u16, dst: [u8; 4], dp: u16, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        PacketBuilder::ethernet2([2, 0, 0, 0, 0, 1], [2, 0, 0, 0, 0, 2])
            .ipv4(src, dst, 64)
            .udp(sp, dp)
            .write(&mut out, payload)
            .unwrap();
        out
    }

    fn run(frames: &[Vec<u8>]) -> Extracted {
        extract(
            Cursor::new(pcap(frames, 65535)),
            &Options::default(),
            |_| true,
        )
        .unwrap()
    }

    #[test]
    fn http_object_out_of_order_with_retransmit() {
        let png: Vec<u8> = b"\x89PNG\r\n\x1a\n"
            .iter()
            .copied()
            .chain(0..200u8)
            .collect();
        let req = b"GET /img/logo%20big.png?v=2 HTTP/1.1\r\nHost: www.example.com\r\n\r\n";
        let mut resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: image/png\r\nContent-Length: {}\r\n\r\n",
            png.len()
        )
        .into_bytes();
        resp.extend_from_slice(&png);
        let (a, b) = resp.split_at(60);
        let frames = vec![
            tcp(C, 50000, S, 80, 1000, true, b""),
            tcp(S, 80, C, 50000, 5000, true, b""),
            tcp(C, 50000, S, 80, 1001, false, req),
            tcp(S, 80, C, 50000, 5001 + 60, false, b), // out of order
            tcp(S, 80, C, 50000, 5001, false, a),
            tcp(S, 80, C, 50000, 5001, false, a), // retransmission
        ];
        let x = run(&frames);
        assert_eq!(x.objects.len(), 1, "{:?}", x.objects);
        let o = &x.objects[0];
        assert_eq!(o.kind, "http");
        assert_eq!(o.name, "logo_big.png");
        assert_eq!(o.content_type, "image/png");
        assert!(o.complete);
        assert_eq!(o.endpoints, "10.1.1.20:80 > 10.1.1.10:50000");
        assert!(
            o.detail
                .contains("GET www.example.com/img/logo%20big.png?v=2 200"),
            "{}",
            o.detail
        );
        assert_eq!(x.data[0], png);
        assert_eq!(o.sha256.len(), 64);
    }

    #[test]
    fn http_chunked_gzip_upload_and_pipelining() {
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(b"hello world, decoded").unwrap();
        let gz = gz.finish().unwrap();
        let mut resp = b"HTTP/1.1 100 Continue\r\n\r\n".to_vec();
        resp.extend_from_slice(b"HTTP/1.1 201 Created\r\nContent-Length: 2\r\n\r\nok");
        resp.extend_from_slice(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Encoding: gzip\r\nTransfer-Encoding: chunked\r\nContent-Disposition: attachment; filename=\"report.txt\"\r\n\r\n");
        let (h1, h2) = gz.split_at(10);
        resp.extend_from_slice(format!("{:x}\r\n", h1.len()).as_bytes());
        resp.extend_from_slice(h1);
        resp.extend_from_slice(format!("\r\n{:x};ext=1\r\n", h2.len()).as_bytes());
        resp.extend_from_slice(h2);
        resp.extend_from_slice(b"\r\n0\r\n\r\n");
        let mut req = b"POST /upload HTTP/1.1\r\nHost: files.example\r\nContent-Type: application/octet-stream\r\nContent-Length: 5\r\n\r\nABCDE".to_vec();
        req.extend_from_slice(b"GET /r HTTP/1.1\r\nHost: files.example\r\n\r\n");
        let frames = vec![
            tcp(C, 50001, S, 8080, 1, false, &req),
            tcp(S, 8080, C, 50001, 1, false, &resp),
        ];
        let x = run(&frames);
        let names: Vec<&str> = x.objects.iter().map(|o| o.name.as_str()).collect();
        assert!(names.contains(&"upload.bin"), "{names:?}");
        assert!(names.contains(&"report.txt"), "{names:?}");
        let i = x
            .objects
            .iter()
            .position(|o| o.name == "report.txt")
            .unwrap();
        assert_eq!(x.data[i], b"hello world, decoded");
        assert!(
            x.objects[i].detail.contains("GET files.example/r 200"),
            "{}",
            x.objects[i].detail
        );
        let u = x
            .objects
            .iter()
            .position(|o| o.name == "upload.bin")
            .unwrap();
        assert_eq!(x.data[u], b"ABCDE");
        // The 201 response body "ok" pairs with the POST.
        let ok = x
            .objects
            .iter()
            .position(|o| o.detail.contains("201"))
            .unwrap();
        assert!(x.objects[ok].detail.contains("POST"));
    }

    #[test]
    fn http_gap_marks_incomplete_and_https_is_ignored() {
        let body = vec![b'x'; 100];
        let mut resp = b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n".to_vec();
        resp.extend_from_slice(&body);
        let frames = vec![
            tcp(
                C,
                50002,
                S,
                80,
                1,
                false,
                b"GET /a HTTP/1.1\r\nHost: h\r\n\r\n",
            ),
            tcp(S, 80, C, 50002, 1, false, &resp[..50]),
            tcp(S, 80, C, 50002, 1 + 70, false, &resp[70..]),
            tcp(C, 50003, S, 443, 1, false, &[22, 3, 1, 0, 5, 1, 0, 0, 1, 0]),
        ];
        let x = run(&frames);
        assert_eq!(x.objects.len(), 1);
        assert!(!x.objects[0].complete);
    }

    #[test]
    fn ftp_passive_retr() {
        let file = b"firmware image bytes".to_vec();
        let frames = vec![
            tcp(S, 21, C, 40000, 1, false, b"220 ready\r\n"),
            tcp(C, 40000, S, 21, 1, false, b"PASV\r\n"),
            tcp(
                S,
                21,
                C,
                40000,
                12,
                false,
                b"227 Entering Passive Mode (10,1,1,20,195,80).\r\n",
            ),
            tcp(C, 40001, S, 50000, 99, true, b""),
            tcp(C, 40000, S, 21, 7, false, b"RETR fw/FGT_60F-v7.bin\r\n"),
            tcp(S, 50000, C, 40001, 1, false, &file),
        ];
        let x = run(&frames);
        assert_eq!(x.objects.len(), 1, "{:?}", x.objects);
        let o = &x.objects[0];
        assert_eq!(
            (o.kind.as_str(), o.name.as_str()),
            ("ftp", "FGT_60F-v7.bin")
        );
        assert_eq!(o.detail, "RETR fw/FGT_60F-v7.bin");
        assert_eq!(x.data[0], file);
        assert_eq!(
            parse_hostport("10,1,1,20,195,80"),
            Some((IpAddr::from([10, 1, 1, 20]), 50000))
        );
    }

    #[test]
    fn tftp_read_with_two_blocks() {
        let mut rrq = vec![0, 1];
        rrq.extend_from_slice(b"config.cfg\0octet\0");
        let block = |n: u16, d: &[u8]| {
            let mut p = vec![0, 3];
            p.extend_from_slice(&n.to_be_bytes());
            p.extend_from_slice(d);
            p
        };
        let one = vec![b'a'; 512];
        let frames = vec![
            udp(C, 3000, S, 69, &rrq),
            udp(S, 4000, C, 3000, &block(1, &one)),
            udp(S, 4000, C, 3000, &block(1, &one)),
            udp(S, 4000, C, 3000, &block(2, b"tail")),
        ];
        let x = run(&frames);
        assert_eq!(x.objects.len(), 1);
        let o = &x.objects[0];
        assert_eq!((o.kind.as_str(), o.name.as_str()), ("tftp", "config.cfg"));
        assert!(o.complete);
        assert_eq!(x.data[0].len(), 516);
    }

    #[test]
    fn rtp_pcmu_to_wav_with_loss() {
        let mut frames = Vec::new();
        for i in 0..30u16 {
            if i == 10 {
                continue; // lost
            }
            let mut p = vec![0x80, 0x00];
            p.extend_from_slice(&(100 + i).to_be_bytes());
            p.extend_from_slice(&(u32::from(i) * 160).to_be_bytes());
            p.extend_from_slice(&0xdead_beefu32.to_be_bytes());
            p.extend_from_slice(&[0xff; 160]);
            frames.push(udp(C, 16384, S, 16386, &p));
        }
        let x = run(&frames);
        assert_eq!(x.objects.len(), 1, "{:?}", x.objects);
        let o = &x.objects[0];
        assert_eq!(o.kind, "voice");
        assert!(o.name.ends_with("deadbeef.wav"), "{}", o.name);
        assert!(
            o.detail.contains("PCMU") && o.detail.contains("1 lost"),
            "{}",
            o.detail
        );
        assert!(!o.complete);
        let w = &x.data[0];
        assert_eq!(&w[..4], b"RIFF");
        assert_eq!(&w[8..16], b"WAVEfmt ");
        assert_eq!(w.len(), 44 + 30 * 160 * 2);
    }

    #[test]
    fn g711_tables() {
        assert_eq!(ulaw(0xff), 0);
        assert_eq!(ulaw(0x00), -32124);
        assert_eq!(ulaw(0x80), 32124);
        assert_eq!(alaw(0xd5), 8);
        assert_eq!(alaw(0x55), -8);
        assert_eq!(alaw(0xaa), 32256);
    }

    #[test]
    fn safe_names() {
        assert_eq!(safe_name("../../etc/passwd", "x", "bin"), "passwd.bin");
        assert_eq!(safe_name("C:\\Windows\\evil.exe", "x", ""), "evil.exe");
        assert_eq!(safe_name("CON", "x", "txt"), "_CON.txt");
        assert_eq!(safe_name("com1.log", "x", ""), "_com1.log");
        assert_eq!(safe_name(".hidden", "x", "bin"), "hidden.bin");
        assert_eq!(safe_name("/", "object", "html"), "object.html");
        assert_eq!(safe_name("a b<c>|d", "x", ""), "a_b_c__d");
        let long = safe_name(&format!("{}.png", "a".repeat(300)), "x", "");
        assert!(long.len() == 100 && long.ends_with(".png"));
        assert_eq!(
            disposition_name("attachment; filename=\"r.txt\""),
            Some("r.txt".into())
        );
    }

    #[test]
    fn hostile_input_is_bounded() {
        // Chunk sizes and lengths that lie, headers without an end, junk.
        let frames = vec![
            tcp(C, 1, S, 80, 1, false, b"GET / HTTP/1.1\r\nHost: h\r\n\r\n"),
            tcp(
                S,
                80,
                C,
                1,
                1,
                false,
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nffffffffff\r\nab",
            ),
            tcp(C, 2, S, 80, 1, false, b"GET / HTTP/1.1\r\nHost: h\r\n\r\n"),
            tcp(
                S,
                80,
                C,
                2,
                1,
                false,
                b"HTTP/1.1 200 OK\r\nContent-Length: 999999999999\r\n\r\nab",
            ),
            tcp(C, 3, S, 80, 1, false, b"GET / HTTP/1.1\r\nX: "),
            udp(C, 5, S, 69, &[0, 1]),
            udp(C, 5, S, 7000, &[0x80, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1]),
            udp(
                C,
                5,
                S,
                7000,
                &[0xbf, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0xff],
            ),
        ];
        let x = run(&frames);
        assert!(x.objects.iter().all(|o| !o.complete));
        assert!(extract(Cursor::new(b"junk".to_vec()), &Options::default(), |_| true).is_err());
    }
}
