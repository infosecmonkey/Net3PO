//! iperf3 driver logic with no process handling: validated argument lists,
//! version parsing, and parsing of iperf3's JSON output (`--json-stream`
//! events or whole `-J` documents). iperf3 output carries values reported by
//! the remote end, so every field is optional and bounded.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

/// Longest client test accepted, in seconds.
pub const MAX_DURATION: u32 = 600;
/// Most parallel streams (iperf3's own limit is 128).
pub const MAX_PARALLEL: u32 = 128;
/// Most omitted warm-up seconds.
pub const MAX_OMIT: u32 = 60;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum OptError {
    #[error("enter the iperf3 server's hostname or IP address")]
    NoHost,
    #[error("invalid server address")]
    BadHost,
    #[error("port must be 1 to 65535")]
    BadPort,
    #[error("duration must be 1 to {MAX_DURATION} seconds")]
    BadDuration,
    #[error("parallel streams must be 1 to {MAX_PARALLEL}")]
    BadParallel,
    #[error("omit must be 0 to {MAX_OMIT} seconds")]
    BadOmit,
    #[error("bitrate must look like 100M, 1.5G or 500K (bits per second)")]
    BadBitrate,
    #[error("this iperf3 ({0}) is too old for bidirectional tests; 3.7 or later is needed")]
    NoBidir(String),
}

/// An iperf3 version, as `iperf3 --version` prints it ("iperf 3.17.1 ...").
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct Version {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

impl Version {
    /// `--json-stream` (live per-interval JSON) arrived in 3.17.
    pub fn json_stream(&self) -> bool {
        (self.major, self.minor) >= (3, 17)
    }
    /// `--bidir` arrived in 3.7.
    pub fn bidir(&self) -> bool {
        (self.major, self.minor) >= (3, 7)
    }
}

/// Parse the first line of `iperf3 --version`. Only iperf 3.x is accepted
/// (iperf 2 has a different command line and no JSON output).
pub fn parse_version(text: &str) -> Option<Version> {
    let line = text.lines().next()?.trim();
    let rest = line.strip_prefix("iperf ")?;
    let ver = rest.split_whitespace().next()?;
    // Builds may append a suffix such as "3.9-mt" or "3.17.1+".
    let ver: String = ver
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    let mut it = ver.split('.').map(|p| p.parse::<u32>());
    let major = it.next()?.ok()?;
    let minor = it.next().and_then(Result::ok).unwrap_or(0);
    let patch = it.next().and_then(Result::ok).unwrap_or(0);
    (major == 3).then_some(Version {
        major,
        minor,
        patch,
    })
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    #[default]
    Tcp,
    Udp,
}

/// Which way data flows, from this computer's point of view.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    /// This computer sends (iperf3 default).
    #[default]
    Upload,
    /// The server sends (`-R`).
    Download,
    /// Both at once (`--bidir`).
    Both,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum Family {
    #[default]
    Auto,
    V4,
    V6,
}

/// Client test settings from the panel.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientOpts {
    pub host: String,
    pub port: u32,
    pub protocol: Protocol,
    pub direction: Direction,
    pub duration: u32,
    pub parallel: u32,
    /// Target bitrate (`-b`), empty for iperf3's default (1 Mbit/s for UDP,
    /// unlimited for TCP).
    pub bitrate: String,
    pub omit: u32,
    pub family: Family,
}

/// Server settings from the panel.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerOpts {
    pub port: u32,
    /// Exit after one test (`-1`).
    pub one_off: bool,
}

/// A host name or address that is safe to pass as one argument: it cannot
/// start with `-` (so it is never taken as an option) and holds only
/// characters valid in a name or an IP literal.
fn check_host(host: &str) -> Result<String, OptError> {
    let h = host.trim();
    if h.is_empty() {
        return Err(OptError::NoHost);
    }
    let h = h
        .strip_prefix('[')
        .and_then(|x| x.strip_suffix(']'))
        .unwrap_or(h);
    let ok = h.len() <= 253
        && !h.starts_with('-')
        && h.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':' | b'_' | b'%'));
    if ok {
        Ok(h.to_string())
    } else {
        Err(OptError::BadHost)
    }
}

fn check_port(p: u32) -> Result<String, OptError> {
    if (1..=65535).contains(&p) {
        Ok(p.to_string())
    } else {
        Err(OptError::BadPort)
    }
}

/// `100M`, `1.5G`, `500K` or a plain number of bits per second.
fn check_bitrate(b: &str) -> Result<Option<String>, OptError> {
    let b = b.trim();
    if b.is_empty() {
        return Ok(None);
    }
    let (num, unit) = match b.char_indices().last() {
        Some((i, c)) if c.is_ascii_alphabetic() => (&b[..i], Some(c.to_ascii_uppercase())),
        _ => (b, None),
    };
    let num_ok = !num.is_empty()
        && num.len() <= 12
        && num.bytes().all(|c| c.is_ascii_digit() || c == b'.')
        && num.bytes().filter(|&c| c == b'.').count() <= 1
        && num.parse::<f64>().is_ok_and(|v| v > 0.0);
    if !num_ok || !matches!(unit, None | Some('K' | 'M' | 'G' | 'T')) {
        return Err(OptError::BadBitrate);
    }
    Ok(Some(format!(
        "{num}{}",
        unit.map(String::from).unwrap_or_default()
    )))
}

/// The JSON output flag this version supports.
fn json_flag(v: &Version) -> &'static str {
    if v.json_stream() {
        "--json-stream"
    } else {
        "-J"
    }
}

/// Arguments for a client test. Each element is one argv entry; nothing is
/// passed through a shell.
pub fn client_args(o: &ClientOpts, v: &Version) -> Result<Vec<String>, OptError> {
    let host = check_host(&o.host)?;
    let port = check_port(o.port)?;
    if !(1..=MAX_DURATION).contains(&o.duration) {
        return Err(OptError::BadDuration);
    }
    if !(1..=MAX_PARALLEL).contains(&o.parallel) {
        return Err(OptError::BadParallel);
    }
    if o.omit > MAX_OMIT {
        return Err(OptError::BadOmit);
    }
    let bitrate = check_bitrate(&o.bitrate)?;
    let mut a: Vec<String> = vec![
        "-c".into(),
        host,
        "-p".into(),
        port,
        "-t".into(),
        o.duration.to_string(),
        "-i".into(),
        "1".into(),
        "-P".into(),
        o.parallel.to_string(),
    ];
    if o.protocol == Protocol::Udp {
        a.push("-u".into());
    }
    if let Some(b) = bitrate {
        a.push("-b".into());
        a.push(b);
    }
    match o.direction {
        Direction::Upload => {}
        Direction::Download => a.push("-R".into()),
        Direction::Both => {
            if !v.bidir() {
                return Err(OptError::NoBidir(v.to_string()));
            }
            a.push("--bidir".into());
        }
    }
    if o.omit > 0 {
        a.push("-O".into());
        a.push(o.omit.to_string());
    }
    match o.family {
        Family::Auto => {}
        Family::V4 => a.push("-4".into()),
        Family::V6 => a.push("-6".into()),
    }
    a.push(json_flag(v).into());
    Ok(a)
}

/// Arguments for server mode.
pub fn server_args(o: &ServerOpts, v: &Version) -> Result<Vec<String>, OptError> {
    let mut a = vec!["-s".into(), "-p".into(), check_port(o.port)?];
    if o.one_off {
        a.push("-1".into());
    }
    a.push(json_flag(v).into());
    Ok(a)
}

/// How long a client run may take before it is stopped: the test, the
/// warm-up, and time to connect and exchange results.
pub fn client_deadline_secs(o: &ClientOpts) -> u64 {
    u64::from(o.duration) + u64::from(o.omit) + 30
}

// ------------------------------------------------------------- results

/// One interval of one direction.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Point {
    pub start: f64,
    pub end: f64,
    pub bits_per_second: f64,
    pub bytes: u64,
    /// TCP sender only.
    pub retransmits: Option<u64>,
    /// UDP receiver only.
    pub jitter_ms: Option<f64>,
    pub lost_packets: Option<u64>,
    pub packets: Option<u64>,
    /// Warm-up interval excluded from the totals (`-O`).
    pub omitted: bool,
    /// True when this computer sent the data.
    pub local_sends: bool,
}

/// End-of-test totals for one direction.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DirResult {
    pub local_sends: bool,
    /// Rate at the sender.
    pub sent_bps: Option<f64>,
    /// Rate at the receiver: the throughput that actually arrived.
    pub received_bps: Option<f64>,
    pub sent_bytes: Option<u64>,
    pub received_bytes: Option<u64>,
    pub retransmits: Option<u64>,
    pub jitter_ms: Option<f64>,
    pub lost_packets: Option<u64>,
    pub packets: Option<u64>,
    pub lost_percent: Option<f64>,
}

/// What a test was, from its start event.
#[derive(Debug, Clone, Serialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct TestInfo {
    pub protocol: String,
    pub streams: u64,
    pub duration: u64,
    pub reverse: bool,
    pub bidir: bool,
    pub local: String,
    pub remote: String,
}

/// End-of-test summary.
#[derive(Debug, Clone, Serialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct Summary {
    pub directions: Vec<DirResult>,
    pub cpu_local: Option<f64>,
    pub cpu_remote: Option<f64>,
}

/// One item parsed from iperf3's output.
#[derive(Debug, Clone, PartialEq)]
pub enum Parsed {
    Start(TestInfo),
    Interval(Vec<Point>),
    End(Summary),
    Error(String),
}

fn f(v: &Value, k: &str) -> Option<f64> {
    v.get(k)?.as_f64().filter(|x| x.is_finite())
}

fn u(v: &Value, k: &str) -> Option<u64> {
    let x = v.get(k)?;
    x.as_u64().or_else(|| {
        x.as_f64()
            .filter(|f| f.is_finite() && *f >= 0.0)
            .map(|f| f as u64)
    })
}

fn b(v: &Value, k: &str) -> bool {
    match v.get(k) {
        Some(Value::Bool(x)) => *x,
        Some(Value::Number(n)) => n.as_u64().unwrap_or(0) != 0,
        _ => false,
    }
}

/// Bounded text from the remote side.
fn text(v: Option<&Value>) -> String {
    let s = match v {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Number(n)) => n.to_string(),
        _ => String::new(),
    };
    s.chars().filter(|c| !c.is_control()).take(300).collect()
}

fn point(sum: &Value) -> Option<Point> {
    Some(Point {
        start: f(sum, "start")?,
        end: f(sum, "end")?,
        bits_per_second: f(sum, "bits_per_second").unwrap_or(0.0),
        bytes: u(sum, "bytes").unwrap_or(0),
        retransmits: u(sum, "retransmits"),
        jitter_ms: f(sum, "jitter_ms"),
        lost_packets: u(sum, "lost_packets"),
        packets: u(sum, "packets"),
        omitted: b(sum, "omitted"),
        local_sends: b(sum, "sender"),
    })
}

fn interval(data: &Value) -> Vec<Point> {
    ["sum", "sum_bidir_reverse"]
        .iter()
        .filter_map(|k| data.get(*k).and_then(point))
        .collect()
}

fn start(data: &Value) -> TestInfo {
    let ts = data.get("test_start").cloned().unwrap_or(Value::Null);
    let conn = data
        .get("connected")
        .and_then(|c| c.as_array())
        .and_then(|a| a.first())
        .cloned()
        .unwrap_or(Value::Null);
    let hostport = |h: &str, p: &str| {
        let host = text(conn.get(h));
        if host.is_empty() {
            String::new()
        } else if host.contains(':') {
            format!("[{host}]:{}", text(conn.get(p)))
        } else {
            format!("{host}:{}", text(conn.get(p)))
        }
    };
    TestInfo {
        protocol: text(ts.get("protocol")),
        streams: u(&ts, "num_streams").unwrap_or(0),
        duration: u(&ts, "duration").unwrap_or(0),
        reverse: b(&ts, "reverse"),
        bidir: b(&ts, "bidir"),
        local: hostport("local_host", "local_port"),
        remote: hostport("remote_host", "remote_port"),
    }
}

fn dir_result(sent: Option<&Value>, recv: Option<&Value>) -> Option<DirResult> {
    let any = sent.or(recv)?;
    let pick_f = |k: &str| {
        recv.and_then(|r| f(r, k))
            .or_else(|| sent.and_then(|s| f(s, k)))
    };
    let pick_u = |k: &str| {
        recv.and_then(|r| u(r, k))
            .or_else(|| sent.and_then(|s| u(s, k)))
    };
    Some(DirResult {
        local_sends: b(any, "sender"),
        sent_bps: sent.and_then(|s| f(s, "bits_per_second")),
        received_bps: recv.and_then(|r| f(r, "bits_per_second")),
        sent_bytes: sent.and_then(|s| u(s, "bytes")),
        received_bytes: recv.and_then(|r| u(r, "bytes")),
        retransmits: sent.and_then(|s| u(s, "retransmits")),
        // Jitter and loss are measured by the receiver.
        jitter_ms: pick_f("jitter_ms"),
        lost_packets: pick_u("lost_packets"),
        packets: pick_u("packets"),
        lost_percent: pick_f("lost_percent"),
    })
}

fn end(data: &Value) -> Summary {
    let mut directions = Vec::new();
    if let Some(d) = dir_result(data.get("sum_sent"), data.get("sum_received")) {
        directions.push(d);
    } else if let Some(d) = dir_result(data.get("sum"), data.get("sum")) {
        // Older UDP output has a single "sum".
        directions.push(d);
    }
    if let Some(d) = dir_result(
        data.get("sum_sent_bidir_reverse"),
        data.get("sum_received_bidir_reverse"),
    ) {
        directions.push(d);
    }
    let cpu = data
        .get("cpu_utilization_percent")
        .cloned()
        .unwrap_or(Value::Null);
    Summary {
        directions,
        cpu_local: f(&cpu, "host_total"),
        cpu_remote: f(&cpu, "remote_total"),
    }
}

/// Interpret one JSON value from iperf3: a `--json-stream` event or a whole
/// `-J` document.
pub fn parse_value(v: &Value) -> Vec<Parsed> {
    if let Some(ev) = v.get("event").and_then(|e| e.as_str()) {
        let data = v.get("data").cloned().unwrap_or(Value::Null);
        return match ev {
            "start" => vec![Parsed::Start(start(&data))],
            "interval" => {
                let pts = interval(&data);
                if pts.is_empty() {
                    vec![]
                } else {
                    vec![Parsed::Interval(pts)]
                }
            }
            // A failed run ends with an empty "end" after its "error".
            "end" if data.as_object().is_some_and(|o| !o.is_empty()) => {
                vec![Parsed::End(end(&data))]
            }
            "error" => vec![Parsed::Error(text(Some(&data)))],
            _ => vec![],
        };
    }
    // A -J document: {"start": ..., "intervals": [...], "end": ..., "error"?}
    let mut out = Vec::new();
    if let Some(s) = v.get("start").filter(|s| s.get("test_start").is_some()) {
        out.push(Parsed::Start(start(s)));
    }
    if let Some(list) = v.get("intervals").and_then(|i| i.as_array()) {
        for i in list {
            let pts = interval(i);
            if !pts.is_empty() {
                out.push(Parsed::Interval(pts));
            }
        }
    }
    if let Some(e) = v
        .get("end")
        .filter(|e| e.as_object().is_some_and(|o| !o.is_empty()))
    {
        out.push(Parsed::End(end(e)));
    }
    if let Some(e) = v.get("error") {
        out.push(Parsed::Error(text(Some(e))));
    }
    out
}

/// Most output buffered while waiting for a JSON value to complete.
pub const MAX_PENDING: usize = 32 * 1024 * 1024;

/// What the reader pulled out of the bytes so far.
#[derive(Debug, PartialEq)]
pub enum Chunk {
    Json(Value),
    /// A line that is not JSON (warnings, server banners).
    Text(String),
}

/// Incremental reader for iperf3's stdout: complete JSON values (one per
/// line with `--json-stream`, or multi-line `-J` documents) and plain text
/// lines, in order.
#[derive(Default)]
pub struct Reader {
    buf: Vec<u8>,
}

impl Reader {
    /// Feed bytes; returns everything now complete. Errors when a single
    /// value would exceed [`MAX_PENDING`].
    pub fn push(&mut self, data: &[u8]) -> Result<Vec<Chunk>, String> {
        self.buf.extend_from_slice(data);
        let mut out = Vec::new();
        loop {
            // Skip leading whitespace.
            let skip = self
                .buf
                .iter()
                .take_while(|b| b.is_ascii_whitespace())
                .count();
            self.buf.drain(..skip);
            if self.buf.is_empty() {
                break;
            }
            if self.buf[0] == b'{' || self.buf[0] == b'[' {
                let mut it = serde_json::Deserializer::from_slice(&self.buf).into_iter::<Value>();
                match it.next() {
                    Some(Ok(v)) => {
                        let used = it.byte_offset();
                        self.buf.drain(..used);
                        out.push(Chunk::Json(v));
                        continue;
                    }
                    Some(Err(e)) if e.is_eof() => break,
                    // Not valid JSON after all: treat the line as text.
                    _ => {}
                }
            }
            match self.buf.iter().position(|&b| b == b'\n') {
                Some(i) => {
                    let line = String::from_utf8_lossy(&self.buf[..i]).trim().to_string();
                    self.buf.drain(..=i);
                    if !line.is_empty() {
                        out.push(Chunk::Text(line.chars().take(500).collect()));
                    }
                }
                None => break,
            }
        }
        if self.buf.len() > MAX_PENDING {
            self.buf.clear();
            return Err("iperf3 output too large".into());
        }
        Ok(out)
    }

    /// Whatever is left when the process exits.
    pub fn finish(&mut self) -> Option<String> {
        let rest = String::from_utf8_lossy(&self.buf).trim().to_string();
        self.buf.clear();
        (!rest.is_empty()).then(|| rest.chars().take(500).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const V322: Version = Version {
        major: 3,
        minor: 22,
        patch: 0,
    };
    const V39: Version = Version {
        major: 3,
        minor: 9,
        patch: 0,
    };
    const V36: Version = Version {
        major: 3,
        minor: 6,
        patch: 0,
    };

    fn opts() -> ClientOpts {
        ClientOpts {
            host: "iperf.example.net".into(),
            port: 5201,
            protocol: Protocol::Tcp,
            direction: Direction::Upload,
            duration: 10,
            parallel: 1,
            bitrate: String::new(),
            omit: 0,
            family: Family::Auto,
        }
    }

    #[test]
    fn versions() {
        assert_eq!(
            parse_version("iperf 3.22 (cJSON 1.7.15)\nDarwin ..."),
            Some(V322)
        );
        assert_eq!(parse_version("iperf 3.9\n"), Some(V39));
        assert_eq!(
            parse_version("iperf 3.17.1+ (cJSON 1.7.15)"),
            Some(Version {
                major: 3,
                minor: 17,
                patch: 1
            })
        );
        assert_eq!(
            parse_version("iperf version 2.1.9 (14 March 2023) pthreads"),
            None
        );
        assert_eq!(parse_version("iperf 2.0.5"), None);
        assert_eq!(parse_version(""), None);
        assert!(V322.json_stream() && !V39.json_stream());
        assert!(V39.bidir() && !V36.bidir());
    }

    #[test]
    fn client_arguments() {
        let a = client_args(&opts(), &V322).unwrap();
        assert_eq!(
            a.join(" "),
            "-c iperf.example.net -p 5201 -t 10 -i 1 -P 1 --json-stream"
        );
        let mut o = opts();
        o.protocol = Protocol::Udp;
        o.bitrate = "1.5g".into();
        o.direction = Direction::Download;
        o.omit = 2;
        o.parallel = 4;
        o.family = Family::V6;
        o.host = "[2001:db8::5]".into();
        assert_eq!(
            client_args(&o, &V39).unwrap().join(" "),
            "-c 2001:db8::5 -p 5201 -t 10 -i 1 -P 4 -u -b 1.5G -R -O 2 -6 -J"
        );
        o.direction = Direction::Both;
        assert!(
            client_args(&o, &V39)
                .unwrap()
                .contains(&"--bidir".to_string())
        );
        assert_eq!(
            client_args(&o, &V36),
            Err(OptError::NoBidir("3.6.0".into()))
        );
    }

    #[test]
    fn hostile_inputs_are_refused() {
        for (host, err) in [
            ("", OptError::NoHost),
            ("-s", OptError::BadHost),
            ("--logfile=/tmp/x", OptError::BadHost),
            ("host name", OptError::BadHost),
            ("a;rm -rf", OptError::BadHost),
            ("$(id)", OptError::BadHost),
        ] {
            let mut o = opts();
            o.host = host.into();
            assert_eq!(client_args(&o, &V322), Err(err), "{host}");
        }
        let mut o = opts();
        o.port = 0;
        assert_eq!(client_args(&o, &V322), Err(OptError::BadPort));
        o = opts();
        o.duration = MAX_DURATION + 1;
        assert_eq!(client_args(&o, &V322), Err(OptError::BadDuration));
        o = opts();
        o.parallel = 0;
        assert_eq!(client_args(&o, &V322), Err(OptError::BadParallel));
        for bad in ["fast", "10X", "-5M", "1.2.3M", "M", "0", "1e9"] {
            o = opts();
            o.bitrate = bad.into();
            assert_eq!(client_args(&o, &V322), Err(OptError::BadBitrate), "{bad}");
        }
        for good in ["100M", "500k", "2000000", "0.5G"] {
            o = opts();
            o.bitrate = good.into();
            assert!(client_args(&o, &V322).is_ok(), "{good}");
        }
    }

    #[test]
    fn server_arguments() {
        let s = server_args(
            &ServerOpts {
                port: 5201,
                one_off: true,
            },
            &V322,
        )
        .unwrap();
        assert_eq!(s.join(" "), "-s -p 5201 -1 --json-stream");
        let s = server_args(
            &ServerOpts {
                port: 5201,
                one_off: false,
            },
            &V39,
        )
        .unwrap();
        assert_eq!(s.join(" "), "-s -p 5201 -J");
        assert!(
            server_args(
                &ServerOpts {
                    port: 70000,
                    one_off: false
                },
                &V39
            )
            .is_err()
        );
    }

    fn read_all(text: &str) -> (Vec<Parsed>, Vec<String>) {
        let mut r = Reader::default();
        let mut parsed = Vec::new();
        let mut lines = Vec::new();
        // Feed in small pieces, as a pipe would deliver it.
        for chunk in text.as_bytes().chunks(97) {
            for c in r.push(chunk).unwrap() {
                match c {
                    Chunk::Json(v) => parsed.extend(parse_value(&v)),
                    Chunk::Text(t) => lines.push(t),
                }
            }
        }
        assert_eq!(r.finish(), None);
        (parsed, lines)
    }

    #[test]
    fn tcp_json_stream() {
        let (p, lines) = read_all(include_str!("fixtures/tcp.jsonl"));
        assert!(lines.is_empty());
        assert!(
            matches!(&p[0], Parsed::Start(i) if i.protocol == "TCP" && i.remote == "127.0.0.1:5299")
        );
        let ivs: Vec<_> = p
            .iter()
            .filter(|x| matches!(x, Parsed::Interval(_)))
            .collect();
        assert_eq!(ivs.len(), 2);
        let Parsed::End(s) = p.last().unwrap() else {
            panic!("no end")
        };
        assert_eq!(s.directions.len(), 1);
        let d = &s.directions[0];
        assert!(d.local_sends);
        assert!(d.received_bps.unwrap() > 1e9);
        assert_eq!(d.retransmits, Some(0));
        assert!(s.cpu_local.is_some() && s.cpu_remote.is_some());
    }

    #[test]
    fn udp_with_warning_lines() {
        let (p, lines) = read_all(include_str!("fixtures/udp.jsonl"));
        assert_eq!(lines.len(), 2, "{lines:?}");
        assert!(lines[0].starts_with("warning:"));
        let Parsed::End(s) = p.last().unwrap() else {
            panic!("no end")
        };
        let d = &s.directions[0];
        assert!(d.jitter_ms.is_some());
        assert_eq!(d.lost_packets, Some(0));
        assert!(d.packets.unwrap() > 0);
        assert_eq!(d.lost_percent, Some(0.0));
    }

    #[test]
    fn reverse_and_bidir() {
        let (p, _) = read_all(include_str!("fixtures/rev.jsonl"));
        let Parsed::End(s) = p.last().unwrap() else {
            panic!()
        };
        assert!(!s.directions[0].local_sends, "reverse: the server sends");
        assert!(matches!(&p[0], Parsed::Start(i) if i.reverse && i.streams == 2));

        let (p, _) = read_all(include_str!("fixtures/bidir.jsonl"));
        let Parsed::Interval(pts) = &p[1] else {
            panic!()
        };
        assert_eq!(pts.len(), 2);
        assert_ne!(pts[0].local_sends, pts[1].local_sends);
        let Parsed::End(s) = p.last().unwrap() else {
            panic!()
        };
        assert_eq!(s.directions.len(), 2);
        assert!(s.directions[0].local_sends && !s.directions[1].local_sends);
    }

    #[test]
    fn whole_json_document() {
        let (p, _) = read_all(include_str!("fixtures/tcp.json"));
        assert!(matches!(p[0], Parsed::Start(_)));
        assert_eq!(
            p.iter()
                .filter(|x| matches!(x, Parsed::Interval(_)))
                .count(),
            2
        );
        assert!(matches!(p.last(), Some(Parsed::End(_))));
    }

    #[test]
    fn errors_and_junk() {
        let text = "{\"event\":\"error\",\"data\":\"unable to connect to server: Connection refused\"}\n{\"event\":\"end\",\"data\":{}}\n";
        let (p, _) = read_all(text);
        assert_eq!(
            p,
            vec![Parsed::Error(
                "unable to connect to server: Connection refused".into()
            )]
        );

        // -J failure document.
        let (p, _) = read_all(
            "{\"start\":{\"connected\":[]},\"intervals\":[],\"end\":{},\"error\":\"error - unable to connect\"}\n",
        );
        assert_eq!(p, vec![Parsed::Error("error - unable to connect".into())]);

        // Broken JSON and stray text do not stop the reader.
        let (p, lines) = read_all("{not json\nplain line\n{\"event\":\"error\",\"data\":\"x\"}\n");
        assert_eq!(lines, vec!["{not json", "plain line"]);
        assert_eq!(p, vec![Parsed::Error("x".into())]);

        // Hostile values: control characters stripped, length capped.
        let long = format!(
            "{{\"event\":\"error\",\"data\":\"a\\u0007{}\"}}\n",
            "b".repeat(1000)
        );
        let (p, _) = read_all(&long);
        let Parsed::Error(e) = &p[0] else { panic!() };
        assert_eq!(e.len(), 300);
        assert!(!e.contains('\u{7}'));

        // Wrong types and NaN-free numbers never panic.
        let odd = r#"{"event":"interval","data":{"sum":{"start":"x","end":1}}}
{"event":"end","data":{"sum_sent":{"bits_per_second":"fast","sender":1},"sum_received":[]}}
"#;
        let (p, _) = read_all(odd);
        assert_eq!(p.len(), 1);
        let Parsed::End(s) = &p[0] else { panic!() };
        assert!(s.directions[0].local_sends);
        assert_eq!(s.directions[0].sent_bps, None);
    }

    #[test]
    fn reader_is_bounded() {
        let mut r = Reader::default();
        // An unterminated value larger than the cap is refused, not kept.
        let mut big = b"{\"a\":\"".to_vec();
        big.extend(std::iter::repeat_n(b'x', MAX_PENDING + 10));
        assert!(r.push(&big).is_err());
        assert_eq!(r.finish(), None);
    }

    #[test]
    fn deadline() {
        let mut o = opts();
        o.duration = 30;
        o.omit = 5;
        assert_eq!(client_deadline_secs(&o), 65);
    }
}
