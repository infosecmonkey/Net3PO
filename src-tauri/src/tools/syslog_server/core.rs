//! Pure syslog message parsing. Decodes the `<PRI>` into facility and severity
//! (present in both RFC 3164 and RFC 5424) and makes a best-effort pass at the
//! timestamp, host, and tag, falling back to treating the whole line as the
//! message. No network here, so it is unit tested directly.

use serde::Serialize;

/// A parsed syslog message. Structured fields are `None` when they could not be
/// determined; `raw` always holds the original text.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SyslogMessage {
    pub pri: Option<u8>,
    pub facility: Option<u8>,
    pub facility_name: Option<String>,
    pub severity: Option<u8>,
    pub severity_name: Option<String>,
    pub timestamp: Option<String>,
    pub host: Option<String>,
    pub tag: Option<String>,
    pub message: String,
    pub raw: String,
}

const FACILITIES: [&str; 24] = [
    "kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news", "uucp", "cron", "authpriv",
    "ftp", "ntp", "audit", "console", "cron2", "local0", "local1", "local2", "local3", "local4",
    "local5", "local6", "local7",
];

const SEVERITIES: [&str; 8] = [
    "emerg", "alert", "crit", "err", "warning", "notice", "info", "debug",
];

const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

pub fn facility_name(facility: u8) -> Option<&'static str> {
    FACILITIES.get(facility as usize).copied()
}

pub fn severity_name(severity: u8) -> Option<&'static str> {
    SEVERITIES.get(severity as usize).copied()
}

/// Parse a single syslog line.
pub fn parse(raw: &str) -> SyslogMessage {
    let trimmed = raw.trim_end_matches(['\r', '\n']);
    let mut msg = SyslogMessage {
        pri: None,
        facility: None,
        facility_name: None,
        severity: None,
        severity_name: None,
        timestamp: None,
        host: None,
        tag: None,
        message: trimmed.to_string(),
        raw: raw.to_string(),
    };

    // PRI: "<N>" with N in 0..=191.
    let rest = match parse_pri(trimmed) {
        Some((pri, rest)) => {
            let facility = pri / 8;
            let severity = pri % 8;
            msg.pri = Some(pri);
            msg.facility = Some(facility);
            msg.facility_name = facility_name(facility).map(String::from);
            msg.severity = Some(severity);
            msg.severity_name = severity_name(severity).map(String::from);
            rest
        }
        None => return msg,
    };

    // RFC 5424 begins with a version digit followed by a space ("1 ").
    if let Some(after_ver) = rest.strip_prefix("1 ") {
        parse_5424(after_ver, &mut msg);
    } else {
        parse_3164(rest, &mut msg);
    }
    msg
}

/// Parse `<N>` at the start, returning (pri, remainder).
fn parse_pri(s: &str) -> Option<(u8, &str)> {
    let s = s.strip_prefix('<')?;
    let end = s.find('>')?;
    let n: u16 = s[..end].parse().ok()?;
    if n > 191 {
        return None;
    }
    Some((n as u8, &s[end + 1..]))
}

fn nil(s: &str) -> Option<String> {
    if s == "-" || s.is_empty() {
        None
    } else {
        Some(s.to_string())
    }
}

/// RFC 5424: `VERSION TIMESTAMP HOST APP PROCID MSGID [SD] MSG` (version already
/// consumed). Structured data is left attached to the message in this pass.
fn parse_5424(s: &str, msg: &mut SyslogMessage) {
    let mut parts = s.splitn(6, ' ');
    msg.timestamp = parts.next().and_then(nil);
    msg.host = parts.next().and_then(nil);
    msg.tag = parts.next().and_then(nil);
    let _procid = parts.next();
    let _msgid = parts.next();
    // What remains is STRUCTURED-DATA followed by the message. Handle the common
    // nil case ("- "); real structured data is left attached to the message.
    let rest = parts.next().unwrap_or("");
    msg.message = if let Some(after) = rest.strip_prefix("- ") {
        after.to_string()
    } else if rest == "-" {
        String::new()
    } else {
        rest.to_string()
    };
}

/// RFC 3164 (BSD): `Mmm dd hh:mm:ss HOST TAG: MSG`. All fields are heuristic.
fn parse_3164(s: &str, msg: &mut SyslogMessage) {
    // A 3164 timestamp is exactly 15 chars: "Mmm dd hh:mm:ss".
    let has_ts = s.len() >= 16 && s.as_bytes()[15] == b' ' && MONTHS.contains(&&s[..3]);

    let after_ts = if has_ts {
        msg.timestamp = Some(s[..15].to_string());
        &s[16..]
    } else {
        s
    };

    // HOST is the next token; the rest is TAG: MSG.
    let mut parts = after_ts.splitn(2, ' ');
    let host = parts.next().unwrap_or("");
    let tail = parts.next().unwrap_or("");

    if has_ts && !host.is_empty() {
        msg.host = Some(host.to_string());
    }

    let body = if has_ts { tail } else { after_ts };
    if let Some(colon) = body.find(':') {
        let tag_raw = &body[..colon];
        // A tag has no spaces; if it does, this is not a real tag.
        if !tag_raw.is_empty() && !tag_raw.contains(' ') {
            // Strip a "[pid]" suffix.
            let tag = tag_raw.split('[').next().unwrap_or(tag_raw);
            msg.tag = Some(tag.to_string());
            msg.message = body[colon + 1..].trim_start().to_string();
            return;
        }
    }
    msg.message = body.to_string();
}

// --- Sender ---------------------------------------------------------------
//
// Generates realistic fake syslog messages for testing another server. Ported
// from Manny's syslog_sender.py. A small built-in PRNG keeps this dependency
// free and lets tests run deterministically with a fixed seed.

use serde::Deserialize;

/// SplitMix64 PRNG. Not cryptographic; just enough variety for test traffic.
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Rng(seed)
    }
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    /// Inclusive range [lo, hi].
    pub fn range(&mut self, lo: u64, hi: u64) -> u64 {
        lo + self.next_u64() % (hi - lo + 1)
    }
    pub fn choice<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[(self.next_u64() % items.len() as u64) as usize]
    }
    pub fn ratio(&mut self, p: f64) -> bool {
        (self.next_u64() >> 11) as f64 / ((1u64 << 53) as f64) < p
    }
}

/// What to send, mirroring the Python sender's options.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SendConfig {
    pub server: String,
    pub port: u16,
    pub proto: String,
    pub format: String,
    pub kind: String,
    pub count: u32,
    pub rate: f64,
    pub hostname: Option<String>,
    pub message: Option<String>,
    pub app: String,
    pub facility: String,
    pub severity: Option<u8>,
}

impl Default for SendConfig {
    fn default() -> Self {
        SendConfig {
            server: String::new(),
            port: 514,
            proto: "udp".to_string(),
            format: "3164".to_string(),
            kind: "mixed".to_string(),
            count: 20,
            rate: 2.0,
            hostname: None,
            message: None,
            app: "testapp".to_string(),
            facility: "local0".to_string(),
            severity: None,
        }
    }
}

const HOSTS: [&str; 7] = [
    "web01",
    "web02",
    "db01",
    "fw-edge01",
    "core-sw01",
    "vpn-gw",
    "app-srv03",
];
const USERS: [&str; 7] = [
    "admin",
    "jdoe",
    "msmith",
    "svc_backup",
    "root",
    "guest",
    "operator",
];

/// The message kinds the sender can generate.
pub const SEND_KINDS: [&str; 7] = ["mixed", "ssh", "sudo", "kernel", "cron", "app", "fortigate"];

/// Facility name to numeric code.
pub fn facility_index(name: &str) -> Option<u8> {
    FACILITIES.iter().position(|f| *f == name).map(|i| i as u8)
}

fn rand_ip(rng: &mut Rng, private: bool) -> String {
    if private {
        format!(
            "10.{}.{}.{}",
            rng.range(0, 255),
            rng.range(0, 255),
            rng.range(1, 254)
        )
    } else {
        format!(
            "{}.{}.{}.{}",
            rng.range(11, 223),
            rng.range(0, 255),
            rng.range(0, 255),
            rng.range(1, 254)
        )
    }
}

/// Generate one message: (app, facility code, severity, text).
fn generate(kind: &str, rng: &mut Rng) -> (&'static str, u8, u8, String) {
    let kind = if kind == "mixed" {
        *rng.choice(&SEND_KINDS[1..])
    } else {
        kind
    };
    match kind {
        "sudo" => {
            let user = *rng.choice(&USERS);
            let cmd = *rng.choice(&[
                "/usr/bin/systemctl restart nginx",
                "/bin/cat /etc/shadow",
                "/usr/bin/apt update",
            ]);
            (
                "sudo",
                10,
                5,
                format!("{user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND={cmd}"),
            )
        }
        "kernel" => {
            let opts: [(u8, String); 4] = [
                (4, "eth0: link down".to_string()),
                (6, "eth0: link up, 1000Mbps, full-duplex".to_string()),
                (
                    3,
                    format!(
                        "Out of memory: Killed process {} (java)",
                        rng.range(1000, 30000)
                    ),
                ),
                (
                    4,
                    format!(
                        "[UFW BLOCK] IN=eth0 OUT= SRC={} DST={} PROTO=TCP DPT={}",
                        rand_ip(rng, false),
                        rand_ip(rng, true),
                        rng.choice(&[22, 23, 445, 3389])
                    ),
                ),
            ];
            let (sev, msg) = rng.choice(&opts).clone();
            ("kernel", 0, sev, msg)
        }
        "cron" => {
            let user = *rng.choice(&["root", "svc_backup"]);
            (
                "CRON",
                9,
                6,
                format!("({user}) CMD (/usr/local/bin/backup.sh >/dev/null 2>&1)"),
            )
        }
        "app" => {
            let opts: [(u8, String); 4] = [
                (6, format!("GET /api/v1/health 200 {}ms", rng.range(1, 40))),
                (
                    4,
                    format!(
                        "Slow query detected: {}ms on table orders",
                        rng.range(1000, 9000)
                    ),
                ),
                (
                    3,
                    format!(
                        "Database connection pool exhausted (max={})",
                        rng.choice(&[20, 50, 100])
                    ),
                ),
                (
                    2,
                    "Unhandled exception in worker thread: NullReferenceException".to_string(),
                ),
            ];
            let (sev, msg) = rng.choice(&opts).clone();
            ("myapp", 16, sev, msg)
        }
        "fortigate" => {
            let action = *rng.choice(&["accept", "deny", "close", "timeout"]);
            let sev = if action == "deny" { 4 } else { 6 };
            let dport = *rng.choice(&[53, 80, 123, 443, 445, 3389, 8080]);
            let level = if sev == 4 { "warning" } else { "notice" };
            let msg = format!(
                "date=2024-01-01 time=00:00:00 devname=\"FGT-TEST01\" devid=\"FGT60FTK00000000\" \
                 logid=\"0000000013\" type=\"traffic\" subtype=\"forward\" level=\"{level}\" \
                 vd=\"root\" srcip={} srcport={} srcintf=\"port2\" dstip={} dstport={dport} \
                 dstintf=\"wan1\" proto=6 action=\"{action}\" policyid={} service=\"tcp/{dport}\" \
                 sentbyte={} rcvdbyte={} duration={}",
                rand_ip(rng, true),
                rng.range(1024, 65535),
                rand_ip(rng, false),
                rng.range(1, 50),
                rng.range(40, 90000),
                rng.range(0, 900000),
                rng.range(0, 300),
            );
            ("fortigate", 23, sev, msg)
        }
        // "ssh" and the default.
        _ => {
            let user = *rng.choice(&USERS);
            let ip = rand_ip(rng, false);
            let port = rng.range(30000, 65000);
            if rng.ratio(0.6) {
                (
                    "sshd",
                    4,
                    5,
                    format!("Failed password for {user} from {ip} port {port} ssh2"),
                )
            } else {
                (
                    "sshd",
                    4,
                    6,
                    format!("Accepted publickey for {user} from {ip} port {port} ssh2"),
                )
            }
        }
    }
}

/// Build one wire-ready syslog line and its severity, given the clock inputs.
pub fn build_line(cfg: &SendConfig, rng: &mut Rng, epoch_secs: u64, millis: u32) -> (String, u8) {
    let (app, facility, severity, msg) = match &cfg.message {
        Some(m) => (
            cfg.app.clone(),
            facility_index(&cfg.facility).unwrap_or(16),
            cfg.severity.unwrap_or(6),
            m.clone(),
        ),
        None => {
            let (a, f, s, m) = generate(&cfg.kind, rng);
            (a.to_string(), f, cfg.severity.unwrap_or(s), m)
        }
    };
    let pri = (facility as u16) * 8 + severity as u16;
    let host = cfg
        .hostname
        .clone()
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| rng.choice(&HOSTS).to_string());
    let pid = rng.range(100, 9999);

    let (y, mo, d, h, mi, s) = epoch_parts(epoch_secs);
    let line = if cfg.format == "5424" {
        let ts = format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}.{millis:03}Z");
        let msgid = format!("ID{}", rng.range(1, 99));
        format!("<{pri}>1 {ts} {host} {app} {pid} {msgid} - {msg}")
    } else {
        // RFC 3164: "Mmm _d HH:MM:SS" with a space-padded day.
        let ts = format!("{} {d:>2} {h:02}:{mi:02}:{s:02}", MONTHS[(mo - 1) as usize]);
        format!("<{pri}>{ts} {host} {app}[{pid}]: {msg}")
    };
    (line, severity)
}

/// Break a Unix epoch (UTC) into calendar parts (Howard Hinnant's algorithm).
fn epoch_parts(secs: u64) -> (i64, u32, u32, u64, u64, u64) {
    let days = (secs / 86400) as i64;
    let rem = secs % 86400;
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let mo = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    let year = if mo <= 2 { y + 1 } else { y };
    (year, mo, d, rem / 3600, (rem % 3600) / 60, rem % 60)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_pri_facility_severity() {
        let m = parse("<34>Oct 11 22:14:15 mymachine su: 'su root' failed for user");
        assert_eq!(m.pri, Some(34));
        assert_eq!(m.facility, Some(4));
        assert_eq!(m.facility_name.as_deref(), Some("auth"));
        assert_eq!(m.severity, Some(2));
        assert_eq!(m.severity_name.as_deref(), Some("crit"));
        assert_eq!(m.timestamp.as_deref(), Some("Oct 11 22:14:15"));
        assert_eq!(m.host.as_deref(), Some("mymachine"));
        assert_eq!(m.tag.as_deref(), Some("su"));
        assert_eq!(m.message, "'su root' failed for user");
    }

    #[test]
    fn parses_tag_with_pid() {
        let m = parse("<13>Jan  1 00:00:00 host sshd[1234]: accepted login");
        // Note: double space in "Jan  1" keeps the 15-char width.
        assert_eq!(m.tag.as_deref(), Some("sshd"));
        assert_eq!(m.message, "accepted login");
    }

    #[test]
    fn parses_rfc5424() {
        let m = parse(
            "<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 an application event",
        );
        assert_eq!(m.pri, Some(165));
        assert_eq!(m.facility, Some(20));
        assert_eq!(m.facility_name.as_deref(), Some("local4"));
        assert_eq!(m.severity, Some(5));
        assert_eq!(m.severity_name.as_deref(), Some("notice"));
        assert_eq!(m.timestamp.as_deref(), Some("2003-10-11T22:14:15.003Z"));
        assert_eq!(m.host.as_deref(), Some("mymachine.example.com"));
        assert_eq!(m.tag.as_deref(), Some("evntslog"));
        assert_eq!(m.message, "an application event");
    }

    #[test]
    fn rfc5424_nil_fields() {
        let m = parse("<34>1 - - - - - - just a message");
        assert_eq!(m.timestamp, None);
        assert_eq!(m.host, None);
        assert_eq!(m.tag, None);
        assert_eq!(m.message, "just a message");
    }

    #[test]
    fn no_pri_is_raw() {
        let m = parse("plain log line with no priority");
        assert_eq!(m.pri, None);
        assert_eq!(m.facility, None);
        assert_eq!(m.message, "plain log line with no priority");
    }

    #[test]
    fn invalid_pri_is_raw() {
        // 300 is out of range, so it is not treated as a PRI.
        let m = parse("<300>something");
        assert_eq!(m.pri, None);
        assert_eq!(m.message, "<300>something");
    }

    #[test]
    fn pri_without_recognizable_body() {
        let m = parse("<13>a short message without timestamp");
        assert_eq!(m.pri, Some(13));
        assert_eq!(m.timestamp, None);
        // No valid "tag:" so the whole remainder is the message.
        assert_eq!(m.message, "a short message without timestamp");
    }

    #[test]
    fn facility_severity_from_pri_zero() {
        let m = parse("<0>Jan  1 00:00:00 h k: kernel emergency");
        assert_eq!(m.facility_name.as_deref(), Some("kern"));
        assert_eq!(m.severity_name.as_deref(), Some("emerg"));
    }

    #[test]
    fn strips_trailing_newline_from_message_not_raw() {
        let m = parse("<13>hello\n");
        assert_eq!(m.message, "hello");
        assert_eq!(m.raw, "<13>hello\n");
    }

    // --- Sender ---

    #[test]
    fn facility_index_known() {
        assert_eq!(facility_index("kern"), Some(0));
        assert_eq!(facility_index("auth"), Some(4));
        assert_eq!(facility_index("local0"), Some(16));
        assert_eq!(facility_index("local7"), Some(23));
        assert_eq!(facility_index("nope"), None);
    }

    fn cfg() -> SendConfig {
        SendConfig::default()
    }

    #[test]
    fn epoch_parts_known() {
        // 1737718656 = 2025-01-24 11:37:36 UTC.
        assert_eq!(epoch_parts(1_737_718_656), (2025, 1, 24, 11, 37, 36));
    }

    #[test]
    fn build_custom_message_3164_roundtrips() {
        let mut c = cfg();
        c.message = Some("custom test message".to_string());
        c.app = "myapp".to_string();
        c.facility = "local0".to_string();
        let mut rng = Rng::new(1);
        let (line, sev) = build_line(&c, &mut rng, 1_737_718_656, 123);
        assert_eq!(sev, 6); // default severity for --message
        // Parsing it back with our own parser should recover the fields.
        let m = parse(&line);
        assert_eq!(m.facility_name.as_deref(), Some("local0"));
        assert_eq!(m.severity_name.as_deref(), Some("info"));
        assert_eq!(m.tag.as_deref(), Some("myapp"));
        assert_eq!(m.message, "custom test message");
    }

    #[test]
    fn build_5424_has_version_and_zulu_timestamp() {
        let mut c = cfg();
        c.format = "5424".to_string();
        c.message = Some("hi".to_string());
        let mut rng = Rng::new(2);
        let (line, _) = build_line(&c, &mut rng, 1_737_718_656, 5);
        assert!(line.contains(">1 2025-01-24T11:37:36.005Z "), "got: {line}");
        let m = parse(&line);
        assert_eq!(m.message, "hi");
    }

    #[test]
    fn generated_lines_parse_with_valid_severity() {
        // Every kind, across seeds, must produce a line our parser accepts with
        // a severity in range and a PRI present.
        for kind in SEND_KINDS {
            let mut c = cfg();
            c.kind = kind.to_string();
            for seed in 0..20 {
                let mut rng = Rng::new(seed);
                let (line, sev) = build_line(&c, &mut rng, 1_737_718_656, 0);
                assert!(sev < 8);
                let m = parse(&line);
                assert!(m.pri.is_some(), "no PRI for kind {kind}: {line}");
                assert_eq!(m.severity, Some(sev));
            }
        }
    }

    #[test]
    fn severity_override_applies() {
        let mut c = cfg();
        c.kind = "ssh".to_string();
        c.severity = Some(0);
        let mut rng = Rng::new(7);
        let (_, sev) = build_line(&c, &mut rng, 0, 0);
        assert_eq!(sev, 0);
    }
}
