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
}
