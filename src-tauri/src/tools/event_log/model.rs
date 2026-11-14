//! The normalized event record shared by every import format, and the
//! conversion from the JSON shape the `evtx` crate produces (the XML import
//! builds the same shape). Original timestamps are kept as written next to a
//! normalized UTC value, so nothing is silently re-interpreted.

use serde::Serialize;
use serde_json::Value;

/// Longest raw record kept for the detail view.
pub const MAX_RAW: usize = 16 * 1024;
/// Longest single field value kept.
pub const MAX_FIELD: usize = 4 * 1024;
/// Most fields kept per record.
pub const MAX_FIELDS: usize = 200;

/// Security audit keyword bits.
const AUDIT_SUCCESS: u64 = 0x0020_0000_0000_0000;
const AUDIT_FAILURE: u64 = 0x0010_0000_0000_0000;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EventRecord {
    /// Position in the loaded set.
    pub index: u32,
    pub record_id: Option<u64>,
    /// Timestamp exactly as in the source.
    pub time_raw: String,
    /// Normalized UTC, in milliseconds, when the source carries a zone.
    pub time_utc_ms: Option<i64>,
    /// True when the source time has no zone (CSV exports in local time);
    /// `sort_ms` then holds that wall-clock time, not UTC.
    pub zone_unknown: bool,
    /// Ordering key: UTC when known, else the zoneless wall-clock time.
    pub sort_ms: i64,
    pub provider: String,
    pub channel: String,
    pub event_id: u32,
    /// 0 LogAlways, 1 Critical, 2 Error, 3 Warning, 4 Information, 5 Verbose.
    pub level: u8,
    /// "Audit Success", "Audit Failure" or empty.
    pub outcome: String,
    pub computer: String,
    pub user_sid: String,
    /// Event data fields as (name, value), in source order.
    pub fields: Vec<(String, String)>,
    /// Rendered message, when the export includes one (CSV).
    pub message: String,
    /// The record as imported (compact JSON, XML or CSV row), capped.
    pub raw: String,
}

impl EventRecord {
    pub fn level_name(&self) -> &'static str {
        level_name(self.level)
    }

    /// Value of a named field, case-insensitively.
    pub fn field(&self, name: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

pub fn level_name(level: u8) -> &'static str {
    match level {
        0 => "Information",
        1 => "Critical",
        2 => "Error",
        3 => "Warning",
        4 => "Information",
        5 => "Verbose",
        _ => "Other",
    }
}

/// Days since 1970-01-01 for a proleptic Gregorian date.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Milliseconds since the epoch for a wall-clock date and time.
pub fn wall_ms(y: i64, mo: i64, d: i64, h: i64, mi: i64, s: i64, ms: i64) -> Option<i64> {
    let ok = (1..=9999).contains(&y)
        && (1..=12).contains(&mo)
        && (1..=31).contains(&d)
        && (0..24).contains(&h)
        && (0..60).contains(&mi)
        && (0..61).contains(&s)
        && (0..1000).contains(&ms);
    ok.then(|| ((days_from_civil(y, mo, d) * 24 + h) * 60 + mi) * 60_000 + s * 1000 + ms)
}

fn num(s: &str) -> Option<i64> {
    (!s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
        .then(|| s.parse().ok())
        .flatten()
}

/// Parse an ISO 8601 / RFC 3339 timestamp such as
/// `2026-11-13T14:05:10.1234567Z` or `2026-11-13 09:05:10-05:00`. Returns
/// (milliseconds, true) when a zone is present (then UTC), or (wall-clock
/// milliseconds, false) when it is not.
pub fn parse_iso(s: &str) -> Option<(i64, bool)> {
    let s = s.trim();
    if s.len() < 19 {
        return None;
    }
    let (date, rest) = s.split_at(10);
    let mut dp = date.split('-');
    let (y, mo, d) = (num(dp.next()?)?, num(dp.next()?)?, num(dp.next()?)?);
    let rest = rest.strip_prefix(['T', 't', ' '])?;
    let (hh, mm, ss) = (
        num(rest.get(0..2)?)?,
        num(rest.get(3..5)?)?,
        num(rest.get(6..8)?)?,
    );
    if rest.get(2..3)? != ":" || rest.get(5..6)? != ":" {
        return None;
    }
    let mut tail = &rest[8..];
    let mut ms = 0;
    if let Some(frac) = tail.strip_prefix('.') {
        let digits: String = frac.chars().take_while(|c| c.is_ascii_digit()).collect();
        if digits.is_empty() {
            return None;
        }
        let first3: String = digits.chars().chain("000".chars()).take(3).collect();
        ms = first3.parse().ok()?;
        tail = &frac[digits.len()..];
    }
    let wall = wall_ms(y, mo, d, hh, mm, ss, ms)?;
    match tail {
        "" => Some((wall, false)),
        "Z" | "z" => Some((wall, true)),
        _ => {
            let sign = match tail.as_bytes().first()? {
                b'+' => 1,
                b'-' => -1,
                _ => return None,
            };
            let z = tail[1..].replace(':', "");
            if z.len() != 4 {
                return None;
            }
            let off = num(&z[..2])? * 60 + num(&z[2..])?;
            Some((wall - sign * off * 60_000, true))
        }
    }
}

/// Text of a JSON node: plain values, or `#text` of an attributed element.
pub fn text(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Object(o) => o.get("#text").map(text).unwrap_or_default(),
        Value::Array(a) => a.iter().map(text).collect::<Vec<_>>().join(", "),
        Value::Null => String::new(),
    }
}

/// Attribute of an element node: `{"#attributes": {"Name": ...}}`.
pub fn attr(v: &Value, name: &str) -> String {
    v.get("#attributes")
        .and_then(|a| a.get(name))
        .map(text)
        .unwrap_or_default()
}

fn clip(s: String, max: usize) -> String {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{} [cut]", &s[..end])
}

/// Flatten EventData / UserData into (name, value) pairs. Nested objects
/// become dotted names; `#attributes` are skipped.
pub fn flatten(prefix: &str, v: &Value, out: &mut Vec<(String, String)>) {
    if out.len() >= MAX_FIELDS {
        return;
    }
    match v {
        Value::Object(o) => {
            for (k, child) in o {
                if k == "#attributes" {
                    continue;
                }
                let name = if k == "#text" {
                    prefix.to_string()
                } else if prefix.is_empty() {
                    k.clone()
                } else {
                    format!("{prefix}.{k}")
                };
                flatten(&name, child, out);
            }
        }
        Value::Array(a) => {
            for (i, child) in a.iter().enumerate() {
                let name = if prefix.is_empty() {
                    format!("{i}")
                } else {
                    format!("{prefix}[{i}]")
                };
                flatten(&name, child, out);
            }
        }
        Value::Null => {}
        other => {
            let name = if prefix.is_empty() {
                "Data".to_string()
            } else {
                prefix.to_string()
            };
            out.push((name, clip(text(other), MAX_FIELD)));
        }
    }
}

/// Build a record from an `{"Event": {"System": ..., "EventData": ...}}`
/// value. `fallback_time` is used when System/TimeCreated is missing.
pub fn from_event_json(
    index: u32,
    v: &Value,
    record_id: Option<u64>,
    fallback_time: &str,
) -> EventRecord {
    let event = v.get("Event").unwrap_or(v);
    let sys = event.get("System").cloned().unwrap_or(Value::Null);
    let time_raw = {
        let t = sys
            .get("TimeCreated")
            .map(|t| attr(t, "SystemTime"))
            .unwrap_or_default();
        if t.is_empty() {
            fallback_time.to_string()
        } else {
            t
        }
    };
    let parsed = parse_iso(&time_raw);
    let keywords = sys
        .get("Keywords")
        .map(text)
        .and_then(|k| u64::from_str_radix(k.trim_start_matches("0x"), 16).ok())
        .unwrap_or(0);
    let outcome = if keywords & AUDIT_FAILURE != 0 {
        "Audit Failure"
    } else if keywords & AUDIT_SUCCESS != 0 {
        "Audit Success"
    } else {
        ""
    };
    let mut fields = Vec::new();
    for key in ["EventData", "UserData"] {
        if let Some(data) = event.get(key) {
            flatten("", data, &mut fields);
        }
    }
    let provider = sys
        .get("Provider")
        .map(|p| {
            let n = attr(p, "Name");
            if n.is_empty() {
                attr(p, "EventSourceName")
            } else {
                n
            }
        })
        .unwrap_or_default();
    EventRecord {
        index,
        record_id: record_id
            .or_else(|| sys.get("EventRecordID").and_then(|r| text(r).parse().ok())),
        time_utc_ms: parsed.filter(|(_, z)| *z).map(|(ms, _)| ms),
        zone_unknown: parsed.is_some_and(|(_, z)| !z),
        sort_ms: parsed.map(|(ms, _)| ms).unwrap_or(0),
        time_raw,
        provider,
        channel: sys.get("Channel").map(text).unwrap_or_default(),
        event_id: sys
            .get("EventID")
            .map(text)
            .and_then(|t| t.trim().parse().ok())
            .unwrap_or(0),
        level: sys
            .get("Level")
            .map(text)
            .and_then(|t| t.trim().parse().ok())
            .unwrap_or(0),
        outcome: outcome.to_string(),
        computer: sys.get("Computer").map(text).unwrap_or_default(),
        user_sid: sys
            .get("Security")
            .map(|s| attr(s, "UserID"))
            .unwrap_or_default(),
        fields,
        message: String::new(),
        raw: clip(serde_json::to_string(v).unwrap_or_default(), MAX_RAW),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn iso_times() {
        let (z, zoned) = parse_iso("2026-11-13T14:05:10.1234567Z").unwrap();
        assert!(zoned);
        assert_eq!(z, 1_794_578_710_123);
        let (o, zoned) = parse_iso("2026-11-13 09:05:10-05:00").unwrap();
        assert!(zoned);
        assert_eq!(o, 1_794_578_710_000);
        let (w, zoned) = parse_iso("2026-11-13T14:05:10").unwrap();
        assert!(!zoned);
        assert_eq!(w, 1_794_578_710_000);
        assert_eq!(parse_iso("1970-01-01T00:00:00Z"), Some((0, true)));
        for bad in [
            "",
            "2026-13-01T00:00:00Z",
            "2026-11-13T25:00:00Z",
            "2026-11-13",
            "2026-11-13T14:05:10.Z",
            "2026-11-13T14:05:10+5",
        ] {
            assert_eq!(parse_iso(bad), None, "{bad}");
        }
    }

    #[test]
    fn event_from_evtx_json() {
        let v = json!({"Event": {
            "#attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"},
            "System": {
                "Provider": {"#attributes": {"Name": "Microsoft-Windows-Security-Auditing", "Guid": "x"}},
                "EventID": 4625,
                "Level": 0,
                "Keywords": "0x8010000000000000",
                "TimeCreated": {"#attributes": {"SystemTime": "2026-11-13T14:05:10.000000Z"}},
                "EventRecordID": 9001,
                "Channel": "Security",
                "Computer": "DC01.corp.example",
                "Security": null
            },
            "EventData": {"TargetUserName": "admin", "LogonType": 3, "IpAddress": "198.51.100.7"}
        }});
        let r = from_event_json(0, &v, None, "");
        assert_eq!(r.provider, "Microsoft-Windows-Security-Auditing");
        assert_eq!(r.event_id, 4625);
        assert_eq!(r.outcome, "Audit Failure");
        assert_eq!(r.channel, "Security");
        assert_eq!(r.computer, "DC01.corp.example");
        assert_eq!(r.record_id, Some(9001));
        assert_eq!(r.time_utc_ms, Some(1_794_578_710_000));
        assert!(!r.zone_unknown);
        assert_eq!(r.field("logontype"), Some("3"));
        assert_eq!(r.fields.len(), 3);
    }

    #[test]
    fn attributed_ids_and_userdata() {
        let v = json!({"Event": {
            "System": {
                "Provider": {"#attributes": {"Name": "Service Control Manager", "EventSourceName": "Service Control Manager"}},
                "EventID": {"#attributes": {"Qualifiers": 16384}, "#text": 7045},
                "Level": 4,
                "TimeCreated": {"#attributes": {"SystemTime": "2026-11-13T14:05:10Z"}},
                "Channel": "System"
            },
            "UserData": {"LogFileCleared": {"SubjectUserName": "bob"}}
        }});
        let r = from_event_json(1, &v, Some(5), "");
        assert_eq!(r.event_id, 7045);
        assert_eq!(r.record_id, Some(5));
        assert_eq!(r.level_name(), "Information");
        assert_eq!(
            r.fields,
            vec![(
                "LogFileCleared.SubjectUserName".to_string(),
                "bob".to_string()
            )]
        );
    }

    #[test]
    fn missing_pieces_do_not_panic() {
        let r = from_event_json(0, &json!({"weird": [1, 2]}), None, "2026-11-13T14:05:10Z");
        assert_eq!(r.event_id, 0);
        assert_eq!(r.time_utc_ms, Some(1_794_578_710_000));
        let r = from_event_json(0, &Value::Null, None, "not a time");
        assert_eq!(r.time_utc_ms, None);
        assert!(!r.zone_unknown);
    }

    #[test]
    fn flatten_bounds() {
        let big: serde_json::Map<String, Value> =
            (0..500).map(|i| (format!("k{i}"), json!("v"))).collect();
        let mut out = Vec::new();
        flatten("", &Value::Object(big), &mut out);
        assert_eq!(out.len(), MAX_FIELDS);
        let mut out = Vec::new();
        flatten("", &json!({"Big": "x".repeat(MAX_FIELD * 2)}), &mut out);
        assert!(out[0].1.len() < MAX_FIELD + 10);
    }
}
