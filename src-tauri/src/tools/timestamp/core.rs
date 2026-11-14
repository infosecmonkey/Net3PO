//! Timestamp conversion. Recognizes Unix seconds/ms/µs/ns, Windows FILETIME
//! (also used by Active Directory), LDAP generalized time, ISO 8601 /
//! RFC 3339, RFC 2822 and syslog-style dates, and shows each reading in UTC
//! and a chosen time zone. Anything inferred (units, year, zone) is stated;
//! times that fall in a DST fold or gap are reported as such, never guessed.

use jiff::civil::DateTime;
use jiff::tz::{AmbiguousOffset, TimeZone};
use jiff::{Timestamp, Zoned};
use serde::Serialize;

/// 100 ns ticks between 1601-01-01 and 1970-01-01.
const FILETIME_EPOCH_DIFF: i128 = 116_444_736_000_000_000;
/// Longest input accepted.
const MAX_INPUT: usize = 200;

/// The same instant in every supported format.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Formats {
    pub iso_utc: String,
    /// In the chosen zone, with offset and abbreviation.
    pub zoned: String,
    pub zone: String,
    pub unix_seconds: String,
    pub unix_millis: String,
    pub filetime: String,
    pub ldap: String,
    pub rfc2822: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Reading {
    /// How the input was read, e.g. "Unix seconds".
    pub label: String,
    pub formats: Formats,
    /// What was inferred or is uncertain about this reading.
    pub notes: Vec<String>,
    /// Falls between 1990 and 2100, so it is the likely intent.
    pub plausible: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub struct Conversion {
    pub readings: Vec<Reading>,
    pub error: Option<String>,
}

/// A timestamp from nanoseconds, range-checked first: jiff can assert on
/// out-of-range values in some paths, and input here is untrusted.
fn from_ns(ns: i128) -> Option<Timestamp> {
    let (lo, hi) = (
        Timestamp::MIN.as_nanosecond(),
        Timestamp::MAX.as_nanosecond(),
    );
    if !(lo..=hi).contains(&ns) {
        return None;
    }
    Timestamp::from_nanosecond(ns).ok()
}

fn formats(ts: Timestamp, tz: &TimeZone, zone_name: &str) -> Formats {
    let z = ts.to_zoned(tz.clone());
    let utc = ts.to_zoned(TimeZone::UTC);
    let ticks = ts.as_nanosecond() / 100 + FILETIME_EPOCH_DIFF;
    Formats {
        iso_utc: utc.strftime("%Y-%m-%dT%H:%M:%S%.fZ").to_string(),
        zoned: z.strftime("%Y-%m-%d %H:%M:%S%.f %Z (UTC%:z)").to_string(),
        zone: zone_name.to_string(),
        unix_seconds: ts.as_second().to_string(),
        unix_millis: ts.as_millisecond().to_string(),
        filetime: if ticks >= 0 {
            ticks.to_string()
        } else {
            "before 1601".into()
        },
        ldap: utc.strftime("%Y%m%d%H%M%S.0Z").to_string(),
        rfc2822: jiff::fmt::rfc2822::to_string(&utc).unwrap_or_default(),
    }
}

fn plausible(ts: Timestamp) -> bool {
    let y = ts.to_zoned(TimeZone::UTC).year();
    (1990..=2100).contains(&y)
}

fn reading(label: &str, ts: Timestamp, tz: &TimeZone, zone: &str, notes: Vec<String>) -> Reading {
    Reading {
        label: label.into(),
        formats: formats(ts, tz, zone),
        plausible: plausible(ts),
        notes,
    }
}

/// Every numeric reading that is a valid instant.
fn numeric(n: i128, tz: &TimeZone, zone: &str) -> Vec<Reading> {
    let mut out = Vec::new();
    let candidates: [(&str, Option<i128>); 5] = [
        ("Unix seconds", n.checked_mul(1_000_000_000)),
        ("Unix milliseconds", n.checked_mul(1_000_000)),
        ("Unix microseconds", n.checked_mul(1_000)),
        ("Unix nanoseconds", Some(n)),
        (
            "Windows FILETIME / AD timestamp (100 ns since 1601)",
            n.checked_sub(FILETIME_EPOCH_DIFF)
                .and_then(|t| t.checked_mul(100)),
        ),
    ];
    for (label, ns) in candidates {
        if let Some(ts) = ns.and_then(from_ns) {
            out.push(reading(label, ts, tz, zone, Vec::new()));
        }
    }
    if n == 0x7FFF_FFFF_FFFF_FFFF || n == 0 {
        for r in &mut out {
            if r.label.starts_with("Windows") {
                r.notes
                    .push("AD uses 0 and 9223372036854775807 to mean never".into());
            }
        }
    }
    // Plausible readings first; the rest stay visible but below.
    out.sort_by_key(|r| !r.plausible);
    out
}

/// A local time in `tz`, with folds and gaps made explicit.
fn local(
    dt: DateTime,
    tz: &TimeZone,
    zone: &str,
    label: &str,
    mut notes: Vec<String>,
) -> Vec<Reading> {
    let amb = tz.to_ambiguous_zoned(dt);
    match amb.offset() {
        AmbiguousOffset::Unambiguous { .. } => match amb.compatible() {
            Ok(z) => vec![reading(label, z.timestamp(), tz, zone, notes)],
            Err(_) => Vec::new(),
        },
        AmbiguousOffset::Fold { before, after } => {
            let mut out = Vec::new();
            for (which, r, off) in [
                ("first", amb.clone().earlier(), before),
                ("second", amb.later(), after),
            ] {
                if let Ok(z) = r {
                    let mut n = notes.clone();
                    n.push(format!("This local time happens twice in {zone} (clocks go back); this is the {which} occurrence, UTC{off}"));
                    out.push(reading(label, z.timestamp(), tz, zone, n));
                }
            }
            out
        }
        AmbiguousOffset::Gap { before, after } => {
            notes.push(format!("This local time does not exist in {zone} (clocks go forward from UTC{before} to UTC{after}); shown as if the old offset still applied"));
            match amb.compatible() {
                Ok(z) => vec![reading(label, z.timestamp(), tz, zone, notes)],
                Err(_) => Vec::new(),
            }
        }
    }
}

/// LDAP generalized time: YYYYMMDDHHMMSS[.f][Z|±HHMM].
fn generalized(s: &str, tz: &TimeZone, zone: &str) -> Option<Vec<Reading>> {
    let digits: String = s.chars().take_while(|c| c.is_ascii_digit()).collect();
    if digits.len() != 14 {
        return None;
    }
    let mut rest = &s[14..];
    let mut frac = String::new();
    if let Some(r) = rest.strip_prefix(['.', ',']) {
        frac = r.chars().take_while(|c| c.is_ascii_digit()).collect();
        rest = &r[frac.len()..];
    }
    let iso = format!(
        "{}-{}-{}T{}:{}:{}{}",
        &digits[0..4],
        &digits[4..6],
        &digits[6..8],
        &digits[8..10],
        &digits[10..12],
        &digits[12..14],
        if frac.is_empty() {
            String::new()
        } else {
            format!(".{frac}")
        }
    );
    let label = "LDAP generalized time";
    if rest == "Z" {
        return format!("{iso}Z")
            .parse::<Timestamp>()
            .ok()
            .map(|t| vec![reading(label, t, tz, zone, Vec::new())]);
    }
    if rest.len() == 5 && (rest.starts_with('+') || rest.starts_with('-')) {
        let off = format!("{}:{}", &rest[..3], &rest[3..]);
        return format!("{iso}{off}")
            .parse::<Timestamp>()
            .ok()
            .map(|t| vec![reading(label, t, tz, zone, Vec::new())]);
    }
    if rest.is_empty() {
        let dt: DateTime = iso.parse().ok()?;
        return Some(local(
            dt,
            tz,
            zone,
            label,
            vec![format!("No zone given; read as {zone} local time")],
        ));
    }
    None
}

/// "Nov 14 09:34:50" (RFC 3164, no year) and "Nov 14 2026 09:34:50[.fff] [UTC|GMT|±hh:mm]".
fn syslog(s: &str, tz: &TimeZone, zone: &str, now: Timestamp) -> Option<Vec<Reading>> {
    let parts: Vec<&str> = s.split_whitespace().collect();
    if parts.len() < 3 || parts[0].len() != 3 || !parts[0].chars().all(|c| c.is_ascii_alphabetic())
    {
        return None;
    }
    let (year, time_i, inferred) = match parts.get(2).and_then(|p| p.parse::<i16>().ok()) {
        Some(y) if parts.len() >= 4 && (1900..=9999).contains(&y) => (y, 3, false),
        _ => (now.to_zoned(tz.clone()).year(), 2, true),
    };
    let time = *parts.get(time_i)?;
    let zone_part = parts.get(time_i + 1).copied();
    let text = format!("{year} {} {} {time}", parts[0], parts[1]);
    let fmt = if time.contains('.') {
        "%Y %b %d %H:%M:%S%.f"
    } else {
        "%Y %b %d %H:%M:%S"
    };
    let dt = jiff::fmt::strtime::parse(fmt, &text)
        .ok()?
        .to_datetime()
        .ok()?;
    let label = if inferred {
        "Syslog (RFC 3164) date"
    } else {
        "Device log date"
    };
    let mut notes = Vec::new();
    if inferred {
        notes.push(format!("No year in the input; assumed {year}"));
    }
    match zone_part {
        Some(z) if z.eq_ignore_ascii_case("UTC") || z.eq_ignore_ascii_case("GMT") || z == "Z" => {
            let ts = dt.to_zoned(TimeZone::UTC).ok()?.timestamp();
            Some(vec![reading(label, ts, tz, zone, notes)])
        }
        Some(z) if z.starts_with('+') || z.starts_with('-') => {
            let ts = format!("{}{z}", dt).parse::<Timestamp>().ok()?;
            Some(vec![reading(label, ts, tz, zone, notes)])
        }
        Some(z) => {
            notes.push(format!("Zone \"{z}\" not recognized (abbreviations are ambiguous); read as {zone} local time"));
            Some(local(dt, tz, zone, label, notes))
        }
        None => {
            notes.push(format!("No zone given; read as {zone} local time"));
            let mut out = local(dt, tz, zone, label, notes);
            if inferred {
                for r in &mut out {
                    if r.formats.unix_seconds.parse::<i64>().unwrap_or(0) > now.as_second() + 86_400
                    {
                        r.notes.push("With the assumed year this is in the future; the log may be from last year".into());
                    }
                }
            }
            Some(out)
        }
    }
}

/// Convert `input`, showing results in the IANA zone `zone`.
pub fn convert(input: &str, zone: &str, now: Timestamp) -> Conversion {
    let s = input.trim();
    let fail = |e: String| Conversion {
        readings: Vec::new(),
        error: Some(e),
    };
    if s.is_empty() {
        return fail("enter a timestamp".into());
    }
    if s.len() > MAX_INPUT {
        return fail("input longer than 200 characters".into());
    }
    let tz = match TimeZone::get(zone) {
        Ok(t) => t,
        Err(_) => return fail(format!("unknown time zone: {zone}")),
    };

    // Numbers: decimal, or hex FILETIME (0x01DB...).
    if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        return match i128::from_str_radix(h, 16) {
            Ok(n) => Conversion {
                readings: numeric(n, &tz, zone)
                    .into_iter()
                    .filter(|r| r.label.starts_with("Windows"))
                    .collect(),
                error: None,
            },
            Err(_) => fail("not a hex number".into()),
        };
    }
    if let Ok(n) = s.parse::<i128>() {
        let mut r = numeric(n, &tz, zone);
        // Fourteen digits may also be LDAP time without a zone suffix.
        if s.len() == 14
            && let Some(g) = generalized(s, &tz, zone)
        {
            let plausible: Vec<Reading> = g.into_iter().filter(|x| x.plausible).collect();
            r.splice(0..0, plausible);
        }
        return if r.is_empty() {
            fail("number is out of range for every supported format".into())
        } else {
            Conversion {
                readings: r,
                error: None,
            }
        };
    }

    if let Ok(f) = s.parse::<f64>()
        && f.is_finite()
        && f.abs() < 1e13
        && let Some(ts) = from_ns((f * 1e9) as i128)
    {
        {
            {
                return Conversion {
                    readings: vec![reading(
                        "Unix seconds with fraction",
                        ts,
                        &tz,
                        zone,
                        Vec::new(),
                    )],
                    error: None,
                };
            }
        }
    }
    if let Some(r) = generalized(s, &tz, zone) {
        return Conversion {
            readings: r,
            error: None,
        };
    }
    // ISO 8601 / RFC 3339 with an offset, or with a [zone] annotation.
    if let Ok(z) = s.parse::<Zoned>() {
        return Conversion {
            readings: vec![reading(
                "ISO 8601 with zone",
                z.timestamp(),
                &tz,
                zone,
                Vec::new(),
            )],
            error: None,
        };
    }
    if let Ok(ts) = s.parse::<Timestamp>() {
        return Conversion {
            readings: vec![reading("ISO 8601 / RFC 3339", ts, &tz, zone, Vec::new())],
            error: None,
        };
    }
    if let Ok(dt) = s.parse::<DateTime>() {
        return Conversion {
            readings: local(
                dt,
                &tz,
                zone,
                "ISO 8601 without zone",
                vec![format!("No offset given; read as {zone} local time")],
            ),
            error: None,
        };
    }
    if let Ok(z) = jiff::fmt::rfc2822::parse(s) {
        return Conversion {
            readings: vec![reading(
                "RFC 2822 (email) date",
                z.timestamp(),
                &tz,
                zone,
                Vec::new(),
            )],
            error: None,
        };
    }
    if let Some(r) = syslog(s, &tz, zone, now)
        && !r.is_empty()
    {
        return Conversion {
            readings: r,
            error: None,
        };
    }
    fail("not a recognized timestamp. Try Unix seconds or ms, FILETIME, ISO 8601, LDAP generalized time, RFC 2822 or a syslog date.".into())
}

/// The current instant in every format.
pub fn now(zone: &str, now: Timestamp) -> Conversion {
    match TimeZone::get(zone) {
        Ok(tz) => Conversion {
            readings: vec![reading("Now", now, &tz, zone, Vec::new())],
            error: None,
        },
        Err(_) => Conversion {
            readings: Vec::new(),
            error: Some(format!("unknown time zone: {zone}")),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now_ts() -> Timestamp {
        "2026-11-14T12:00:00Z".parse().unwrap()
    }

    fn conv(s: &str, zone: &str) -> Conversion {
        convert(s, zone, now_ts())
    }

    #[test]
    fn unix_units_ranked() {
        let c = conv("1794614400", "UTC");
        assert_eq!(c.readings[0].label, "Unix seconds");
        assert_eq!(c.readings[0].formats.iso_utc, "2026-11-14T00:00:00Z");
        assert!(c.readings[0].plausible);
        assert!(c.readings.iter().skip(1).all(|r| !r.plausible));
        let c = conv("1794614400123", "UTC");
        assert_eq!(c.readings[0].label, "Unix milliseconds");
        assert_eq!(c.readings[0].formats.iso_utc, "2026-11-14T00:00:00.123Z");
    }

    #[test]
    fn filetime_and_ldap() {
        // 2026-11-14T00:00:00Z as FILETIME.
        let ft = (1_794_614_400i128 * 10_000_000 + FILETIME_EPOCH_DIFF).to_string();
        let c = conv(&ft, "UTC");
        let r = c.readings.iter().find(|r| r.plausible).unwrap();
        assert!(r.label.starts_with("Windows FILETIME"));
        assert_eq!(r.formats.iso_utc, "2026-11-14T00:00:00Z");
        assert_eq!(r.formats.filetime, ft);
        assert_eq!(r.formats.ldap, "20261114000000.0Z");
        let c = conv("20261114093450.0Z", "UTC");
        assert_eq!(c.readings[0].formats.iso_utc, "2026-11-14T09:34:50Z");
        let c = conv("20261114093450+0100", "UTC");
        assert_eq!(c.readings[0].formats.iso_utc, "2026-11-14T08:34:50Z");
        let hex = format!("0x{:X}", ft.parse::<i128>().unwrap());
        assert_eq!(conv(&hex, "UTC").readings.len(), 1);
    }

    #[test]
    fn iso_rfc2822_and_zones() {
        let c = conv("2026-11-14T09:34:50-05:00", "Europe/Madrid");
        assert_eq!(c.readings[0].formats.iso_utc, "2026-11-14T14:34:50Z");
        assert!(
            c.readings[0]
                .formats
                .zoned
                .starts_with("2026-11-14 15:34:50 CET (UTC+01:00)"),
            "{}",
            c.readings[0].formats.zoned
        );
        let c = conv("Sat, 14 Nov 2026 09:34:50 +0000", "UTC");
        assert_eq!(c.readings[0].label, "RFC 2822 (email) date");
        let c = conv("2026-11-14 09:34:50", "America/New_York");
        assert_eq!(c.readings[0].formats.iso_utc, "2026-11-14T14:34:50Z");
        assert!(c.readings[0].notes[0].contains("No offset"));
    }

    #[test]
    fn dst_fold_and_gap() {
        // 01:30 happens twice in New York on 2026-11-01.
        let c = conv("2026-11-01T01:30:00", "America/New_York");
        assert_eq!(c.readings.len(), 2);
        assert_eq!(c.readings[0].formats.iso_utc, "2026-11-01T05:30:00Z");
        assert_eq!(c.readings[1].formats.iso_utc, "2026-11-01T06:30:00Z");
        assert!(c.readings[0].notes.iter().any(|n| n.contains("twice")));
        // 02:30 does not exist on 2026-03-08.
        let c = conv("2026-03-08T02:30:00", "America/New_York");
        assert_eq!(c.readings.len(), 1);
        assert!(
            c.readings[0]
                .notes
                .iter()
                .any(|n| n.contains("does not exist"))
        );
    }

    #[test]
    fn syslog_dates() {
        let c = conv("Nov 14 09:34:50", "UTC");
        assert_eq!(c.readings[0].formats.iso_utc, "2026-11-14T09:34:50Z");
        assert!(
            c.readings[0]
                .notes
                .iter()
                .any(|n| n.contains("assumed 2026"))
        );
        let c = conv("Dec 31 23:00:00", "UTC");
        assert!(c.readings[0].notes.iter().any(|n| n.contains("last year")));
        let c = conv("Nov 14 2026 09:34:50.123 UTC", "America/Chicago");
        assert_eq!(c.readings[0].formats.iso_utc, "2026-11-14T09:34:50.123Z");
        assert!(c.readings[0].notes.is_empty());
        let c = conv("Nov 14 2026 09:34:50 EST", "UTC");
        assert!(
            c.readings[0]
                .notes
                .iter()
                .any(|n| n.contains("not recognized"))
        );
    }

    #[test]
    fn bare_generalized_time() {
        let c = conv("20261114093450", "UTC");
        assert_eq!(c.readings[0].label, "LDAP generalized time");
        assert_eq!(c.readings[0].formats.iso_utc, "2026-11-14T09:34:50Z");
        assert!(c.readings[0].notes[0].contains("No zone"));
    }

    #[test]
    fn bad_input() {
        assert!(conv("", "UTC").error.is_some());
        assert!(conv("hello world", "UTC").error.is_some());
        assert!(
            conv("1700000000", "Mars/Olympus")
                .error
                .unwrap()
                .contains("unknown time zone")
        );
        assert!(conv(&"9".repeat(300), "UTC").error.is_some());
        assert!(
            conv("99999999999999999999999999999999", "UTC")
                .error
                .is_some()
        );
        let c = conv("0", "UTC");
        assert!(
            c.readings
                .iter()
                .any(|r| r.notes.iter().any(|n| n.contains("never")))
        );
        assert_eq!(
            now("UTC", now_ts()).readings[0].formats.unix_seconds,
            "1794657600"
        );
    }
}
#[cfg(test)]
mod fuzz {
    use super::*;

    /// Untrusted numbers of every size must never panic.
    #[test]
    fn extreme_numbers_do_not_panic() {
        let now: Timestamp = "2026-11-14T12:00:00Z".parse().unwrap();
        for s in [
            "170141183460469231731687303715884105727",
            "-170141183460469231731687303715884105728",
            "253402207200",
            "253402207201",
            "-377705116801",
            "0x7FFFFFFFFFFFFFFF",
            "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
            "1e300",
            "-1e300",
            "9999999999999.9",
            "Feb 30 10:00:00",
            "99991231235959Z",
            "00000101000000Z",
        ] {
            let _ = convert(s, "UTC", now);
        }
        let mut n: i128 = 1;
        while let Some(m) = n.checked_mul(7) {
            let _ = convert(&m.to_string(), "Pacific/Chatham", now);
            let _ = convert(&(-m).to_string(), "UTC", now);
            n = m;
        }
    }
}
