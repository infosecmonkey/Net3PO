//! CSV event exports: Event Viewer "Save All Events As" CSV (which has an
//! unnamed trailing description column) and PowerShell `Export-Csv` of
//! Get-WinEvent or Get-EventLog. Columns are matched by name. These exports
//! carry local time without a zone, so records are marked zone-unknown.

use super::model::{self, EventRecord, MAX_FIELD, MAX_FIELDS, MAX_RAW};

/// Parse RFC 4180 CSV: quoted fields may contain commas, quotes ("") and
/// newlines. Stops after `max_rows` rows.
pub fn parse_rows(text: &str, max_rows: usize) -> Vec<Vec<String>> {
    let mut rows = Vec::new();
    let mut row = Vec::new();
    let mut field = String::new();
    let mut quoted = false;
    let mut chars = text.trim_start_matches('\u{feff}').chars().peekable();
    while let Some(c) = chars.next() {
        if quoted {
            if c == '"' {
                if chars.peek() == Some(&'"') {
                    chars.next();
                    field.push('"');
                } else {
                    quoted = false;
                }
            } else if field.len() < MAX_FIELD * 4 {
                field.push(c);
            }
            continue;
        }
        match c {
            '"' if field.is_empty() => quoted = true,
            ',' => row.push(std::mem::take(&mut field)),
            '\r' => {}
            '\n' => {
                row.push(std::mem::take(&mut field));
                if !(row.len() == 1 && row[0].is_empty()) {
                    rows.push(std::mem::take(&mut row));
                    if rows.len() >= max_rows {
                        return rows;
                    }
                } else {
                    row.clear();
                }
            }
            _ => field.push(c),
        }
    }
    if !field.is_empty() || !row.is_empty() {
        row.push(field);
        rows.push(row);
    }
    rows
}

/// Parse US-style `11/13/2026 9:05:10 AM` (or 24-hour) into wall-clock ms.
pub fn parse_local(s: &str) -> Option<i64> {
    let s = s.trim();
    if let Some((ms, _)) = model::parse_iso(s) {
        return Some(ms);
    }
    let mut parts = s.split_whitespace();
    let date = parts.next()?;
    let time = parts.next().unwrap_or("0:00:00");
    let ampm = parts.next().map(|x| x.to_ascii_uppercase());
    let d: Vec<i64> = date
        .split(['/', '-', '.'])
        .map(|x| x.parse().ok())
        .collect::<Option<_>>()?;
    let t: Vec<i64> = time
        .split(':')
        .map(|x| x.parse().ok())
        .collect::<Option<_>>()?;
    if d.len() != 3 || t.len() < 2 {
        return None;
    }
    let (mo, day, y) = (d[0], d[1], d[2]);
    let mut h = t[0];
    match ampm.as_deref() {
        Some("PM") if h < 12 => h += 12,
        Some("AM") if h == 12 => h = 0,
        Some("AM") | Some("PM") | None => {}
        Some(_) => return None,
    }
    model::wall_ms(y, mo, day, h, t[1], *t.get(2).unwrap_or(&0), 0)
}

fn level_from(s: &str) -> (u8, &'static str) {
    let l = s.trim().to_ascii_lowercase();
    match l.as_str() {
        "critical" | "1" => (1, ""),
        "error" | "2" => (2, ""),
        "warning" | "3" => (3, ""),
        "information" | "informational" | "4" => (4, ""),
        "verbose" | "5" => (5, ""),
        "audit success" | "successaudit" => (0, "Audit Success"),
        "audit failure" | "failureaudit" => (0, "Audit Failure"),
        _ => (4, ""),
    }
}

pub struct CsvImport {
    pub records: Vec<EventRecord>,
    pub warnings: Vec<String>,
    pub truncated: bool,
}

/// Import CSV rows; the first row is the header.
pub fn import(text: &str, max: usize) -> Result<CsvImport, String> {
    // One extra row beyond the header and the limit shows truncation.
    let rows = parse_rows(text, max + 2);
    let Some((header, body)) = rows.split_first() else {
        return Err("the CSV file is empty".into());
    };
    let names: Vec<String> = header
        .iter()
        .map(|h| h.trim().to_ascii_lowercase())
        .collect();
    let find = |aliases: &[&str]| names.iter().position(|n| aliases.contains(&n.as_str()));
    let c_time = find(&[
        "date and time",
        "timecreated",
        "timegenerated",
        "timestamp",
        "systemtime",
        "time",
    ]);
    let c_id = find(&["event id", "eventid", "id"]);
    if c_time.is_none() || c_id.is_none() {
        return Err("this CSV has no recognizable time and event ID columns (expected Event Viewer or PowerShell Export-Csv output)".into());
    }
    let c_provider = find(&["source", "providername", "provider"]);
    let c_channel = find(&["logname", "channel", "log"]);
    let c_level = find(&["level", "leveldisplayname", "entrytype", "keywords"]);
    let c_computer = find(&["machinename", "computer", "computername"]);
    let c_record = find(&["recordid", "eventrecordid", "index"]);
    let c_message = find(&["message", "description"]);
    let c_user = find(&["userid", "username"]);
    let known: Vec<usize> = [
        c_time, c_id, c_provider, c_channel, c_level, c_computer, c_record, c_message, c_user,
    ]
    .into_iter()
    .flatten()
    .collect();

    let mut records = Vec::with_capacity(body.len().min(max));
    let mut ambiguous = false;
    let mut bad_time = 0usize;
    for row in body.iter().take(max) {
        let get = |c: Option<usize>| {
            c.and_then(|i| row.get(i))
                .map(|s| s.trim().to_string())
                .unwrap_or_default()
        };
        let time_raw = get(c_time);
        let sort = parse_local(&time_raw);
        if sort.is_none() {
            bad_time += 1;
        }
        if let Some((a, b)) = time_raw.split_once('/')
            && let (Ok(x), Some(Ok(y))) =
                (a.parse::<u32>(), b.split('/').next().map(str::parse::<u32>))
            && x <= 12
            && y <= 12
            && x != y
        {
            ambiguous = true;
        }
        let (level, outcome) = level_from(&get(c_level));
        // Event Viewer puts the description in an extra, unnamed column.
        let message = if c_message.is_some() {
            get(c_message)
        } else {
            row.get(names.len()).cloned().unwrap_or_default()
        };
        let fields: Vec<(String, String)> = header
            .iter()
            .enumerate()
            .filter(|(i, _)| !known.contains(i))
            .filter_map(|(i, h)| {
                row.get(i).map(|v| {
                    (
                        h.trim().to_string(),
                        v.trim().chars().take(MAX_FIELD).collect(),
                    )
                })
            })
            .filter(|(_, v): &(String, String)| !v.is_empty())
            .take(MAX_FIELDS)
            .collect();
        let raw: String = row.join(",").chars().take(MAX_RAW).collect();
        records.push(EventRecord {
            index: records.len() as u32,
            record_id: get(c_record).parse().ok(),
            time_raw,
            time_utc_ms: None,
            zone_unknown: true,
            sort_ms: sort.unwrap_or(0),
            provider: get(c_provider),
            channel: get(c_channel),
            event_id: get(c_id).parse().unwrap_or(0),
            level,
            outcome: outcome.to_string(),
            computer: get(c_computer),
            user_sid: get(c_user),
            fields,
            message: message.chars().take(MAX_FIELD * 4).collect(),
            raw,
        });
    }
    let mut warnings = vec![
        "CSV exports use the exporting computer's local time without a time zone; times are shown as written and are not converted to UTC.".to_string(),
    ];
    if ambiguous {
        warnings.push("Dates such as 03/04/2026 are read as month/day (US order). If this export used day/month, the order of events is wrong.".into());
    }
    if bad_time > 0 {
        warnings.push(format!(
            "{bad_time} row(s) have a time Net3PO could not read; they sort first."
        ));
    }
    Ok(CsvImport {
        truncated: body.len() > max,
        records,
        warnings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc4180_rows() {
        let rows = parse_rows(
            "a,b,c\n\"x, y\",\"he said \"\"hi\"\"\",\"line1\nline2\"\r\n\n1,2,3",
            10,
        );
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[1], vec!["x, y", "he said \"hi\"", "line1\nline2"]);
        assert_eq!(rows[2], vec!["1", "2", "3"]);
        assert_eq!(parse_rows("a\nb\nc\n", 2).len(), 2);
    }

    #[test]
    fn local_times() {
        assert_eq!(
            parse_local("11/13/2026 2:05:10 PM"),
            model::wall_ms(2026, 11, 13, 14, 5, 10, 0)
        );
        assert_eq!(
            parse_local("11/13/2026 12:00:00 AM"),
            model::wall_ms(2026, 11, 13, 0, 0, 0, 0)
        );
        assert_eq!(
            parse_local("2026-11-13T14:05:10Z"),
            model::wall_ms(2026, 11, 13, 14, 5, 10, 0)
        );
        assert_eq!(parse_local("13/13/2026 1:00:00"), None);
        assert_eq!(parse_local("garbage"), None);
    }

    #[test]
    fn event_viewer_csv() {
        let csv = "\u{feff}Keywords,Date and Time,Source,Event ID,Task Category\n\
Audit Failure,11/13/2026 2:05:10 PM,Microsoft-Windows-Security-Auditing,4625,Logon,\"An account failed to log on.\n\nSubject: ...\"\n\
Audit Success,11/13/2026 2:06:00 PM,Microsoft-Windows-Security-Auditing,4624,Logon,\"An account was successfully logged on.\"\n";
        let imp = import(csv, 100).unwrap();
        assert_eq!(imp.records.len(), 2);
        let r = &imp.records[0];
        assert_eq!(r.event_id, 4625);
        assert_eq!(r.outcome, "Audit Failure");
        assert!(r.zone_unknown);
        assert_eq!(r.time_utc_ms, None);
        assert!(r.message.starts_with("An account failed"));
        assert_eq!(
            r.fields,
            vec![("Task Category".to_string(), "Logon".to_string())]
        );
        assert!(imp.warnings[0].contains("local time"));
        assert!(!imp.truncated);
    }

    #[test]
    fn powershell_csv_and_errors() {
        let csv = "\"Message\",\"Id\",\"Level\",\"ProviderName\",\"LogName\",\"MachineName\",\"RecordId\",\"TimeCreated\"\n\
\"Service installed\",\"7045\",\"4\",\"Service Control Manager\",\"System\",\"WS01\",\"12\",\"03/04/2026 10:00:00\"\n";
        let imp = import(csv, 100).unwrap();
        let r = &imp.records[0];
        assert_eq!(
            (
                r.event_id,
                r.channel.as_str(),
                r.computer.as_str(),
                r.record_id
            ),
            (7045, "System", "WS01", Some(12))
        );
        assert!(imp.warnings.iter().any(|w| w.contains("month/day")));
        assert!(import("", 10).is_err());
        assert!(import("a,b\n1,2\n", 10).is_err());
        let many = format!(
            "Event ID,Date and Time\n{}",
            "1,1/1/2026 1:00:00\n".repeat(50)
        );
        let imp = import(&many, 10).unwrap();
        assert_eq!(imp.records.len(), 10);
        assert!(imp.truncated);
    }
}
