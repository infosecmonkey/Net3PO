//! Filtering, facet counts, the timeline and paging over a loaded set of
//! records. Pure functions over `&[EventRecord]`, so the UI only ever holds
//! one page.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use super::explain;
use super::model::EventRecord;

/// Most rows returned per page.
pub const MAX_PAGE: usize = 500;
/// Timeline bucket count target.
const BUCKETS: i64 = 60;

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Filter {
    pub providers: Vec<String>,
    pub channels: Vec<String>,
    /// Event IDs and ranges, comma separated; a leading '-' excludes:
    /// `4624,4625,4688-4690,-4634`.
    pub ids: String,
    pub levels: Vec<u8>,
    /// "success", "failure" or empty.
    pub outcome: String,
    pub computers: Vec<String>,
    /// Compared with each record's sort time (UTC, or wall clock for
    /// zone-unknown records).
    pub from_ms: Option<i64>,
    pub to_ms: Option<i64>,
    /// Case-insensitive text anywhere in the record.
    pub text: String,
    /// `Name=value` (value contains, case-insensitive) or just `Name`.
    pub field: String,
    /// Newest first when true.
    pub newest_first: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct IdSpec {
    include: Vec<(u32, u32)>,
    exclude: Vec<(u32, u32)>,
}

fn parse_ids(s: &str) -> Result<IdSpec, String> {
    let mut spec = IdSpec {
        include: Vec::new(),
        exclude: Vec::new(),
    };
    for part in s.split([',', ' ']).map(str::trim).filter(|p| !p.is_empty()) {
        let (neg, body) = match part.strip_prefix('-') {
            Some(b) => (true, b),
            None => (false, part),
        };
        let range = match body.split_once('-') {
            Some((a, b)) => (a.trim().parse::<u32>(), b.trim().parse::<u32>()),
            None => (body.parse::<u32>(), body.parse::<u32>()),
        };
        let (Ok(a), Ok(b)) = range else {
            return Err(format!("'{part}' is not an event ID or range"));
        };
        if a > b {
            return Err(format!("range '{part}' is backwards"));
        }
        if neg {
            spec.exclude.push((a, b))
        } else {
            spec.include.push((a, b))
        }
    }
    Ok(spec)
}

struct Compiled<'f> {
    f: &'f Filter,
    ids: IdSpec,
    text: String,
    field_name: String,
    field_value: Option<String>,
}

fn compile(f: &Filter) -> Result<Compiled<'_>, String> {
    let (field_name, field_value) = match f.field.split_once('=') {
        Some((n, v)) => (n.trim().to_string(), Some(v.trim().to_lowercase())),
        None => (f.field.trim().to_string(), None),
    };
    Ok(Compiled {
        f,
        ids: parse_ids(&f.ids)?,
        text: f.text.trim().to_lowercase(),
        field_name,
        field_value,
    })
}

fn contains_ci(hay: &str, needle_lower: &str) -> bool {
    hay.to_lowercase().contains(needle_lower)
}

fn matches(r: &EventRecord, c: &Compiled) -> bool {
    let f = c.f;
    let in_ranges = |v: &[(u32, u32)]| v.iter().any(|(a, b)| (*a..=*b).contains(&r.event_id));
    if (!c.ids.include.is_empty() && !in_ranges(&c.ids.include)) || in_ranges(&c.ids.exclude) {
        return false;
    }
    if !f.providers.is_empty() && !f.providers.contains(&r.provider) {
        return false;
    }
    if !f.channels.is_empty() && !f.channels.contains(&r.channel) {
        return false;
    }
    if !f.computers.is_empty() && !f.computers.contains(&r.computer) {
        return false;
    }
    if !f.levels.is_empty() && !f.levels.contains(&r.level) {
        return false;
    }
    match f.outcome.as_str() {
        "success" if r.outcome != "Audit Success" => return false,
        "failure" if r.outcome != "Audit Failure" => return false,
        _ => {}
    }
    if f.from_ms.is_some_and(|t| r.sort_ms < t) || f.to_ms.is_some_and(|t| r.sort_ms > t) {
        return false;
    }
    if !c.field_name.is_empty() {
        match r.field(&c.field_name) {
            None => return false,
            Some(v) => {
                if let Some(want) = &c.field_value
                    && !contains_ci(v, want)
                {
                    return false;
                }
            }
        }
    }
    if !c.text.is_empty() {
        let hit = contains_ci(&r.provider, &c.text)
            || contains_ci(&r.computer, &c.text)
            || contains_ci(&r.message, &c.text)
            || r.event_id.to_string() == c.text
            || r.fields
                .iter()
                .any(|(k, v)| contains_ci(v, &c.text) || contains_ci(k, &c.text));
        if !hit {
            return false;
        }
    }
    true
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Row {
    pub index: u32,
    pub time_raw: String,
    pub time_utc_ms: Option<i64>,
    pub zone_unknown: bool,
    pub event_id: u32,
    pub provider: String,
    pub channel: String,
    pub level: String,
    pub outcome: String,
    pub computer: String,
    /// Explanation title, when the event is known for its provider.
    pub title: String,
    /// The most useful fields, shortened.
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Count {
    pub value: String,
    pub count: usize,
    pub label: String,
}

#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Facets {
    pub providers: Vec<Count>,
    pub channels: Vec<Count>,
    pub ids: Vec<Count>,
    pub levels: Vec<Count>,
    pub computers: Vec<Count>,
}

#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Timeline {
    pub start_ms: i64,
    pub bucket_ms: i64,
    pub counts: Vec<usize>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct QueryResult {
    pub total: usize,
    pub matched: usize,
    pub offset: usize,
    pub rows: Vec<Row>,
    pub facets: Facets,
    pub timeline: Timeline,
}

fn summary(r: &EventRecord) -> String {
    let mut parts: Vec<String> = Vec::new();
    if let Some(e) = explain::explain(r) {
        for name in e.look_at {
            if let Some(v) = r.field(name)
                && !v.is_empty()
                && v != "-"
            {
                parts.push(format!("{name}={v}"));
            }
            if parts.len() >= 4 {
                break;
            }
        }
    }
    if parts.is_empty() {
        parts = r
            .fields
            .iter()
            .filter(|(_, v)| !v.is_empty() && v != "-")
            .take(3)
            .map(|(k, v)| format!("{k}={v}"))
            .collect();
    }
    if parts.is_empty() && !r.message.is_empty() {
        parts.push(r.message.lines().next().unwrap_or("").to_string());
    }
    let s = parts.join("  ");
    if s.chars().count() > 240 {
        format!("{}...", s.chars().take(240).collect::<String>())
    } else {
        s
    }
}

pub fn row(r: &EventRecord) -> Row {
    Row {
        index: r.index,
        time_raw: r.time_raw.clone(),
        time_utc_ms: r.time_utc_ms,
        zone_unknown: r.zone_unknown,
        event_id: r.event_id,
        provider: r.provider.clone(),
        channel: r.channel.clone(),
        level: r.level_name().to_string(),
        outcome: r.outcome.clone(),
        computer: r.computer.clone(),
        title: explain::explain(r)
            .map(|e| e.title.to_string())
            .unwrap_or_default(),
        summary: summary(r),
    }
}

fn top(map: HashMap<String, usize>, n: usize, label: impl Fn(&str) -> String) -> Vec<Count> {
    let mut v: Vec<Count> = map
        .into_iter()
        .map(|(value, count)| Count {
            label: label(&value),
            value,
            count,
        })
        .collect();
    v.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.value.cmp(&b.value)));
    v.truncate(n);
    v
}

/// A tidy bucket size giving about `BUCKETS` bars over `span`.
fn bucket_size(span: i64) -> i64 {
    const STEPS: &[i64] = &[
        1_000,
        5_000,
        15_000,
        60_000,
        300_000,
        900_000,
        3_600_000,
        10_800_000,
        21_600_000,
        43_200_000,
        86_400_000,
        604_800_000,
    ];
    let want = (span / BUCKETS).max(1);
    STEPS
        .iter()
        .copied()
        .find(|s| *s >= want)
        .unwrap_or(2_592_000_000)
}

/// Filter, count and page.
pub fn run(
    records: &[EventRecord],
    f: &Filter,
    offset: usize,
    limit: usize,
) -> Result<QueryResult, String> {
    let c = compile(f)?;
    let mut hits: Vec<&EventRecord> = records.iter().filter(|r| matches(r, &c)).collect();
    hits.sort_by(|a, b| a.sort_ms.cmp(&b.sort_ms).then(a.index.cmp(&b.index)));

    let mut providers = HashMap::new();
    let mut channels = HashMap::new();
    let mut ids: HashMap<String, usize> = HashMap::new();
    let mut levels = HashMap::new();
    let mut computers = HashMap::new();
    let mut id_titles: HashMap<String, String> = HashMap::new();
    for r in &hits {
        *providers.entry(r.provider.clone()).or_default() += 1;
        *channels.entry(r.channel.clone()).or_default() += 1;
        let key = format!("{}|{}", r.event_id, r.provider);
        *ids.entry(key.clone()).or_default() += 1;
        id_titles.entry(key).or_insert_with(|| {
            explain::explain(r)
                .map(|e| e.title.to_string())
                .unwrap_or_default()
        });
        *levels.entry(r.level.to_string()).or_default() += 1;
        *computers.entry(r.computer.clone()).or_default() += 1;
    }
    let facets = Facets {
        providers: top(providers, 15, |_| String::new()),
        channels: top(channels, 15, |_| String::new()),
        ids: top(ids, 25, |k| id_titles.get(k).cloned().unwrap_or_default()),
        levels: top(levels, 6, |l| {
            super::model::level_name(l.parse().unwrap_or(9)).to_string()
        }),
        computers: top(computers, 15, |_| String::new()),
    };

    let timed: Vec<i64> = hits.iter().map(|r| r.sort_ms).filter(|t| *t != 0).collect();
    let timeline = match (timed.first(), timed.last()) {
        (Some(&start), Some(&end)) => {
            let bucket = bucket_size(end - start);
            let start = start - start.rem_euclid(bucket);
            let n = ((end - start) / bucket + 1) as usize;
            let mut counts = vec![0usize; n.min(1000)];
            for t in &timed {
                let i = ((t - start) / bucket) as usize;
                if let Some(c) = counts.get_mut(i) {
                    *c += 1;
                }
            }
            Timeline {
                start_ms: start,
                bucket_ms: bucket,
                counts,
            }
        }
        _ => Timeline::default(),
    };

    let matched = hits.len();
    if f.newest_first {
        hits.reverse();
    }
    let limit = limit.clamp(1, MAX_PAGE);
    let rows = hits
        .iter()
        .skip(offset)
        .take(limit)
        .map(|r| row(r))
        .collect();
    Ok(QueryResult {
        total: records.len(),
        matched,
        offset,
        rows,
        facets,
        timeline,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(i: u32, id: u32, t: i64, fields: &[(&str, &str)]) -> EventRecord {
        EventRecord {
            index: i,
            record_id: Some(i as u64),
            time_raw: t.to_string(),
            time_utc_ms: Some(t),
            zone_unknown: false,
            sort_ms: t,
            provider: if (4600..5200).contains(&id) {
                "Microsoft-Windows-Security-Auditing".into()
            } else {
                "Service Control Manager".into()
            },
            channel: if (4600..5200).contains(&id) {
                "Security".into()
            } else {
                "System".into()
            },
            event_id: id,
            level: if id == 7034 { 2 } else { 0 },
            outcome: if id == 4625 {
                "Audit Failure".into()
            } else if (4600..5200).contains(&id) {
                "Audit Success".into()
            } else {
                String::new()
            },
            computer: "WS01".into(),
            user_sid: String::new(),
            fields: fields
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            message: String::new(),
            raw: String::new(),
        }
    }

    fn sample() -> Vec<EventRecord> {
        vec![
            rec(
                0,
                4624,
                3_000,
                &[
                    ("TargetUserName", "alice"),
                    ("LogonType", "10"),
                    ("IpAddress", "198.51.100.7"),
                ],
            ),
            rec(
                1,
                4625,
                1_000,
                &[("TargetUserName", "admin"), ("IpAddress", "203.0.113.9")],
            ),
            rec(
                2,
                4625,
                2_000,
                &[
                    ("TargetUserName", "Administrator"),
                    ("IpAddress", "203.0.113.9"),
                ],
            ),
            rec(
                3,
                7045,
                4_000,
                &[("ServiceName", "evil"), ("ImagePath", "C:\\Temp\\x.exe")],
            ),
            rec(4, 7034, 5_000, &[("param1", "Spooler")]),
        ]
    }

    #[test]
    fn id_specs() {
        let s = parse_ids("4624, 4688-4690 -4634").unwrap();
        assert_eq!(s.include, vec![(4624, 4624), (4688, 4690)]);
        assert_eq!(s.exclude, vec![(4634, 4634)]);
        assert!(parse_ids("46x").is_err());
        assert!(parse_ids("10-5").is_err());
        assert_eq!(parse_ids("").unwrap().include, vec![]);
    }

    #[test]
    fn filters_combine() {
        let s = sample();
        let q = |f: Filter| run(&s, &f, 0, 100).unwrap();
        assert_eq!(q(Filter::default()).matched, 5);
        assert_eq!(
            q(Filter {
                ids: "4625".into(),
                ..Default::default()
            })
            .matched,
            2
        );
        assert_eq!(
            q(Filter {
                ids: "-4625".into(),
                ..Default::default()
            })
            .matched,
            3
        );
        assert_eq!(
            q(Filter {
                outcome: "failure".into(),
                ..Default::default()
            })
            .matched,
            2
        );
        assert_eq!(
            q(Filter {
                channels: vec!["System".into()],
                ..Default::default()
            })
            .matched,
            2
        );
        assert_eq!(
            q(Filter {
                levels: vec![2],
                ..Default::default()
            })
            .matched,
            1
        );
        assert_eq!(
            q(Filter {
                field: "TargetUserName=admin".into(),
                ..Default::default()
            })
            .matched,
            2
        );
        assert_eq!(
            q(Filter {
                field: "ImagePath".into(),
                ..Default::default()
            })
            .matched,
            1
        );
        assert_eq!(
            q(Filter {
                text: "203.0.113.9".into(),
                ..Default::default()
            })
            .matched,
            2
        );
        assert_eq!(
            q(Filter {
                text: "TEMP".into(),
                ..Default::default()
            })
            .matched,
            1
        );
        assert_eq!(
            q(Filter {
                from_ms: Some(2_000),
                to_ms: Some(4_000),
                ..Default::default()
            })
            .matched,
            3
        );
        assert!(
            run(
                &s,
                &Filter {
                    ids: "abc".into(),
                    ..Default::default()
                },
                0,
                10
            )
            .is_err()
        );
    }

    #[test]
    fn ordering_paging_and_rows() {
        let s = sample();
        let r = run(&s, &Filter::default(), 0, 2).unwrap();
        assert_eq!(
            r.rows.iter().map(|x| x.index).collect::<Vec<_>>(),
            vec![1, 2]
        );
        let r = run(
            &s,
            &Filter {
                newest_first: true,
                ..Default::default()
            },
            1,
            2,
        )
        .unwrap();
        assert_eq!(
            r.rows.iter().map(|x| x.index).collect::<Vec<_>>(),
            vec![3, 0]
        );
        let logon = run(
            &s,
            &Filter {
                ids: "4624".into(),
                ..Default::default()
            },
            0,
            10,
        )
        .unwrap()
        .rows
        .remove(0);
        assert_eq!(logon.title, "An account logged on");
        assert!(
            logon
                .summary
                .starts_with("LogonType=10  TargetUserName=alice"),
            "{}",
            logon.summary
        );
    }

    #[test]
    fn facets_and_timeline() {
        let s = sample();
        let r = run(&s, &Filter::default(), 0, 10).unwrap();
        assert_eq!(
            r.facets.ids[0].value,
            "4625|Microsoft-Windows-Security-Auditing"
        );
        assert_eq!(r.facets.ids[0].count, 2);
        assert_eq!(r.facets.ids[0].label, "An account failed to log on");
        assert_eq!(r.facets.channels.len(), 2);
        assert_eq!(r.timeline.bucket_ms, 1_000);
        assert_eq!(r.timeline.counts.iter().sum::<usize>(), 5);
        assert_eq!(bucket_size(3_600_000 * 24), 3_600_000);
        assert_eq!(
            run(&[], &Filter::default(), 0, 10)
                .unwrap()
                .timeline
                .counts
                .len(),
            0
        );
    }
}
