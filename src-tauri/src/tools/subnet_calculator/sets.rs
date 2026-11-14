//! Address-set tools: normalize IPv4/IPv6 lists, aggregate them into the
//! fewest prefixes that cover exactly the same addresses, find overlaps and
//! compare two sets. Everything works on integer ranges, so aggregation can
//! never add an address that was not in the input. IPv4 and IPv6 are kept
//! apart throughout.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::Serialize;

/// Largest input text accepted.
pub const MAX_INPUT: usize = 2 * 1024 * 1024;
/// Most entries accepted from one input.
pub const MAX_ENTRIES: usize = 20_000;
/// Most prefixes returned in one list.
pub const MAX_OUTPUT: usize = 50_000;
/// Most overlap findings returned.
pub const MAX_OVERLAPS: usize = 1_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Range {
    start: u128,
    end: u128,
}

/// One parsed input entry.
#[derive(Debug, Clone)]
struct Entry {
    v6: bool,
    range: Range,
    text: String,
    line: usize,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Invalid {
    pub line: usize,
    pub text: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Note {
    pub line: usize,
    pub text: String,
    pub note: String,
}

#[derive(Debug, Default)]
struct Parsed {
    entries: Vec<Entry>,
    invalid: Vec<Invalid>,
    notes: Vec<Note>,
    truncated: bool,
}

fn bits(v6: bool) -> u32 {
    if v6 { 128 } else { 32 }
}

fn mask(v6: bool, len: u32) -> u128 {
    let b = bits(v6);
    if len == 0 {
        0
    } else {
        let full = if v6 { u128::MAX } else { u32::MAX as u128 };
        full & !((1u128 << (b - len)) - 1)
    }
}

fn to_num(ip: IpAddr) -> (bool, u128) {
    match ip {
        IpAddr::V4(a) => (false, u32::from(a) as u128),
        IpAddr::V6(a) => (true, u128::from(a)),
    }
}

fn to_ip(v6: bool, n: u128) -> String {
    if v6 {
        Ipv6Addr::from(n).to_string()
    } else {
        Ipv4Addr::from(n as u32).to_string()
    }
}

/// A dotted netmask as a prefix length, if it is contiguous.
fn mask_len(m: Ipv4Addr) -> Option<u32> {
    let n = u32::from(m);
    let len = n.leading_ones();
    (n.checked_shl(len).unwrap_or(0) == 0).then_some(len)
}

fn parse_entry(token: &str) -> Result<(bool, Range, Option<String>), String> {
    if let Some((a, b)) = token.split_once('-') {
        let a: IpAddr = a
            .trim()
            .parse()
            .map_err(|_| "range start is not an address".to_string())?;
        let b: IpAddr = b
            .trim()
            .parse()
            .map_err(|_| "range end is not an address".to_string())?;
        let ((va, na), (vb, nb)) = (to_num(a), to_num(b));
        if va != vb {
            return Err("range mixes IPv4 and IPv6".into());
        }
        if na > nb {
            return Err("range start is after its end".into());
        }
        return Ok((va, Range { start: na, end: nb }, None));
    }
    let (addr, len) = match token.split_once('/') {
        Some((a, l)) => (a, Some(l)),
        None => (token, None),
    };
    let ip: IpAddr = addr
        .parse()
        .map_err(|_| "not an IP address, prefix or range".to_string())?;
    let (v6, n) = to_num(ip);
    let len = match len {
        None => bits(v6),
        Some(l) => match l.parse::<u32>() {
            Ok(l) if l <= bits(v6) => l,
            Ok(_) => return Err(format!("prefix length above /{}", bits(v6))),
            Err(_) if !v6 => {
                let m: Ipv4Addr = l
                    .parse()
                    .map_err(|_| "bad prefix length or netmask".to_string())?;
                mask_len(m).ok_or("netmask is not contiguous")?
            }
            Err(_) => return Err("bad prefix length".into()),
        },
    };
    let m = mask(v6, len);
    let start = n & m;
    let span = if len == bits(v6) {
        0
    } else {
        !m & if v6 { u128::MAX } else { u32::MAX as u128 }
    };
    let note =
        (start != n).then(|| format!("host bits set; treated as {}/{len}", to_ip(v6, start)));
    Ok((
        v6,
        Range {
            start,
            end: start | span,
        },
        note,
    ))
}

fn parse(text: &str) -> Parsed {
    let mut p = Parsed::default();
    if text.len() > MAX_INPUT {
        p.invalid.push(Invalid {
            line: 0,
            text: String::new(),
            reason: "input larger than 2 MB".into(),
        });
        return p;
    }
    for (i, raw) in text.lines().enumerate() {
        let line = raw.split('#').next().unwrap_or("");
        // Commas, semicolons and whitespace separate entries; spaces around a
        // range dash are allowed ("10.0.0.1 - 10.0.0.9").
        let normalized = line
            .replace(" - ", "-")
            .replace(" -", "-")
            .replace("- ", "-");
        for token in normalized
            .split([',', ';', ' ', '\t'])
            .map(str::trim)
            .filter(|t| !t.is_empty())
        {
            if p.entries.len() >= MAX_ENTRIES {
                p.truncated = true;
                return p;
            }
            match parse_entry(token) {
                Ok((v6, range, note)) => {
                    if let Some(n) = note {
                        p.notes.push(Note {
                            line: i + 1,
                            text: token.into(),
                            note: n,
                        });
                    }
                    p.entries.push(Entry {
                        v6,
                        range,
                        text: token.into(),
                        line: i + 1,
                    });
                }
                Err(reason) => p.invalid.push(Invalid {
                    line: i + 1,
                    text: token.into(),
                    reason,
                }),
            }
        }
    }
    p
}

/// Sort and merge overlapping or adjacent ranges.
fn merge(mut r: Vec<Range>) -> Vec<Range> {
    r.sort();
    let mut out: Vec<Range> = Vec::with_capacity(r.len());
    for x in r {
        match out.last_mut() {
            Some(last) if x.start <= last.end.saturating_add(1) => last.end = last.end.max(x.end),
            _ => out.push(x),
        }
    }
    out
}

/// The fewest prefixes that cover exactly `r`.
fn range_to_cidrs(v6: bool, r: Range, out: &mut Vec<String>, limit: usize) -> bool {
    let b = bits(v6);
    let mut start = r.start;
    loop {
        if out.len() >= limit {
            return false;
        }
        // Largest block aligned at `start` that does not pass `end`.
        let align = if start == 0 {
            b
        } else {
            start.trailing_zeros().min(b)
        };
        let mut size_bits = align;
        while size_bits > 0 {
            let fits = if size_bits >= 128 {
                start == 0 && r.end == u128::MAX
            } else {
                start
                    .checked_add((1u128 << size_bits) - 1)
                    .is_some_and(|l| l <= r.end)
            };
            if fits {
                break;
            }
            size_bits -= 1;
        }
        out.push(format!("{}/{}", to_ip(v6, start), b - size_bits));
        let block_end = if size_bits == 128 {
            u128::MAX
        } else {
            start + ((1u128 << size_bits) - 1)
        };
        if block_end >= r.end {
            return true;
        }
        start = block_end + 1;
    }
}

fn cidrs(v6: bool, ranges: &[Range]) -> (Vec<String>, bool) {
    let mut out = Vec::new();
    for &r in ranges {
        if !range_to_cidrs(v6, r, &mut out, MAX_OUTPUT) {
            return (out, true);
        }
    }
    (out, false)
}

fn count(ranges: &[Range]) -> String {
    let mut total: u128 = 0;
    for r in ranges {
        // The whole IPv6 space (2^128 addresses) does not fit in a u128.
        let Some(n) = (r.end - r.start).checked_add(1) else {
            return "2^128".into();
        };
        total = match total.checked_add(n) {
            Some(t) => t,
            None => return "2^128".into(),
        };
    }
    total.to_string()
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub struct FamilySet {
    pub entries: usize,
    pub prefixes: Vec<String>,
    pub truncated: bool,
    /// Unique addresses covered, as a decimal string (IPv6 counts are huge).
    pub addresses: String,
}

fn family(entries: &[&Entry], v6: bool) -> (FamilySet, Vec<Range>) {
    let ranges = merge(
        entries
            .iter()
            .filter(|e| e.v6 == v6)
            .map(|e| e.range)
            .collect(),
    );
    let (prefixes, truncated) = cidrs(v6, &ranges);
    let set = FamilySet {
        entries: entries.iter().filter(|e| e.v6 == v6).count(),
        prefixes,
        truncated,
        addresses: count(&ranges),
    };
    (set, ranges)
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum OverlapKind {
    Duplicate,
    Contains,
    Partial,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Overlap {
    pub kind: OverlapKind,
    pub a: String,
    pub a_line: usize,
    pub b: String,
    pub b_line: usize,
}

/// Pairs of entries that share addresses, found with a sorted sweep.
fn overlaps(entries: &[Entry]) -> (Vec<Overlap>, bool) {
    let mut out = Vec::new();
    for v6 in [false, true] {
        let mut list: Vec<&Entry> = entries.iter().filter(|e| e.v6 == v6).collect();
        list.sort_by(|a, b| {
            a.range
                .start
                .cmp(&b.range.start)
                .then(b.range.end.cmp(&a.range.end))
        });
        // Active entries whose end has not been passed yet.
        let mut active: Vec<&Entry> = Vec::new();
        for e in list {
            active.retain(|a| a.range.end >= e.range.start);
            for a in &active {
                let kind = if a.range == e.range {
                    OverlapKind::Duplicate
                } else if a.range.end >= e.range.end {
                    OverlapKind::Contains
                } else {
                    OverlapKind::Partial
                };
                if out.len() >= MAX_OVERLAPS {
                    return (out, true);
                }
                out.push(Overlap {
                    kind,
                    a: a.text.clone(),
                    a_line: a.line,
                    b: e.text.clone(),
                    b_line: e.line,
                });
            }
            active.push(e);
        }
    }
    (out, false)
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AggregateResult {
    pub v4: FamilySet,
    pub v6: FamilySet,
    pub invalid: Vec<Invalid>,
    pub notes: Vec<Note>,
    pub overlaps: Vec<Overlap>,
    pub overlaps_truncated: bool,
    /// Stopped reading after MAX_ENTRIES.
    pub input_truncated: bool,
}

/// Normalize and aggregate a list; report overlaps within it.
pub fn aggregate(text: &str) -> AggregateResult {
    let p = parse(text);
    let all: Vec<&Entry> = p.entries.iter().collect();
    let (v4, _) = family(&all, false);
    let (v6, _) = family(&all, true);
    let (overlaps, overlaps_truncated) = overlaps(&p.entries);
    AggregateResult {
        v4,
        v6,
        invalid: p.invalid,
        notes: p.notes,
        overlaps,
        overlaps_truncated,
        input_truncated: p.truncated,
    }
}

/// `a` minus `b`, both merged and sorted.
fn subtract(a: &[Range], b: &[Range]) -> Vec<Range> {
    let mut out = Vec::new();
    let mut j = 0;
    for &r in a {
        let mut start = r.start;
        let mut done = false;
        while j < b.len() && b[j].end < start {
            j += 1;
        }
        let mut k = j;
        while k < b.len() && b[k].start <= r.end {
            if b[k].start > start {
                out.push(Range {
                    start,
                    end: b[k].start - 1,
                });
            }
            if b[k].end >= r.end {
                done = true;
                break;
            }
            start = b[k].end + 1;
            k += 1;
        }
        if !done && start <= r.end {
            out.push(Range { start, end: r.end });
        }
    }
    out
}

fn intersect(a: &[Range], b: &[Range]) -> Vec<Range> {
    let (mut i, mut j, mut out) = (0, 0, Vec::new());
    while i < a.len() && j < b.len() {
        let start = a[i].start.max(b[j].start);
        let end = a[i].end.min(b[j].end);
        if start <= end {
            out.push(Range { start, end });
        }
        if a[i].end < b[j].end { i += 1 } else { j += 1 }
    }
    out
}

#[derive(Debug, Clone, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct FamilyCompare {
    pub only_a: FamilySet,
    pub only_b: FamilySet,
    pub both: FamilySet,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CompareResult {
    pub v4: FamilyCompare,
    pub v6: FamilyCompare,
    pub invalid_a: Vec<Invalid>,
    pub invalid_b: Vec<Invalid>,
    pub identical: bool,
}

fn set_of(v6: bool, ranges: Vec<Range>) -> FamilySet {
    let (prefixes, truncated) = cidrs(v6, &ranges);
    FamilySet {
        entries: 0,
        addresses: count(&ranges),
        prefixes,
        truncated,
    }
}

/// Addresses only in A, only in B, and in both.
pub fn compare(a: &str, b: &str) -> CompareResult {
    let (pa, pb) = (parse(a), parse(b));
    let fam = |v6: bool| {
        let ra = merge(
            pa.entries
                .iter()
                .filter(|e| e.v6 == v6)
                .map(|e| e.range)
                .collect(),
        );
        let rb = merge(
            pb.entries
                .iter()
                .filter(|e| e.v6 == v6)
                .map(|e| e.range)
                .collect(),
        );
        FamilyCompare {
            only_a: set_of(v6, subtract(&ra, &rb)),
            only_b: set_of(v6, subtract(&rb, &ra)),
            both: set_of(v6, intersect(&ra, &rb)),
        }
    };
    let (v4, v6) = (fam(false), fam(true));
    let identical = v4.only_a.prefixes.is_empty()
        && v4.only_b.prefixes.is_empty()
        && v6.only_a.prefixes.is_empty()
        && v6.only_b.prefixes.is_empty();
    CompareResult {
        v4,
        v6,
        invalid_a: pa.invalid,
        invalid_b: pb.invalid,
        identical,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aggregates_exactly() {
        let r = aggregate("10.0.0.0/25\n10.0.0.128/25, 10.0.1.0/24\n10.0.3.0/24\n192.0.2.7");
        assert_eq!(
            r.v4.prefixes,
            vec!["10.0.0.0/23", "10.0.3.0/24", "192.0.2.7/32"]
        );
        assert_eq!(r.v4.addresses, (512 + 256 + 1).to_string());
        assert!(r.invalid.is_empty());
        // Not mergeable without adding addresses: 10.0.1.0/24 + 10.0.2.0/24.
        let r = aggregate("10.0.1.0/24 10.0.2.0/24");
        assert_eq!(r.v4.prefixes, vec!["10.0.1.0/24", "10.0.2.0/24"]);
    }

    #[test]
    fn ranges_masks_and_host_bits() {
        let r = aggregate(
            "10.0.0.1 - 10.0.0.6\n172.16.5.9/255.255.0.0\n2001:db8::/33 2001:db8:8000::/33",
        );
        assert_eq!(
            r.v4.prefixes,
            vec![
                "10.0.0.1/32",
                "10.0.0.2/31",
                "10.0.0.4/31",
                "10.0.0.6/32",
                "172.16.0.0/16"
            ]
        );
        assert_eq!(r.notes.len(), 1);
        assert!(r.notes[0].note.contains("172.16.0.0/16"));
        assert_eq!(r.v6.prefixes, vec!["2001:db8::/32"]);
        assert_eq!(r.v6.entries, 2);
    }

    #[test]
    fn invalid_entries_reported_with_lines() {
        let r = aggregate(
            "10.0.0.0/24\n10.0.0.0/33\n# comment\nbad\n10.0.0.9-10.0.0.1\n10.0.0.1-2001:db8::1\n10.0.0.0/255.0.255.0",
        );
        let lines: Vec<usize> = r.invalid.iter().map(|i| i.line).collect();
        assert_eq!(lines, vec![2, 4, 5, 6, 7]);
        assert_eq!(r.v4.prefixes, vec!["10.0.0.0/24"]);
    }

    #[test]
    fn edges() {
        assert_eq!(aggregate("0.0.0.0/0").v4.prefixes, vec!["0.0.0.0/0"]);
        assert_eq!(
            aggregate("0.0.0.0/1 128.0.0.0/1").v4.prefixes,
            vec!["0.0.0.0/0"]
        );
        assert_eq!(aggregate("::/0").v6.prefixes, vec!["::/0"]);
        assert_eq!(aggregate("::/0").v6.addresses, "2^128");
        assert_eq!(
            aggregate("255.255.255.255").v4.prefixes,
            vec!["255.255.255.255/32"]
        );
        assert_eq!(aggregate("::/1 8000::/1").v6.prefixes, vec!["::/0"]);
    }

    #[test]
    fn overlap_kinds() {
        let r =
            aggregate("10.0.0.0/16\n10.0.5.0/24\n10.0.5.0/24\n10.1.0.0 - 10.1.0.20\n10.1.0.16/28");
        let kinds: Vec<OverlapKind> = r.overlaps.iter().map(|o| o.kind).collect();
        assert!(kinds.contains(&OverlapKind::Duplicate));
        assert!(kinds.contains(&OverlapKind::Contains));
        assert!(kinds.contains(&OverlapKind::Partial));
        let dup = r
            .overlaps
            .iter()
            .find(|o| o.kind == OverlapKind::Duplicate)
            .unwrap();
        assert_eq!((dup.a_line, dup.b_line), (2, 3));
        assert!(aggregate("10.0.0.0/24 10.0.1.0/24").overlaps.is_empty());
    }

    #[test]
    fn compare_sets() {
        let c = compare(
            "10.0.0.0/23\n2001:db8::/48",
            "10.0.1.0/24\n10.0.2.0/24\n2001:db8::/48",
        );
        assert_eq!(c.v4.only_a.prefixes, vec!["10.0.0.0/24"]);
        assert_eq!(c.v4.only_b.prefixes, vec!["10.0.2.0/24"]);
        assert_eq!(c.v4.both.prefixes, vec!["10.0.1.0/24"]);
        assert_eq!(c.v6.both.prefixes, vec!["2001:db8::/48"]);
        assert!(c.v6.only_a.prefixes.is_empty() && !c.identical);
        assert!(compare("10.0.0.0/24", "10.0.0.0/25 10.0.0.128/25").identical);
        let c = compare("10.0.0.0/24", "10.0.0.64/26");
        assert_eq!(c.v4.only_a.prefixes, vec!["10.0.0.0/26", "10.0.0.128/25"]);
    }

    /// Addresses covered by a prefix list, inside 10.0.0.0/22.
    fn covered(prefixes: &[String]) -> Vec<bool> {
        let mut m = vec![false; 1024];
        for p in prefixes {
            let (_, r, _) = parse_entry(p).unwrap();
            for a in r.start..=r.end {
                m[(a - 0x0a00_0000) as usize] = true;
            }
        }
        m
    }

    #[test]
    fn randomized_exact_coverage() {
        use rand::RngExt;
        let mut rng = rand::rng();
        for _ in 0..300 {
            let mut want = vec![false; 1024];
            let mut lines = Vec::new();
            let mut b_want = vec![false; 1024];
            let mut b_lines = Vec::new();
            for (set, out) in [(&mut want, &mut lines), (&mut b_want, &mut b_lines)] {
                for _ in 0..rng.random_range(1..12) {
                    let start: u32 = rng.random_range(0..1024);
                    let len: u32 = rng.random_range(0..40);
                    let end = (start + len).min(1023);
                    for a in start..=end {
                        set[a as usize] = true;
                    }
                    let ip = |n: u32| Ipv4Addr::from(0x0a00_0000 + n).to_string();
                    out.push(format!("{} - {}", ip(start), ip(end)));
                }
            }
            let agg = aggregate(&lines.join("\n"));
            assert_eq!(covered(&agg.v4.prefixes), want, "{lines:?}");
            let c = compare(&lines.join("\n"), &b_lines.join("\n"));
            let only_a: Vec<bool> = (0..1024).map(|i| want[i] && !b_want[i]).collect();
            let both: Vec<bool> = (0..1024).map(|i| want[i] && b_want[i]).collect();
            assert_eq!(covered(&c.v4.only_a.prefixes), only_a);
            assert_eq!(covered(&c.v4.both.prefixes), both);
        }
    }

    #[test]
    fn limits() {
        let many = "10.0.0.1\n".repeat(MAX_ENTRIES + 10);
        let r = aggregate(&many);
        assert!(r.input_truncated);
        assert!(r.overlaps_truncated);
        assert_eq!(r.v4.prefixes, vec!["10.0.0.1/32"]);
        let big = "x".repeat(MAX_INPUT + 1);
        assert!(aggregate(&big).invalid[0].reason.contains("2 MB"));
    }
}
