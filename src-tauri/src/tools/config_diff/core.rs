//! Pure config-diff logic: line diff of two texts with normalization options,
//! side-by-side rows with inline word highlights, a config section breadcrumb
//! per hunk, and a unified diff export. No Tauri types here.
//!
//! Normalization (whitespace, case, ignored lines) only changes what is
//! compared. Rows always show the original text and original line numbers.

use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use similar::{Algorithm, DiffOp, DiffTag, capture_diff_slices_deadline, group_diff_ops};
use thiserror::Error;

use crate::tools::regex_builder::core as rx;

/// Cap on each input, to bound work and memory.
pub const MAX_INPUT_BYTES: usize = 5_000_000;

/// Time budget for the line diff. Past it the algorithm settles for a valid
/// but possibly less minimal result instead of running on.
const DIFF_DEADLINE: Duration = Duration::from_secs(2);

/// How far back to look for the enclosing config section of a hunk.
const BREADCRUMB_LOOKBACK: usize = 5000;

/// How whitespace differences are treated when comparing lines.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Whitespace {
    /// Compare exactly.
    Exact,
    /// Ignore trailing whitespace.
    #[default]
    Trailing,
    /// Ignore changes in the amount of whitespace (diff -b).
    Amount,
    /// Ignore all whitespace (diff -w).
    All,
}

/// Line diff algorithm.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Algo {
    /// Histogram (git's choice for readable diffs). Good default for configs.
    #[default]
    Histogram,
    Patience,
    Myers,
}

impl From<Algo> for Algorithm {
    fn from(a: Algo) -> Self {
        match a {
            Algo::Histogram => Algorithm::Histogram,
            Algo::Patience => Algorithm::Patience,
            Algo::Myers => Algorithm::Myers,
        }
    }
}

/// Diff options from the UI.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct DiffOptions {
    pub whitespace: Whitespace,
    pub ignore_case: bool,
    pub ignore_blank_lines: bool,
    /// Lines matching this regex are left out of the comparison. Empty means
    /// none, for example `^#config-version|set uuid`.
    pub ignore_pattern: String,
    /// Unchanged lines shown around each change. `None` shows everything.
    pub context: Option<usize>,
    pub algorithm: Algo,
    /// Names for the unified diff header.
    pub left_name: String,
    pub right_name: String,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DiffError {
    #[error("{side} input is too large ({got} bytes, limit {limit})")]
    TooLarge {
        side: &'static str,
        got: usize,
        limit: usize,
    },
    #[error("ignore pattern: {0}")]
    IgnorePattern(rx::RegexError),
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RowKind {
    Equal,
    Delete,
    Insert,
    /// A left line replaced by a right line, with inline highlights.
    Change,
}

/// A changed range within a line, in character offsets.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub struct Span {
    pub start: usize,
    pub end: usize,
}

/// One side of a row.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Side {
    /// 1-based line number in the original input.
    pub number: usize,
    pub text: String,
    /// Changed ranges for `Change` rows; empty otherwise.
    pub spans: Vec<Span>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Row {
    pub kind: RowKind,
    pub left: Option<Side>,
    pub right: Option<Side>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Hunk {
    /// `@@ -a,b +c,d @@` header.
    pub header: String,
    /// Enclosing config sections of the first change, outermost first, such as
    /// `["config firewall policy", "edit 12"]` or `["interface Vlan10"]`.
    pub section: Vec<String>,
    pub rows: Vec<Row>,
}

#[derive(Debug, Clone, Copy, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Stats {
    pub added: usize,
    pub removed: usize,
    pub changed: usize,
    pub left_lines: usize,
    pub right_lines: usize,
    /// Lines left out of the comparison by the ignore options.
    pub ignored_left: usize,
    pub ignored_right: usize,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DiffResult {
    /// True when the compared lines are the same.
    pub identical: bool,
    pub hunks: Vec<Hunk>,
    pub stats: Stats,
    /// Unified diff text for copy or save.
    pub unified: String,
}

/// Input lines that take part in the comparison.
struct Prepared<'a> {
    /// Every original line.
    all: Vec<&'a str>,
    /// Original index of each compared line.
    kept: Vec<usize>,
    /// Comparison key of each compared line.
    keys: Vec<String>,
}

/// Compare `left` and `right`.
pub fn diff(left: &str, right: &str, opts: &DiffOptions) -> Result<DiffResult, DiffError> {
    for (side, text) in [("left", left), ("right", right)] {
        if text.len() > MAX_INPUT_BYTES {
            return Err(DiffError::TooLarge {
                side,
                got: text.len(),
                limit: MAX_INPUT_BYTES,
            });
        }
    }
    let ignore = if opts.ignore_pattern.is_empty() {
        None
    } else {
        Some(
            rx::Matcher::compile(
                &opts.ignore_pattern,
                &rx::RegexFlags::default(),
                rx::Engine::Standard,
            )
            .map_err(DiffError::IgnorePattern)?,
        )
    };

    let l = prepare(left, opts, ignore.as_ref());
    let r = prepare(right, opts, ignore.as_ref());

    let ops = capture_diff_slices_deadline(
        opts.algorithm.into(),
        &l.keys,
        &r.keys,
        Some(Instant::now() + DIFF_DEADLINE),
    );

    let mut stats = Stats {
        left_lines: l.all.len(),
        right_lines: r.all.len(),
        ignored_left: l.all.len() - l.kept.len(),
        ignored_right: r.all.len() - r.kept.len(),
        ..Default::default()
    };

    // Full context is one group of every op. group_diff_ops overflows on
    // usize::MAX, so it only handles the bounded case.
    let groups = match opts.context {
        Some(n) => group_diff_ops(ops, n),
        None if ops.is_empty() => Vec::new(),
        None => vec![ops],
    };
    let mut hunks = Vec::with_capacity(groups.len());
    for group in &groups {
        let rows = group_rows(group, &l, &r, opts);
        for row in &rows {
            match row.kind {
                RowKind::Equal => {}
                RowKind::Delete => stats.removed += 1,
                RowKind::Insert => stats.added += 1,
                RowKind::Change => stats.changed += 1,
            }
        }
        hunks.push(Hunk {
            header: hunk_header(group, &l, &r),
            section: hunk_section(&rows, &l, &r),
            rows,
        });
    }

    let identical = stats.added == 0 && stats.removed == 0 && stats.changed == 0;
    if identical {
        // Full context still yields one all-equal group.
        hunks.clear();
    }
    let unified = if identical {
        String::new()
    } else {
        unified_text(&hunks, opts)
    };

    Ok(DiffResult {
        identical,
        hunks,
        stats,
        unified,
    })
}

fn prepare<'a>(text: &'a str, opts: &DiffOptions, ignore: Option<&rx::Matcher>) -> Prepared<'a> {
    let all: Vec<&str> = text.lines().collect();
    let mut kept = Vec::with_capacity(all.len());
    let mut keys = Vec::with_capacity(all.len());
    for (i, line) in all.iter().enumerate() {
        if opts.ignore_blank_lines && line.trim().is_empty() {
            continue;
        }
        // A regex runtime error cannot happen on the standard engine; treat
        // it as no match to be safe.
        if ignore.is_some_and(|m| m.is_match(line).unwrap_or(false)) {
            continue;
        }
        kept.push(i);
        keys.push(line_key(line, opts));
    }
    Prepared { all, kept, keys }
}

/// The text a line is compared by.
fn line_key(line: &str, opts: &DiffOptions) -> String {
    let mut key = match opts.whitespace {
        Whitespace::Exact => line.to_string(),
        Whitespace::Trailing => line.trim_end().to_string(),
        Whitespace::Amount => collapse_whitespace(line.trim_end()),
        Whitespace::All => line.chars().filter(|c| !c.is_whitespace()).collect(),
    };
    if opts.ignore_case {
        key = key.to_lowercase();
    }
    key
}

/// Replace each run of whitespace with one space.
fn collapse_whitespace(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut in_ws = false;
    for c in s.chars() {
        if c.is_whitespace() {
            if !in_ws {
                out.push(' ');
            }
            in_ws = true;
        } else {
            out.push(c);
            in_ws = false;
        }
    }
    out
}

fn side(p: &Prepared, idx: usize) -> Side {
    let orig = p.kept[idx];
    Side {
        number: orig + 1,
        text: p.all[orig].to_string(),
        spans: Vec::new(),
    }
}

/// Turn one group of ops into rows. Runs of deletes and inserts between equal
/// stretches are paired line by line as `Change` rows; leftovers become plain
/// deletes or inserts.
fn group_rows(group: &[DiffOp], l: &Prepared, r: &Prepared, opts: &DiffOptions) -> Vec<Row> {
    let mut rows = Vec::new();
    let mut dels: Vec<usize> = Vec::new();
    let mut ins: Vec<usize> = Vec::new();

    let flush = |rows: &mut Vec<Row>, dels: &mut Vec<usize>, ins: &mut Vec<usize>| {
        let paired = dels.len().min(ins.len());
        for k in 0..paired {
            let mut left = side(l, dels[k]);
            let mut right = side(r, ins[k]);
            let (ls, rs) = inline_spans(&left.text, &right.text, opts);
            left.spans = ls;
            right.spans = rs;
            rows.push(Row {
                kind: RowKind::Change,
                left: Some(left),
                right: Some(right),
            });
        }
        for &d in &dels[paired..] {
            rows.push(Row {
                kind: RowKind::Delete,
                left: Some(side(l, d)),
                right: None,
            });
        }
        for &i in &ins[paired..] {
            rows.push(Row {
                kind: RowKind::Insert,
                left: None,
                right: Some(side(r, i)),
            });
        }
        dels.clear();
        ins.clear();
    };

    for op in group {
        let (tag, old, new) = op.as_tag_tuple();
        match tag {
            DiffTag::Equal => {
                flush(&mut rows, &mut dels, &mut ins);
                for (o, n) in old.zip(new) {
                    rows.push(Row {
                        kind: RowKind::Equal,
                        left: Some(side(l, o)),
                        right: Some(side(r, n)),
                    });
                }
            }
            DiffTag::Delete => dels.extend(old),
            DiffTag::Insert => ins.extend(new),
            DiffTag::Replace => {
                dels.extend(old);
                ins.extend(new);
            }
        }
    }
    flush(&mut rows, &mut dels, &mut ins);
    rows
}

/// `@@ -a,b +c,d @@` in original line numbers. When ignore options drop lines
/// inside the hunk, counts cover the compared lines only.
fn hunk_header(group: &[DiffOp], l: &Prepared, r: &Prepared) -> String {
    let (Some(first), Some(last)) = (group.first(), group.last()) else {
        return String::new();
    };
    let old = first.old_range().start..last.old_range().end;
    let new = first.new_range().start..last.new_range().end;
    format!("@@ -{} +{} @@", range_label(&old, l), range_label(&new, r))
}

fn range_label(range: &std::ops::Range<usize>, p: &Prepared) -> String {
    let len = range.len();
    // An empty range names the line before it, as diff -u does.
    let start = if len == 0 {
        if range.start == 0 {
            0
        } else {
            p.kept[range.start - 1] + 1
        }
    } else {
        p.kept[range.start] + 1
    };
    format!("{start},{len}")
}

/// Breadcrumb for the first changed row of a hunk.
fn hunk_section(rows: &[Row], l: &Prepared, r: &Prepared) -> Vec<String> {
    let Some(row) = rows.iter().find(|row| row.kind != RowKind::Equal) else {
        return Vec::new();
    };
    match (&row.left, &row.right) {
        (Some(s), _) => breadcrumb(&l.all, s.number - 1),
        (None, Some(s)) => breadcrumb(&r.all, s.number - 1),
        (None, None) => Vec::new(),
    }
}

fn indent_of(line: &str) -> usize {
    line.chars().take_while(|c| *c == ' ' || *c == '\t').count()
}

/// Lines that close a block rather than open one.
fn is_closer(trimmed: &str) -> bool {
    matches!(trimmed, "end" | "next" | "exit" | "!" | "}" | "]")
        || trimmed.starts_with('!')
        || trimmed.starts_with('#')
}

/// Enclosing sections of line `at`, found by walking back to lines with less
/// indentation. Works for FortiOS (`config` / `edit`), Cisco and Arista style
/// (`interface ...` then indented lines), and similar indented configs.
pub fn breadcrumb(lines: &[&str], at: usize) -> Vec<String> {
    let Some(line) = lines.get(at) else {
        return Vec::new();
    };
    let mut current = indent_of(line);
    let mut out = Vec::new();
    let floor = at.saturating_sub(BREADCRUMB_LOOKBACK);
    let mut i = at;
    while current > 0 && i > floor {
        i -= 1;
        let candidate = lines[i];
        let trimmed = candidate.trim();
        if trimmed.is_empty() || is_closer(trimmed) {
            continue;
        }
        let ind = indent_of(candidate);
        if ind < current {
            out.push(trimmed.to_string());
            current = ind;
        }
    }
    out.reverse();
    out
}

/// Split a line into word, whitespace and single punctuation tokens.
fn tokenize(s: &str) -> Vec<&str> {
    #[derive(PartialEq, Clone, Copy)]
    enum Class {
        Word,
        Space,
        Other,
    }
    let class = |c: char| {
        if c.is_alphanumeric() || c == '_' {
            Class::Word
        } else if c.is_whitespace() {
            Class::Space
        } else {
            Class::Other
        }
    };
    let mut out = Vec::new();
    let mut start = 0;
    let mut prev: Option<Class> = None;
    for (i, c) in s.char_indices() {
        let k = class(c);
        // Punctuation is one token per char; words and spaces group.
        if prev.is_some() && (Some(k) != prev || k == Class::Other) {
            out.push(&s[start..i]);
            start = i;
        }
        prev = Some(k);
    }
    if start < s.len() {
        out.push(&s[start..]);
    }
    out
}

/// Changed char ranges in each of two paired lines, by word diff.
fn inline_spans(left: &str, right: &str, opts: &DiffOptions) -> (Vec<Span>, Vec<Span>) {
    let lt = tokenize(left);
    let rt = tokenize(right);
    let key = |t: &&str| {
        let k = if opts.whitespace != Whitespace::Exact && t.trim().is_empty() {
            " ".to_string()
        } else {
            t.to_string()
        };
        if opts.ignore_case {
            k.to_lowercase()
        } else {
            k
        }
    };
    let lk: Vec<String> = lt.iter().map(key).collect();
    let rk: Vec<String> = rt.iter().map(key).collect();
    let ops = similar::capture_diff_slices(Algorithm::Myers, &lk, &rk);

    let char_starts = |tokens: &[&str]| {
        let mut v = Vec::with_capacity(tokens.len() + 1);
        let mut n = 0;
        v.push(0);
        for t in tokens {
            n += t.chars().count();
            v.push(n);
        }
        v
    };
    let lc = char_starts(&lt);
    let rc = char_starts(&rt);

    let mut ls = Vec::new();
    let mut rs = Vec::new();
    for op in ops {
        let (tag, old, new) = op.as_tag_tuple();
        if tag == DiffTag::Equal {
            continue;
        }
        push_span(&mut ls, lc[old.start], lc[old.end]);
        push_span(&mut rs, rc[new.start], rc[new.end]);
    }
    (ls, rs)
}

/// Add a span, merging with the previous one when they touch.
fn push_span(spans: &mut Vec<Span>, start: usize, end: usize) {
    if end <= start {
        return;
    }
    if let Some(last) = spans.last_mut()
        && last.end >= start
    {
        last.end = last.end.max(end);
        return;
    }
    spans.push(Span { start, end });
}

/// Render hunks as unified diff text.
fn unified_text(hunks: &[Hunk], opts: &DiffOptions) -> String {
    let name = |n: &str, fallback: &'static str| {
        if n.is_empty() {
            fallback.to_string()
        } else {
            n.to_string()
        }
    };
    let mut out = format!(
        "--- {}\n+++ {}\n",
        name(&opts.left_name, "left"),
        name(&opts.right_name, "right")
    );
    for h in hunks {
        out.push_str(&h.header);
        if !h.section.is_empty() {
            out.push(' ');
            out.push_str(&h.section.join(" > "));
        }
        out.push('\n');
        // Within each run of changes, all removals come before additions.
        let mut minus: Vec<&str> = Vec::new();
        let mut plus: Vec<&str> = Vec::new();
        let flush = |out: &mut String, minus: &mut Vec<&str>, plus: &mut Vec<&str>| {
            for m in minus.drain(..) {
                out.push('-');
                out.push_str(m);
                out.push('\n');
            }
            for p in plus.drain(..) {
                out.push('+');
                out.push_str(p);
                out.push('\n');
            }
        };
        for row in &h.rows {
            if row.kind == RowKind::Equal {
                flush(&mut out, &mut minus, &mut plus);
                if let Some(l) = &row.left {
                    out.push(' ');
                    out.push_str(&l.text);
                    out.push('\n');
                }
                continue;
            }
            if let Some(l) = &row.left {
                minus.push(&l.text);
            }
            if let Some(r) = &row.right {
                plus.push(&r.text);
            }
        }
        flush(&mut out, &mut minus, &mut plus);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts() -> DiffOptions {
        DiffOptions {
            context: Some(3),
            ..Default::default()
        }
    }

    fn kinds(r: &DiffResult) -> Vec<RowKind> {
        r.hunks
            .iter()
            .flat_map(|h| h.rows.iter().map(|row| row.kind))
            .collect()
    }

    #[test]
    fn identical_inputs() {
        let r = diff("a\nb\n", "a\nb\n", &opts()).unwrap();
        assert!(r.identical);
        assert!(r.hunks.is_empty());
        assert!(r.unified.is_empty());
        assert_eq!(r.stats.left_lines, 2);
    }

    #[test]
    fn identical_with_full_context_has_no_hunks() {
        let o = DiffOptions {
            context: None,
            ..Default::default()
        };
        assert!(diff("a\nb", "a\nb", &o).unwrap().hunks.is_empty());
    }

    #[test]
    fn simple_change_pairs_lines() {
        let r = diff("a\nset ip 10.0.0.1\nc", "a\nset ip 10.0.0.2\nc", &opts()).unwrap();
        assert_eq!(kinds(&r), [RowKind::Equal, RowKind::Change, RowKind::Equal]);
        assert_eq!(r.stats.changed, 1);
        assert_eq!(r.stats.added + r.stats.removed, 0);
    }

    #[test]
    fn inline_spans_mark_changed_word() {
        let r = diff("set ip 10.0.0.1", "set ip 10.0.0.2", &opts()).unwrap();
        let row = &r.hunks[0].rows[0];
        // Only the final octet differs: tokens are "10", ".", "0", ".", ...
        assert_eq!(
            row.left.as_ref().unwrap().spans,
            [Span { start: 14, end: 15 }]
        );
        assert_eq!(
            row.right.as_ref().unwrap().spans,
            [Span { start: 14, end: 15 }]
        );
    }

    #[test]
    fn adds_and_removes() {
        let r = diff("a\nb\nc", "a\nc\nd", &opts()).unwrap();
        assert_eq!(r.stats.removed, 1);
        assert_eq!(r.stats.added, 1);
        assert_eq!(r.stats.changed, 0);
    }

    #[test]
    fn uneven_replace_leaves_insert() {
        let r = diff("a\nx\nz", "a\ny1\ny2\nz", &opts()).unwrap();
        assert_eq!(
            kinds(&r),
            [
                RowKind::Equal,
                RowKind::Change,
                RowKind::Insert,
                RowKind::Equal
            ]
        );
    }

    #[test]
    fn context_limits_rows_and_splits_hunks() {
        let left: String = (1..=30).map(|i| format!("l{i}\n")).collect();
        let right = left.replace("l2\n", "X\n").replace("l28\n", "Y\n");
        let r = diff(&left, &right, &opts()).unwrap();
        assert_eq!(r.hunks.len(), 2);
        assert_eq!(r.hunks[0].header, "@@ -1,5 +1,5 @@");
        assert_eq!(r.hunks[1].header, "@@ -25,6 +25,6 @@");
    }

    #[test]
    fn full_context_is_one_hunk() {
        let left: String = (1..=30).map(|i| format!("l{i}\n")).collect();
        let right = left.replace("l2\n", "X\n").replace("l28\n", "Y\n");
        let o = DiffOptions {
            context: None,
            ..Default::default()
        };
        let r = diff(&left, &right, &o).unwrap();
        assert_eq!(r.hunks.len(), 1);
        assert_eq!(r.hunks[0].rows.len(), 30);
    }

    #[test]
    fn trailing_whitespace_ignored_by_default() {
        assert!(diff("a  \nb", "a\nb", &opts()).unwrap().identical);
        let exact = DiffOptions {
            whitespace: Whitespace::Exact,
            ..opts()
        };
        assert!(!diff("a  \nb", "a\nb", &exact).unwrap().identical);
    }

    #[test]
    fn crlf_matches_lf() {
        let exact = DiffOptions {
            whitespace: Whitespace::Exact,
            ..opts()
        };
        assert!(diff("a\r\nb\r\n", "a\nb\n", &exact).unwrap().identical);
    }

    #[test]
    fn amount_and_all_whitespace() {
        let amount = DiffOptions {
            whitespace: Whitespace::Amount,
            ..opts()
        };
        assert!(diff("set  a   b", "set a b", &amount).unwrap().identical);
        assert!(!diff("    set a", "set a", &amount).unwrap().identical);
        let all = DiffOptions {
            whitespace: Whitespace::All,
            ..opts()
        };
        assert!(diff("    set a", "set a", &all).unwrap().identical);
    }

    #[test]
    fn ignore_case() {
        let o = DiffOptions {
            ignore_case: true,
            ..opts()
        };
        assert!(diff("Hostname FW", "hostname fw", &o).unwrap().identical);
    }

    #[test]
    fn ignore_blank_lines() {
        let o = DiffOptions {
            ignore_blank_lines: true,
            ..opts()
        };
        let r = diff("a\n\nb", "a\nb", &o).unwrap();
        assert!(r.identical);
        assert_eq!(r.stats.ignored_left, 1);
    }

    #[test]
    fn ignore_pattern_drops_volatile_lines() {
        let o = DiffOptions {
            ignore_pattern: r"^#config-version|set uuid ".to_string(),
            ..opts()
        };
        let left = "#config-version=FGT60F-7.6.7\nconfig firewall policy\n    edit 1\n        set uuid 1111\n";
        let right = "#config-version=FGT60F-7.6.8\nconfig firewall policy\n    edit 1\n        set uuid 2222\n";
        let r = diff(left, right, &o).unwrap();
        assert!(r.identical);
        assert_eq!(r.stats.ignored_right, 2);
    }

    #[test]
    fn bad_ignore_pattern_errors() {
        let o = DiffOptions {
            ignore_pattern: "(".to_string(),
            ..opts()
        };
        assert!(matches!(
            diff("a", "b", &o),
            Err(DiffError::IgnorePattern(_))
        ));
    }

    #[test]
    fn original_line_numbers_survive_ignored_lines() {
        let o = DiffOptions {
            ignore_blank_lines: true,
            ..opts()
        };
        let r = diff("\n\na\nb", "a\nc", &o).unwrap();
        let change = r.hunks[0]
            .rows
            .iter()
            .find(|row| row.kind == RowKind::Change)
            .unwrap();
        assert_eq!(change.left.as_ref().unwrap().number, 4);
        assert_eq!(change.right.as_ref().unwrap().number, 2);
    }

    #[test]
    fn too_large_errors() {
        let big = "a".repeat(MAX_INPUT_BYTES + 1);
        assert!(matches!(
            diff(&big, "", &opts()),
            Err(DiffError::TooLarge { side: "left", .. })
        ));
    }

    #[test]
    fn fortios_breadcrumb() {
        let left = "config firewall policy\n    edit 12\n        set action accept\n        set srcintf \"port1\"\n    next\nend\n";
        let right = left.replace("accept", "deny");
        let r = diff(left, &right, &opts()).unwrap();
        assert_eq!(r.hunks[0].section, ["config firewall policy", "edit 12"]);
        assert!(r.unified.contains("@@ config firewall policy > edit 12\n"));
    }

    #[test]
    fn breadcrumb_skips_closed_blocks() {
        let lines = [
            "config firewall policy",
            "    edit 1",
            "        set a",
            "    next",
            "    edit 2",
            "        set b",
        ];
        assert_eq!(breadcrumb(&lines, 5), ["config firewall policy", "edit 2"]);
        assert_eq!(breadcrumb(&lines, 4), ["config firewall policy"]);
        assert!(breadcrumb(&lines, 0).is_empty());
    }

    #[test]
    fn cisco_breadcrumb() {
        let lines = [
            "interface Vlan10",
            " description Users",
            " ip address 10.10.10.1 255.255.255.0",
        ];
        assert_eq!(breadcrumb(&lines, 2), ["interface Vlan10"]);
    }

    #[test]
    fn unified_output() {
        let mut o = opts();
        o.left_name = "running.conf".to_string();
        o.right_name = "candidate.conf".to_string();
        let r = diff("a\nb\nc\n", "a\nB\nc\nd\n", &o).unwrap();
        assert_eq!(
            r.unified,
            "--- running.conf\n+++ candidate.conf\n@@ -1,3 +1,4 @@\n a\n-b\n+B\n c\n+d\n"
        );
    }

    #[test]
    fn unified_insert_at_start_header() {
        let r = diff("b\n", "a\nb\n", &opts()).unwrap();
        assert!(r.unified.contains("@@ -1,1 +1,2 @@"), "{}", r.unified);
        let r = diff("", "a\n", &opts()).unwrap();
        assert!(r.unified.contains("@@ -0,0 +1,1 @@"), "{}", r.unified);
    }

    #[test]
    fn tokenize_groups_words_and_splits_punctuation() {
        assert_eq!(
            tokenize("set ip 10.0"),
            ["set", " ", "ip", " ", "10", ".", "0"]
        );
        assert_eq!(tokenize("\"port1\""), ["\"", "port1", "\""]);
        assert!(tokenize("").is_empty());
    }

    #[test]
    fn unicode_inline_offsets_are_chars() {
        let r = diff("é a", "é b", &opts()).unwrap();
        let row = &r.hunks[0].rows[0];
        assert_eq!(
            row.left.as_ref().unwrap().spans,
            [Span { start: 2, end: 3 }]
        );
    }
}
