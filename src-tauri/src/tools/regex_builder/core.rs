//! Pure regex-builder logic. No Tauri types here so it can be unit tested in
//! isolation.
//!
//! Two engines are supported:
//! - `Standard` uses the `regex` crate: RE2 style, linear time, no catastrophic
//!   backtracking, so hostile input cannot trigger ReDoS. No backreferences or
//!   lookaround.
//! - `Pcre` uses `fancy-regex`: adds backreferences and lookaround, but
//!   backtracks, so it runs under a backtrack limit and reports a clear error
//!   when that limit is hit.

use std::collections::HashMap;

use regex::RegexBuilder;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Cap on detailed matches returned to the UI. The total count is still
/// reported accurately; only the per-match detail list is bounded.
pub const MAX_MATCHES: usize = 1000;

/// Cap on sample text size, to bound work and memory.
pub const MAX_TEXT_BYTES: usize = 1_000_000;

/// Cap on the compiled program size for the standard engine, a second guard
/// against pathological patterns.
const COMPILE_SIZE_LIMIT: usize = 10 * (1 << 20);

/// Maximum backtracking steps for the PCRE-style engine before it gives up.
pub const BACKTRACK_LIMIT: usize = 1_000_000;

/// Which matching engine to use.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Engine {
    #[default]
    Standard,
    Pcre,
}

/// Toggles applied to both engines (as builder options for the standard engine,
/// as inline flags for the PCRE engine).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct RegexFlags {
    pub case_insensitive: bool,
    pub multiline: bool,
    /// `.` matches newlines when true.
    pub dot_all: bool,
    /// Ignore whitespace in the pattern and allow `#` comments (verbose mode).
    pub ignore_whitespace: bool,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RegexError {
    #[error("enter a pattern")]
    EmptyPattern,
    #[error("sample text is too large ({got} bytes, limit {limit})")]
    TextTooLarge { got: usize, limit: usize },
    #[error("invalid pattern: {0}")]
    Invalid(String),
    #[error("backtrack limit exceeded ({limit} steps); simplify the pattern or reduce the input")]
    BacktrackLimit { limit: usize },
}

/// One capture group within a match. `value` and offsets are `None` when the
/// group did not participate in the match.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GroupMatch {
    pub index: usize,
    pub name: Option<String>,
    pub value: Option<String>,
    pub start: Option<usize>,
    pub end: Option<usize>,
}

/// One whole-pattern match. Offsets are character (Unicode scalar) positions so
/// the UI can slice the string safely for highlighting.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Match {
    pub start: usize,
    pub end: usize,
    pub value: String,
    pub groups: Vec<GroupMatch>,
}

/// Result of testing a pattern against sample text.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RegexResult {
    pub matches: Vec<Match>,
    /// True total number of matches, even when `matches` is truncated.
    pub total: usize,
    /// True when `matches` was capped at [`MAX_MATCHES`].
    pub truncated: bool,
    /// Names for capture groups 1..n (`None` for unnamed), for table headers.
    pub group_names: Vec<Option<String>>,
}

/// Intermediate match with byte offsets, before conversion to char offsets.
struct RawGroup {
    index: usize,
    span: Option<(usize, usize)>,
    value: Option<String>,
}
struct RawMatch {
    start: usize,
    end: usize,
    value: String,
    groups: Vec<RawGroup>,
}

fn check_text_size(text: &str) -> Result<(), RegexError> {
    if text.len() > MAX_TEXT_BYTES {
        return Err(RegexError::TextTooLarge {
            got: text.len(),
            limit: MAX_TEXT_BYTES,
        });
    }
    Ok(())
}

/// Test `pattern` against `text` with the chosen engine.
pub fn test(
    pattern: &str,
    text: &str,
    flags: &RegexFlags,
    engine: Engine,
) -> Result<RegexResult, RegexError> {
    check_text_size(text)?;
    if pattern.is_empty() {
        return Err(RegexError::EmptyPattern);
    }
    match engine {
        Engine::Standard => test_standard(pattern, text, flags),
        Engine::Pcre => test_pcre(pattern, text, flags),
    }
}

/// Replace every match with `replacement` (supports `$1` and `${name}`).
pub fn replace_all(
    pattern: &str,
    text: &str,
    flags: &RegexFlags,
    replacement: &str,
    engine: Engine,
) -> Result<String, RegexError> {
    check_text_size(text)?;
    if pattern.is_empty() {
        return Err(RegexError::EmptyPattern);
    }
    match engine {
        Engine::Standard => {
            let re = build_standard(pattern, flags)?;
            Ok(re.replace_all(text, replacement).into_owned())
        }
        Engine::Pcre => replace_pcre(pattern, text, flags, replacement),
    }
}

// --- Standard engine (regex crate) ---------------------------------------

fn build_standard(pattern: &str, flags: &RegexFlags) -> Result<regex::Regex, RegexError> {
    RegexBuilder::new(pattern)
        .case_insensitive(flags.case_insensitive)
        .multi_line(flags.multiline)
        .dot_matches_new_line(flags.dot_all)
        .ignore_whitespace(flags.ignore_whitespace)
        .size_limit(COMPILE_SIZE_LIMIT)
        .build()
        .map_err(|e| RegexError::Invalid(e.to_string()))
}

fn test_standard(pattern: &str, text: &str, flags: &RegexFlags) -> Result<RegexResult, RegexError> {
    let re = build_standard(pattern, flags)?;

    // Count every match cheaply (no capture allocation), then collect detail
    // for the first MAX_MATCHES only.
    let total = re.find_iter(text).count();

    let mut raw: Vec<RawMatch> = Vec::new();
    let mut byte_positions: Vec<usize> = Vec::new();
    for caps in re.captures_iter(text).take(MAX_MATCHES) {
        let whole = caps.get(0).expect("group 0 always present");
        byte_positions.push(whole.start());
        byte_positions.push(whole.end());

        let mut groups = Vec::with_capacity(caps.len().saturating_sub(1));
        for i in 1..caps.len() {
            match caps.get(i) {
                Some(g) => {
                    byte_positions.push(g.start());
                    byte_positions.push(g.end());
                    groups.push(RawGroup {
                        index: i,
                        span: Some((g.start(), g.end())),
                        value: Some(g.as_str().to_string()),
                    });
                }
                None => groups.push(RawGroup {
                    index: i,
                    span: None,
                    value: None,
                }),
            }
        }
        raw.push(RawMatch {
            start: whole.start(),
            end: whole.end(),
            value: whole.as_str().to_string(),
            groups,
        });
    }

    let group_names = re
        .capture_names()
        .skip(1)
        .map(|o| o.map(|s| s.to_string()))
        .collect();

    Ok(finish(text, raw, &byte_positions, group_names, total))
}

// --- PCRE-style engine (fancy-regex) -------------------------------------

/// fancy-regex has no builder flag setters, so flags are applied as an inline
/// group prefix like `(?ims)`.
fn flag_prefix(flags: &RegexFlags) -> String {
    let mut s = String::new();
    if flags.case_insensitive {
        s.push('i');
    }
    if flags.multiline {
        s.push('m');
    }
    if flags.dot_all {
        s.push('s');
    }
    if flags.ignore_whitespace {
        s.push('x');
    }
    if s.is_empty() {
        String::new()
    } else {
        format!("(?{s})")
    }
}

fn build_pcre(pattern: &str, flags: &RegexFlags) -> Result<fancy_regex::Regex, RegexError> {
    let prefixed = format!("{}{}", flag_prefix(flags), pattern);
    fancy_regex::RegexBuilder::new(&prefixed)
        .backtrack_limit(BACKTRACK_LIMIT)
        .build()
        .map_err(|e| RegexError::Invalid(e.to_string()))
}

/// Map a fancy-regex runtime error, distinguishing the backtrack limit so the
/// UI can explain it.
fn map_fancy_runtime(e: fancy_regex::Error) -> RegexError {
    match e {
        fancy_regex::Error::RuntimeError(fancy_regex::RuntimeError::BacktrackLimitExceeded) => {
            RegexError::BacktrackLimit {
                limit: BACKTRACK_LIMIT,
            }
        }
        other => RegexError::Invalid(other.to_string()),
    }
}

fn test_pcre(pattern: &str, text: &str, flags: &RegexFlags) -> Result<RegexResult, RegexError> {
    let re = build_pcre(pattern, flags)?;

    let mut total = 0;
    let mut raw: Vec<RawMatch> = Vec::new();
    let mut byte_positions: Vec<usize> = Vec::new();
    for item in re.captures_iter(text) {
        let caps = item.map_err(map_fancy_runtime)?;
        total += 1;
        if raw.len() >= MAX_MATCHES {
            continue;
        }
        let whole = caps.get(0).expect("group 0 always present");
        byte_positions.push(whole.start());
        byte_positions.push(whole.end());

        let mut groups = Vec::with_capacity(caps.len().saturating_sub(1));
        for i in 1..caps.len() {
            match caps.get(i) {
                Some(g) => {
                    byte_positions.push(g.start());
                    byte_positions.push(g.end());
                    groups.push(RawGroup {
                        index: i,
                        span: Some((g.start(), g.end())),
                        value: Some(g.as_str().to_string()),
                    });
                }
                None => groups.push(RawGroup {
                    index: i,
                    span: None,
                    value: None,
                }),
            }
        }
        raw.push(RawMatch {
            start: whole.start(),
            end: whole.end(),
            value: whole.as_str().to_string(),
            groups,
        });
    }

    let group_names = re
        .capture_names()
        .skip(1)
        .map(|o| o.map(|s| s.to_string()))
        .collect();

    Ok(finish(text, raw, &byte_positions, group_names, total))
}

fn replace_pcre(
    pattern: &str,
    text: &str,
    flags: &RegexFlags,
    replacement: &str,
) -> Result<String, RegexError> {
    let re = build_pcre(pattern, flags)?;
    let mut out = String::with_capacity(text.len());
    let mut last = 0usize;
    for item in re.captures_iter(text) {
        let caps = item.map_err(map_fancy_runtime)?;
        let whole = caps.get(0).expect("group 0 always present");
        out.push_str(&text[last..whole.start()]);
        caps.expand(replacement, &mut out);
        last = whole.end();
    }
    out.push_str(&text[last..]);
    Ok(out)
}

// --- Shared offset conversion --------------------------------------------

/// Turn raw byte-offset matches into char-offset matches and attach group
/// names.
fn finish(
    text: &str,
    raw: Vec<RawMatch>,
    byte_positions: &[usize],
    group_names: Vec<Option<String>>,
    total: usize,
) -> RegexResult {
    let map = char_offsets(text, byte_positions);
    let char_at = |b: usize| map.get(&b).copied().unwrap_or(b);

    let matches = raw
        .into_iter()
        .map(|m| Match {
            start: char_at(m.start),
            end: char_at(m.end),
            value: m.value,
            groups: m
                .groups
                .into_iter()
                .map(|g| GroupMatch {
                    name: group_names.get(g.index - 1).and_then(|n| n.clone()),
                    index: g.index,
                    value: g.value,
                    start: g.span.map(|(s, _)| char_at(s)),
                    end: g.span.map(|(_, e)| char_at(e)),
                })
                .collect(),
        })
        .collect();

    RegexResult {
        matches,
        total,
        truncated: total > MAX_MATCHES,
        group_names,
    }
}

/// Map a set of byte offsets to character (scalar) offsets in one pass. All
/// offsets produced by the regex engines fall on char boundaries.
fn char_offsets(text: &str, byte_positions: &[usize]) -> HashMap<usize, usize> {
    let mut want: Vec<usize> = byte_positions.to_vec();
    want.sort_unstable();
    want.dedup();

    let mut map = HashMap::with_capacity(want.len());
    let mut wi = 0;
    let mut char_idx = 0;
    for (byte_idx, _) in text.char_indices() {
        // Advance past any wanted offsets at or before this boundary.
        while wi < want.len() && want[wi] <= byte_idx {
            if want[wi] == byte_idx {
                map.insert(byte_idx, char_idx);
            }
            wi += 1;
        }
        char_idx += 1;
    }
    // Offsets equal to the text length map to the final char count.
    let end_byte = text.len();
    while wi < want.len() {
        if want[wi] == end_byte {
            map.insert(end_byte, char_idx);
        }
        wi += 1;
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flags() -> RegexFlags {
        RegexFlags::default()
    }

    fn std_test(pattern: &str, text: &str, flags: &RegexFlags) -> Result<RegexResult, RegexError> {
        test(pattern, text, flags, Engine::Standard)
    }

    #[test]
    fn empty_pattern_errors() {
        assert_eq!(
            std_test("", "abc", &flags()).unwrap_err(),
            RegexError::EmptyPattern
        );
    }

    #[test]
    fn invalid_pattern_errors() {
        assert!(matches!(
            std_test("(unclosed", "abc", &flags()).unwrap_err(),
            RegexError::Invalid(_)
        ));
    }

    #[test]
    fn text_too_large_errors() {
        let big = "a".repeat(MAX_TEXT_BYTES + 1);
        assert!(matches!(
            std_test("a", &big, &flags()).unwrap_err(),
            RegexError::TextTooLarge { .. }
        ));
    }

    #[test]
    fn counts_and_offsets() {
        let r = std_test(r"\d+", "a12 b3 c456", &flags()).unwrap();
        assert_eq!(r.total, 3);
        assert!(!r.truncated);
        assert_eq!(r.matches[0].value, "12");
        assert_eq!((r.matches[0].start, r.matches[0].end), (1, 3));
        assert_eq!(r.matches[2].value, "456");
        assert_eq!((r.matches[2].start, r.matches[2].end), (8, 11));
    }

    #[test]
    fn numbered_groups() {
        let r = std_test(r"(\w+)=(\w+)", "key=val", &flags()).unwrap();
        let g = &r.matches[0].groups;
        assert_eq!(g.len(), 2);
        assert_eq!(g[0].value.as_deref(), Some("key"));
        assert_eq!(g[1].value.as_deref(), Some("val"));
        assert_eq!(g[0].index, 1);
    }

    #[test]
    fn named_groups() {
        let r = std_test(r"(?<proto>\w+)://", "https://x", &flags()).unwrap();
        assert_eq!(r.group_names, vec![Some("proto".to_string())]);
        assert_eq!(r.matches[0].groups[0].name.as_deref(), Some("proto"));
        assert_eq!(r.matches[0].groups[0].value.as_deref(), Some("https"));
    }

    #[test]
    fn optional_group_absent() {
        let r = std_test(r"a(b)?c", "ac", &flags()).unwrap();
        let g = &r.matches[0].groups[0];
        assert_eq!(g.value, None);
        assert_eq!(g.start, None);
    }

    #[test]
    fn case_insensitive_flag() {
        let mut f = flags();
        assert_eq!(std_test("abc", "ABC", &f).unwrap().total, 0);
        f.case_insensitive = true;
        assert_eq!(std_test("abc", "ABC", &f).unwrap().total, 1);
    }

    #[test]
    fn multiline_flag() {
        let mut f = flags();
        let text = "a\nb\nc";
        assert_eq!(std_test("^.", text, &f).unwrap().total, 1);
        f.multiline = true;
        assert_eq!(std_test("^.", text, &f).unwrap().total, 3);
    }

    #[test]
    fn dot_all_flag() {
        let mut f = flags();
        assert_eq!(std_test("a.b", "a\nb", &f).unwrap().total, 0);
        f.dot_all = true;
        assert_eq!(std_test("a.b", "a\nb", &f).unwrap().total, 1);
    }

    #[test]
    fn unicode_char_offsets() {
        // "héllo hello": é is two bytes, so char offsets differ from bytes.
        let r = std_test("llo", "héllo hello", &flags()).unwrap();
        assert_eq!(r.total, 2);
        assert_eq!((r.matches[0].start, r.matches[0].end), (2, 5));
        assert_eq!((r.matches[1].start, r.matches[1].end), (8, 11));
    }

    #[test]
    fn truncation_reports_full_total() {
        let text = "x".repeat(MAX_MATCHES + 50);
        let r = std_test("x", &text, &flags()).unwrap();
        assert_eq!(r.total, MAX_MATCHES + 50);
        assert!(r.truncated);
        assert_eq!(r.matches.len(), MAX_MATCHES);
    }

    #[test]
    fn replace_with_backrefs() {
        let out = replace_all(
            r"(\w+)@(\w+)",
            "user@host",
            &flags(),
            "$2.$1",
            Engine::Standard,
        )
        .unwrap();
        assert_eq!(out, "host.user");
    }

    #[test]
    fn replace_named_backref() {
        let out = replace_all(
            r"(?<y>\d{4})-(?<m>\d{2})",
            "2026-10",
            &flags(),
            "${m}/${y}",
            Engine::Standard,
        )
        .unwrap();
        assert_eq!(out, "10/2026");
    }

    #[test]
    fn backreference_rejected_by_standard() {
        // \1 is a backreference, unsupported by the regex crate.
        assert!(matches!(
            std_test(r"(\w)\1", "aa", &flags()).unwrap_err(),
            RegexError::Invalid(_)
        ));
    }

    // --- PCRE engine ---

    fn pcre_test(pattern: &str, text: &str, flags: &RegexFlags) -> Result<RegexResult, RegexError> {
        test(pattern, text, flags, Engine::Pcre)
    }

    #[test]
    fn pcre_backreference() {
        // Doubled word characters via a backreference.
        let r = pcre_test(r"(\w)\1", "bookkeeper", &flags()).unwrap();
        let vals: Vec<&str> = r.matches.iter().map(|m| m.value.as_str()).collect();
        assert_eq!(vals, vec!["oo", "kk", "ee"]);
    }

    #[test]
    fn pcre_lookahead() {
        // Match "foo" only when followed by "bar".
        let r = pcre_test(r"foo(?=bar)", "foobar foobaz", &flags()).unwrap();
        assert_eq!(r.total, 1);
        assert_eq!(r.matches[0].value, "foo");
    }

    #[test]
    fn pcre_lookbehind() {
        let r = pcre_test(r"(?<=\$)\d+", "price $42 not 7", &flags()).unwrap();
        assert_eq!(r.total, 1);
        assert_eq!(r.matches[0].value, "42");
    }

    #[test]
    fn pcre_named_group() {
        let r = pcre_test(r"(?<k>\w+)=(?<v>\w+)", "a=1", &flags()).unwrap();
        assert_eq!(
            r.group_names,
            vec![Some("k".to_string()), Some("v".to_string())]
        );
        assert_eq!(r.matches[0].groups[0].name.as_deref(), Some("k"));
    }

    #[test]
    fn pcre_flags_via_inline_prefix() {
        let mut f = flags();
        assert_eq!(pcre_test("abc", "ABC", &f).unwrap().total, 0);
        f.case_insensitive = true;
        assert_eq!(pcre_test("abc", "ABC", &f).unwrap().total, 1);
    }

    #[test]
    fn pcre_replace_backref() {
        let out =
            replace_all(r"(\w+)@(\w+)", "user@host", &flags(), "$2.$1", Engine::Pcre).unwrap();
        assert_eq!(out, "host.user");
    }

    #[test]
    fn pcre_backtrack_limit_hit() {
        // Catastrophic backtracking: the backreference forces the backtracking
        // engine, and (a+)+ explodes across partitions of the input.
        let text = format!("{}b", "a".repeat(25));
        let err = pcre_test(r"(a+)+\1$", &text, &flags()).unwrap_err();
        assert_eq!(
            err,
            RegexError::BacktrackLimit {
                limit: BACKTRACK_LIMIT
            }
        );
    }
}
