//! Pure grep-builder logic. Builds a correct, shell-quoted `grep` command (or
//! pipeline, for several patterns) from a set of options, and previews it
//! line by line by reusing the regex builder core so the two tools agree on
//! what matches.
//!
//! Combination rules, ported from macGREP:
//! - OR: every match pattern goes into one grep as repeated `-e` patterns.
//! - AND: each match pattern becomes its own grep stage joined with `|`.
//! - Excludes always run last, together in one `grep -v -e A -e B` stage.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::tools::regex_builder::core as rx;

/// Cap on output lines returned by the preview. Counts stay accurate.
pub const MAX_PREVIEW_LINES: usize = 500;

/// grep pattern dialect, mapped to a command flag and a preview engine.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GrepMode {
    /// Basic regular expressions (grep default, no flag).
    #[default]
    Basic,
    /// Extended regular expressions (-E).
    Extended,
    /// Perl-compatible regular expressions (-P).
    Perl,
    /// Fixed strings, no regex (-F).
    Fixed,
}

/// How several match patterns combine.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Combine {
    /// Every pattern must match the line (a pipeline).
    #[default]
    All,
    /// Any pattern may match the line (one grep, several `-e`).
    Any,
}

/// Which grep the command is written for. Drives compatibility warnings.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GrepTarget {
    /// GNU grep (Linux, `ggrep` from Homebrew).
    #[default]
    Gnu,
    /// BSD grep (macOS and FreeBSD default).
    Bsd,
}

/// File name prefix on output lines.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FilenameDisplay {
    /// grep's default: shown when searching more than one file.
    #[default]
    Auto,
    /// Always show (-H).
    Always,
    /// Never show (-h).
    Never,
}

/// One pattern in the query.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Condition {
    pub pattern: String,
    /// Drop lines matching this pattern instead of keeping them.
    pub exclude: bool,
}

/// Everything needed to build and preview a grep command.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct GrepOptions {
    pub conditions: Vec<Condition>,
    pub combine: Combine,
    pub mode: GrepMode,
    pub target: GrepTarget,
    pub ignore_case: bool,
    pub word: bool,
    pub line_match: bool,
    pub only_matching: bool,
    pub line_number: bool,
    pub count: bool,
    pub files_with_matches: bool,
    pub recursive: bool,
    pub color: bool,
    /// Skip binary files (-I).
    pub skip_binary: bool,
    pub filename: FilenameDisplay,
    /// Lines of context. `context` (-C) wins over `before`/`after` when set.
    pub before: u32,
    pub after: u32,
    pub context: u32,
    /// Comma or space separated globs for `--include=`.
    pub include: String,
    /// Comma or space separated globs for `--exclude=`.
    pub exclude: String,
    /// Comma or space separated directory names for `--exclude-dir=`.
    pub exclude_dir: String,
    /// Files or directories, each quoted independently.
    pub paths: Vec<String>,
}

/// The built command plus anything the user should know about it.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BuiltCommand {
    pub command: String,
    /// Number of grep stages joined with `|`.
    pub stages: usize,
    pub warnings: Vec<String>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum GrepError {
    #[error("pattern {index}: {source}")]
    Pattern {
        index: usize,
        source: rx::RegexError,
    },
    #[error(transparent)]
    Regex(#[from] rx::RegexError),
}

/// A highlight range in character (Unicode scalar) offsets.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub struct Span {
    pub start: usize,
    pub end: usize,
}

/// One line the pipeline would print.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct OutputLine {
    /// 1-based line number in the sample.
    pub number: usize,
    pub text: String,
}

/// Line-by-line simulation of the pipeline over sample text.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GrepPreview {
    /// Match-pattern highlights within kept lines, sorted and non-overlapping.
    pub matches: Vec<Span>,
    pub lines_total: usize,
    pub lines_kept: usize,
    /// Kept lines, capped at [`MAX_PREVIEW_LINES`].
    pub output: Vec<OutputLine>,
    /// True when `matches` or `output` was capped.
    pub truncated: bool,
}

/// A pattern with its 1-based position in the condition list, for messages.
type Numbered<'a> = (usize, &'a str);

/// Conditions with a pattern, split into (match, exclude).
fn split_conditions(opts: &GrepOptions) -> (Vec<Numbered<'_>>, Vec<Numbered<'_>>) {
    let mut keep = Vec::new();
    let mut drop = Vec::new();
    for (i, c) in opts.conditions.iter().enumerate() {
        if c.pattern.is_empty() {
            continue;
        }
        if c.exclude {
            drop.push((i + 1, c.pattern.as_str()));
        } else {
            keep.push((i + 1, c.pattern.as_str()));
        }
    }
    (keep, drop)
}

/// One grep invocation in the pipeline.
struct Stage<'a> {
    patterns: Vec<&'a str>,
    exclude: bool,
}

/// Build the grep command line (a pipeline when needed) and its warnings.
pub fn build_command(opts: &GrepOptions) -> BuiltCommand {
    let (keep, drop) = split_conditions(opts);
    let mut warnings = Vec::new();

    let mut stages: Vec<Stage> = Vec::new();
    match opts.combine {
        Combine::Any if !keep.is_empty() => stages.push(Stage {
            patterns: keep.iter().map(|(_, p)| *p).collect(),
            exclude: false,
        }),
        Combine::Any => {}
        Combine::All => stages.extend(keep.iter().map(|(_, p)| Stage {
            patterns: vec![*p],
            exclude: false,
        })),
    }
    if !drop.is_empty() {
        stages.push(Stage {
            patterns: drop.iter().map(|(_, p)| *p).collect(),
            exclude: true,
        });
    }

    if stages.is_empty() {
        return BuiltCommand {
            command: "grep".to_string(),
            stages: 0,
            warnings: vec!["Add a pattern to build a command.".to_string()],
        };
    }

    let last = stages.len() - 1;
    let command = stages
        .iter()
        .enumerate()
        .map(|(i, st)| build_stage(opts, st, i == 0, i == last))
        .collect::<Vec<_>>()
        .join(" | ");

    syntax_warnings(opts, &keep, &drop, &mut warnings);
    pipeline_warnings(
        opts,
        stages.len(),
        !keep.is_empty(),
        !drop.is_empty(),
        &mut warnings,
    );

    BuiltCommand {
        command,
        stages: stages.len(),
        warnings,
    }
}

/// Render one stage. File-level options (paths, -r, -n, -H/-h, -I, -o, -l,
/// context, globs) go on the first stage only, since later stages read the
/// pipe. -c and color go on the last stage, so the count covers the whole
/// pipeline and color codes never reach a later grep.
fn build_stage(opts: &GrepOptions, st: &Stage, first: bool, last: bool) -> String {
    let mut parts: Vec<String> = vec!["grep".to_string()];

    let mut cluster = String::new();
    match opts.mode {
        GrepMode::Basic => {}
        GrepMode::Extended => cluster.push('E'),
        GrepMode::Perl => cluster.push('P'),
        GrepMode::Fixed => cluster.push('F'),
    }
    if opts.ignore_case {
        cluster.push('i');
    }
    if st.exclude {
        cluster.push('v');
    }
    if opts.word {
        cluster.push('w');
    }
    if opts.line_match {
        cluster.push('x');
    }
    if first && opts.only_matching {
        cluster.push('o');
    }
    if first && opts.line_number {
        cluster.push('n');
    }
    if last && opts.count {
        cluster.push('c');
    }
    if first && opts.files_with_matches {
        cluster.push('l');
    }
    if first && opts.recursive {
        cluster.push('r');
    }
    if first {
        match opts.filename {
            FilenameDisplay::Auto => {}
            FilenameDisplay::Always => cluster.push('H'),
            FilenameDisplay::Never => cluster.push('h'),
        }
        if opts.skip_binary {
            cluster.push('I');
        }
    }
    if !cluster.is_empty() {
        parts.push(format!("-{cluster}"));
    }

    if first {
        // Context lines. -C overrides -A/-B.
        if opts.context > 0 {
            parts.push("-C".to_string());
            parts.push(opts.context.to_string());
        } else {
            if opts.before > 0 {
                parts.push("-B".to_string());
                parts.push(opts.before.to_string());
            }
            if opts.after > 0 {
                parts.push("-A".to_string());
                parts.push(opts.after.to_string());
            }
        }
        for (flag, list) in [
            ("--include", &opts.include),
            ("--exclude", &opts.exclude),
            ("--exclude-dir", &opts.exclude_dir),
        ] {
            for item in split_list(list) {
                parts.push(format!("{flag}={}", quote_if_needed(item)));
            }
        }
    }

    if last && opts.color {
        parts.push("--color=auto".to_string());
    }

    // A lone pattern goes bare unless it starts with '-', which grep would
    // read as a flag. Several patterns each get -e.
    if st.patterns.len() == 1 && !st.patterns[0].starts_with('-') {
        parts.push(quote_always(st.patterns[0]));
    } else {
        for p in &st.patterns {
            parts.push("-e".to_string());
            parts.push(quote_always(p));
        }
    }

    if first {
        let paths: Vec<&String> = opts.paths.iter().filter(|p| !p.is_empty()).collect();
        if paths.is_empty() && opts.recursive {
            // BSD grep -r with no path reads stdin; name the current dir.
            parts.push(".".to_string());
        }
        for p in paths {
            parts.push(quote_if_needed(p));
        }
    }

    parts.join(" ")
}

/// Warnings about pattern syntax the chosen mode or target will not accept.
fn syntax_warnings(
    opts: &GrepOptions,
    keep: &[Numbered],
    drop: &[Numbered],
    warnings: &mut Vec<String>,
) {
    if opts.mode == GrepMode::Perl && opts.target == GrepTarget::Bsd {
        warnings.push(
            "BSD grep (macOS default) has no -P. Install GNU grep (brew install grep, run as ggrep) or use -E."
                .to_string(),
        );
    }
    if matches!(opts.mode, GrepMode::Basic | GrepMode::Extended) {
        for (index, pattern) in keep.iter().chain(drop) {
            for feature in pcre_only_features(pattern) {
                warnings.push(format!(
                    "Pattern {index} uses {feature}, which grep {} does not support. Switch to Perl (-P).",
                    if opts.mode == GrepMode::Basic { "BRE" } else { "-E" }
                ));
            }
        }
    }
}

/// Warnings about how a multi-stage pipeline changes grep's output.
fn pipeline_warnings(
    opts: &GrepOptions,
    stages: usize,
    has_keep: bool,
    has_drop: bool,
    warnings: &mut Vec<String>,
) {
    if opts.combine == Combine::Any && has_keep && has_drop {
        warnings.push("Excludes apply after the OR: (A or B) and not C.".to_string());
    }
    if stages < 2 {
        return;
    }
    let paths = opts.paths.iter().filter(|p| !p.is_empty()).count();
    let prefixed = opts.line_number
        || opts.filename == FilenameDisplay::Always
        || (opts.filename == FilenameDisplay::Auto && (opts.recursive || paths > 1));
    if prefixed {
        warnings.push(
            "Later stages see the file:line: prefix the first stage adds, so ^ anchors and -x there will not line up."
                .to_string(),
        );
    }
    if opts.files_with_matches {
        warnings.push(
            "-l on the first stage passes file names, not lines, to later stages.".to_string(),
        );
    }
    if opts.only_matching {
        warnings.push(
            "-o on the first stage passes only the matched text to later stages.".to_string(),
        );
    }
    if opts.context > 0 || opts.before > 0 || opts.after > 0 {
        warnings.push(
            "Context lines from the first stage are filtered again by later stages.".to_string(),
        );
    }
    if opts.count {
        warnings.push(
            "-c counts lines that pass the whole pipeline, as one total, not per file.".to_string(),
        );
    }
}

/// PCRE-only constructs found in a pattern, by name. Escape aware, so `\\d`
/// (a literal backslash then d) is not flagged.
pub fn pcre_only_features(pattern: &str) -> Vec<&'static str> {
    let mut found: Vec<&'static str> = Vec::new();
    let mut add = |f: &'static str| {
        if !found.contains(&f) {
            found.push(f);
        }
    };
    let chars: Vec<char> = pattern.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        match chars[i] {
            '\\' => {
                match chars.get(i + 1) {
                    Some('d' | 'D') => add(r"\d (use [0-9])"),
                    Some('K') => add(r"\K"),
                    _ => {}
                }
                i += 2;
                continue;
            }
            '(' if chars.get(i + 1) == Some(&'?') => match chars.get(i + 2) {
                Some('=' | '!') => add("lookahead (?=...)"),
                Some('<') if matches!(chars.get(i + 3), Some('=' | '!')) => {
                    add("lookbehind (?<=...)")
                }
                Some('<') => add("named groups (?<name>...)"),
                Some(':') => add("non-capturing groups (?:...)"),
                _ => add("inline (?...) syntax"),
            },
            '*' | '+' | '?' | '}' if chars.get(i + 1) == Some(&'?') && i > 0 => {
                // `(?` is handled above; this is a lazy quantifier.
                add("lazy quantifiers (*?)");
            }
            _ => {}
        }
        i += 1;
    }
    found
}

/// Turn one condition's pattern into what the preview engine runs, honoring
/// mode, -w and -x.
fn preview_pattern(opts: &GrepOptions, pattern: &str) -> (String, rx::Engine) {
    let (base, engine) = match opts.mode {
        GrepMode::Basic => (translate_bre_to_ere(pattern), rx::Engine::Standard),
        GrepMode::Extended => (pattern.to_string(), rx::Engine::Standard),
        GrepMode::Perl => (pattern.to_string(), rx::Engine::Pcre),
        GrepMode::Fixed => (regex::escape(pattern), rx::Engine::Standard),
    };
    // -x anchors the whole line, -w requires word boundaries. -x wins.
    let wrapped = if opts.line_match {
        format!("^(?:{base})$")
    } else if opts.word {
        format!(r"\b(?:{base})\b")
    } else {
        base
    };
    (wrapped, engine)
}

/// Simulate the command over sample text, one line at a time as grep reads
/// it. Output flags (-o, -c, -l, context, -n prefixes) are not simulated; the
/// result shows which lines the patterns keep.
pub fn preview(opts: &GrepOptions, text: &str) -> Result<GrepPreview, GrepError> {
    if text.len() > rx::MAX_TEXT_BYTES {
        return Err(rx::RegexError::TextTooLarge {
            got: text.len(),
            limit: rx::MAX_TEXT_BYTES,
        }
        .into());
    }
    let (keep, drop) = split_conditions(opts);
    let flags = rx::RegexFlags {
        case_insensitive: opts.ignore_case,
        ..Default::default()
    };
    let compile = |(index, p): &Numbered| {
        let (pat, engine) = preview_pattern(opts, p);
        rx::Matcher::compile(&pat, &flags, engine).map_err(|source| GrepError::Pattern {
            index: *index,
            source,
        })
    };
    let keep_m = keep.iter().map(compile).collect::<Result<Vec<_>, _>>()?;
    let drop_m = drop.iter().map(compile).collect::<Result<Vec<_>, _>>()?;

    // grep does not count the empty piece after a final newline as a line.
    let body = text.strip_suffix('\n').unwrap_or(text);
    let lines: Vec<&str> = if text.is_empty() {
        Vec::new()
    } else {
        body.split('\n').collect()
    };

    let mut out = GrepPreview {
        matches: Vec::new(),
        lines_total: lines.len(),
        lines_kept: 0,
        output: Vec::new(),
        truncated: false,
    };
    if keep_m.is_empty() && drop_m.is_empty() {
        return Ok(out);
    }

    let mut line_char_start = 0usize;
    for (n, line) in lines.iter().enumerate() {
        let line_chars = line.chars().count();
        if line_kept(opts.combine, &keep_m, &drop_m, line)? {
            out.lines_kept += 1;
            if out.output.len() < MAX_PREVIEW_LINES {
                out.output.push(OutputLine {
                    number: n + 1,
                    text: line.to_string(),
                });
            } else {
                out.truncated = true;
            }
            if out.matches.len() < rx::MAX_MATCHES {
                let spans = line_highlights(&keep_m, line, line_char_start)?;
                out.matches.extend(spans);
            } else {
                out.truncated = true;
            }
        }
        line_char_start += line_chars + 1;
    }
    out.matches.truncate(rx::MAX_MATCHES);
    Ok(out)
}

/// Whether a line survives the match and exclude patterns.
fn line_kept(
    combine: Combine,
    keep: &[rx::Matcher],
    drop: &[rx::Matcher],
    line: &str,
) -> Result<bool, rx::RegexError> {
    let kept = match combine {
        _ if keep.is_empty() => true,
        Combine::All => {
            let mut all = true;
            for m in keep {
                if !m.is_match(line)? {
                    all = false;
                    break;
                }
            }
            all
        }
        Combine::Any => {
            let mut any = false;
            for m in keep {
                if m.is_match(line)? {
                    any = true;
                    break;
                }
            }
            any
        }
    };
    if !kept {
        return Ok(false);
    }
    for m in drop {
        if m.is_match(line)? {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Match-pattern spans in a kept line, as text-wide char offsets, merged so
/// they are sorted and non-overlapping.
fn line_highlights(
    keep: &[rx::Matcher],
    line: &str,
    line_char_start: usize,
) -> Result<Vec<Span>, rx::RegexError> {
    let mut spans: Vec<(usize, usize)> = Vec::new();
    for m in keep {
        for (s, e) in m.find_spans(line)? {
            if e > s {
                spans.push((s, e));
            }
        }
    }
    spans.sort_unstable();
    let mut merged: Vec<(usize, usize)> = Vec::new();
    for (s, e) in spans {
        match merged.last_mut() {
            Some(last) if s <= last.1 => last.1 = last.1.max(e),
            _ => merged.push((s, e)),
        }
    }
    let to_char = |b: usize| line_char_start + line[..b].chars().count();
    Ok(merged
        .into_iter()
        .map(|(s, e)| Span {
            start: to_char(s),
            end: to_char(e),
        })
        .collect())
}

/// Split a comma or whitespace separated list, dropping empty items.
fn split_list(s: &str) -> impl Iterator<Item = &str> {
    s.split(|c: char| c == ',' || c.is_whitespace())
        .filter(|x| !x.is_empty())
}

/// Translate a basic regular expression to an extended one so our RE2-style
/// engine can run it. In BRE, `( ) { } + ? |` are literal unless backslashed;
/// in ERE it is the reverse.
pub fn translate_bre_to_ere(pattern: &str) -> String {
    const SPECIALS: [char; 7] = ['(', ')', '{', '}', '+', '?', '|'];
    let mut out = String::with_capacity(pattern.len());
    let mut chars = pattern.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.peek() {
                Some(&next) if SPECIALS.contains(&next) => {
                    // Escaped special in BRE becomes bare special in ERE.
                    out.push(next);
                    chars.next();
                }
                Some(&next) => {
                    // Other escapes pass through unchanged (\. \\ \1 ...).
                    out.push('\\');
                    out.push(next);
                    chars.next();
                }
                None => out.push('\\'),
            }
        } else if SPECIALS.contains(&c) {
            // Bare special in BRE is literal, so escape it for ERE.
            out.push('\\');
            out.push(c);
        } else {
            out.push(c);
        }
    }
    out
}

/// Characters that are safe to leave unquoted in a POSIX shell.
fn is_shell_safe(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "_./=:@%+,-".contains(c))
}

/// Single-quote a string for the shell, escaping embedded single quotes.
fn single_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Quote only when the shell would otherwise mangle the value (used for paths).
fn quote_if_needed(s: &str) -> String {
    if is_shell_safe(s) {
        s.to_string()
    } else {
        single_quote(s)
    }
}

/// Always quote (used for the pattern, which usually holds regex metacharacters
/// and is clearer shown quoted even when technically safe).
fn quote_always(s: &str) -> String {
    single_quote(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cond(p: &str) -> Condition {
        Condition {
            pattern: p.to_string(),
            exclude: false,
        }
    }

    fn excl(p: &str) -> Condition {
        Condition {
            pattern: p.to_string(),
            exclude: true,
        }
    }

    fn opts(pattern: &str, mode: GrepMode) -> GrepOptions {
        GrepOptions {
            conditions: vec![cond(pattern)],
            mode,
            ..Default::default()
        }
    }

    fn cmd(o: &GrepOptions) -> String {
        build_command(o).command
    }

    // --- single pattern ---------------------------------------------------

    #[test]
    fn basic_pattern_is_quoted() {
        assert_eq!(cmd(&opts("foo", GrepMode::Basic)), "grep 'foo'");
    }

    #[test]
    fn extended_with_flags_and_path() {
        let mut o = opts("a|b", GrepMode::Extended);
        o.ignore_case = true;
        o.line_number = true;
        o.paths = vec!["log.txt".to_string()];
        assert_eq!(cmd(&o), "grep -Ein 'a|b' log.txt");
    }

    #[test]
    fn perl_recursive_color() {
        let mut o = opts(r"\d+", GrepMode::Perl);
        o.recursive = true;
        o.color = true;
        o.paths = vec![".".to_string()];
        assert_eq!(cmd(&o), r"grep -Pr --color=auto '\d+' .");
    }

    #[test]
    fn fixed_mode() {
        assert_eq!(cmd(&opts("a.b*c", GrepMode::Fixed)), "grep -F 'a.b*c'");
    }

    #[test]
    fn context_c_overrides_a_and_b() {
        let mut o = opts("x", GrepMode::Basic);
        o.before = 2;
        o.after = 4;
        o.context = 3;
        assert_eq!(cmd(&o), "grep -C 3 'x'");
    }

    #[test]
    fn context_before_and_after() {
        let mut o = opts("x", GrepMode::Basic);
        o.before = 2;
        o.after = 4;
        assert_eq!(cmd(&o), "grep -B 2 -A 4 'x'");
    }

    #[test]
    fn pattern_starting_with_dash_uses_e() {
        assert_eq!(cmd(&opts("-v", GrepMode::Basic)), "grep -e '-v'");
    }

    #[test]
    fn embedded_single_quote_is_escaped() {
        assert_eq!(cmd(&opts("it's", GrepMode::Basic)), r"grep 'it'\''s'");
    }

    #[test]
    fn path_with_space_is_quoted() {
        let mut o = opts("x", GrepMode::Basic);
        o.paths = vec!["my logs/app.log".to_string()];
        assert_eq!(cmd(&o), "grep 'x' 'my logs/app.log'");
    }

    #[test]
    fn no_pattern_warns() {
        let b = build_command(&GrepOptions::default());
        assert_eq!(b.command, "grep");
        assert_eq!(b.stages, 0);
        assert_eq!(b.warnings.len(), 1);
    }

    #[test]
    fn empty_conditions_are_ignored() {
        let mut o = opts("x", GrepMode::Basic);
        o.conditions.push(cond(""));
        assert_eq!(cmd(&o), "grep 'x'");
    }

    // --- new flags --------------------------------------------------------

    #[test]
    fn skip_binary_and_filename_flags() {
        let mut o = opts("x", GrepMode::Extended);
        o.recursive = true;
        o.skip_binary = true;
        o.filename = FilenameDisplay::Never;
        assert_eq!(cmd(&o), "grep -ErhI 'x' .");
        o.filename = FilenameDisplay::Always;
        assert_eq!(cmd(&o), "grep -ErHI 'x' .");
    }

    #[test]
    fn recursive_without_path_searches_current_dir() {
        let mut o = opts("x", GrepMode::Basic);
        o.recursive = true;
        assert_eq!(cmd(&o), "grep -r 'x' .");
    }

    #[test]
    fn include_exclude_globs() {
        let mut o = opts("x", GrepMode::Extended);
        o.recursive = true;
        o.include = "*.log, *.txt".to_string();
        o.exclude = "*.gz".to_string();
        o.exclude_dir = ".git node_modules".to_string();
        assert_eq!(
            cmd(&o),
            "grep -Er --include='*.log' --include='*.txt' --exclude='*.gz' \
             --exclude-dir=.git --exclude-dir=node_modules 'x' ."
        );
    }

    // --- pipelines --------------------------------------------------------

    #[test]
    fn and_builds_a_pipeline() {
        let mut o = opts("error", GrepMode::Extended);
        o.conditions.push(cond("10\\.1\\."));
        o.line_number = true;
        o.paths = vec!["fw.log".to_string()];
        let b = build_command(&o);
        assert_eq!(b.command, r"grep -En 'error' fw.log | grep -E '10\.1\.'");
        assert_eq!(b.stages, 2);
    }

    #[test]
    fn or_uses_repeated_e() {
        let mut o = opts("deny", GrepMode::Extended);
        o.conditions.push(cond("drop"));
        o.combine = Combine::Any;
        let b = build_command(&o);
        assert_eq!(b.command, "grep -E -e 'deny' -e 'drop'");
        assert_eq!(b.stages, 1);
    }

    #[test]
    fn excludes_share_one_final_stage() {
        let mut o = opts("action", GrepMode::Extended);
        o.conditions.push(excl("accept"));
        o.conditions.push(excl("close"));
        assert_eq!(
            cmd(&o),
            "grep -E 'action' | grep -Ev -e 'accept' -e 'close'"
        );
    }

    #[test]
    fn exclude_only_is_a_single_inverted_grep() {
        let o = GrepOptions {
            conditions: vec![excl("DEBUG")],
            paths: vec!["app.log".to_string()],
            ..Default::default()
        };
        assert_eq!(cmd(&o), "grep -v 'DEBUG' app.log");
    }

    #[test]
    fn file_options_on_first_stage_count_and_color_on_last() {
        let mut o = opts("a", GrepMode::Extended);
        o.conditions.push(cond("b"));
        o.recursive = true;
        o.skip_binary = true;
        o.count = true;
        o.color = true;
        o.context = 2;
        o.include = "*.log".to_string();
        assert_eq!(
            cmd(&o),
            "grep -ErI -C 2 --include='*.log' 'a' . | grep -Ec --color=auto 'b'"
        );
    }

    #[test]
    fn match_flags_apply_to_every_stage() {
        let mut o = opts("a", GrepMode::Fixed);
        o.conditions.push(excl("b"));
        o.ignore_case = true;
        o.word = true;
        assert_eq!(cmd(&o), "grep -Fiw 'a' | grep -Fivw 'b'");
    }

    #[test]
    fn pipeline_prefix_warning() {
        let mut o = opts("a", GrepMode::Extended);
        o.conditions.push(cond("b"));
        o.line_number = true;
        let b = build_command(&o);
        assert!(b.warnings.iter().any(|w| w.contains("file:line:")));
    }

    #[test]
    fn single_stage_has_no_pipeline_warnings() {
        let mut o = opts("a", GrepMode::Extended);
        o.line_number = true;
        o.count = true;
        assert!(build_command(&o).warnings.is_empty());
    }

    #[test]
    fn or_with_exclude_explains_order() {
        let mut o = opts("a", GrepMode::Extended);
        o.conditions.push(cond("b"));
        o.conditions.push(excl("c"));
        o.combine = Combine::Any;
        let b = build_command(&o);
        assert!(b.warnings.iter().any(|w| w.contains("(A or B) and not C")));
    }

    // --- target and syntax warnings ---------------------------------------

    #[test]
    fn bsd_perl_warns() {
        let mut o = opts("x", GrepMode::Perl);
        o.target = GrepTarget::Bsd;
        assert!(
            build_command(&o)
                .warnings
                .iter()
                .any(|w| w.contains("no -P"))
        );
        o.target = GrepTarget::Gnu;
        assert!(build_command(&o).warnings.is_empty());
    }

    #[test]
    fn pcre_syntax_in_extended_warns() {
        let o = opts(r"foo(?=bar)\d", GrepMode::Extended);
        let w = build_command(&o).warnings;
        assert_eq!(w.len(), 2, "{w:?}");
        assert!(w[0].contains("lookahead") && w[0].starts_with("Pattern 1"));
        assert!(w[1].contains(r"\d"));
    }

    #[test]
    fn pcre_syntax_in_perl_mode_is_fine() {
        assert!(
            build_command(&opts(r"(?<=a)\d+?", GrepMode::Perl))
                .warnings
                .is_empty()
        );
    }

    #[test]
    fn pcre_feature_detection() {
        assert_eq!(pcre_only_features(r"(?<=x)"), ["lookbehind (?<=...)"]);
        assert_eq!(
            pcre_only_features(r"(?<n>x)"),
            ["named groups (?<name>...)"]
        );
        assert_eq!(
            pcre_only_features(r"(?:x)"),
            ["non-capturing groups (?:...)"]
        );
        assert_eq!(pcre_only_features(r"a+?"), ["lazy quantifiers (*?)"]);
        // An escaped backslash followed by d is a literal, not \d.
        assert!(pcre_only_features(r"\\d").is_empty());
        assert!(pcre_only_features(r"(a|b)?[0-9]+").is_empty());
    }

    // --- BRE translation --------------------------------------------------

    #[test]
    fn bre_to_ere_group_and_interval() {
        assert_eq!(translate_bre_to_ere(r"\(ab\)\{2\}"), "(ab){2}");
    }

    #[test]
    fn bre_to_ere_literal_specials() {
        assert_eq!(translate_bre_to_ere("a+b(c)"), r"a\+b\(c\)");
    }

    #[test]
    fn bre_to_ere_alternation() {
        assert_eq!(translate_bre_to_ere(r"cat\|dog"), "cat|dog");
    }

    #[test]
    fn bre_to_ere_passes_other_escapes() {
        assert_eq!(translate_bre_to_ere(r"a\.b\\c"), r"a\.b\\c");
    }

    // --- preview ----------------------------------------------------------

    fn kept(p: &GrepPreview) -> Vec<usize> {
        p.output.iter().map(|l| l.number).collect()
    }

    #[test]
    fn preview_extended_counts() {
        let r = preview(&opts(r"[0-9]+", GrepMode::Extended), "a1 b22 c333").unwrap();
        assert_eq!(r.matches.len(), 3);
        assert_eq!(r.lines_kept, 1);
    }

    #[test]
    fn preview_basic_translates() {
        // BRE: \(ab\)\+ means one or more "ab".
        let r = preview(&opts(r"\(ab\)\+", GrepMode::Basic), "abab x ab").unwrap();
        assert_eq!(
            r.matches,
            [Span { start: 0, end: 4 }, Span { start: 7, end: 9 }]
        );
    }

    #[test]
    fn preview_fixed_is_literal() {
        let r = preview(&opts("a.b", GrepMode::Fixed), "a.b axb").unwrap();
        assert_eq!(r.matches, [Span { start: 0, end: 3 }]);
    }

    #[test]
    fn preview_perl_lookahead() {
        let r = preview(&opts(r"foo(?=bar)", GrepMode::Perl), "foobar foobaz").unwrap();
        assert_eq!(r.matches.len(), 1);
    }

    #[test]
    fn preview_word_boundary() {
        let mut o = opts("cat", GrepMode::Extended);
        o.word = true;
        let r = preview(&o, "cat category cat").unwrap();
        assert_eq!(r.matches.len(), 2);
    }

    #[test]
    fn preview_line_match_anchors() {
        let mut o = opts("cat", GrepMode::Extended);
        o.line_match = true;
        let r = preview(&o, "cat\ncategory\ncat").unwrap();
        assert_eq!(kept(&r), [1, 3]);
    }

    #[test]
    fn preview_caret_anchors_each_line() {
        let r = preview(&opts("^b", GrepMode::Extended), "a\nb\nab").unwrap();
        assert_eq!(kept(&r), [2]);
    }

    #[test]
    fn preview_ignore_case() {
        let mut o = opts("abc", GrepMode::Extended);
        o.ignore_case = true;
        assert_eq!(preview(&o, "ABC abc").unwrap().matches.len(), 2);
    }

    #[test]
    fn preview_and_keeps_lines_matching_all() {
        let mut o = opts("deny", GrepMode::Extended);
        o.conditions.push(cond("10\\.1\\."));
        let text = "deny 10.1.1.1\ndeny 10.2.2.2\naccept 10.1.1.1\n";
        let r = preview(&o, text).unwrap();
        assert_eq!(r.lines_total, 3);
        assert_eq!(kept(&r), [1]);
        // Both patterns highlight, in order, in line 1.
        assert_eq!(
            r.matches,
            [Span { start: 0, end: 4 }, Span { start: 5, end: 10 }]
        );
    }

    #[test]
    fn preview_or_keeps_lines_matching_any() {
        let mut o = opts("deny", GrepMode::Extended);
        o.conditions.push(cond("drop"));
        o.combine = Combine::Any;
        let r = preview(&o, "deny\naccept\ndrop").unwrap();
        assert_eq!(kept(&r), [1, 3]);
    }

    #[test]
    fn preview_exclude_drops_lines() {
        let mut o = opts("action", GrepMode::Extended);
        o.conditions.push(excl("accept"));
        let r = preview(&o, "action=deny\naction=accept\nother").unwrap();
        assert_eq!(kept(&r), [1]);
    }

    #[test]
    fn preview_exclude_only() {
        let o = GrepOptions {
            conditions: vec![excl("DEBUG")],
            ..Default::default()
        };
        let r = preview(&o, "INFO a\nDEBUG b\nWARN c").unwrap();
        assert_eq!(kept(&r), [1, 3]);
        assert!(r.matches.is_empty());
    }

    #[test]
    fn preview_matches_do_not_cross_lines() {
        // [^x]* could span the newline on whole-text search; grep is per line.
        let r = preview(&opts("a[^x]*c", GrepMode::Extended), "ab\nbc").unwrap();
        assert_eq!(r.lines_kept, 0);
    }

    #[test]
    fn preview_overlapping_highlights_merge() {
        let mut o = opts("abc", GrepMode::Extended);
        o.conditions.push(cond("bcd"));
        let r = preview(&o, "abcd").unwrap();
        assert_eq!(r.matches, [Span { start: 0, end: 4 }]);
    }

    #[test]
    fn preview_unicode_offsets_across_lines() {
        let r = preview(&opts("x", GrepMode::Extended), "é\nüx").unwrap();
        assert_eq!(r.matches, [Span { start: 3, end: 4 }]);
    }

    #[test]
    fn preview_trailing_newline_is_not_a_line() {
        let r = preview(&opts("a", GrepMode::Extended), "a\nb\n").unwrap();
        assert_eq!(r.lines_total, 2);
    }

    #[test]
    fn preview_error_names_the_pattern() {
        let mut o = opts("ok", GrepMode::Extended);
        o.conditions.push(cond("("));
        let e = preview(&o, "x").unwrap_err();
        assert!(e.to_string().starts_with("pattern 2:"), "{e}");
    }

    #[test]
    fn preview_caps_output_lines() {
        let text = "a\n".repeat(MAX_PREVIEW_LINES + 10);
        let r = preview(&opts("a", GrepMode::Extended), &text).unwrap();
        assert_eq!(r.lines_kept, MAX_PREVIEW_LINES + 10);
        assert_eq!(r.output.len(), MAX_PREVIEW_LINES);
        assert!(r.truncated);
    }
}
