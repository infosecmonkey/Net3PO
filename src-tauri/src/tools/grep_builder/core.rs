//! Pure grep-builder logic. Builds a correct, shell-quoted `grep` command from
//! a set of options, and previews the pattern by reusing the regex builder core
//! so the two tools agree on what matches.

use serde::Deserialize;

use crate::tools::regex_builder::core as rx;

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

/// Everything needed to build and preview a grep command.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct GrepOptions {
    pub pattern: String,
    pub mode: GrepMode,
    pub ignore_case: bool,
    pub invert: bool,
    pub word: bool,
    pub line_match: bool,
    pub only_matching: bool,
    pub line_number: bool,
    pub count: bool,
    pub files_with_matches: bool,
    pub recursive: bool,
    pub color: bool,
    /// Lines of context. `context` (-C) wins over `before`/`after` when set.
    pub before: u32,
    pub after: u32,
    pub context: u32,
    /// Files or directories, each quoted independently.
    pub paths: Vec<String>,
}

/// Build the grep command line.
pub fn build_command(opts: &GrepOptions) -> String {
    let mut parts: Vec<String> = vec!["grep".to_string()];

    // Cluster the boolean short flags (and the mode flag) into one token.
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
    if opts.invert {
        cluster.push('v');
    }
    if opts.word {
        cluster.push('w');
    }
    if opts.line_match {
        cluster.push('x');
    }
    if opts.only_matching {
        cluster.push('o');
    }
    if opts.line_number {
        cluster.push('n');
    }
    if opts.count {
        cluster.push('c');
    }
    if opts.files_with_matches {
        cluster.push('l');
    }
    if opts.recursive {
        cluster.push('r');
    }
    if !cluster.is_empty() {
        parts.push(format!("-{cluster}"));
    }

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

    if opts.color {
        parts.push("--color=auto".to_string());
    }

    // A pattern starting with '-' needs -e so grep does not read it as a flag.
    if opts.pattern.starts_with('-') {
        parts.push("-e".to_string());
    }
    parts.push(quote_always(&opts.pattern));

    for p in &opts.paths {
        if !p.is_empty() {
            parts.push(quote_if_needed(p));
        }
    }

    parts.join(" ")
}

/// Preview the pattern against sample text using the regex builder core, so the
/// highlight matches what grep would match. Output-formatting flags (-v, -c,
/// -n, -o, context, -r) do not change what is matched and are ignored here.
pub fn preview(opts: &GrepOptions, text: &str) -> Result<rx::RegexResult, rx::RegexError> {
    let (base, engine) = match opts.mode {
        GrepMode::Basic => (translate_bre_to_ere(&opts.pattern), rx::Engine::Standard),
        GrepMode::Extended => (opts.pattern.clone(), rx::Engine::Standard),
        GrepMode::Perl => (opts.pattern.clone(), rx::Engine::Pcre),
        GrepMode::Fixed => (regex::escape(&opts.pattern), rx::Engine::Standard),
    };

    // -x anchors the whole line, -w requires word boundaries. -x wins.
    let pattern = if opts.line_match {
        format!("^(?:{base})$")
    } else if opts.word {
        format!(r"\b(?:{base})\b")
    } else {
        base
    };

    let flags = rx::RegexFlags {
        case_insensitive: opts.ignore_case,
        // Anchor per line for -x so each matching line highlights.
        multiline: opts.line_match,
        dot_all: false,
        ignore_whitespace: false,
    };

    rx::test(&pattern, text, &flags, engine)
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

    fn opts(pattern: &str, mode: GrepMode) -> GrepOptions {
        GrepOptions {
            pattern: pattern.to_string(),
            mode,
            ..Default::default()
        }
    }

    #[test]
    fn basic_pattern_is_quoted() {
        assert_eq!(build_command(&opts("foo", GrepMode::Basic)), "grep 'foo'");
    }

    #[test]
    fn extended_with_flags_and_path() {
        let mut o = opts("a|b", GrepMode::Extended);
        o.ignore_case = true;
        o.line_number = true;
        o.paths = vec!["log.txt".to_string()];
        assert_eq!(build_command(&o), "grep -Ein 'a|b' log.txt");
    }

    #[test]
    fn perl_recursive_color() {
        let mut o = opts(r"\d+", GrepMode::Perl);
        o.recursive = true;
        o.color = true;
        o.paths = vec![".".to_string()];
        assert_eq!(build_command(&o), r"grep -Pr --color=auto '\d+' .");
    }

    #[test]
    fn fixed_mode() {
        assert_eq!(
            build_command(&opts("a.b*c", GrepMode::Fixed)),
            "grep -F 'a.b*c'"
        );
    }

    #[test]
    fn context_c_overrides_a_and_b() {
        let mut o = opts("x", GrepMode::Basic);
        o.before = 2;
        o.after = 4;
        o.context = 3;
        assert_eq!(build_command(&o), "grep -C 3 'x'");
    }

    #[test]
    fn context_before_and_after() {
        let mut o = opts("x", GrepMode::Basic);
        o.before = 2;
        o.after = 4;
        assert_eq!(build_command(&o), "grep -B 2 -A 4 'x'");
    }

    #[test]
    fn pattern_starting_with_dash_uses_e() {
        assert_eq!(build_command(&opts("-v", GrepMode::Basic)), "grep -e '-v'");
    }

    #[test]
    fn embedded_single_quote_is_escaped() {
        assert_eq!(
            build_command(&opts("it's", GrepMode::Basic)),
            r"grep 'it'\''s'"
        );
    }

    #[test]
    fn path_with_space_is_quoted() {
        let mut o = opts("x", GrepMode::Basic);
        o.paths = vec!["my logs/app.log".to_string()];
        assert_eq!(build_command(&o), "grep 'x' 'my logs/app.log'");
    }

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

    #[test]
    fn preview_extended_counts() {
        let r = preview(&opts(r"\d+", GrepMode::Extended), "a1 b22 c333").unwrap();
        assert_eq!(r.total, 3);
    }

    #[test]
    fn preview_basic_translates() {
        // BRE: \(ab\)\+ means one or more "ab".
        let r = preview(&opts(r"\(ab\)\+", GrepMode::Basic), "abab x ab").unwrap();
        assert_eq!(r.total, 2);
        assert_eq!(r.matches[0].value, "abab");
    }

    #[test]
    fn preview_fixed_is_literal() {
        // In fixed mode the dot is literal, so it matches only "a.b".
        let r = preview(&opts("a.b", GrepMode::Fixed), "a.b axb").unwrap();
        assert_eq!(r.total, 1);
        assert_eq!(r.matches[0].value, "a.b");
    }

    #[test]
    fn preview_perl_lookahead() {
        let r = preview(&opts(r"foo(?=bar)", GrepMode::Perl), "foobar foobaz").unwrap();
        assert_eq!(r.total, 1);
    }

    #[test]
    fn preview_word_boundary() {
        let mut o = opts("cat", GrepMode::Extended);
        o.word = true;
        let r = preview(&o, "cat category cat").unwrap();
        // Only the standalone "cat" tokens, not "category".
        assert_eq!(r.total, 2);
    }

    #[test]
    fn preview_line_match_anchors() {
        let mut o = opts("cat", GrepMode::Extended);
        o.line_match = true;
        let r = preview(&o, "cat\ncategory\ncat").unwrap();
        assert_eq!(r.total, 2);
    }

    #[test]
    fn preview_ignore_case() {
        let mut o = opts("abc", GrepMode::Extended);
        o.ignore_case = true;
        assert_eq!(preview(&o, "ABC abc").unwrap().total, 2);
    }
}
