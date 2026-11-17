//! Command documentation: the built-in database (`commands.txt`, written for
//! this project) and the shared `Doc` type that local man pages also parse into.
//!
//! Database format, one directive per line:
//!
//! ```text
//! @cmd curl wget2          names (aliases share the entry)
//! Transfer data from or to a server.     first plain line: summary
//! -o --output <file> | Write output to <file>.
//! -s --silent | Silent mode.
//! --compressed | Ask for a compressed response.
//! -name <pattern> | (single dash, several letters) a whole-word option
//! if= <file> | (no dash, ends in =) a key=value operand, for dd
//! @arg URL | Positional argument help; the last one repeats.
//! @wrap 1                  after options and 1 operand, the rest is a command
//! @remote 1                after 1 operand, the rest is a shell command line
//! @shellc                  `-c` makes the first operand a script to explain
//! @style bundled           first operand may be letters without a dash (tar)
//! @sub clone | Clone a repository.   then indented lines belong to the sub
//! ```
//!
//! An option argument written `<command!>` is a shell command to explain.

use std::collections::HashMap;
use std::sync::LazyLock;

use serde::Serialize;

/// Where a description came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Source {
    Builtin,
    Man,
    Shell,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Style {
    #[default]
    Normal,
    /// The first operand may be option letters without a dash (`tar xzf`).
    Bundled,
}

/// One option.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Opt {
    pub short: Vec<char>,
    pub long: Vec<String>,
    /// Single-dash options with several letters (`-name`), or `key=` operands.
    pub word: Vec<String>,
    /// Argument name, if the option takes one.
    pub arg: Option<String>,
    pub arg_optional: bool,
    pub help: String,
}

impl Opt {
    /// How the option is written in a description, for example `-o, --output <file>`.
    pub fn term(&self) -> String {
        let mut names: Vec<String> = self.short.iter().map(|c| format!("-{c}")).collect();
        names.extend(self.word.iter().map(|w| {
            if w.ends_with('=') {
                w.clone()
            } else {
                format!("-{w}")
            }
        }));
        names.extend(self.long.iter().map(|l| format!("--{l}")));
        let mut t = names.join(", ");
        if let Some(a) = &self.arg {
            let a = a.trim_end_matches('!');
            if self.arg_optional {
                t.push_str(&format!(" [{a}]"));
            } else {
                t.push_str(&format!(" {a}"));
            }
        }
        t
    }

    /// The argument is a shell command line.
    pub fn arg_is_command(&self) -> bool {
        self.arg
            .as_deref()
            .is_some_and(|a| a.ends_with("!>") || a.ends_with('!'))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArgDoc {
    pub name: String,
    pub help: String,
}

/// Documentation for one command or subcommand.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Doc {
    pub name: String,
    pub summary: String,
    pub opts: Vec<Opt>,
    pub args: Vec<ArgDoc>,
    pub subs: Vec<Doc>,
    pub style: Style,
    pub wrap: Option<usize>,
    pub remote: Option<usize>,
    pub shell_c: bool,
    pub source: Source,
}

impl Doc {
    fn new(name: &str, source: Source) -> Self {
        Doc {
            name: name.to_string(),
            summary: String::new(),
            opts: Vec::new(),
            args: Vec::new(),
            subs: Vec::new(),
            style: Style::Normal,
            wrap: None,
            remote: None,
            shell_c: false,
            source,
        }
    }

    /// A man page entry.
    pub fn from_man(name: &str, summary: String, opts: Vec<Opt>) -> Self {
        let mut d = Doc::new(name, Source::Man);
        d.summary = summary;
        d.opts = opts;
        d
    }

    pub fn sub(&self, name: &str) -> Option<&Doc> {
        self.subs.iter().find(|s| s.name == name)
    }

    /// Help for the `n`th operand; the last documented one repeats.
    pub fn arg(&self, n: usize) -> Option<&ArgDoc> {
        self.args.get(n).or(self.args.last())
    }
}

/// Parse an option spec such as `-o --output <file>` into an `Opt` (without help).
pub fn parse_opt_spec(spec: &str) -> Option<Opt> {
    let mut o = Opt::default();
    for part in spec.split_whitespace() {
        if let Some(l) = part.strip_prefix("--") {
            let (name, arg) = match l.split_once('=') {
                Some((n, a)) => (n, Some(a)),
                None => (l, None),
            };
            if name.is_empty() {
                return None;
            }
            o.long.push(name.to_string());
            if let Some(a) = arg.filter(|a| !a.is_empty()) {
                o.arg = Some(a.to_string());
            }
        } else if let Some(s) = part.strip_prefix('-') {
            let mut chars = s.chars();
            match (chars.next(), chars.next()) {
                (Some(c), None) => o.short.push(c),
                (Some(_), Some(_)) => o.word.push(s.to_string()),
                _ => return None,
            }
        } else if part.ends_with('=') && o.short.is_empty() && o.long.is_empty() {
            o.word.push(part.to_string());
        } else if part.starts_with('[') {
            o.arg = Some(part.trim_matches(['[', ']']).to_string());
            o.arg_optional = true;
        } else {
            o.arg = Some(part.to_string());
        }
    }
    if o.short.is_empty() && o.long.is_empty() && o.word.is_empty() {
        None
    } else {
        Some(o)
    }
}

/// Parse the database text. Malformed lines are skipped.
pub fn parse_db(text: &str) -> HashMap<String, Doc> {
    let mut out: HashMap<String, Doc> = HashMap::new();
    let mut cur: Option<(Vec<String>, Doc)> = None;
    let mut in_sub = false;

    fn finish(out: &mut HashMap<String, Doc>, cur: Option<(Vec<String>, Doc)>) {
        if let Some((names, doc)) = cur {
            for n in names {
                let mut d = doc.clone();
                d.name = n.clone();
                out.insert(n, d);
            }
        }
    }

    for raw in text.lines() {
        if raw.trim().is_empty() || raw.trim_start().starts_with("##") {
            continue;
        }
        let indented = raw.starts_with(' ') || raw.starts_with('\t');
        let line = raw.trim();
        if let Some(rest) = line.strip_prefix("@cmd ") {
            finish(&mut out, cur.take());
            let names: Vec<String> = rest.split_whitespace().map(String::from).collect();
            if let Some(first) = names.first() {
                cur = Some((names.clone(), Doc::new(first, Source::Builtin)));
            }
            in_sub = false;
            continue;
        }
        let Some((_, doc)) = cur.as_mut() else {
            continue;
        };
        if !indented {
            in_sub = false;
        }
        let target: &mut Doc = if in_sub && indented {
            match doc.subs.last_mut() {
                Some(s) => s,
                None => doc,
            }
        } else {
            doc
        };
        if let Some(rest) = line.strip_prefix("@sub ") {
            let (name, help) = rest.split_once(" | ").unwrap_or((rest, ""));
            let mut s = Doc::new(name.trim(), Source::Builtin);
            s.summary = help.trim().to_string();
            doc.subs.push(s);
            in_sub = true;
        } else if let Some(rest) = line.strip_prefix("@arg ") {
            let (name, help) = rest.split_once(" | ").unwrap_or((rest, ""));
            target.args.push(ArgDoc {
                name: name.trim().to_string(),
                help: help.trim().to_string(),
            });
        } else if let Some(n) = line.strip_prefix("@wrap ") {
            target.wrap = n.trim().parse().ok();
        } else if let Some(n) = line.strip_prefix("@remote ") {
            target.remote = n.trim().parse().ok();
        } else if line == "@shellc" {
            target.shell_c = true;
        } else if line == "@style bundled" {
            target.style = Style::Bundled;
        } else if line.starts_with('-') || line.split(' ').next().is_some_and(|w| w.ends_with('='))
        {
            if let Some((spec, help)) = line.split_once(" | ")
                && let Some(mut o) = parse_opt_spec(spec)
            {
                o.help = help.trim().to_string();
                target.opts.push(o);
            }
        } else if target.summary.is_empty() {
            target.summary = line.to_string();
        }
    }
    finish(&mut out, cur);
    out
}

static DB: LazyLock<HashMap<String, Doc>> =
    LazyLock::new(|| parse_db(include_str!("commands.txt")));

/// The built-in entry for a command name.
pub fn builtin(name: &str) -> Option<&'static Doc> {
    DB.get(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spec_parsing() {
        let o = parse_opt_spec("-o --output <file>").unwrap();
        assert_eq!(o.short, ['o']);
        assert_eq!(o.long, ["output"]);
        assert_eq!(o.arg.as_deref(), Some("<file>"));
        assert_eq!(o.term(), "-o, --output <file>");
        let o = parse_opt_spec("-name <pattern>").unwrap();
        assert_eq!(o.word, ["name"]);
        let o = parse_opt_spec("if= <file>").unwrap();
        assert_eq!(o.word, ["if="]);
        let o = parse_opt_spec("--color [when]").unwrap();
        assert!(o.arg_optional);
        let o = parse_opt_spec("-c --command <command!>").unwrap();
        assert!(o.arg_is_command());
        assert!(parse_opt_spec("plain").is_none());
    }

    #[test]
    fn db_parses_and_is_sane() {
        let db = &*DB;
        assert!(db.len() > 100, "only {} commands", db.len());
        for (name, d) in db {
            assert!(!d.summary.is_empty(), "{name} has no summary");
            for o in &d.opts {
                assert!(!o.help.is_empty(), "{name} {} has no help", o.term());
            }
            for s in &d.subs {
                assert!(!s.summary.is_empty(), "{name} {} has no summary", s.name);
            }
        }
        let curl = builtin("curl").unwrap();
        assert!(curl.opts.iter().any(|o| o.short == ['o']));
        let git = builtin("git").unwrap();
        assert!(git.sub("clone").is_some());
        assert!(builtin("sudo").unwrap().wrap.is_some());
        assert!(builtin("bash").unwrap().shell_c);
        assert_eq!(builtin("tar").unwrap().style, Style::Bundled);
    }

    #[test]
    fn sub_options_are_scoped() {
        let db = parse_db("@cmd t\nTop.\n-a | top a\n@sub s | Sub.\n  -b | sub b\n-c | top c\n");
        let t = &db["t"];
        assert_eq!(t.opts.len(), 2);
        assert_eq!(t.subs[0].opts.len(), 1);
    }
}
