//! Local man pages as a fallback for commands and options the built-in list
//! does not cover (macOS and Linux). `man` runs with a timeout and an output
//! cap; results are cached for the life of the app. Nothing goes online.

use std::collections::HashMap;
use std::io::Read;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};

use super::core::ManLookup;
use super::db::{self, Doc, Opt};

/// Longest `man` may run for one page.
const TIMEOUT: Duration = Duration::from_secs(4);
/// Most output read from one page.
const MAX_OUTPUT: u64 = 4 * 1024 * 1024;
/// Most pages remembered.
const MAX_CACHE: usize = 512;
/// Most options taken from one page.
const MAX_OPTS: usize = 2000;
/// Longest description kept for one option.
const MAX_HELP: usize = 600;

static CACHE: LazyLock<Mutex<HashMap<String, Option<Arc<Doc>>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Reads man pages on this computer, at most `limit` new pages per explanation.
pub struct SystemMan {
    used: AtomicUsize,
    limit: usize,
}

impl SystemMan {
    pub fn new(limit: usize) -> Self {
        SystemMan {
            used: AtomicUsize::new(0),
            limit,
        }
    }
}

impl ManLookup for SystemMan {
    fn lookup(&self, name: &str) -> Option<Arc<Doc>> {
        if !valid_name(name) {
            return None;
        }
        if let Ok(c) = CACHE.lock()
            && let Some(hit) = c.get(name)
        {
            return hit.clone();
        }
        if self.used.fetch_add(1, Ordering::Relaxed) >= self.limit {
            return None;
        }
        let doc = fetch(name).and_then(|t| parse_man(&t, name)).map(Arc::new);
        if let Ok(mut c) = CACHE.lock() {
            if c.len() >= MAX_CACHE {
                c.clear();
            }
            c.insert(name.to_string(), doc.clone());
        }
        doc
    }
}

/// Command names worth asking `man` about.
fn valid_name(name: &str) -> bool {
    let mut chars = name.chars();
    name.len() <= 64
        && chars.next().is_some_and(|c| c.is_ascii_alphanumeric())
        && chars.all(|c| c.is_ascii_alphanumeric() || "._+-".contains(c))
}

#[cfg(windows)]
fn fetch(_name: &str) -> Option<String> {
    None
}

#[cfg(not(windows))]
fn fetch(name: &str) -> Option<String> {
    use std::process::{Command, Stdio};
    let mut child = Command::new("man")
        .arg(name)
        .env("MANPAGER", "cat")
        .env("PAGER", "cat")
        .env("MANWIDTH", "120")
        .env("GROFF_NO_SGR", "1")
        .env_remove("MAN_KEEP_FORMATTING")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let stdout = child.stdout.take()?;
    let reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stdout.take(MAX_OUTPUT).read_to_end(&mut buf);
        buf
    });
    let deadline = Instant::now() + TIMEOUT;
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break Some(s),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
        }
    };
    let out = reader.join().ok()?;
    if !status?.success() || out.is_empty() {
        return None;
    }
    Some(String::from_utf8_lossy(&out).into_owned())
}

/// Remove overstrike bold and underline, terminal escapes, and typographic hyphens.
fn clean(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\u{8}' => {
                out.pop();
            }
            '\u{1b}' => {
                if chars.peek() == Some(&'[') {
                    chars.next();
                    for n in chars.by_ref() {
                        if n.is_ascii_alphabetic() {
                            break;
                        }
                    }
                }
            }
            '\u{2010}' | '\u{2011}' | '\u{2212}' => out.push('-'),
            _ => out.push(c),
        }
    }
    out
}

fn indent(line: &str) -> usize {
    line.chars().take_while(|c| *c == ' ').count()
}

/// Parse rendered man page text into a `Doc`.
pub fn parse_man(text: &str, name: &str) -> Option<Doc> {
    let text = clean(&text.replace('\t', "        "));
    let lines: Vec<&str> = text.lines().collect();
    let summary = summary(&lines).unwrap_or_default();
    let mut opts: Vec<Opt> = Vec::new();
    let mut i = 0;
    while i < lines.len() && opts.len() < MAX_OPTS {
        let line = lines[i];
        let ind = indent(line);
        let t = line.trim();
        let looks = ind > 0
            && ind <= 24
            && t.starts_with('-')
            && t.chars()
                .nth(1)
                .is_some_and(|c| c.is_ascii_alphanumeric() || c == '-');
        if !looks {
            i += 1;
            continue;
        }
        let (head, inline) = match t.find("  ") {
            Some(p) => (&t[..p], t[p..].trim()),
            None => (t, ""),
        };
        let Some(mut opt) = parse_heading(head) else {
            i += 1;
            continue;
        };
        let mut help = String::from(inline);
        let mut j = i + 1;
        while j < lines.len() {
            let l = lines[j];
            if l.trim().is_empty() {
                if !help.is_empty() {
                    break;
                }
                j += 1;
                continue;
            }
            if indent(l) <= ind {
                break;
            }
            if !help.is_empty() {
                help.push(' ');
            }
            help.push_str(l.trim());
            if help.len() > MAX_HELP {
                break;
            }
            j += 1;
        }
        if !help.is_empty() {
            let mut h: String = help.split_whitespace().collect::<Vec<_>>().join(" ");
            if h.len() > MAX_HELP {
                let mut cut = MAX_HELP;
                while !h.is_char_boundary(cut) {
                    cut -= 1;
                }
                h.truncate(cut);
                h.push_str("...");
            }
            opt.help = h;
            opts.push(opt);
        }
        i = j.max(i + 1);
    }
    if summary.is_empty() && opts.is_empty() {
        return None;
    }
    Some(Doc::from_man(name, summary, opts))
}

fn summary(lines: &[&str]) -> Option<String> {
    let at = lines.iter().position(|l| l.trim() == "NAME")?;
    let mut s = String::new();
    for l in &lines[at + 1..] {
        let t = l.trim();
        if t.is_empty() {
            if s.is_empty() {
                continue;
            }
            break;
        }
        if indent(l) == 0 {
            break;
        }
        if !s.is_empty() {
            s.push(' ');
        }
        s.push_str(t);
    }
    let desc = [" - ", " \u{2013} ", " \u{2014} ", " -- "]
        .iter()
        .find_map(|sep| s.split_once(sep).map(|(_, d)| d.trim().to_string()))
        .unwrap_or(s);
    let desc: String = desc.chars().take(300).collect();
    let mut c = desc.chars();
    Some({
        let f = c.next()?;
        f.to_uppercase().collect::<String>() + c.as_str()
    })
}

/// Parse an option heading such as `-o, --output=FILE` or `-f file`.
fn parse_heading(head: &str) -> Option<Opt> {
    let mut spec = Vec::new();
    for part in head.split(", ") {
        let part = part.trim();
        if !part.starts_with('-') {
            break;
        }
        let end = part.find([' ', '=', '[', '<']).unwrap_or(part.len());
        let (name, rest) = part.split_at(end);
        if name.len() < 2
            || name
                .chars()
                .any(|c| !(c.is_ascii_alphanumeric() || "-_.".contains(c)))
        {
            break;
        }
        spec.push(name.to_string());
        let rest = rest.trim();
        if !rest.is_empty() {
            let optional = rest.starts_with('[');
            let arg = rest.trim_matches(['[', ']', '=']).trim();
            if !arg.is_empty() {
                spec.push(if optional {
                    format!("[{arg}]")
                } else {
                    arg.split_whitespace().next().unwrap_or(arg).to_string()
                });
            }
        }
    }
    if spec.is_empty() {
        return None;
    }
    db::parse_opt_spec(&spec.join(" "))
}

#[cfg(test)]
mod tests {
    use super::*;

    const GNU: &str = "\
CURL(1)                     User Commands                    CURL(1)

NAME
       frob - frobnicate the bar

SYNOPSIS
       frob [options]

OPTIONS
       -a, --all
              Show everything,
              including hidden things.

       -o, --output=FILE
              Write to FILE.

       --color[=WHEN]
              Colorize.
";

    const BSD: &str = "\
NAME
     ls \u{2013} list directory contents

DESCRIPTION
     -A      Include directory entries whose names begin with a dot (\u{2018}.\u{2019}) except
             for . and ...
     -f file  Read from file.
";

    #[test]
    fn parses_gnu_layout() {
        let d = parse_man(GNU, "frob").unwrap();
        assert_eq!(d.summary, "Frobnicate the bar");
        assert_eq!(d.opts.len(), 3);
        assert_eq!(d.opts[0].short, ['a']);
        assert_eq!(d.opts[0].long, ["all"]);
        assert_eq!(d.opts[0].help, "Show everything, including hidden things.");
        assert_eq!(d.opts[1].arg.as_deref(), Some("FILE"));
        assert!(d.opts[2].arg_optional);
    }

    #[test]
    fn parses_bsd_layout_and_overstrike() {
        let bold = "N\u{8}NA\u{8}AM\u{8}ME\u{8}E\n";
        let d = parse_man(&BSD.replacen("NAME\n", bold, 1), "ls").unwrap();
        assert_eq!(d.summary, "List directory contents");
        assert_eq!(d.opts[0].short, ['A']);
        assert!(d.opts[0].help.starts_with("Include directory entries"));
        assert!(d.opts[0].help.ends_with("for . and ..."));
        assert_eq!(d.opts[1].arg.as_deref(), Some("file"));
    }

    #[test]
    fn rejects_odd_names_and_junk() {
        assert!(!valid_name("-rf"));
        assert!(!valid_name("a b"));
        assert!(!valid_name("../x"));
        assert!(valid_name("python3.12"));
        assert!(parse_man("", "x").is_none());
        assert!(parse_man("\u{1b}[1m\u{8}\u{8}\u{8}", "x").is_none());
    }

    #[test]
    #[ignore = "needs a local man installation"]
    fn live_man_page() {
        let m = SystemMan::new(5);
        let d = m.lookup("ls").expect("man ls");
        assert!(!d.opts.is_empty(), "{d:?}");
    }
}
