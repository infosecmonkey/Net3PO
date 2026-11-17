//! A tokenizer for POSIX shell and Bash command lines. It never fails:
//! unbalanced quotes or substitutions run to the end of the input, so hostile
//! text degrades to a best-effort split instead of an error. Spans are byte
//! offsets into the input and always fall on character boundaries.

/// Most tokens produced from one input.
pub const MAX_TOKENS: usize = 20_000;
/// Deepest nesting of quotes and substitutions the scanner follows; deeper
/// text is treated as running to the end of the input.
const MAX_NEST: usize = 200;

/// The kind of an embedded substitution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubKind {
    /// `$(...)`
    Command,
    /// `` `...` ``
    Backtick,
    /// `$((...))`
    Arith,
    /// `<(...)`
    ProcIn,
    /// `>(...)`
    ProcOut,
}

/// A substitution inside a word, with its inner text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sub {
    pub kind: SubKind,
    pub inner: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokKind {
    /// A word. `value` has quotes removed and escapes applied; substitutions
    /// and parameter expansions stay as written.
    Word {
        value: String,
        /// Some part was quoted or escaped.
        quoted: bool,
        /// Contains an unquoted or double-quoted `$` expansion or substitution.
        expands: bool,
        /// Contains an unquoted glob character.
        glob: bool,
        subs: Vec<Sub>,
    },
    /// A control operator: `|`, `||`, `&&`, `;`, `&`, `(`, `)`, newline and so on.
    Op(&'static str),
    /// A redirection operator, with an optional file descriptor number in front.
    Redir {
        fd: Option<String>,
        op: &'static str,
    },
    Comment,
    /// The body of a here-document, including its terminating line.
    Heredoc,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tok {
    pub kind: TokKind,
    pub start: usize,
    pub end: usize,
}

impl Tok {
    /// The word value, if this is a word.
    pub fn word(&self) -> Option<&str> {
        match &self.kind {
            TokKind::Word { value, .. } => Some(value),
            _ => None,
        }
    }
}

#[derive(Debug, Default)]
pub struct Lexed {
    pub toks: Vec<Tok>,
    pub truncated: bool,
}

const REDIRS: &[&str] = &[
    "&>>", "&>", "<<<", "<<-", "<<", "<>", ">>", ">|", ">&", "<&", ">", "<",
];
const CONTROLS: &[&str] = &[
    ";;&", "||", "|&", "|", "&&", "&", ";;", ";&", ";", "(", ")", "\n",
];

/// Split `src` into tokens.
pub fn lex(src: &str) -> Lexed {
    let mut l = Lexer {
        s: src,
        i: 0,
        out: Lexed::default(),
        want_delim: None,
        heredocs: Vec::new(),
    };
    l.run();
    l.out
}

struct Lexer<'a> {
    s: &'a str,
    i: usize,
    out: Lexed,
    /// The next word is a here-document delimiter (`true`: strip tabs).
    want_delim: Option<bool>,
    /// Delimiters waiting for the next newline.
    heredocs: Vec<(String, bool)>,
}

impl Lexer<'_> {
    fn byte(&self, i: usize) -> u8 {
        self.s.as_bytes().get(i).copied().unwrap_or(0)
    }

    fn char_at(&self, i: usize) -> Option<char> {
        self.s.get(i..).and_then(|r| r.chars().next())
    }

    fn push(&mut self, kind: TokKind, start: usize, end: usize) {
        self.out.toks.push(Tok { kind, start, end });
    }

    fn run(&mut self) {
        while self.i < self.s.len() {
            if self.out.toks.len() >= MAX_TOKENS {
                self.out.truncated = true;
                return;
            }
            let c = self.byte(self.i);
            match c {
                b' ' | b'\t' | b'\r' => self.i += 1,
                b'\\' if self.byte(self.i + 1) == b'\n' => self.i += 2,
                b'\n' => {
                    self.push(TokKind::Op("\n"), self.i, self.i + 1);
                    self.i += 1;
                    self.read_heredocs();
                }
                b'#' => {
                    let end = self.s[self.i..]
                        .find('\n')
                        .map_or(self.s.len(), |n| self.i + n);
                    self.push(TokKind::Comment, self.i, end);
                    self.i = end;
                }
                b'0'..=b'9' => {
                    let mut j = self.i;
                    while self.byte(j).is_ascii_digit() {
                        j += 1;
                    }
                    if matches!(self.byte(j), b'<' | b'>') && self.byte(j + 1) != b'(' {
                        let fd = self.s[self.i..j].to_string();
                        self.operator(Some((fd, self.i)), j);
                    } else {
                        self.word();
                    }
                }
                b'<' | b'>' if self.byte(self.i + 1) == b'(' => self.word(),
                b'|' | b'&' | b';' | b'(' | b')' | b'<' | b'>' => self.operator(None, self.i),
                _ => self.word(),
            }
        }
    }

    /// Read an operator at `at`; `fd` is a number that came just before it.
    fn operator(&mut self, fd: Option<(String, usize)>, at: usize) {
        let rest = &self.s[at..];
        let start = fd.as_ref().map_or(at, |(_, s)| *s);
        if let Some(op) = REDIRS.iter().find(|op| rest.starts_with(**op)) {
            // `&>` only counts as a redirection without an fd number.
            if !(op.starts_with('&') && fd.is_some()) {
                self.i = at + op.len();
                if *op == "<<" || *op == "<<-" {
                    self.want_delim = Some(*op == "<<-");
                }
                self.push(
                    TokKind::Redir {
                        fd: fd.map(|(f, _)| f),
                        op,
                    },
                    start,
                    self.i,
                );
                return;
            }
        }
        match CONTROLS.iter().find(|op| rest.starts_with(**op)) {
            Some(op) => {
                self.i = at + op.len();
                self.push(TokKind::Op(op), start, self.i);
            }
            None => {
                // Not reachable for the bytes routed here; stay safe anyway.
                self.i = at + 1;
            }
        }
    }

    /// Consume here-document bodies after a newline.
    fn read_heredocs(&mut self) {
        for (delim, strip) in std::mem::take(&mut self.heredocs) {
            let start = self.i;
            let mut end = self.s.len();
            let mut pos = self.i;
            while pos < self.s.len() {
                let line_end = self.s[pos..].find('\n').map_or(self.s.len(), |n| pos + n);
                let line = &self.s[pos..line_end];
                let line = if strip {
                    line.trim_start_matches('\t')
                } else {
                    line
                };
                if line.trim_end_matches('\r') == delim {
                    end = line_end;
                    break;
                }
                pos = line_end + 1;
            }
            if end > start {
                self.push(TokKind::Heredoc, start, end);
            }
            self.i = end;
            if self.byte(self.i) == b'\n' {
                self.i += 1;
            }
        }
    }

    /// Index of the `)` that closes a `(` just before `i`, or the end.
    fn close_paren(&self, i: usize) -> usize {
        self.close_paren_at(i, 0)
    }

    fn close_paren_at(&self, mut i: usize, nest: usize) -> usize {
        if nest > MAX_NEST {
            return self.s.len();
        }
        let mut depth = 1usize;
        while i < self.s.len() {
            match self.byte(i) {
                b'\\' => i += 1,
                b'\'' => {
                    i = self.s[i + 1..]
                        .find('\'')
                        .map_or(self.s.len(), |n| i + 1 + n);
                }
                b'"' => i = self.skip_dquote(i, nest + 1),
                b'`' => i = self.close_backtick(i + 1),
                b'(' => depth += 1,
                b')' => {
                    depth -= 1;
                    if depth == 0 {
                        return i;
                    }
                }
                _ => {}
            }
            i += 1;
        }
        self.s.len()
    }

    /// Index of the closing `"` for a `"` at `i`, or the end.
    fn skip_dquote(&self, mut i: usize, nest: usize) -> usize {
        if nest > MAX_NEST {
            return self.s.len();
        }
        i += 1;
        while i < self.s.len() {
            match self.byte(i) {
                b'\\' => i += 1,
                b'"' => return i,
                b'$' if self.byte(i + 1) == b'(' => i = self.close_paren_at(i + 2, nest + 1),
                b'`' => i = self.close_backtick(i + 1),
                _ => {}
            }
            i += 1;
        }
        self.s.len()
    }

    /// Index of the `` ` `` closing a backtick that started before `i`.
    fn close_backtick(&self, mut i: usize) -> usize {
        while i < self.s.len() {
            match self.byte(i) {
                b'\\' => i += 1,
                b'`' => return i,
                _ => {}
            }
            i += 1;
        }
        self.s.len()
    }

    /// Index of the `}` closing a `${` whose `{` is just before `i`.
    fn close_brace(&self, mut i: usize) -> usize {
        let mut depth = 1usize;
        while i < self.s.len() {
            match self.byte(i) {
                b'\\' => i += 1,
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        return i;
                    }
                }
                _ => {}
            }
            i += 1;
        }
        self.s.len()
    }

    fn slice(&self, a: usize, b: usize) -> &str {
        self.s
            .get(a.min(self.s.len())..b.min(self.s.len()))
            .unwrap_or("")
    }

    /// Read a `$...` expansion at `self.i` into `value`.
    fn dollar(&mut self, w: &mut WordAcc) {
        let i = self.i;
        match self.byte(i + 1) {
            b'(' if self.byte(i + 2) == b'(' => {
                let close = self.close_paren(i + 3);
                // `$((...))`: the outer paren closes right after the inner one.
                let end = (close + 2).min(self.s.len());
                w.subs.push(Sub {
                    kind: SubKind::Arith,
                    inner: self.slice(i + 3, close).to_string(),
                });
                w.value.push_str(self.slice(i, end));
                self.i = end;
            }
            b'(' => {
                let close = self.close_paren(i + 2);
                w.subs.push(Sub {
                    kind: SubKind::Command,
                    inner: self.slice(i + 2, close).to_string(),
                });
                let end = (close + 1).min(self.s.len());
                w.value.push_str(self.slice(i, end));
                self.i = end;
            }
            b'{' => {
                let close = self.close_brace(i + 2);
                let end = (close + 1).min(self.s.len());
                w.value.push_str(self.slice(i, end));
                self.i = end;
            }
            _ => {
                w.value.push('$');
                self.i += 1;
            }
        }
        w.expands = true;
    }

    fn backtick(&mut self, w: &mut WordAcc) {
        let close = self.close_backtick(self.i + 1);
        let inner = self.slice(self.i + 1, close).replace("\\`", "`");
        w.subs.push(Sub {
            kind: SubKind::Backtick,
            inner,
        });
        let end = (close + 1).min(self.s.len());
        w.value.push_str(self.slice(self.i, end));
        w.expands = true;
        self.i = end;
    }

    fn word(&mut self) {
        let start = self.i;
        let mut w = WordAcc::default();
        while self.i < self.s.len() {
            let c = self.byte(self.i);
            match c {
                b' ' | b'\t' | b'\r' | b'\n' | b';' | b'&' | b'|' | b')' => break,
                b'(' => {
                    // `name=(a b)` array assignment or an extglob; otherwise an operator.
                    if w.value.ends_with('=') || w.value.ends_with(['@', '!', '?', '*', '+']) {
                        let close = self.close_paren(self.i + 1);
                        let end = (close + 1).min(self.s.len());
                        w.value.push_str(self.slice(self.i, end));
                        self.i = end;
                    } else {
                        break;
                    }
                }
                b'<' | b'>' => {
                    if self.byte(self.i + 1) != b'(' {
                        break;
                    }
                    let close = self.close_paren(self.i + 2);
                    w.subs.push(Sub {
                        kind: if c == b'<' {
                            SubKind::ProcIn
                        } else {
                            SubKind::ProcOut
                        },
                        inner: self.slice(self.i + 2, close).to_string(),
                    });
                    let end = (close + 1).min(self.s.len());
                    w.value.push_str(self.slice(self.i, end));
                    w.expands = true;
                    self.i = end;
                }
                b'\\' => {
                    w.quoted = true;
                    if self.byte(self.i + 1) == b'\n' {
                        self.i += 2;
                    } else if let Some(n) = self.char_at(self.i + 1) {
                        w.value.push(n);
                        self.i += 1 + n.len_utf8();
                    } else {
                        self.i += 1;
                    }
                }
                b'\'' => {
                    w.quoted = true;
                    let close = self.s[self.i + 1..]
                        .find('\'')
                        .map_or(self.s.len(), |n| self.i + 1 + n);
                    w.value.push_str(self.slice(self.i + 1, close));
                    self.i = (close + 1).min(self.s.len());
                }
                b'"' => self.dquote(&mut w),
                b'$' if self.byte(self.i + 1) == b'\'' => {
                    w.quoted = true;
                    let (text, end) = ansi_c(self.s, self.i + 2);
                    w.value.push_str(&text);
                    self.i = end;
                }
                b'$' if self.byte(self.i + 1) == b'"' => {
                    self.i += 1;
                    self.dquote(&mut w);
                }
                b'$' => self.dollar(&mut w),
                b'`' => self.backtick(&mut w),
                b'*' | b'?' | b'[' => {
                    w.glob = true;
                    w.value.push(c as char);
                    self.i += 1;
                }
                _ => {
                    let ch = self.char_at(self.i).unwrap_or('\u{FFFD}');
                    w.value.push(ch);
                    self.i += ch.len_utf8().max(1);
                }
            }
        }
        if self.i == start {
            // Defensive: always make progress.
            self.i += self.char_at(self.i).map_or(1, char::len_utf8);
            return;
        }
        if let Some(strip) = self.want_delim.take() {
            self.heredocs.push((w.value.clone(), strip));
        }
        self.push(
            TokKind::Word {
                value: w.value,
                quoted: w.quoted,
                expands: w.expands,
                glob: w.glob,
                subs: w.subs,
            },
            start,
            self.i,
        );
    }

    fn dquote(&mut self, w: &mut WordAcc) {
        w.quoted = true;
        self.i += 1;
        while self.i < self.s.len() {
            match self.byte(self.i) {
                b'"' => {
                    self.i += 1;
                    return;
                }
                b'\\' => {
                    let n = self.byte(self.i + 1);
                    if n == b'\n' {
                        self.i += 2;
                    } else if matches!(n, b'$' | b'`' | b'"' | b'\\') {
                        w.value.push(n as char);
                        self.i += 2;
                    } else {
                        w.value.push('\\');
                        self.i += 1;
                    }
                }
                b'$' => self.dollar(w),
                b'`' => self.backtick(w),
                _ => {
                    let ch = self.char_at(self.i).unwrap_or('\u{FFFD}');
                    w.value.push(ch);
                    self.i += ch.len_utf8().max(1);
                }
            }
        }
    }
}

#[derive(Default)]
struct WordAcc {
    value: String,
    quoted: bool,
    expands: bool,
    glob: bool,
    subs: Vec<Sub>,
}

/// Decode a `$'...'` body starting at `i`; returns the text and the index after
/// the closing quote.
fn ansi_c(s: &str, mut i: usize) -> (String, usize) {
    let b = s.as_bytes();
    let mut out: Vec<u8> = Vec::new();
    while i < b.len() {
        match b[i] {
            b'\'' => return (String::from_utf8_lossy(&out).into_owned(), i + 1),
            b'\\' if i + 1 < b.len() => {
                let e = b[i + 1];
                i += 2;
                match e {
                    b'n' => out.push(b'\n'),
                    b't' => out.push(b'\t'),
                    b'r' => out.push(b'\r'),
                    b'a' => out.push(7),
                    b'b' => out.push(8),
                    b'e' | b'E' => out.push(27),
                    b'f' => out.push(12),
                    b'v' => out.push(11),
                    b'x' => {
                        let (v, n) = hex_digits(&b[i..], 2);
                        if n == 0 {
                            out.extend_from_slice(b"\\x");
                        } else {
                            out.push(v as u8);
                        }
                        i += n;
                    }
                    b'u' | b'U' => {
                        let (v, n) = hex_digits(&b[i..], if e == b'u' { 4 } else { 8 });
                        match char::from_u32(v).filter(|_| n > 0) {
                            Some(c) => {
                                let mut buf = [0u8; 4];
                                out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
                            }
                            None => out.extend_from_slice(&[b'\\', e]),
                        }
                        i += n;
                    }
                    b'0'..=b'7' => {
                        let mut v: u32 = u32::from(e - b'0');
                        let mut n = 0;
                        while n < 2 && i < b.len() && (b'0'..=b'7').contains(&b[i]) {
                            v = v * 8 + u32::from(b[i] - b'0');
                            i += 1;
                            n += 1;
                        }
                        out.push((v & 0xFF) as u8);
                    }
                    b'c' if i < b.len() => {
                        out.push(b[i] & 0x1F);
                        i += 1;
                    }
                    other => out.push(other),
                }
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    (String::from_utf8_lossy(&out).into_owned(), b.len())
}

fn hex_digits(b: &[u8], max: usize) -> (u32, usize) {
    let mut v = 0u32;
    let mut n = 0;
    while n < max && n < b.len() && b[n].is_ascii_hexdigit() {
        v = v * 16 + (b[n] as char).to_digit(16).unwrap_or(0);
        n += 1;
    }
    (v, n)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(s: &str) -> Vec<String> {
        lex(s)
            .toks
            .iter()
            .map(|t| match &t.kind {
                TokKind::Word { value, .. } => value.clone(),
                TokKind::Op(o) => format!("<{o}>"),
                TokKind::Redir { fd, op } => format!("[{}{op}]", fd.clone().unwrap_or_default()),
                TokKind::Comment => "#".into(),
                TokKind::Heredoc => "HEREDOC".into(),
            })
            .collect()
    }

    #[test]
    fn basic_split() {
        assert_eq!(
            words("curl -s http://x/a|bash && echo ok; ls>out 2>&1 &"),
            [
                "curl",
                "-s",
                "http://x/a",
                "<|>",
                "bash",
                "<&&>",
                "echo",
                "ok",
                "<;>",
                "ls",
                "[>]",
                "out",
                "[2>&]",
                "1",
                "<&>"
            ]
        );
    }

    #[test]
    fn quoting() {
        assert_eq!(
            words(r#"echo 'a b' "c $HOME d" e\ f $'x\x41\n'"#),
            ["echo", "a b", "c $HOME d", "e f", "xA\n"]
        );
        let l = lex("echo \"$(id -u)\" `whoami`");
        let TokKind::Word { subs, expands, .. } = &l.toks[1].kind else {
            panic!()
        };
        assert!(expands);
        assert_eq!(subs[0].inner, "id -u");
        let TokKind::Word { subs, .. } = &l.toks[2].kind else {
            panic!()
        };
        assert_eq!(subs[0].kind, SubKind::Backtick);
        assert_eq!(subs[0].inner, "whoami");
    }

    #[test]
    fn nested_substitution_and_arith() {
        let l = lex("echo $(echo $(date) \")\") $((1+2)) <(ls)");
        let subs: Vec<_> = l
            .toks
            .iter()
            .filter_map(|t| match &t.kind {
                TokKind::Word { subs, .. } => subs.first().cloned(),
                _ => None,
            })
            .collect();
        assert_eq!(subs[0].inner, "echo $(date) \")\"");
        assert_eq!(subs[1].kind, SubKind::Arith);
        assert_eq!(subs[1].inner, "1+2");
        assert_eq!(subs[2].kind, SubKind::ProcIn);
    }

    #[test]
    fn heredoc_and_comment() {
        assert_eq!(
            words("cat <<EOF > f # note\nline $x\nEOF\necho done"),
            [
                "cat", "[<<]", "EOF", "[>]", "f", "#", "<\n>", "HEREDOC", "echo", "done"
            ]
        );
    }

    #[test]
    fn array_assignment() {
        assert_eq!(words("a=(1 2) b"), ["a=(1 2)", "b"]);
        assert_eq!(words("(cd x)"), ["<(>", "cd", "x", "<)>"]);
    }

    #[test]
    fn hostile_input_never_panics() {
        for s in [
            "\"",
            "'",
            "$(",
            "$((",
            "${",
            "`",
            "<(",
            "\\",
            "$'\\x",
            "$'\\u",
            "2>",
            "<<",
            "é$'\\c",
            "a=(",
            "cat <<-X\n\tX",
            "\u{1F600}|\u{1F600}",
        ] {
            let l = lex(s);
            for t in &l.toks {
                assert!(
                    s.is_char_boundary(t.start) && s.is_char_boundary(t.end),
                    "{s:?}"
                );
            }
        }
        let long = "a|".repeat(MAX_TOKENS);
        assert!(lex(&long).truncated);
        let deep = "\"$(".repeat(30_000);
        let _ = lex(&deep);
    }
}
