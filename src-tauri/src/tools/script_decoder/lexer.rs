//! A tokenizer for the subset of Python that obfuscated loaders use: names,
//! string and bytes literals (all prefixes and quote styles, with escapes),
//! integers, operators and logical newlines. It never fails: anything it does
//! not understand becomes an `Other` token, so hostile input degrades to "no
//! decode found" rather than an error.

/// A string or bytes literal value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lit {
    Str(String),
    Bytes(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Tok {
    Name(String),
    Lit(Lit),
    Int(i64),
    /// Operators and punctuation, one or two characters.
    Op(&'static str),
    /// End of a logical line (outside brackets) or `;`.
    Newline,
    /// Anything else (floats, stray characters).
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    pub tok: Tok,
    /// 1-based line where the token starts.
    pub line: usize,
}

const TWO_CHAR_OPS: &[&str] = &[
    "**", "//", "==", "!=", "<=", ">=", "->", ":=", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=",
    "<<", ">>",
];

const ONE_CHAR_OPS: &[&str] = &[
    "(", ")", "[", "]", "{", "}", ",", ":", ".", "=", "+", "-", "*", "/", "%", "&", "|", "^", "~",
    "<", ">", "@", "!",
];

fn op1(c: char) -> Option<&'static str> {
    ONE_CHAR_OPS
        .iter()
        .copied()
        .find(|o| o.starts_with(c) && o.len() == 1)
}

/// Tokenize Python source.
pub fn tokenize(src: &str) -> Vec<Token> {
    let chars: Vec<char> = src.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    let mut line = 1;
    let mut depth: i32 = 0;

    let push_newline = |out: &mut Vec<Token>, line: usize| {
        if !matches!(
            out.last(),
            Some(Token {
                tok: Tok::Newline,
                ..
            }) | None
        ) {
            out.push(Token {
                tok: Tok::Newline,
                line,
            });
        }
    };

    while i < chars.len() {
        let c = chars[i];
        match c {
            '\n' => {
                if depth == 0 {
                    push_newline(&mut out, line);
                }
                line += 1;
                i += 1;
            }
            '#' => {
                while i < chars.len() && chars[i] != '\n' {
                    i += 1;
                }
            }
            '\\' if chars.get(i + 1) == Some(&'\n') => {
                // Explicit line continuation.
                line += 1;
                i += 2;
            }
            ';' => {
                if depth == 0 {
                    push_newline(&mut out, line);
                }
                i += 1;
            }
            c if c.is_whitespace() => i += 1,
            c if c.is_alphabetic() || c == '_' => {
                let start = i;
                while i < chars.len() && (chars[i].is_alphanumeric() || chars[i] == '_') {
                    i += 1;
                }
                let word: String = chars[start..i].iter().collect();
                // A string prefix directly followed by a quote.
                if matches!(chars.get(i), Some('\'' | '"')) && is_prefix(&word) {
                    let (lit, next, lines) = string_literal(&chars, i, &word.to_ascii_lowercase());
                    out.push(Token {
                        tok: Tok::Lit(lit),
                        line,
                    });
                    line += lines;
                    i = next;
                } else {
                    out.push(Token {
                        tok: Tok::Name(word),
                        line,
                    });
                }
            }
            '\'' | '"' => {
                let (lit, next, lines) = string_literal(&chars, i, "");
                out.push(Token {
                    tok: Tok::Lit(lit),
                    line,
                });
                line += lines;
                i = next;
            }
            c if c.is_ascii_digit() => {
                let (tok, next) = number(&chars, i);
                out.push(Token { tok, line });
                i = next;
            }
            _ => {
                let two: String = chars[i..chars.len().min(i + 2)].iter().collect();
                if let Some(op) = TWO_CHAR_OPS.iter().copied().find(|o| *o == two) {
                    out.push(Token {
                        tok: Tok::Op(op),
                        line,
                    });
                    i += 2;
                } else if let Some(op) = op1(c) {
                    match op {
                        "(" | "[" | "{" => depth += 1,
                        ")" | "]" | "}" => depth = (depth - 1).max(0),
                        _ => {}
                    }
                    out.push(Token {
                        tok: Tok::Op(op),
                        line,
                    });
                    i += 1;
                } else {
                    out.push(Token {
                        tok: Tok::Other,
                        line,
                    });
                    i += 1;
                }
            }
        }
    }
    push_newline(&mut out, line);
    out
}

fn is_prefix(word: &str) -> bool {
    matches!(
        word.to_ascii_lowercase().as_str(),
        "r" | "u" | "b" | "f" | "br" | "rb" | "fr" | "rf"
    )
}

/// Parse a number starting at `i`. Integers (decimal, hex, octal, binary,
/// with underscores) become `Int`; floats and complex become `Other`.
fn number(chars: &[char], mut i: usize) -> (Tok, usize) {
    let start = i;
    while i < chars.len()
        && (chars[i].is_ascii_alphanumeric() || chars[i] == '_' || chars[i] == '.')
    {
        // Stop at a method call on an int literal like `1 .bit_length` is rare;
        // a dot followed by a non-digit ends the number.
        if chars[i] == '.' && !chars.get(i + 1).is_some_and(|c| c.is_ascii_digit()) {
            break;
        }
        i += 1;
    }
    let raw: String = chars[start..i].iter().filter(|c| **c != '_').collect();
    let lower = raw.to_ascii_lowercase();
    let parsed = if let Some(h) = lower.strip_prefix("0x") {
        i64::from_str_radix(h, 16).ok()
    } else if let Some(o) = lower.strip_prefix("0o") {
        i64::from_str_radix(o, 8).ok()
    } else if let Some(b) = lower.strip_prefix("0b") {
        i64::from_str_radix(b, 2).ok()
    } else {
        lower.parse::<i64>().ok()
    };
    (parsed.map(Tok::Int).unwrap_or(Tok::Other), i)
}

/// Parse a string literal whose opening quote is at `i`. Returns the value,
/// the index after it, and how many newlines it spanned.
fn string_literal(chars: &[char], i: usize, prefix: &str) -> (Lit, usize, usize) {
    let raw = prefix.contains('r');
    let bytes = prefix.contains('b');
    let q = chars[i];
    let triple = chars.get(i + 1) == Some(&q) && chars.get(i + 2) == Some(&q);
    let mut j = if triple { i + 3 } else { i + 1 };
    let mut lines = 0;
    let mut out: Vec<u32> = Vec::new();

    while j < chars.len() {
        let c = chars[j];
        if triple {
            if c == q && chars.get(j + 1) == Some(&q) && chars.get(j + 2) == Some(&q) {
                j += 3;
                break;
            }
        } else if c == q {
            j += 1;
            break;
        } else if c == '\n' {
            // Unterminated single-quoted string: stop at the line end.
            break;
        }
        if c == '\n' {
            lines += 1;
        }
        if c == '\\' && j + 1 < chars.len() {
            if raw {
                out.push('\\' as u32);
                out.push(chars[j + 1] as u32);
                if chars[j + 1] == '\n' {
                    lines += 1;
                }
                j += 2;
                continue;
            }
            j = escape(chars, j + 1, bytes, &mut out, &mut lines);
            continue;
        }
        out.push(c as u32);
        j += 1;
    }

    let lit = if bytes {
        Lit::Bytes(out.iter().map(|&u| (u & 0xff) as u8).collect())
    } else {
        Lit::Str(out.iter().filter_map(|&u| char::from_u32(u)).collect())
    };
    (lit, j, lines)
}

/// Decode one escape after a backslash at `j - 1`. Returns the next index.
fn escape(chars: &[char], j: usize, bytes: bool, out: &mut Vec<u32>, lines: &mut usize) -> usize {
    let c = chars[j];
    let simple = match c {
        '\n' => {
            *lines += 1;
            return j + 1;
        }
        '\\' => Some('\\'),
        '\'' => Some('\''),
        '"' => Some('"'),
        'a' => Some('\x07'),
        'b' => Some('\x08'),
        'f' => Some('\x0c'),
        'n' => Some('\n'),
        'r' => Some('\r'),
        't' => Some('\t'),
        'v' => Some('\x0b'),
        _ => None,
    };
    if let Some(s) = simple {
        out.push(s as u32);
        return j + 1;
    }
    let hex = |from: usize, n: usize| -> Option<u32> {
        let s: String = chars.get(from..from + n)?.iter().collect();
        if s.len() == n && s.chars().all(|c| c.is_ascii_hexdigit()) {
            u32::from_str_radix(&s, 16).ok()
        } else {
            None
        }
    };
    match c {
        'x' => {
            if let Some(v) = hex(j + 1, 2) {
                out.push(v);
                return j + 3;
            }
        }
        'u' if !bytes => {
            if let Some(v) = hex(j + 1, 4) {
                out.push(v);
                return j + 5;
            }
        }
        'U' if !bytes => {
            if let Some(v) = hex(j + 1, 8) {
                out.push(v);
                return j + 9;
            }
        }
        '0'..='7' => {
            let mut k = j;
            let mut v = 0u32;
            while k < chars.len() && k < j + 3 && ('0'..='7').contains(&chars[k]) {
                v = v * 8 + chars[k].to_digit(8).unwrap_or(0);
                k += 1;
            }
            out.push(v);
            return k;
        }
        _ => {}
    }
    // Unknown escape: Python keeps the backslash.
    out.push('\\' as u32);
    out.push(c as u32);
    j + 1
}

#[cfg(test)]
mod tests {
    use super::*;

    fn toks(s: &str) -> Vec<Tok> {
        tokenize(s).into_iter().map(|t| t.tok).collect()
    }

    fn s(v: &str) -> Tok {
        Tok::Lit(Lit::Str(v.to_string()))
    }

    #[test]
    fn names_ops_and_newlines() {
        assert_eq!(
            toks("x = a.b(1)\ny += 'z'"),
            [
                Tok::Name("x".into()),
                Tok::Op("="),
                Tok::Name("a".into()),
                Tok::Op("."),
                Tok::Name("b".into()),
                Tok::Op("("),
                Tok::Int(1),
                Tok::Op(")"),
                Tok::Newline,
                Tok::Name("y".into()),
                Tok::Op("+="),
                s("z"),
                Tok::Newline,
            ]
        );
    }

    #[test]
    fn newlines_inside_brackets_are_joined() {
        let t = toks("f(\n 'a',\n 'b')\n");
        assert_eq!(t.iter().filter(|t| **t == Tok::Newline).count(), 1);
    }

    #[test]
    fn comments_and_semicolons() {
        assert_eq!(
            toks("a # c\nb; c"),
            [
                Tok::Name("a".into()),
                Tok::Newline,
                Tok::Name("b".into()),
                Tok::Newline,
                Tok::Name("c".into()),
                Tok::Newline,
            ]
        );
    }

    #[test]
    fn string_escapes() {
        assert_eq!(toks(r"'\x41B\103\n'")[0], s("ABC\n"));
        assert_eq!(toks(r"r'\x41'")[0], s(r"\x41"));
        assert_eq!(toks(r"b'\x00\xff'")[0], Tok::Lit(Lit::Bytes(vec![0, 255])));
        assert_eq!(toks(r"'\q'")[0], s(r"\q"));
    }

    #[test]
    fn triple_quoted_spans_lines() {
        let t = tokenize("x = '''a\nb'''\ny");
        assert_eq!(t[2].tok, s("a\nb"));
        let y = t.iter().find(|t| t.tok == Tok::Name("y".into())).unwrap();
        assert_eq!(y.line, 3);
    }

    #[test]
    fn prefixes_and_numbers() {
        assert_eq!(toks("RB'a'")[0], Tok::Lit(Lit::Bytes(b"a".to_vec())));
        assert_eq!(toks("f'{x}'")[0], s("{x}"));
        assert_eq!(
            toks("0x41 0o17 0b11 1_000 1.5")[..5],
            [
                Tok::Int(65),
                Tok::Int(15),
                Tok::Int(3),
                Tok::Int(1000),
                Tok::Other
            ]
        );
    }

    #[test]
    fn hostile_input_does_not_panic() {
        for s in [
            "'", "'''", "\\", "b'\\x", "'\\u12", "\"\\", "0x", "(((", ")))",
        ] {
            let _ = tokenize(s);
        }
    }
}
