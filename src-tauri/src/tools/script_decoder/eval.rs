//! A static evaluator for the small slice of Python expressions obfuscated
//! loaders are built from: literals, concatenation, slicing, `chr`/`ord`
//! joins and comprehensions, `bytes(...)`, and calls into base64, binascii,
//! codecs, zlib, gzip, lzma and marshal. It knows nothing about I/O: there is
//! no way for input to reach the filesystem, network or a real interpreter.
//!
//! Evaluation runs on a step budget with recursion and size caps, and
//! anything outside the subset evaluates to `Unknown` instead of failing.

use std::collections::HashMap;

use super::codecs;
use super::lexer::{Lit, Tok, Token};

/// Work allowed for one top-level evaluation.
const BUDGET: usize = 2_000_000;
/// Deepest expression nesting followed.
const MAX_DEPTH: usize = 200;
/// Most items a comprehension or list may produce.
const MAX_ITEMS: usize = 1_000_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum V {
    Str(String),
    Bytes(Vec<u8>),
    Int(i64),
    List(Vec<V>),
    /// A module, by dotted name.
    Module(String),
    /// A function or callable attribute, by dotted name.
    Func(String),
    /// A method bound to a value.
    Method(Box<V>, String),
    /// Bytes passed to `marshal.loads`.
    Marshal(Vec<u8>),
    Unknown,
}

impl V {
    fn size(&self) -> usize {
        match self {
            V::Str(s) => s.len(),
            V::Bytes(b) | V::Marshal(b) => b.len(),
            V::List(l) => l.len(),
            _ => 0,
        }
    }

    fn as_bytes(&self) -> Option<Vec<u8>> {
        match self {
            V::Bytes(b) => Some(b.clone()),
            V::Str(s) => Some(latin1_or_utf8(s)),
            _ => None,
        }
    }

    fn as_str(&self) -> Option<&str> {
        match self {
            V::Str(s) => Some(s),
            _ => None,
        }
    }
}

/// Bytes for a str passed where bytes are expected (Python would encode
/// ASCII; anything else is passed through as UTF-8).
fn latin1_or_utf8(s: &str) -> Vec<u8> {
    if s.chars().all(|c| (c as u32) < 256) {
        s.chars().map(|c| c as u32 as u8).collect()
    } else {
        s.as_bytes().to_vec()
    }
}

/// Decode bytes with a Python codec name.
fn decode_bytes(b: &[u8], enc: &str) -> Option<String> {
    match norm(enc).as_str() {
        "utf_8" | "utf8" | "u8" | "" => Some(String::from_utf8_lossy(b).into_owned()),
        "latin_1" | "latin1" | "iso_8859_1" | "l1" | "cp1252" => {
            Some(b.iter().map(|&c| c as char).collect())
        }
        "ascii" | "us_ascii" => Some(
            b.iter()
                .map(|&c| if c < 128 { c as char } else { '\u{fffd}' })
                .collect(),
        ),
        "utf_16" | "utf16" | "utf_16_le" | "utf_16le" => {
            let start = if b.starts_with(&[0xff, 0xfe]) { 2 } else { 0 };
            let units: Vec<u16> = b[start..]
                .as_chunks::<2>()
                .0
                .iter()
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            Some(String::from_utf16_lossy(&units))
        }
        "utf_16_be" | "utf_16be" => {
            let units: Vec<u16> = b
                .as_chunks::<2>()
                .0
                .iter()
                .map(|c| u16::from_be_bytes([c[0], c[1]]))
                .collect();
            Some(String::from_utf16_lossy(&units))
        }
        _ => None,
    }
}

fn norm(enc: &str) -> String {
    enc.trim().to_ascii_lowercase().replace('-', "_")
}

/// Top-level modules recognized even without a visible import statement.
const MODULES: &[&str] = &[
    "base64",
    "binascii",
    "codecs",
    "zlib",
    "gzip",
    "lzma",
    "bz2",
    "marshal",
    "importlib",
    "builtins",
    "os",
    "sys",
    "subprocess",
    "socket",
    "urllib",
    "requests",
    "ctypes",
    "pty",
];

const BUILTINS: &[&str] = &[
    "chr",
    "ord",
    "bytes",
    "bytearray",
    "str",
    "list",
    "tuple",
    "map",
    "reversed",
    "int",
    "len",
    "exec",
    "eval",
    "compile",
    "__import__",
    "getattr",
    "sorted",
];

/// Calls that run code: their first argument is the payload.
pub const SINKS: &[&str] = &[
    "exec",
    "eval",
    "compile",
    "builtins.exec",
    "builtins.eval",
    "builtins.compile",
];

/// A variable binding with the decode steps that produced it.
#[derive(Debug, Clone)]
pub struct Binding {
    pub value: V,
    pub steps: Vec<String>,
}

/// Names visible to the evaluator: assignments and import aliases.
#[derive(Debug, Default, Clone)]
pub struct Env {
    pub vars: HashMap<String, Binding>,
    /// Local name to dotted module or function path.
    pub aliases: HashMap<String, String>,
}

/// Outcome of evaluating one expression.
#[derive(Debug, Clone)]
pub struct Outcome {
    pub value: V,
    /// Decode steps applied, innermost first, such as `["base64", "zlib"]`.
    pub steps: Vec<String>,
    /// Set when the outermost call was a code sink such as `exec`; holds the
    /// sink name. `value` is then the sink's payload argument.
    pub sink: Option<String>,
    /// Index just past the expression.
    pub end: usize,
    /// Notes such as unsupported codecs.
    pub notes: Vec<String>,
}

pub struct Eval<'a> {
    toks: &'a [Token],
    env: &'a Env,
    locals: Vec<(String, V)>,
    steps: Vec<String>,
    notes: Vec<String>,
    budget: usize,
    depth: usize,
    /// Payload of the most recent sink call, and its name.
    sink: Option<(String, V)>,
}

impl<'a> Eval<'a> {
    pub fn new(toks: &'a [Token], env: &'a Env) -> Self {
        Self {
            toks,
            env,
            locals: Vec::new(),
            steps: Vec::new(),
            notes: Vec::new(),
            budget: BUDGET,
            depth: 0,
            sink: None,
        }
    }

    fn tok(&self, i: usize) -> Option<&Tok> {
        self.toks.get(i).map(|t| &t.tok)
    }

    fn is_op(&self, i: usize, op: &str) -> bool {
        matches!(self.tok(i), Some(Tok::Op(o)) if *o == op)
    }

    fn is_name(&self, i: usize, n: &str) -> bool {
        matches!(self.tok(i), Some(Tok::Name(x)) if x == n)
    }

    fn spend(&mut self) -> bool {
        if self.budget == 0 {
            return false;
        }
        self.budget -= 1;
        true
    }

    /// Evaluate a full expression at `i`, reporting steps and sink use.
    pub fn run(mut self, i: usize) -> Outcome {
        let (value, end) = self.expr(i);
        let (sink, value) = match self.sink.take() {
            Some((name, payload)) => (Some(name), payload),
            None => (None, value),
        };
        Outcome {
            value,
            steps: self.steps,
            sink,
            end,
            notes: self.notes,
        }
    }

    /// Evaluate only a postfix chain at `i` (a name with calls, attributes and
    /// subscripts), for scanning candidates inside larger statements.
    pub fn run_postfix(mut self, i: usize) -> Outcome {
        let (value, end) = self.postfix(i);
        let (sink, value) = match self.sink.take() {
            Some((name, payload)) => (Some(name), payload),
            None => (None, value),
        };
        Outcome {
            value,
            steps: self.steps,
            sink,
            end,
            notes: self.notes,
        }
    }

    fn expr(&mut self, i: usize) -> (V, usize) {
        self.binary(i, 0)
    }

    /// Precedence climbing over the binary operators the subset uses.
    fn binary(&mut self, i: usize, min_level: u8) -> (V, usize) {
        let (mut left, mut j) = self.unary(i);
        while let Some(Tok::Op(op)) = self.tok(j).cloned() {
            let level = match op {
                "|" => 1,
                "^" => 2,
                "&" => 3,
                "<<" | ">>" => 4,
                "+" | "-" => 5,
                "*" | "%" | "//" => 6,
                _ => break,
            };
            if level < min_level {
                break;
            }
            let (right, k) = self.binary(j + 1, level + 1);
            left = self.apply_op(op, left, right);
            j = k;
        }
        (left, j)
    }

    fn apply_op(&mut self, op: &str, a: V, b: V) -> V {
        use V::*;
        let capped = |v: V| {
            if v.size() > codecs::MAX_OUTPUT {
                Unknown
            } else {
                v
            }
        };
        match (op, a, b) {
            ("+", Str(x), Str(y)) => capped(Str(x + &y)),
            ("+", Bytes(mut x), Bytes(y)) => {
                x.extend(y);
                capped(Bytes(x))
            }
            ("+", List(mut x), List(y)) => {
                x.extend(y);
                capped(List(x))
            }
            ("*", Str(s), Int(n)) | ("*", Int(n), Str(s)) => {
                let n = n.max(0) as usize;
                if s.len().saturating_mul(n) > codecs::MAX_OUTPUT {
                    Unknown
                } else {
                    Str(s.repeat(n))
                }
            }
            (op, Int(x), Int(y)) => match op {
                "+" => Int(x.wrapping_add(y)),
                "-" => Int(x.wrapping_sub(y)),
                "*" => Int(x.wrapping_mul(y)),
                "%" if y != 0 => Int(x.rem_euclid(y)),
                "//" if y != 0 => Int(x.div_euclid(y)),
                "^" => Int(x ^ y),
                "&" => Int(x & y),
                "|" => Int(x | y),
                "<<" if (0..63).contains(&y) => Int(x.wrapping_shl(y as u32)),
                ">>" if (0..63).contains(&y) => Int(x >> y),
                _ => Unknown,
            },
            _ => Unknown,
        }
    }

    fn unary(&mut self, i: usize) -> (V, usize) {
        if self.is_op(i, "-") {
            let (v, j) = self.unary(i + 1);
            return (
                if let V::Int(n) = v {
                    V::Int(n.wrapping_neg())
                } else {
                    V::Unknown
                },
                j,
            );
        }
        if self.is_op(i, "+") {
            return self.unary(i + 1);
        }
        if self.is_op(i, "~") {
            let (v, j) = self.unary(i + 1);
            return (
                if let V::Int(n) = v {
                    V::Int(!n)
                } else {
                    V::Unknown
                },
                j,
            );
        }
        self.postfix(i)
    }

    fn postfix(&mut self, i: usize) -> (V, usize) {
        if self.depth >= MAX_DEPTH || !self.spend() {
            return (V::Unknown, self.skip_expr(i));
        }
        self.depth += 1;
        let (mut v, mut j) = self.atom(i);
        loop {
            if !self.spend() {
                break;
            }
            if self.is_op(j, "(") {
                let (args, kwargs, k) = self.args(j + 1, ")");
                v = self.call(v, args, kwargs);
                j = k;
            } else if self.is_op(j, ".") {
                if let Some(Tok::Name(attr)) = self.tok(j + 1).cloned() {
                    v = attribute(v, &attr);
                    j += 2;
                } else {
                    break;
                }
            } else if self.is_op(j, "[") {
                let (sub, k) = self.subscript(v, j + 1);
                v = sub;
                j = k;
            } else {
                break;
            }
        }
        self.depth -= 1;
        (v, j)
    }

    fn atom(&mut self, i: usize) -> (V, usize) {
        match self.tok(i).cloned() {
            Some(Tok::Lit(first)) => {
                // Adjacent literals concatenate: 'ab' 'cd'.
                let mut v = lit_value(first);
                let mut j = i + 1;
                while let Some(Tok::Lit(next)) = self.tok(j).cloned() {
                    v = self.apply_op("+", v, lit_value(next));
                    j += 1;
                }
                (v, j)
            }
            Some(Tok::Int(n)) => (V::Int(n), i + 1),
            Some(Tok::Name(n)) => (self.lookup(&n), i + 1),
            Some(Tok::Op("(")) => {
                if self.is_op(i + 1, ")") {
                    return (V::List(Vec::new()), i + 2);
                }
                let (items, _, j) = self.args(i + 1, ")");
                // A parenthesized expression, or a tuple treated as a list.
                if items.len() == 1 {
                    (items.into_iter().next().unwrap_or(V::Unknown), j)
                } else {
                    (V::List(items), j)
                }
            }
            Some(Tok::Op("[")) => {
                // A list comprehension is the list itself, not one item.
                let (_, after) = self.expr(i + 1);
                if self.is_name(after, "for") {
                    let (v, j) = self.comprehension(i + 1, after);
                    let j = self.skip_to_sep(j, "]");
                    return (v, if self.is_op(j, "]") { j + 1 } else { j });
                }
                let (items, _, j) = self.args(i + 1, "]");
                (V::List(items), j)
            }
            _ => (V::Unknown, self.skip_expr(i)),
        }
    }

    fn lookup(&mut self, name: &str) -> V {
        if let Some((_, v)) = self.locals.iter().rev().find(|(n, _)| n == name) {
            return v.clone();
        }
        if let Some(b) = self.env.vars.get(name) {
            self.steps.extend(b.steps.iter().cloned());
            return b.value.clone();
        }
        if let Some(path) = self.env.aliases.get(name) {
            let top = path.split('.').next().unwrap_or(path);
            return if path.contains('.')
                && !MODULES.contains(&path.as_str())
                && MODULES.contains(&top)
            {
                V::Func(path.clone())
            } else {
                V::Module(path.clone())
            };
        }
        if BUILTINS.contains(&name) {
            return V::Func(name.to_string());
        }
        if MODULES.contains(&name) {
            return V::Module(name.to_string());
        }
        V::Unknown
    }

    /// Parse call arguments or list items up to `close`. Handles keyword
    /// arguments, generator expressions and comprehensions, and skips
    /// anything unrecognized to the next comma.
    fn args(&mut self, mut i: usize, close: &str) -> (Vec<V>, Vec<(String, V)>, usize) {
        let mut args = Vec::new();
        let mut kwargs = Vec::new();
        loop {
            if self.is_op(i, close) {
                return (args, kwargs, i + 1);
            }
            if self.tok(i).is_none() || matches!(self.tok(i), Some(Tok::Newline)) {
                return (args, kwargs, i);
            }
            // Keyword argument.
            let mut key = None;
            if let (Some(Tok::Name(k)), true) = (self.tok(i).cloned(), self.is_op(i + 1, "=")) {
                key = Some(k);
                i += 2;
            }
            // Star-args are not followed.
            if self.is_op(i, "*") || self.is_op(i, "**") {
                i += 1;
            }
            let start = i;
            let (mut v, mut j) = self.expr(i);
            if self.is_name(j, "for") {
                let (cv, k) = self.comprehension(start, j);
                v = cv;
                j = k;
            }
            // Skip whatever the subset did not consume.
            if !self.is_op(j, ",") && !self.is_op(j, close) {
                v = V::Unknown;
                j = self.skip_to_sep(j, close);
            }
            match key {
                Some(k) => kwargs.push((k, v)),
                None => args.push(v),
            }
            if self.is_op(j, ",") {
                j += 1;
            }
            i = j;
        }
    }

    /// `ELEM for NAME in ITER [if ...]` where ELEM starts at `elem` and
    /// `for` is at `for_at`. Returns the produced list.
    fn comprehension(&mut self, elem: usize, for_at: usize) -> (V, usize) {
        let Some(Tok::Name(var)) = self.tok(for_at + 1).cloned() else {
            return (V::Unknown, for_at);
        };
        if !self.is_name(for_at + 2, "in") {
            return (V::Unknown, for_at);
        }
        let (iter, end) = self.expr(for_at + 3);
        // A trailing filter is not evaluated.
        let end = if self.is_name(end, "if") {
            self.skip_to_sep(end, ")")
        } else {
            end
        };
        let items: Vec<V> = match iter {
            V::List(l) => l,
            V::Str(s) => s.chars().map(|c| V::Str(c.to_string())).collect(),
            V::Bytes(b) => b.into_iter().map(|x| V::Int(x as i64)).collect(),
            _ => return (V::Unknown, end),
        };
        if items.len() > MAX_ITEMS {
            return (V::Unknown, end);
        }
        let mut out = Vec::with_capacity(items.len());
        for item in items {
            if self.budget == 0 {
                return (V::Unknown, end);
            }
            self.locals.push((var.clone(), item));
            let (v, _) = self.expr(elem);
            self.locals.pop();
            out.push(v);
        }
        (V::List(out), end)
    }

    fn subscript(&mut self, v: V, i: usize) -> (V, usize) {
        // Collect up to three slice parts separated by ':'.
        let mut parts: Vec<Option<i64>> = Vec::new();
        let mut j = i;
        let mut is_slice = false;
        loop {
            if self.is_op(j, ":") {
                parts.push(None);
                is_slice = true;
                j += 1;
                continue;
            }
            if self.is_op(j, "]") {
                if is_slice && parts.len() < 3 {
                    parts.push(None);
                }
                j += 1;
                break;
            }
            let (x, k) = self.expr(j);
            let n = if let V::Int(n) = x { Some(n) } else { None };
            if n.is_none() {
                return (V::Unknown, self.skip_to_sep(k, "]") + 1);
            }
            parts.push(n);
            j = k;
            if self.is_op(j, ":") {
                is_slice = true;
                j += 1;
            } else if !self.is_op(j, "]") {
                return (V::Unknown, self.skip_to_sep(j, "]") + 1);
            }
        }
        if !is_slice {
            return (index(v, parts.first().copied().flatten()), j);
        }
        let get = |k: usize| parts.get(k).copied().flatten();
        if get(2).is_some_and(|s| s < 0) && matches!(v, V::Str(_) | V::Bytes(_)) {
            self.transform("reverse");
        }
        (slice(v, get(0), get(1), get(2)), j)
    }

    fn call(&mut self, f: V, args: Vec<V>, kwargs: Vec<(String, V)>) -> V {
        let arg = |k: usize| args.get(k).cloned().unwrap_or(V::Unknown);
        let kw = |name: &str| {
            kwargs
                .iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.clone())
        };
        match f {
            V::Func(name) => {
                let name = name.strip_prefix("builtins.").unwrap_or(&name).to_string();
                self.call_func(&name, &args, arg, kw)
            }
            V::Method(recv, m) => self.call_method(*recv, &m, &args),
            _ => V::Unknown,
        }
    }

    fn step(&mut self, s: &str, out: Option<Vec<u8>>) -> V {
        match out {
            Some(b) => {
                self.steps.push(s.to_string());
                V::Bytes(b)
            }
            None => V::Unknown,
        }
    }

    /// Record a string transform step, skipping an immediate repeat.
    fn transform(&mut self, s: &str) {
        if self.steps.last().map(String::as_str) != Some(s) {
            self.steps.push(s.to_string());
        }
    }

    fn call_func(
        &mut self,
        name: &str,
        args: &[V],
        arg: impl Fn(usize) -> V,
        kw: impl Fn(&str) -> Option<V>,
    ) -> V {
        let bytes0 = || arg(0).as_bytes();
        match name {
            "exec" | "eval" | "compile" => {
                // Record the payload; the caller reports it as a sink. For
                // exec(compile(src, ...)) keep compile's payload.
                let payload = arg(0);
                match (&payload, self.sink.take()) {
                    (V::Unknown, Some((_, inner))) => self.sink = Some((name.to_string(), inner)),
                    _ => self.sink = Some((name.to_string(), payload)),
                }
                V::Unknown
            }
            "base64.b64decode"
            | "base64.standard_b64decode"
            | "base64.decodebytes"
            | "base64.decodestring"
            | "binascii.a2b_base64" => {
                let out = bytes0().and_then(|b| codecs::b64(&b, false));
                self.step("base64", out)
            }
            "base64.urlsafe_b64decode" => {
                let out = bytes0().and_then(|b| codecs::b64(&b, true));
                self.step("base64url", out)
            }
            "base64.b32decode" => {
                let out = bytes0().and_then(|b| codecs::b32(&b));
                self.step("base32", out)
            }
            "base64.b16decode" | "binascii.unhexlify" | "binascii.a2b_hex" | "bytes.fromhex"
            | "bytearray.fromhex" => {
                let out = bytes0().and_then(|b| codecs::hex(&b));
                self.step("hex", out)
            }
            "base64.b85decode" => {
                let out = bytes0().and_then(|b| codecs::b85(&b));
                self.step("base85", out)
            }
            "zlib.decompress" => {
                let out = bytes0().and_then(|b| codecs::inflate(&b));
                self.step("zlib", out)
            }
            "gzip.decompress" => {
                let out = bytes0().and_then(|b| codecs::gunzip(&b));
                self.step("gzip", out)
            }
            "lzma.decompress" => {
                let out = bytes0().and_then(|b| codecs::unlzma(&b));
                self.step("lzma", out)
            }
            "bz2.decompress" => {
                self.notes
                    .push("bz2 decompression is not supported yet".to_string());
                V::Unknown
            }
            "marshal.loads" => match bytes0() {
                Some(b) => {
                    self.steps.push("marshal".to_string());
                    V::Marshal(b)
                }
                None => V::Unknown,
            },
            "codecs.decode" | "codecs.encode" => {
                let enc = arg(1)
                    .as_str()
                    .map(norm)
                    .or_else(|| kw("encoding").and_then(|v| v.as_str().map(norm)));
                self.codec(
                    arg(0),
                    enc.as_deref().unwrap_or("utf_8"),
                    name == "codecs.encode",
                )
            }
            "chr" => match arg(0) {
                V::Int(n) => char::from_u32(n as u32)
                    .map(|c| V::Str(c.to_string()))
                    .unwrap_or(V::Unknown),
                _ => V::Unknown,
            },
            "ord" => match arg(0) {
                V::Str(s) if s.chars().count() == 1 => {
                    V::Int(s.chars().next().map(|c| c as i64).unwrap_or(0))
                }
                V::Bytes(b) if b.len() == 1 => V::Int(b[0] as i64),
                _ => V::Unknown,
            },
            "bytes" | "bytearray" => match arg(0) {
                V::List(l) => l
                    .iter()
                    .map(|x| match x {
                        V::Int(n) if (0..256).contains(n) => Some(*n as u8),
                        _ => None,
                    })
                    .collect::<Option<Vec<u8>>>()
                    .map(V::Bytes)
                    .unwrap_or(V::Unknown),
                V::Str(s) => V::Bytes(s.into_bytes()),
                V::Bytes(b) => V::Bytes(b),
                _ => V::Unknown,
            },
            "str" => match (arg(0), arg(1)) {
                (V::Bytes(b), V::Str(enc)) => {
                    decode_bytes(&b, &enc).map(V::Str).unwrap_or(V::Unknown)
                }
                (V::Str(s), _) => V::Str(s),
                (V::Int(n), _) => V::Str(n.to_string()),
                _ => V::Unknown,
            },
            "list" | "tuple" | "sorted" => {
                let v = match arg(0) {
                    V::List(l) => V::List(l),
                    V::Str(s) => V::List(s.chars().map(|c| V::Str(c.to_string())).collect()),
                    V::Bytes(b) => V::List(b.into_iter().map(|x| V::Int(x as i64)).collect()),
                    _ => V::Unknown,
                };
                if name == "sorted" { V::Unknown } else { v }
            }
            "reversed" => match arg(0) {
                V::Str(s) => V::List(s.chars().rev().map(|c| V::Str(c.to_string())).collect()),
                V::List(mut l) => {
                    l.reverse();
                    V::List(l)
                }
                V::Bytes(b) => V::List(b.into_iter().rev().map(|x| V::Int(x as i64)).collect()),
                _ => V::Unknown,
            },
            "map" => {
                let f = arg(0);
                let items = match arg(1) {
                    V::List(l) => l,
                    V::Str(s) => s.chars().map(|c| V::Str(c.to_string())).collect(),
                    V::Bytes(b) => b.into_iter().map(|x| V::Int(x as i64)).collect(),
                    _ => return V::Unknown,
                };
                let mut out = Vec::with_capacity(items.len());
                for it in items {
                    if !self.spend() {
                        return V::Unknown;
                    }
                    out.push(self.call(f.clone(), vec![it], Vec::new()));
                }
                V::List(out)
            }
            "int" => match (arg(0), args.get(1)) {
                (V::Str(s), Some(V::Int(base))) if (2..=36).contains(base) => {
                    i64::from_str_radix(s.trim(), *base as u32)
                        .map(V::Int)
                        .unwrap_or(V::Unknown)
                }
                (V::Str(s), None) => s.trim().parse().map(V::Int).unwrap_or(V::Unknown),
                (V::Int(n), _) => V::Int(n),
                _ => V::Unknown,
            },
            "len" => match arg(0) {
                V::Str(s) => V::Int(s.chars().count() as i64),
                V::Bytes(b) => V::Int(b.len() as i64),
                V::List(l) => V::Int(l.len() as i64),
                _ => V::Unknown,
            },
            "__import__" | "importlib.import_module" => match arg(0) {
                V::Str(m) => V::Module(m),
                _ => V::Unknown,
            },
            "getattr" => match arg(1) {
                V::Str(a) => attribute(arg(0), &a),
                _ => V::Unknown,
            },
            _ => V::Unknown,
        }
    }

    fn codec(&mut self, v: V, enc: &str, encode: bool) -> V {
        match enc {
            "rot13" | "rot_13" => {
                let s = match v {
                    V::Str(s) => s,
                    V::Bytes(b) => String::from_utf8_lossy(&b).into_owned(),
                    _ => return V::Unknown,
                };
                self.steps.push("rot13".to_string());
                V::Str(codecs::rot13(&s))
            }
            "hex" | "hex_codec" if !encode => {
                let out = v.as_bytes().and_then(|b| codecs::hex(&b));
                self.step("hex", out)
            }
            "base64" | "base64_codec" if !encode => {
                let out = v.as_bytes().and_then(|b| codecs::b64(&b, false));
                self.step("base64", out)
            }
            "zlib" | "zlib_codec" if !encode => {
                let out = v.as_bytes().and_then(|b| codecs::inflate(&b));
                self.step("zlib", out)
            }
            other => match (v, encode) {
                (V::Bytes(b), false) => decode_bytes(&b, other).map(V::Str).unwrap_or(V::Unknown),
                (V::Str(s), true) => V::Bytes(s.into_bytes()),
                (V::Str(s), false) => V::Str(s),
                _ => V::Unknown,
            },
        }
    }

    fn call_method(&mut self, recv: V, m: &str, args: &[V]) -> V {
        let arg = |k: usize| args.get(k).cloned().unwrap_or(V::Unknown);
        match (recv, m) {
            (V::Str(sep), "join") => match arg(0) {
                V::List(items) => {
                    let mut out = String::new();
                    for (k, it) in items.iter().enumerate() {
                        let V::Str(s) = it else { return V::Unknown };
                        if k > 0 {
                            out.push_str(&sep);
                        }
                        out.push_str(s);
                        if out.len() > codecs::MAX_OUTPUT {
                            return V::Unknown;
                        }
                    }
                    if items.len() > 1 {
                        self.transform("join");
                    }
                    V::Str(out)
                }
                V::Str(s) => V::Str(
                    s.chars()
                        .map(|c| c.to_string())
                        .collect::<Vec<_>>()
                        .join(&sep),
                ),
                _ => V::Unknown,
            },
            (V::Bytes(sep), "join") => match arg(0) {
                V::List(items) => {
                    let mut out = Vec::new();
                    for (k, it) in items.iter().enumerate() {
                        let V::Bytes(b) = it else { return V::Unknown };
                        if k > 0 {
                            out.extend_from_slice(&sep);
                        }
                        out.extend_from_slice(b);
                    }
                    V::Bytes(out)
                }
                _ => V::Unknown,
            },
            (V::Str(s), "replace") => match (arg(0), arg(1)) {
                (V::Str(a), V::Str(b)) if !a.is_empty() => {
                    self.transform("replace");
                    V::Str(s.replace(&a, &b))
                }
                _ => V::Unknown,
            },
            (V::Bytes(s), "replace") => match (arg(0), arg(1)) {
                (V::Bytes(a), V::Bytes(b)) if !a.is_empty() => V::Bytes(replace_bytes(&s, &a, &b)),
                _ => V::Unknown,
            },
            (V::Str(s), "encode") => {
                let enc = arg(0)
                    .as_str()
                    .map(norm)
                    .unwrap_or_else(|| "utf_8".to_string());
                match enc.as_str() {
                    "latin_1" | "latin1" | "iso_8859_1" => V::Bytes(latin1_or_utf8(&s)),
                    _ => V::Bytes(s.into_bytes()),
                }
            }
            (V::Bytes(b), "decode") => {
                let enc = arg(0).as_str().map(str::to_string).unwrap_or_default();
                decode_bytes(&b, &enc).map(V::Str).unwrap_or(V::Unknown)
            }
            (V::Bytes(b), "hex") => V::Str(b.iter().map(|x| format!("{x:02x}")).collect()),
            (V::Str(s), "strip") => V::Str(s.trim().to_string()),
            (V::Str(s), "lstrip") => V::Str(s.trim_start().to_string()),
            (V::Str(s), "rstrip") => V::Str(s.trim_end().to_string()),
            (V::Str(s), "lower") => V::Str(s.to_lowercase()),
            (V::Str(s), "upper") => V::Str(s.to_uppercase()),
            (V::Bytes(b), "strip") => V::Bytes(b.trim_ascii().to_vec()),
            _ => V::Unknown,
        }
    }

    /// Skip a balanced expression we cannot evaluate, stopping at a comma,
    /// closing bracket or newline at depth zero.
    fn skip_expr(&self, i: usize) -> usize {
        let mut j = i;
        let mut depth = 0i32;
        while let Some(t) = self.tok(j) {
            match t {
                Tok::Op("(" | "[" | "{") => depth += 1,
                Tok::Op(")" | "]" | "}") => {
                    if depth == 0 {
                        break;
                    }
                    depth -= 1;
                }
                Tok::Op(",") if depth == 0 => break,
                Tok::Newline => break,
                _ => {}
            }
            j += 1;
            if depth == 0 && j > i {
                // Stop after one balanced unit at top level.
                if !matches!(self.tok(j), Some(Tok::Op("(" | "[" | "."))) {
                    break;
                }
            }
        }
        j.max(i + 1).min(self.toks.len())
    }

    /// Advance to the next `,` or `close` at bracket depth zero.
    fn skip_to_sep(&self, i: usize, close: &str) -> usize {
        let mut j = i;
        let mut depth = 0i32;
        while let Some(t) = self.tok(j) {
            match t {
                Tok::Op("(" | "[" | "{") => depth += 1,
                Tok::Op(o @ (")" | "]" | "}")) => {
                    if depth == 0 {
                        if *o == close {
                            break;
                        }
                        return j;
                    }
                    depth -= 1;
                }
                Tok::Op(",") if depth == 0 => break,
                Tok::Newline => break,
                _ => {}
            }
            j += 1;
        }
        j
    }
}

fn lit_value(l: Lit) -> V {
    match l {
        Lit::Str(s) => V::Str(s),
        Lit::Bytes(b) => V::Bytes(b),
    }
}

fn attribute(v: V, attr: &str) -> V {
    match v {
        V::Module(m) => V::Func(format!("{m}.{attr}")),
        V::Func(f) => V::Func(format!("{f}.{attr}")),
        V::Str(_) | V::Bytes(_) | V::List(_) => V::Method(Box::new(v), attr.to_string()),
        _ => V::Unknown,
    }
}

fn norm_index(i: i64, len: usize) -> usize {
    if i < 0 {
        (len as i64 + i).max(0) as usize
    } else {
        (i as usize).min(len)
    }
}

fn index(v: V, i: Option<i64>) -> V {
    let Some(i) = i else { return V::Unknown };
    match v {
        V::Str(s) => {
            let chars: Vec<char> = s.chars().collect();
            let k = if i < 0 { chars.len() as i64 + i } else { i };
            chars
                .get(k as usize)
                .map(|c| V::Str(c.to_string()))
                .unwrap_or(V::Unknown)
        }
        V::Bytes(b) => {
            let k = if i < 0 { b.len() as i64 + i } else { i };
            b.get(k as usize)
                .map(|x| V::Int(*x as i64))
                .unwrap_or(V::Unknown)
        }
        V::List(l) => {
            let k = if i < 0 { l.len() as i64 + i } else { i };
            l.get(k as usize).cloned().unwrap_or(V::Unknown)
        }
        _ => V::Unknown,
    }
}

/// Python slice semantics for str, bytes and lists.
fn slice(v: V, start: Option<i64>, stop: Option<i64>, step: Option<i64>) -> V {
    let step = step.unwrap_or(1);
    if step == 0 {
        return V::Unknown;
    }
    fn pick<T: Clone>(items: &[T], start: Option<i64>, stop: Option<i64>, step: i64) -> Vec<T> {
        let len = items.len();
        let mut out = Vec::new();
        if step > 0 {
            let a = start.map(|s| norm_index(s, len)).unwrap_or(0);
            let b = stop.map(|s| norm_index(s, len)).unwrap_or(len);
            let mut k = a;
            while k < b {
                out.push(items[k].clone());
                k += step as usize;
            }
        } else {
            let last = len as i64 - 1;
            let a = start
                .map(|s| if s < 0 { len as i64 + s } else { s.min(last) })
                .unwrap_or(last);
            let b = stop
                .map(|s| if s < 0 { len as i64 + s } else { s })
                .unwrap_or(-1);
            let mut k = a;
            while k > b && k >= 0 {
                out.push(items[k as usize].clone());
                k += step;
            }
        }
        out
    }
    match v {
        V::Str(s) => {
            let chars: Vec<char> = s.chars().collect();
            V::Str(pick(&chars, start, stop, step).into_iter().collect())
        }
        V::Bytes(b) => V::Bytes(pick(&b, start, stop, step)),
        V::List(l) => V::List(pick(&l, start, stop, step)),
        _ => V::Unknown,
    }
}

fn replace_bytes(s: &[u8], a: &[u8], b: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        if s[i..].starts_with(a) {
            out.extend_from_slice(b);
            i += a.len();
        } else {
            out.push(s[i]);
            i += 1;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::super::lexer::tokenize;
    use super::*;

    fn ev(src: &str) -> Outcome {
        let toks = tokenize(src);
        let env = Env::default();
        Eval::new(&toks, &env).run(0)
    }

    fn val(src: &str) -> V {
        ev(src).value
    }

    #[test]
    fn literals_and_concat() {
        assert_eq!(val("'ab' + 'cd'"), V::Str("abcd".into()));
        assert_eq!(val("'ab' 'cd'"), V::Str("abcd".into()));
        assert_eq!(val("b'a' + b'b'"), V::Bytes(b"ab".to_vec()));
        assert_eq!(val("3 + 4 * 2"), V::Int(11));
        assert_eq!(val("(3 + 4) * 2"), V::Int(14));
        assert_eq!(val("0x41 ^ 0x20"), V::Int(0x61));
    }

    #[test]
    fn slices() {
        assert_eq!(val("'olleh'[::-1]"), V::Str("hello".into()));
        assert_eq!(val("'abcdef'[1:4]"), V::Str("bcd".into()));
        assert_eq!(val("'abcdef'[::2]"), V::Str("ace".into()));
        assert_eq!(val("'abcdef'[-2:]"), V::Str("ef".into()));
        assert_eq!(val("'abc'[1]"), V::Str("b".into()));
    }

    #[test]
    fn chr_joins() {
        assert_eq!(
            val("''.join(chr(x) for x in [104, 105])"),
            V::Str("hi".into())
        );
        assert_eq!(
            val("''.join([chr(c) for c in [72, 73]])"),
            V::Str("HI".into())
        );
        assert_eq!(val("''.join(map(chr, [111, 107]))"), V::Str("ok".into()));
        assert_eq!(val("chr(104) + chr(105)"), V::Str("hi".into()));
        assert_eq!(
            val("''.join(chr(c ^ 1) for c in [105, 104])"),
            V::Str("hi".into())
        );
        assert_eq!(val("bytes([104, 105]).decode()"), V::Str("hi".into()));
    }

    #[test]
    fn decode_calls_record_steps() {
        let o = ev("base64.b64decode('cHJpbnQoMSk=').decode()");
        assert_eq!(o.value, V::Str("print(1)".into()));
        assert_eq!(o.steps, ["base64"]);
        assert_eq!(val("bytes.fromhex('6869')"), V::Bytes(b"hi".to_vec()));
        assert_eq!(
            val("codecs.decode('uryyb', 'rot13')"),
            V::Str("hello".into())
        );
        assert_eq!(
            val("codecs.decode(b'6869', 'hex')"),
            V::Bytes(b"hi".to_vec())
        );
        assert_eq!(
            val("__import__('base64').b64decode('aGk=')"),
            V::Bytes(b"hi".to_vec())
        );
        assert_eq!(
            val("getattr(__import__('base64'), 'b64decode')('aGk=')"),
            V::Bytes(b"hi".to_vec())
        );
        assert_eq!(
            val("base64.b64decode('aGk=', validate=False)"),
            V::Bytes(b"hi".to_vec())
        );
    }

    #[test]
    fn exec_compile_keeps_payload() {
        let o = ev("exec(compile(base64.b64decode('cHJpbnQoMSk='), '<s>', 'exec'))");
        assert_eq!(o.sink.as_deref(), Some("exec"));
        assert_eq!(o.value, V::Bytes(b"print(1)".to_vec()));
    }

    #[test]
    fn exec_is_a_sink() {
        let o = ev("exec(base64.b64decode('cHJpbnQoMSk='))");
        assert_eq!(o.sink.as_deref(), Some("exec"));
        assert_eq!(o.value, V::Bytes(b"print(1)".to_vec()));
    }

    #[test]
    fn variables_and_aliases() {
        let toks = tokenize("b.b64decode(p)");
        let mut env = Env::default();
        env.aliases.insert("b".into(), "base64".into());
        env.vars.insert(
            "p".into(),
            Binding {
                value: V::Str("aGk=".into()),
                steps: vec!["rot13".into()],
            },
        );
        let o = Eval::new(&toks, &env).run(0);
        assert_eq!(o.value, V::Bytes(b"hi".to_vec()));
        assert_eq!(o.steps, ["rot13", "base64"]);
    }

    #[test]
    fn from_import_alias_is_a_function() {
        let toks = tokenize("d('aGk=')");
        let mut env = Env::default();
        env.aliases.insert("d".into(), "base64.b64decode".into());
        assert_eq!(
            Eval::new(&toks, &env).run(0).value,
            V::Bytes(b"hi".to_vec())
        );
    }

    #[test]
    fn unknown_things_stay_unknown_and_end_is_right() {
        let o = ev("foo(bar, baz=1).qux + 1, next");
        assert_eq!(o.value, V::Unknown);
        let toks = tokenize("foo(bar, baz=1).qux + 1, next");
        assert!(matches!(toks[o.end].tok, Tok::Op(",")));
    }

    #[test]
    fn big_repeat_is_refused() {
        assert_eq!(val("'a' * 100000000"), V::Unknown);
    }

    #[test]
    fn deep_nesting_is_bounded() {
        let src = format!("{}1{}", "(".repeat(5000), ")".repeat(5000));
        let _ = ev(&src);
    }

    #[test]
    fn huge_comprehension_is_bounded() {
        let _ = ev("''.join(chr(x) for x in list('a' * 5000000))");
    }
}
