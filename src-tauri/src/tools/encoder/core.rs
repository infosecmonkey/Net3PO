//! Encoder/decoder workbench: an explicit chain of transformations over
//! bytes. Decoders reuse the Script Decoder's capped codecs, so no single
//! step can produce more than 10 MB. Results are shown, never executed.

use std::io::Write;

use base64::Engine as _;
use serde::{Deserialize, Serialize};

use crate::tools::script_decoder::codecs::{self, MAX_OUTPUT};

/// Largest input accepted.
pub const MAX_INPUT: usize = 5 * 1024 * 1024;
/// Most steps in one chain.
pub const MAX_STEPS: usize = 30;
/// Text and hex shown per step.
const SHOW_TEXT: usize = 256 * 1024;
const SHOW_HEX: usize = 4096;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum Op {
    Base64Encode,
    Base64Decode,
    Base64UrlEncode,
    Base64UrlDecode,
    Base32Encode,
    Base32Decode,
    HexEncode,
    HexDecode,
    Base85Decode,
    UrlEncode,
    UrlDecode,
    /// Form encoding: `+` means a space.
    UrlDecodeForm,
    HtmlEncode,
    HtmlDecode,
    Rot13,
    GzipCompress,
    GzipDecompress,
    /// zlib, gzip or raw deflate, chosen by the header.
    Inflate,
    LzmaDecompress,
}

impl Op {
    pub fn label(self) -> &'static str {
        match self {
            Op::Base64Encode => "Base64 encode",
            Op::Base64Decode => "Base64 decode",
            Op::Base64UrlEncode => "Base64url encode",
            Op::Base64UrlDecode => "Base64url decode",
            Op::Base32Encode => "Base32 encode",
            Op::Base32Decode => "Base32 decode",
            Op::HexEncode => "Hex encode",
            Op::HexDecode => "Hex decode",
            Op::Base85Decode => "Base85 decode",
            Op::UrlEncode => "URL encode",
            Op::UrlDecode => "URL decode",
            Op::UrlDecodeForm => "URL decode (+ as space)",
            Op::HtmlEncode => "HTML entity encode",
            Op::HtmlDecode => "HTML entity decode",
            Op::Rot13 => "ROT13",
            Op::GzipCompress => "Gzip compress",
            Op::GzipDecompress => "Gzip decompress",
            Op::Inflate => "Zlib/deflate decompress",
            Op::LzmaDecompress => "XZ/LZMA decompress",
        }
    }
}

fn url_encode(b: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(b.len() * 3);
    for &c in b {
        if c.is_ascii_alphanumeric() || b"-._~".contains(&c) {
            out.push(c);
        } else {
            out.extend_from_slice(format!("%{c:02X}").as_bytes());
        }
    }
    out
}

fn url_decode(b: &[u8], plus_space: bool) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' => {
                let hex = b
                    .get(i + 1..i + 3)
                    .and_then(|h| std::str::from_utf8(h).ok())
                    .and_then(|h| u8::from_str_radix(h, 16).ok());
                match hex {
                    Some(v) => {
                        out.push(v);
                        i += 3;
                    }
                    None => return Err(format!("bad percent escape at byte {i}")),
                }
            }
            b'+' if plus_space => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    Ok(out)
}

fn html_encode(b: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(b.len());
    for &c in b {
        match c {
            b'&' => out.extend_from_slice(b"&amp;"),
            b'<' => out.extend_from_slice(b"&lt;"),
            b'>' => out.extend_from_slice(b"&gt;"),
            b'"' => out.extend_from_slice(b"&quot;"),
            b'\'' => out.extend_from_slice(b"&#39;"),
            _ => out.push(c),
        }
    }
    out
}

const NAMED: &[(&str, char)] = &[
    ("amp", '&'),
    ("lt", '<'),
    ("gt", '>'),
    ("quot", '"'),
    ("apos", '\''),
    ("nbsp", '\u{a0}'),
    ("copy", '©'),
    ("reg", '®'),
    ("trade", '\u{2122}'),
    ("hellip", '\u{2026}'),
    ("ndash", '\u{2013}'),
    ("mdash", '\u{2014}'),
    ("lsquo", '\u{2018}'),
    ("rsquo", '\u{2019}'),
    ("ldquo", '\u{201c}'),
    ("rdquo", '\u{201d}'),
    ("euro", '€'),
    ("pound", '£'),
    ("yen", '¥'),
    ("cent", '¢'),
    ("sect", '§'),
    ("deg", '°'),
    ("plusmn", '±'),
    ("times", '×'),
    ("divide", '÷'),
    ("laquo", '«'),
    ("raquo", '»'),
    ("bull", '\u{2022}'),
];

/// Decode HTML character references; unknown names are left as written.
fn html_decode(b: &[u8]) -> Result<(Vec<u8>, usize), String> {
    let s = std::str::from_utf8(b).map_err(|_| "input is not UTF-8 text".to_string())?;
    let mut out = String::with_capacity(s.len());
    let mut unknown = 0;
    let mut rest = s;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        let tail = &rest[i..];
        let end = tail.find(';').filter(|&e| e <= 12);
        let decoded = end.and_then(|e| {
            let name = &tail[1..e];
            let c = if let Some(n) = name.strip_prefix("#x").or_else(|| name.strip_prefix("#X")) {
                u32::from_str_radix(n, 16).ok().and_then(char::from_u32)
            } else if let Some(n) = name.strip_prefix('#') {
                n.parse::<u32>().ok().and_then(char::from_u32)
            } else {
                NAMED.iter().find(|(k, _)| *k == name).map(|(_, c)| *c)
            };
            c.map(|c| (c, e))
        });
        match decoded {
            Some((c, e)) => {
                out.push(c);
                rest = &tail[e + 1..];
            }
            None => {
                if end.is_some() {
                    unknown += 1;
                }
                out.push('&');
                rest = &tail[1..];
            }
        }
    }
    out.push_str(rest);
    Ok((out.into_bytes(), unknown))
}

fn gzip(b: &[u8]) -> Result<Vec<u8>, String> {
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    e.write_all(b)
        .and_then(|_| e.finish())
        .map_err(|e| e.to_string())
}

/// Apply one step. Returns the output and an optional note.
pub fn apply(op: Op, b: &[u8]) -> Result<(Vec<u8>, Option<String>), String> {
    let none = |v: Vec<u8>| Ok((v, None));
    let need = |o: Option<Vec<u8>>, what: &str| {
        o.ok_or_else(|| format!("not valid {what}, or larger than 10 MB when decoded"))
    };
    match op {
        Op::Base64Encode => none(
            base64::engine::general_purpose::STANDARD
                .encode(b)
                .into_bytes(),
        ),
        Op::Base64UrlEncode => none(
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(b)
                .into_bytes(),
        ),
        Op::Base64Decode => none(need(codecs::b64(b, false), "Base64")?),
        Op::Base64UrlDecode => none(need(codecs::b64(b, true), "Base64url")?),
        Op::Base32Encode => none(data_encoding::BASE32.encode(b).into_bytes()),
        Op::Base32Decode => none(need(codecs::b32(b), "Base32")?),
        Op::HexEncode => none(data_encoding::HEXLOWER.encode(b).into_bytes()),
        Op::HexDecode => none(need(codecs::hex(b), "hex")?),
        Op::Base85Decode => none(need(codecs::b85(b), "Base85")?),
        Op::UrlEncode => none(url_encode(b)),
        Op::UrlDecode => none(url_decode(b, false)?),
        Op::UrlDecodeForm => none(url_decode(b, true)?),
        Op::HtmlEncode => none(html_encode(b)),
        Op::HtmlDecode => {
            let (v, unknown) = html_decode(b)?;
            Ok((
                v,
                (unknown > 0)
                    .then(|| format!("{unknown} unrecognized named reference(s) left as written")),
            ))
        }
        Op::Rot13 => none(
            b.iter()
                .map(|&c| match c {
                    b'a'..=b'z' => (c - b'a' + 13) % 26 + b'a',
                    b'A'..=b'Z' => (c - b'A' + 13) % 26 + b'A',
                    _ => c,
                })
                .collect(),
        ),
        Op::GzipCompress => none(gzip(b)?),
        Op::GzipDecompress => none(need(codecs::gunzip(b), "gzip data")?),
        Op::Inflate => none(need(codecs::inflate(b), "zlib/deflate data")?),
        Op::LzmaDecompress => none(need(codecs::unlzma(b), "XZ/LZMA data")?),
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct View {
    pub bytes: usize,
    /// Present when the bytes are UTF-8 text.
    pub text: Option<String>,
    pub text_truncated: bool,
    pub hex: String,
    pub hex_truncated: bool,
    /// Likely next decoding steps, from the content.
    pub suggestions: Vec<Op>,
    pub hint: Option<String>,
}

fn hexdump(b: &[u8]) -> String {
    b.chunks(16)
        .enumerate()
        .map(|(i, c)| {
            let h: Vec<String> = c.iter().map(|x| format!("{x:02x}")).collect();
            let a: String = c
                .iter()
                .map(|&x| {
                    if (0x20..0x7f).contains(&x) {
                        x as char
                    } else {
                        '.'
                    }
                })
                .collect();
            format!("{:08x}  {:<47}  {a}", i * 16, h.join(" "))
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn is_textual(s: &str) -> bool {
    let ctrl = s
        .chars()
        .filter(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t'))
        .count();
    ctrl * 20 <= s.chars().count().max(1)
}

/// Guess the next decode step from what the bytes look like.
pub fn suggest(b: &[u8]) -> (Vec<Op>, Option<String>) {
    let mut s = Vec::new();
    let mut hint = None;
    if b.starts_with(&[0x1f, 0x8b]) {
        s.push(Op::GzipDecompress);
    } else if b.starts_with(&[0xfd, b'7', b'z', b'X', b'Z', 0]) {
        s.push(Op::LzmaDecompress);
    } else if b.len() >= 2 && b[0] == 0x78 && matches!(b[1], 0x01 | 0x5e | 0x9c | 0xda) {
        s.push(Op::Inflate);
    }
    let t: Vec<u8> = b
        .iter()
        .copied()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();
    if t.len() >= 8 {
        let all = |f: fn(&u8) -> bool| t.iter().all(f);
        if t.len().is_multiple_of(2) && all(|c| c.is_ascii_hexdigit()) {
            s.push(Op::HexDecode);
        }
        let b64 = |c: &u8| c.is_ascii_alphanumeric() || *c == b'+' || *c == b'/' || *c == b'=';
        let b64u = |c: &u8| c.is_ascii_alphanumeric() || *c == b'-' || *c == b'_' || *c == b'=';
        if t.len() >= 12 && t.len() % 4 != 1 && all(b64) && !all(|c| c.is_ascii_hexdigit()) {
            s.push(Op::Base64Decode);
        } else if t.len() >= 12 && all(b64u) && t.iter().any(|c| *c == b'-' || *c == b'_') {
            s.push(Op::Base64UrlDecode);
        }
        if let Ok(text) = std::str::from_utf8(b) {
            if text.contains('%')
                && text
                    .as_bytes()
                    .windows(3)
                    .any(|w| w[0] == b'%' && w[1].is_ascii_hexdigit() && w[2].is_ascii_hexdigit())
            {
                s.push(Op::UrlDecode);
            }
            if (text.contains("&#")
                || ["&amp;", "&lt;", "&gt;", "&quot;"]
                    .iter()
                    .any(|e| text.contains(e)))
                && text.contains(';')
            {
                s.push(Op::HtmlDecode);
            }
            let parts: Vec<&str> = text.trim().split('.').collect();
            if parts.len() == 3 && parts[0].starts_with("eyJ") && parts[1].starts_with("eyJ") {
                hint = Some("This looks like a JWT. Base64url-decoding each part shows its header and claims, but nothing here checks its signature or validity.".into());
            } else if text.contains("<saml") || text.contains("<samlp:") {
                hint = Some("This looks like a SAML message. Decoding shows its XML; nothing here validates its signature or conditions.".into());
            }
        }
    }
    (s, hint)
}

pub fn view(b: &[u8]) -> View {
    let (suggestions, hint) = suggest(b);
    let text = std::str::from_utf8(b).ok().filter(|s| is_textual(s));
    let text_truncated = text.is_some_and(|t| t.len() > SHOW_TEXT);
    let text = text.map(|t| {
        let mut end = t.len().min(SHOW_TEXT);
        while !t.is_char_boundary(end) {
            end -= 1;
        }
        t[..end].to_string()
    });
    View {
        bytes: b.len(),
        text,
        text_truncated,
        hex: hexdump(&b[..b.len().min(SHOW_HEX)]),
        hex_truncated: b.len() > SHOW_HEX,
        suggestions,
        hint,
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Step {
    pub op: Op,
    pub label: String,
    pub ok: bool,
    pub error: Option<String>,
    pub note: Option<String>,
    pub view: Option<View>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Run {
    pub input: View,
    pub steps: Vec<Step>,
    pub error: Option<String>,
}

/// Parse the input (UTF-8 text, or hex bytes) and run the chain. The chain
/// stops at the first failing step.
pub fn run(input: &str, input_is_hex: bool, ops: &[Op]) -> Run {
    let fail = |e: &str| Run {
        input: view(b""),
        steps: Vec::new(),
        error: Some(e.into()),
    };
    if input.len() > MAX_INPUT {
        return fail("input larger than 5 MB");
    }
    if ops.len() > MAX_STEPS {
        return fail("more than 30 steps");
    }
    let mut data = if input_is_hex {
        match codecs::hex(input.as_bytes()) {
            Some(b) => b,
            None => return fail("input is not valid hex"),
        }
    } else {
        input.as_bytes().to_vec()
    };
    let mut steps = Vec::new();
    let input_view = view(&data);
    for &op in ops {
        match apply(op, &data) {
            Ok((out, note)) if out.len() <= MAX_OUTPUT => {
                steps.push(Step {
                    op,
                    label: op.label().into(),
                    ok: true,
                    error: None,
                    note,
                    view: Some(view(&out)),
                });
                data = out;
            }
            Ok(_) => {
                steps.push(Step {
                    op,
                    label: op.label().into(),
                    ok: false,
                    error: Some("output larger than 10 MB".into()),
                    note: None,
                    view: None,
                });
                break;
            }
            Err(e) => {
                steps.push(Step {
                    op,
                    label: op.label().into(),
                    ok: false,
                    error: Some(e),
                    note: None,
                    view: None,
                });
                break;
            }
        }
    }
    Run {
        input: input_view,
        steps,
        error: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn last_text(r: &Run) -> String {
        r.steps
            .last()
            .and_then(|s| s.view.as_ref())
            .and_then(|v| v.text.clone())
            .unwrap_or_default()
    }

    #[test]
    fn round_trips() {
        let s = "Héllo <world> & 'friends' 100% /?=";
        let pairs = [
            (Op::Base64Encode, Op::Base64Decode),
            (Op::Base64UrlEncode, Op::Base64UrlDecode),
            (Op::Base32Encode, Op::Base32Decode),
            (Op::HexEncode, Op::HexDecode),
            (Op::UrlEncode, Op::UrlDecode),
            (Op::HtmlEncode, Op::HtmlDecode),
            (Op::Rot13, Op::Rot13),
            (Op::GzipCompress, Op::GzipDecompress),
            (Op::GzipCompress, Op::Inflate),
        ];
        for (enc, dec) in pairs {
            let r = run(s, false, &[enc, dec]);
            assert_eq!(last_text(&r), s, "{enc:?}/{dec:?}");
        }
    }

    #[test]
    fn known_outputs() {
        assert_eq!(
            last_text(&run("hello", false, &[Op::Base64Encode])),
            "aGVsbG8="
        );
        assert_eq!(
            last_text(&run("a b/c", false, &[Op::UrlEncode])),
            "a%20b%2Fc"
        );
        assert_eq!(
            last_text(&run("a+b%20c", false, &[Op::UrlDecodeForm])),
            "a b c"
        );
        assert_eq!(last_text(&run("a+b", false, &[Op::UrlDecode])), "a+b");
        assert_eq!(
            last_text(&run(
                "&lt;p&gt; &#65;&#x42; &copy; &bogus; & x",
                false,
                &[Op::HtmlDecode]
            )),
            "<p> AB © &bogus; & x"
        );
        let r = run("&bogus; x", false, &[Op::HtmlDecode]);
        assert!(r.steps[0].note.as_ref().unwrap().contains("unrecognized"));
        assert_eq!(last_text(&run("68656c6c6f", true, &[])), "");
        assert_eq!(
            run("68656c6c6f", true, &[]).input.text.as_deref(),
            Some("hello")
        );
    }

    #[test]
    fn errors_stop_the_chain() {
        let r = run("not%zzvalid", false, &[Op::UrlDecode, Op::Base64Encode]);
        assert_eq!(r.steps.len(), 1);
        assert!(!r.steps[0].ok && r.steps[0].error.as_ref().unwrap().contains("percent"));
        let r = run("plain text", false, &[Op::GzipDecompress]);
        assert!(r.steps[0].error.is_some());
        assert!(run("zz", true, &[]).error.is_some());
        assert!(run("x", false, &[Op::Rot13; 31]).error.is_some());
    }

    #[test]
    fn decompression_bomb_is_capped() {
        let zeros = vec![0u8; MAX_OUTPUT + 1024];
        let packed = gzip(&zeros).unwrap();
        let hexed = data_encoding::HEXLOWER.encode(&packed);
        let r = run(&hexed, true, &[Op::GzipDecompress]);
        assert!(!r.steps[0].ok);
        assert!(r.steps[0].error.as_ref().unwrap().contains("10 MB"));
    }

    #[test]
    fn suggestions_and_hints() {
        let v = view(b"SGVsbG8gd29ybGQsIHRoaXMgaXMgYmFzZTY0");
        assert!(v.suggestions.contains(&Op::Base64Decode));
        assert!(
            view(b"48656c6c6f20776f726c64")
                .suggestions
                .contains(&Op::HexDecode)
        );
        assert!(
            view(b"hello%20world%21")
                .suggestions
                .contains(&Op::UrlDecode)
        );
        assert!(
            view(b"&lt;script&gt;x")
                .suggestions
                .contains(&Op::HtmlDecode)
        );
        assert!(
            view(&gzip(b"x").unwrap())
                .suggestions
                .contains(&Op::GzipDecompress)
        );
        let jwt = view(b"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln");
        assert!(jwt.hint.unwrap().contains("JWT"));
        assert!(view(b"just words here").suggestions.is_empty());
        let bin = view(&[0u8, 1, 2, 3, 255]);
        assert!(bin.text.is_none() && bin.hex.starts_with("00000000  00 01 02 03 ff"));
    }
}
