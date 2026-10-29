//! PowerShell decoding by targeted pattern matching: `-EncodedCommand` (in
//! any abbreviation), `[Convert]::FromBase64String(...)` with optional
//! Gzip/Deflate streams and the text encoding used, and `[char]` code
//! arrays. Simple `$var = 'literal'` assignments (including `+` joins of
//! literals) feed later references. `IEX`, `Invoke-Expression`,
//! `[scriptblock]::Create` and `.Invoke()` mark a payload as executed.

use std::collections::HashMap;
use std::sync::LazyLock;

use regex::Regex;

use super::codecs;
use super::core::Found;
use super::eval::V;

static ENCODED: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b(?:powershell|pwsh)(?:\.exe)?\b[^\n]*?\s[-/](?:e|ec|en|enc|enco|encod|encode|encoded|encodedc|encodedco|encodedcom|encodedcomm|encodedcomma|encodedcomman|encodedcommand)\s+["']?([A-Za-z0-9+/=]{8,})"#).unwrap()
});
static FROM_B64: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)FromBase64String\(\s*\(?\s*(?:'((?:[^']|'')*)'|"([^"$]*)"|\$(\w+))\s*\)?\s*\)"#,
    )
    .unwrap()
});
static ASSIGN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?im)^\s*\$(\w+)\s*=\s*(.+?)\s*;?\s*$").unwrap());
static LITERAL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"'((?:[^']|'')*)'|"([^"$`]*)""#).unwrap());
static CHAR_ARRAY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)\[char\[\]\]\s*\(\s*((?:0x[0-9a-f]+|\d+)(?:\s*,\s*(?:0x[0-9a-f]+|\d+)){3,})\s*\)",
    )
    .unwrap()
});
static CHAR_PIPE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\(?\s*((?:0x[0-9a-f]+|\d+)(?:\s*,\s*(?:0x[0-9a-f]+|\d+)){3,})\s*\)?\s*\|\s*(?:%|foreach(?:-object)?)\s*\{\s*\[char\]\s*\$_\s*\}").unwrap()
});
static CHAR_PLUS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)(?:\[char\]\s*(?:0x[0-9a-f]+|\d+)\s*\+?\s*){4,}").unwrap());
static CHAR_ONE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\[char\]\s*(0x[0-9a-f]+|\d+)").unwrap());
static RUNS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)\b(?:iex|invoke-expression)\b|\[scriptblock\]::create|\.invoke\s*\(|^\s*&\s*\(",
    )
    .unwrap()
});

/// A literal or `+` join of literals, as PowerShell would build it.
fn literal_value(expr: &str) -> Option<String> {
    let trimmed = expr
        .trim()
        .trim_start_matches('(')
        .trim_end_matches(')')
        .trim();
    let mut out = String::new();
    let mut rest = trimmed;
    loop {
        let m = LITERAL.find(rest)?;
        if !rest[..m.start()].trim().is_empty() {
            return None;
        }
        let caps = LITERAL.captures(m.as_str())?;
        let s = caps
            .get(1)
            .map(|x| x.as_str().replace("''", "'"))
            .or_else(|| caps.get(2).map(|x| x.as_str().to_string()))?;
        out.push_str(&s);
        rest = rest[m.end()..].trim_start();
        if rest.is_empty() {
            return Some(out);
        }
        rest = rest.strip_prefix('+')?.trim_start();
    }
}

fn parse_num(s: &str) -> Option<u32> {
    let s = s.trim();
    match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(h) => u32::from_str_radix(h, 16).ok(),
        None => s.parse().ok(),
    }
}

fn chars_from(nums: impl Iterator<Item = u32>) -> Option<String> {
    nums.map(char::from_u32).collect()
}

/// UTF-16LE text, as PowerShell's `-EncodedCommand` and `Encoding.Unicode`
/// use.
fn utf16le(b: &[u8]) -> String {
    let start = if b.starts_with(&[0xff, 0xfe]) { 2 } else { 0 };
    let units: Vec<u16> = b[start..]
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&units)
}

/// Bytes that look like UTF-16LE ASCII (every odd byte zero).
fn looks_utf16(b: &[u8]) -> bool {
    let sample = &b[..b.len().min(64)];
    sample.len() >= 4 && sample.iter().skip(1).step_by(2).all(|x| *x == 0)
}

fn line_of(text: &str, byte: usize) -> usize {
    text[..byte].matches('\n').count() + 1
}

fn line_text(text: &str, byte: usize) -> &str {
    let start = text[..byte].rfind('\n').map(|i| i + 1).unwrap_or(0);
    let end = text[byte..]
        .find('\n')
        .map(|i| byte + i)
        .unwrap_or(text.len());
    &text[start..end]
}

/// Whether the payload on this line is run, directly or through the
/// variable it is assigned to.
fn sink_for(text: &str, byte: usize) -> Option<String> {
    let line = line_text(text, byte);
    if RUNS.is_match(line) {
        return Some("IEX".to_string());
    }
    // `$x = ...payload...` then `IEX $x` / `Invoke-Expression $x` later.
    let var = ASSIGN
        .captures(line)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().to_string())?;
    let later = &text[byte..];
    let pat = Regex::new(&format!(
        r"(?i)\b(?:iex|invoke-expression)\b\s*\(?\s*\${}\b",
        regex::escape(&var)
    ))
    .ok()?;
    pat.is_match(later).then(|| "IEX".to_string())
}

/// Scan a script for PowerShell payloads.
pub fn analyze(text: &str) -> Vec<Found> {
    let mut found = Vec::new();

    for c in ENCODED.captures_iter(text) {
        let Some(m) = c.get(1) else { continue };
        let Some(bytes) = codecs::b64(m.as_str().as_bytes(), false) else {
            continue;
        };
        found.push(Found {
            line: line_of(text, m.start()),
            sink: Some("powershell -EncodedCommand".to_string()),
            steps: vec!["base64".to_string(), "utf-16le".to_string()],
            value: V::Str(utf16le(&bytes)),
        });
    }

    let vars: HashMap<String, String> = ASSIGN
        .captures_iter(text)
        .filter_map(|c| {
            let name = c.get(1)?.as_str().to_ascii_lowercase();
            let v = literal_value(c.get(2)?.as_str())?;
            Some((name, v))
        })
        .collect();

    for c in FROM_B64.captures_iter(text) {
        let Some(whole) = c.get(0) else { continue };
        let blob = c
            .get(1)
            .map(|m| m.as_str().replace("''", "'"))
            .or_else(|| c.get(2).map(|m| m.as_str().to_string()))
            .or_else(|| {
                c.get(3)
                    .and_then(|m| vars.get(&m.as_str().to_ascii_lowercase()).cloned())
            });
        let Some(blob) = blob else { continue };
        let Some(mut bytes) = codecs::b64(blob.as_bytes(), false) else {
            continue;
        };
        let mut steps = vec!["base64".to_string()];
        let line = line_text(text, whole.start()).to_ascii_lowercase();
        if line.contains("gzipstream") {
            match codecs::gunzip(&bytes) {
                Some(b) => {
                    bytes = b;
                    steps.push("gzip".to_string());
                }
                None => continue,
            }
        } else if line.contains("deflatestream") {
            match codecs::inflate(&bytes) {
                Some(b) => {
                    bytes = b;
                    steps.push("deflate".to_string());
                }
                None => continue,
            }
        }
        let value = if line.contains("encoding]::unicode")
            || (!line.contains("utf8") && looks_utf16(&bytes))
        {
            steps.push("utf-16le".to_string());
            V::Str(utf16le(&bytes))
        } else {
            V::Bytes(bytes)
        };
        found.push(Found {
            line: line_of(text, whole.start()),
            sink: sink_for(text, whole.start()),
            steps,
            value,
        });
    }

    let mut char_finds = |start: usize, s: Option<String>| {
        if let Some(s) = s.filter(|s| s.chars().count() >= 4) {
            found.push(Found {
                line: line_of(text, start),
                sink: sink_for(text, start),
                steps: vec!["char codes".to_string()],
                value: V::Str(s),
            });
        }
    };
    for c in CHAR_ARRAY.captures_iter(text) {
        let (Some(w), Some(nums)) = (c.get(0), c.get(1)) else {
            continue;
        };
        char_finds(
            w.start(),
            chars_from(nums.as_str().split(',').filter_map(parse_num)),
        );
    }
    for c in CHAR_PIPE.captures_iter(text) {
        let (Some(w), Some(nums)) = (c.get(0), c.get(1)) else {
            continue;
        };
        char_finds(
            w.start(),
            chars_from(nums.as_str().split(',').filter_map(parse_num)),
        );
    }
    for m in CHAR_PLUS.find_iter(text) {
        let s = chars_from(
            CHAR_ONE
                .captures_iter(m.as_str())
                .filter_map(|c| parse_num(c.get(1)?.as_str())),
        );
        char_finds(m.start(), s);
    }

    found
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use std::io::Write;

    fn b64(b: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(b)
    }

    fn utf16(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect()
    }

    fn text(f: &Found) -> String {
        match &f.value {
            V::Str(s) => s.clone(),
            V::Bytes(b) => String::from_utf8_lossy(b).into_owned(),
            _ => String::new(),
        }
    }

    #[test]
    fn encoded_command_any_abbreviation() {
        let enc = b64(&utf16("Write-Host hi"));
        for flag in ["-e", "-enc", "-EncodedCommand", "-ec", "/enc"] {
            let f = analyze(&format!("powershell.exe -nop -w hidden {flag} {enc}"));
            assert_eq!(f.len(), 1, "{flag}");
            assert_eq!(text(&f[0]), "Write-Host hi");
            assert_eq!(f[0].sink.as_deref(), Some("powershell -EncodedCommand"));
        }
        // echo -e in bash is not PowerShell.
        assert!(analyze(&format!("echo -e {enc}")).is_empty());
    }

    #[test]
    fn from_base64_with_encoding_and_iex() {
        let src = format!(
            "IEX ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('{}')))",
            b64(b"Get-Process")
        );
        let f = analyze(&src);
        assert_eq!(text(&f[0]), "Get-Process");
        assert_eq!(f[0].sink.as_deref(), Some("IEX"));

        let uni = format!(
            "$s = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String(\"{}\"))",
            b64(&utf16("whoami"))
        );
        let f = analyze(&uni);
        assert_eq!(text(&f[0]), "whoami");
        assert_eq!(f[0].steps, ["base64", "utf-16le"]);
        assert_eq!(f[0].sink, None);
    }

    #[test]
    fn gzip_stream_and_variable() {
        let mut g = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        g.write_all(b"Invoke-WebRequest http://x").unwrap();
        let blob = b64(&g.finish().unwrap());
        let (a, b) = blob.split_at(10);
        let src = format!(
            "$d = '{a}' + '{b}'\n$x = (New-Object IO.StreamReader(New-Object IO.Compression.GzipStream((New-Object IO.MemoryStream(,[Convert]::FromBase64String($d))),[IO.Compression.CompressionMode]::Decompress))).ReadToEnd()\nInvoke-Expression $x"
        );
        let f = analyze(&src);
        assert_eq!(f.len(), 1);
        assert_eq!(text(&f[0]), "Invoke-WebRequest http://x");
        assert_eq!(f[0].steps, ["base64", "gzip"]);
        assert_eq!(f[0].sink.as_deref(), Some("IEX"));
        assert_eq!(f[0].line, 2);
    }

    #[test]
    fn deflate_stream() {
        let mut d = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        d.write_all(b"Get-ChildItem").unwrap();
        let src = format!(
            "iex (New-Object IO.StreamReader(New-Object IO.Compression.DeflateStream([IO.MemoryStream][Convert]::FromBase64String('{}'),[IO.Compression.CompressionMode]::Decompress))).ReadToEnd()",
            b64(&d.finish().unwrap())
        );
        let f = analyze(&src);
        assert_eq!(text(&f[0]), "Get-ChildItem");
        assert_eq!(f[0].steps, ["base64", "deflate"]);
    }

    #[test]
    fn char_codes() {
        let f = analyze("-join [char[]](73,69,88,32,49) | iex");
        assert_eq!(text(&f[0]), "IEX 1");
        assert_eq!(f[0].sink.as_deref(), Some("IEX"));
        let f = analyze("((119,104,111,97,109,105) | % {[char]$_}) -join ''");
        assert_eq!(text(&f[0]), "whoami");
        let f = analyze("$c = [char]0x77+[char]104+[char]111+[char]97+[char]109+[char]105");
        assert_eq!(text(&f[0]), "whoami");
    }

    #[test]
    fn literal_joins() {
        assert_eq!(literal_value("'ab' + 'c''d'").as_deref(), Some("abc'd"));
        assert_eq!(literal_value("(\"x\"+'y')").as_deref(), Some("xy"));
        assert_eq!(literal_value("'a' + $b"), None);
    }

    #[test]
    fn plain_scripts_have_nothing() {
        assert!(
            analyze("Get-Process | Where-Object { $_.CPU -gt 10 }\nWrite-Host 'done'").is_empty()
        );
    }
}
