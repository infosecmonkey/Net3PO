//! Obfuscator helpers on top of `report::redact`: find replaced values in
//! text (for highlighting the output) and map a reply that uses them back to
//! the originals. The mapping only ever lives in memory.

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::LazyLock;

use regex::Regex;
use serde::Serialize;

use crate::report::redact::{Kind, MAC, MappingEntry, V4_RUN, V6_RUN};

/// Largest output split into highlighted pieces; bigger output is shown plain.
pub const MAX_HIGHLIGHT: usize = 1024 * 1024;
/// Most distinct unknown tokens reported by a restore.
const MAX_UNKNOWN: usize = 200;

static TOKEN_ANY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\[[A-Z]+-\d+\]|\[(?:PRIVATE KEY|CERTIFICATE) REMOVED\]")
        .expect("valid built-in pattern")
});

/// One run of output text; `kind` is set when it is a replacement.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Piece {
    pub text: String,
    pub kind: Option<Kind>,
}

/// Result of mapping a reply back.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Restored {
    pub text: String,
    pub restored: usize,
    /// Secret tokens left in place because secrets were not requested.
    pub secrets_kept: usize,
    /// Tokens in the reply that this session never produced.
    pub unknown: Vec<String>,
}

struct Hit<'a> {
    start: usize,
    end: usize,
    kind: Kind,
    original: Option<&'a str>,
}

/// Replacement text in a normal form, so `[IP-1]`, `10.0.0.1` and
/// `00-09-0F-AA-BB-CC` can be looked up however the reply writes them.
fn norm_fake(kind: Kind, s: &str) -> String {
    match kind {
        Kind::Ip => s
            .parse::<Ipv6Addr>()
            .map(|a| a.to_string())
            .unwrap_or_else(|_| s.to_string()),
        Kind::Mac if !s.starts_with('[') => s
            .chars()
            .filter(char::is_ascii_hexdigit)
            .collect::<String>()
            .to_ascii_lowercase(),
        _ => s.to_string(),
    }
}

struct Lookup<'a> {
    map: HashMap<String, (Kind, &'a str)>,
    /// Fixed replacements from manual rules, matched as whole words.
    fixed: Vec<(&'a str, &'a str)>,
}

impl<'a> Lookup<'a> {
    fn new(entries: &'a [MappingEntry]) -> Self {
        let mut map = HashMap::new();
        let mut fixed = Vec::new();
        for e in entries {
            if e.kind == Kind::Custom && !TOKEN_ANY.is_match(&e.token) {
                if !e.token.trim().is_empty() {
                    fixed.push((e.token.as_str(), e.original.as_str()));
                }
                continue;
            }
            map.entry(norm_fake(e.kind, &e.token))
                .or_insert((e.kind, e.original.as_str()));
        }
        fixed.sort_by_key(|(t, _)| std::cmp::Reverse(t.len()));
        Lookup { map, fixed }
    }

    fn get(&self, kind: Kind, s: &str) -> Option<(Kind, &'a str)> {
        self.map
            .get(&norm_fake(kind, s))
            .copied()
            .filter(|(k, _)| *k == kind || s.starts_with('['))
    }
}

fn word_edge(text: &str, at: usize, before: bool) -> bool {
    let c = if before {
        text[..at].chars().next_back()
    } else {
        text[at..].chars().next()
    };
    !c.is_some_and(|c| c.is_alphanumeric() || c == '_')
}

/// Every replaced value in `text`, in order, without overlaps.
fn hits<'a>(text: &str, lk: &Lookup<'a>, unknown: &mut Vec<String>) -> Vec<Hit<'a>> {
    let mut found: Vec<Hit<'a>> = Vec::new();
    for m in TOKEN_ANY.find_iter(text) {
        let s = m.as_str();
        if s.ends_with(" REMOVED]") {
            found.push(Hit {
                start: m.start(),
                end: m.end(),
                kind: Kind::Secret,
                original: None,
            });
        } else if let Some((kind, orig)) = lk.map.get(s).copied() {
            // An email address is `[USER-n]@[HOST-m]`, and the user token
            // already stands for the whole address.
            let mut end = m.end();
            if kind == Kind::User
                && orig.contains('@')
                && let Some(rest) = text[end..].strip_prefix('@')
                && let Some(h) = TOKEN_ANY.find(rest)
                && h.start() == 0
            {
                end += 1 + h.end();
            }
            found.push(Hit {
                start: m.start(),
                end,
                kind,
                original: Some(orig),
            });
        } else if unknown.len() < MAX_UNKNOWN && !unknown.iter().any(|u| u == s) {
            unknown.push(s.to_string());
        }
    }
    for m in MAC.find_iter(text) {
        if let Some((kind, orig)) = lk.get(Kind::Mac, m.as_str()) {
            found.push(Hit {
                start: m.start(),
                end: m.end(),
                kind,
                original: Some(orig),
            });
        }
    }
    for m in V6_RUN.find_iter(text) {
        let s = m.as_str().trim_end_matches('.');
        if s.matches(':').count() >= 2
            && s.parse::<Ipv6Addr>().is_ok()
            && let Some((kind, orig)) = lk.get(Kind::Ip, s)
        {
            found.push(Hit {
                start: m.start(),
                end: m.start() + s.len(),
                kind,
                original: Some(orig),
            });
        }
    }
    for m in V4_RUN.find_iter(text) {
        if m.as_str().parse::<Ipv4Addr>().is_ok()
            && let Some((kind, orig)) = lk.get(Kind::Ip, m.as_str())
        {
            found.push(Hit {
                start: m.start(),
                end: m.end(),
                kind,
                original: Some(orig),
            });
        }
    }
    for (token, orig) in &lk.fixed {
        for (at, _) in text.match_indices(token) {
            let end = at + token.len();
            if word_edge(text, at, true) && word_edge(text, end, false) {
                found.push(Hit {
                    start: at,
                    end,
                    kind: Kind::Custom,
                    original: Some(orig),
                });
            }
        }
    }
    found.sort_by(|a, b| a.start.cmp(&b.start).then(b.end.cmp(&a.end)));
    let mut out: Vec<Hit<'a>> = Vec::with_capacity(found.len());
    for h in found {
        if out.last().is_none_or(|l| h.start >= l.end) {
            out.push(h);
        }
    }
    out
}

/// Split obfuscated output into plain and replaced runs for display.
pub fn highlight(text: &str, mapping: &[MappingEntry]) -> Option<Vec<Piece>> {
    if text.len() > MAX_HIGHLIGHT {
        return None;
    }
    let lk = Lookup::new(mapping);
    let mut pieces = Vec::new();
    let mut at = 0;
    for h in hits(text, &lk, &mut Vec::new()) {
        if h.start > at {
            pieces.push(Piece {
                text: text[at..h.start].to_string(),
                kind: None,
            });
        }
        pieces.push(Piece {
            text: text[h.start..h.end].to_string(),
            kind: Some(h.kind),
        });
        at = h.end;
    }
    if at < text.len() {
        pieces.push(Piece {
            text: text[at..].to_string(),
            kind: None,
        });
    }
    Some(pieces)
}

/// Put the original values back into a reply that uses this session's
/// replacements. Secrets come back only when `secrets` is set.
pub fn restore(text: &str, mapping: &[MappingEntry], secrets: bool) -> Restored {
    let lk = Lookup::new(mapping);
    let mut unknown = Vec::new();
    let mut out = String::with_capacity(text.len());
    let mut at = 0;
    let mut restored = 0;
    let mut secrets_kept = 0;
    for h in hits(text, &lk, &mut unknown) {
        out.push_str(&text[at..h.start]);
        match h.original {
            Some(orig) if h.kind != Kind::Secret || secrets => {
                out.push_str(orig);
                restored += 1;
            }
            Some(_) => {
                out.push_str(&text[h.start..h.end]);
                secrets_kept += 1;
            }
            None => out.push_str(&text[h.start..h.end]),
        }
        at = h.end;
    }
    out.push_str(&text[at..]);
    Restored {
        text: out,
        restored,
        secrets_kept,
        unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::redact::{RedactOptions, redact_text};

    fn opts() -> RedactOptions {
        RedactOptions {
            macs: true,
            serials: true,
            certificates: true,
            fake_addresses: true,
            ..RedactOptions::default()
        }
    }

    const INPUT: &str = "fw 10.20.30.1 talks to 10.20.30.9 and 2600:1f18:aaaa:1::10; \
mac 00:09:0f:aa:bb:cc; contact alice@acme.com; password=hunter2";

    #[test]
    fn round_trip() {
        let r = redact_text(INPUT, &opts(), "", &[]).unwrap();
        assert!(!r.text.contains("10.20.30.1"));
        let back = restore(&r.text, &r.mapping, true);
        assert_eq!(back.text, INPUT);
        assert!(back.unknown.is_empty());
        // Secrets stay masked unless asked for.
        let back = restore(&r.text, &r.mapping, false);
        assert!(back.text.contains("password=[SECRET-1]"));
        assert_eq!(back.secrets_kept, 1);
    }

    #[test]
    fn restores_a_rewritten_reply() {
        let r = redact_text(INPUT, &opts(), "", &[]).unwrap();
        let ip = r
            .mapping
            .iter()
            .find(|m| m.original == "10.20.30.1")
            .unwrap();
        let mac = r.mapping.iter().find(|m| m.kind == Kind::Mac).unwrap();
        let reply = format!(
            "Check {}/24 and {}. Also [IP-9] and [USER-1].",
            ip.token,
            mac.token.to_uppercase().replace(':', "-")
        );
        let back = restore(&reply, &r.mapping, false);
        assert!(
            back.text
                .starts_with("Check 10.20.30.1/24 and 00:09:0f:aa:bb:cc."),
            "{}",
            back.text
        );
        assert!(back.text.contains("alice@acme.com"));
        assert_eq!(back.unknown, ["[IP-9]"]);
        // A longer address that merely starts with a fake is left alone.
        let near = format!("{}5", ip.token);
        assert_eq!(restore(&near, &r.mapping, false).text, near);
    }

    #[test]
    fn restore_is_single_pass() {
        // A restored value that happens to equal another fake is not
        // replaced a second time.
        let mapping = vec![
            MappingEntry {
                kind: Kind::Ip,
                original: "10.0.0.2".into(),
                token: "10.0.0.1".into(),
                count: 1,
            },
            MappingEntry {
                kind: Kind::Ip,
                original: "10.0.0.3".into(),
                token: "10.0.0.2".into(),
                count: 1,
            },
        ];
        assert_eq!(
            restore("10.0.0.1 10.0.0.2", &mapping, false).text,
            "10.0.0.2 10.0.0.3"
        );
    }

    #[test]
    fn fixed_rules_restore_as_words() {
        let mapping = vec![MappingEntry {
            kind: Kind::Custom,
            original: "Acme Widgets".into(),
            token: "Customer".into(),
            count: 1,
        }];
        assert_eq!(
            restore("Customer and Customers", &mapping, false).text,
            "Acme Widgets and Customers"
        );
    }

    #[test]
    fn highlight_marks_replacements() {
        let r = redact_text(
            "a 10.1.1.1 b password=x [CERTIFICATE REMOVED]",
            &opts(),
            "",
            &[],
        )
        .unwrap();
        let p = highlight(&r.text, &r.mapping).unwrap();
        let joined: String = p.iter().map(|x| x.text.as_str()).collect();
        assert_eq!(joined, r.text);
        let kinds: Vec<Kind> = p.iter().filter_map(|x| x.kind).collect();
        assert_eq!(kinds, [Kind::Ip, Kind::Secret, Kind::Secret]);
        assert!(highlight(&"a".repeat(MAX_HIGHLIGHT + 1), &[]).is_none());
    }
}
