//! IOC extraction: IPv4/IPv6 addresses, domains, URLs, email addresses and
//! hash candidates from pasted text. Defanged input (`hxxp`, `[.]`, `[at]`)
//! is refanged before matching, but every result keeps where and how it
//! appeared. Nothing is resolved, fetched or opened.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::LazyLock;

use regex::Regex;
use serde::Serialize;

/// Largest input accepted.
pub const MAX_INPUT: usize = 5 * 1024 * 1024;
/// Most distinct indicators returned.
pub const MAX_IOCS: usize = 50_000;

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Url,
    Domain,
    Ipv4,
    Ipv6,
    Email,
    Md5,
    Sha1,
    Sha256,
    Sha512,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Ioc {
    pub kind: Kind,
    /// Normalized (refanged, lowercased where case does not matter).
    pub value: String,
    pub defanged: String,
    /// The text as it first appeared in the input.
    pub original: String,
    pub count: usize,
    /// 1-based line and column of the first occurrence.
    pub line: usize,
    pub column: usize,
    pub flags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub struct Extraction {
    pub iocs: Vec<Ioc>,
    pub truncated: bool,
    pub error: Option<String>,
}

fn re(p: &str) -> Regex {
    Regex::new(p).expect("valid built-in pattern")
}

static URL: LazyLock<Regex> =
    LazyLock::new(|| re(r#"(?i)\b(?:https?|ftp)://[^\s<>"'`{}|\\^\[\]]+"#));
static EMAIL: LazyLock<Regex> =
    LazyLock::new(|| re(r"(?i)\b[a-z0-9._%+-]{1,64}@(?:[a-z0-9-]{1,63}\.)+[a-z]{2,24}\b"));
static DOMAIN: LazyLock<Regex> = LazyLock::new(|| {
    re(r"(?i)\b(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,23}\b")
});
static V4: LazyLock<Regex> = LazyLock::new(|| re(r"[0-9][0-9.]*[0-9]"));
static V6: LazyLock<Regex> = LazyLock::new(|| re(r"(?i)[0-9a-f:]*:[0-9a-f:]*[0-9a-f.]*"));
static HEX: LazyLock<Regex> = LazyLock::new(|| re(r"(?i)[0-9a-f]+"));

/// Generic and internal top-level labels taken as domains; any other
/// two-letter label counts as a country code unless it is a common file
/// extension.
const TLDS: &[&str] = &[
    "com", "net", "org", "edu", "gov", "mil", "int", "info", "biz", "name", "pro", "app", "dev",
    "cloud", "online", "site", "tech", "xyz", "store", "shop", "blog", "top", "club", "work",
    "live", "link", "click", "zip", "mov", "icu", "buzz", "monster", "rest", "cyou", "sbs", "lol",
    "pw", "email", "support", "services", "network", "local", "lan", "corp", "internal", "onion",
    "arpa", "page", "news", "space", "website", "host", "fun", "vip", "win", "bid",
];
const FILE_EXT_2: &[&str] = &[
    "py", "rs", "ts", "js", "md", "sh", "pl", "rb", "cs", "ps", "db", "gz", "xz", "7z", "go", "cc",
];
const FILE_EXT: &[&str] = &[
    "exe", "dll", "sys", "bat", "cmd", "ps1", "vbs", "txt", "log", "json", "xml", "html", "htm",
    "php", "aspx", "jsp", "png", "jpg", "gif", "pdf", "doc", "docx", "xls", "xlsx", "lnk", "tmp",
    "dat", "ini", "cfg", "conf", "yml", "yaml",
];

/// Refanged text plus, for every byte of it, the byte offset in the original.
struct Refanged {
    text: String,
    map: Vec<usize>,
    /// Original byte ranges that were rewritten, to flag defanged matches.
    rewritten: Vec<(usize, usize)>,
}

const FANGS: &[(&str, &str)] = &[
    ("hxxps://", "https://"),
    ("hxxp://", "http://"),
    ("hxxps[:]//", "https://"),
    ("hxxp[:]//", "http://"),
    ("fxp://", "ftp://"),
    ("[://]", "://"),
    ("[:]//", "://"),
    ("[.]", "."),
    ("(.)", "."),
    ("{.}", "."),
    ("[dot]", "."),
    ("(dot)", "."),
    ("{dot}", "."),
    ("[:]", ":"),
    ("[@]", "@"),
    ("[at]", "@"),
    ("(at)", "@"),
    ("{at}", "@"),
    ("\\.", "."),
];

fn refang(input: &str) -> Refanged {
    let lower = input.to_ascii_lowercase();
    let bytes = input.as_bytes();
    let mut text = String::with_capacity(input.len());
    let mut map = Vec::with_capacity(input.len());
    let mut rewritten = Vec::new();
    let mut i = 0;
    'outer: while i < bytes.len() {
        for (from, to) in FANGS {
            if lower[i..].starts_with(from) {
                text.push_str(to);
                map.extend(std::iter::repeat_n(i, to.len()));
                rewritten.push((i, i + from.len()));
                i += from.len();
                continue 'outer;
            }
        }
        // Copy one whole character.
        let ch_len = input[i..].chars().next().map(|c| c.len_utf8()).unwrap_or(1);
        text.push_str(&input[i..i + ch_len]);
        map.extend(i..i + ch_len);
        i += ch_len;
    }
    map.push(input.len());
    Refanged {
        text,
        map,
        rewritten,
    }
}

fn defang(kind: Kind, v: &str) -> String {
    match kind {
        Kind::Url => {
            let v = v
                .replacen("https://", "hxxps://", 1)
                .replacen("http://", "hxxp://", 1)
                .replacen("ftp://", "fxp://", 1);
            // Defang dots in the host only.
            match v.split_once("://") {
                Some((scheme, rest)) => {
                    let (host, path) =
                        rest.split_at(rest.find(['/', '?', '#']).unwrap_or(rest.len()));
                    format!("{scheme}://{}{path}", host.replace('.', "[.]"))
                }
                None => v,
            }
        }
        Kind::Domain | Kind::Ipv4 => v.replace('.', "[.]"),
        Kind::Ipv6 => v.replace(':', "[:]"),
        Kind::Email => v.replace('@', "[@]").replace('.', "[.]"),
        _ => v.to_string(),
    }
}

fn looks_like_domain(d: &str) -> Option<Vec<String>> {
    let tld = d.rsplit('.').next()?.to_ascii_lowercase();
    if !tld.bytes().all(|b| b.is_ascii_alphabetic()) {
        return None;
    }
    if FILE_EXT.contains(&tld.as_str()) {
        return None;
    }
    if tld.len() == 2 {
        return (!FILE_EXT_2.contains(&tld.as_str())).then(Vec::new);
    }
    if TLDS.contains(&tld.as_str()) {
        return Some(Vec::new());
    }
    // Other long labels may be real new gTLDs; keep them but say so.
    (tld.len() <= 24).then(|| vec!["uncommon top-level label; may not be a domain".into()])
}

fn ip_flags(ip: IpAddr) -> Vec<String> {
    let mut f = Vec::new();
    let tag = match ip {
        IpAddr::V4(a) => {
            let o = a.octets();
            if a.is_private() {
                Some("private (RFC 1918)")
            } else if a.is_loopback() {
                Some("loopback")
            } else if a.is_link_local() {
                Some("link-local")
            } else if o[0] == 100 && (64..128).contains(&o[1]) {
                Some("carrier-grade NAT (RFC 6598)")
            } else if a.is_documentation() {
                Some("documentation range")
            } else if a.is_multicast() || a.is_broadcast() || a.is_unspecified() {
                Some("not a host address")
            } else {
                None
            }
        }
        IpAddr::V6(a) => {
            let s = a.segments();
            if a.is_loopback() || a.is_unspecified() {
                Some("not a host address")
            } else if (s[0] & 0xfe00) == 0xfc00 {
                Some("unique local (private)")
            } else if (s[0] & 0xffc0) == 0xfe80 {
                Some("link-local")
            } else if s[0] == 0x2001 && s[1] == 0x0db8 {
                Some("documentation range")
            } else {
                None
            }
        }
    };
    if let Some(t) = tag {
        f.push(t.to_string());
    }
    f
}

struct Collector {
    found: HashMap<(Kind, String), usize>,
    out: Vec<Ioc>,
    truncated: bool,
}

impl Collector {
    #[allow(clippy::too_many_arguments)]
    fn add(
        &mut self,
        kind: Kind,
        value: String,
        original: &str,
        offset: usize,
        src: &str,
        defanged: bool,
        mut flags: Vec<String>,
    ) {
        if let Some(&i) = self.found.get(&(kind, value.clone())) {
            self.out[i].count += 1;
            return;
        }
        if self.out.len() >= MAX_IOCS {
            self.truncated = true;
            return;
        }
        let before = &src[..offset.min(src.len())];
        let line = before.matches('\n').count() + 1;
        let column = before
            .rsplit('\n')
            .next()
            .map(|l| l.chars().count())
            .unwrap_or(0)
            + 1;
        if defanged {
            flags.insert(0, "was defanged in the input".into());
        }
        self.found.insert((kind, value.clone()), self.out.len());
        self.out.push(Ioc {
            kind,
            defanged: defang(kind, &value),
            value,
            original: original.to_string(),
            count: 1,
            line,
            column,
            flags,
        });
    }
}

/// Trailing punctuation that usually ends a sentence, not a URL.
fn trim_url(u: &str) -> &str {
    let mut u = u.trim_end_matches(['.', ',', ';', ':', '!', '?', '\'', '"']);
    // Drop a closing parenthesis that has no opening partner in the URL.
    while u.ends_with(')') && u.matches('(').count() < u.matches(')').count() {
        u = &u[..u.len() - 1];
    }
    u
}

/// Extract indicators from `input`.
pub fn extract(input: &str) -> Extraction {
    if input.len() > MAX_INPUT {
        return Extraction {
            error: Some("input larger than 5 MB".into()),
            ..Default::default()
        };
    }
    let r = refang(input);
    let t = &r.text;
    let mut c = Collector {
        found: HashMap::new(),
        out: Vec::new(),
        truncated: false,
    };
    let orig = |s: usize, e: usize| -> (usize, &str, bool) {
        let (os, oe) = (r.map[s], r.map[e.min(r.map.len() - 1)]);
        let oe = oe.max(os);
        let was = r.rewritten.iter().any(|&(a, b)| a < oe && b > os);
        (os, input.get(os..oe).unwrap_or(""), was)
    };

    // Spans already claimed by URLs and emails, so their hosts are not
    // reported twice as separate "domain" hits at the same place.
    let mut claimed: Vec<(usize, usize)> = Vec::new();
    for m in URL.find_iter(t) {
        let u = trim_url(m.as_str());
        let (os, o, was) = orig(m.start(), m.start() + u.len());
        let flags = Vec::new();
        c.add(Kind::Url, u.to_string(), o, os, input, was, flags);
        claimed.push((m.start(), m.start() + u.len()));
        // The URL's host is also an indicator on its own.
        if let Some(rest) = u.split_once("://").map(|x| x.1) {
            let host = rest
                .split(['/', '?', '#'])
                .next()
                .unwrap_or("")
                .rsplit('@')
                .next()
                .unwrap_or("");
            let host = host
                .split(':')
                .next()
                .unwrap_or("")
                .trim_matches(['[', ']']);
            if let Ok(ip) = host.parse::<IpAddr>() {
                let kind = if ip.is_ipv4() { Kind::Ipv4 } else { Kind::Ipv6 };
                let mut f = ip_flags(ip);
                f.push("host of a URL".into());
                c.add(kind, ip.to_string(), host, os, input, was, f);
            } else if !host.is_empty()
                && let Some(mut f) = looks_like_domain(host)
            {
                f.push("host of a URL".into());
                c.add(
                    Kind::Domain,
                    host.to_ascii_lowercase(),
                    host,
                    os,
                    input,
                    was,
                    f,
                );
            }
        }
    }
    for m in EMAIL.find_iter(t) {
        if claimed.iter().any(|&(a, b)| m.start() >= a && m.end() <= b) {
            continue;
        }
        let (os, o, was) = orig(m.start(), m.end());
        c.add(
            Kind::Email,
            m.as_str().to_ascii_lowercase(),
            o,
            os,
            input,
            was,
            Vec::new(),
        );
        claimed.push((m.start(), m.end()));
    }
    for m in DOMAIN.find_iter(t) {
        if claimed.iter().any(|&(a, b)| m.start() >= a && m.end() <= b) {
            continue;
        }
        let d = m.as_str().trim_end_matches('.');
        if d.parse::<Ipv4Addr>().is_ok() {
            continue;
        }
        if let Some(f) = looks_like_domain(d) {
            let (os, o, was) = orig(m.start(), m.start() + d.len());
            c.add(Kind::Domain, d.to_ascii_lowercase(), o, os, input, was, f);
        }
    }
    for m in V4.find_iter(t) {
        if claimed.iter().any(|&(a, b)| m.start() >= a && m.end() <= b) {
            continue;
        }
        if let Ok(ip) = m.as_str().parse::<Ipv4Addr>() {
            let (os, o, was) = orig(m.start(), m.end());
            c.add(
                Kind::Ipv4,
                ip.to_string(),
                o,
                os,
                input,
                was,
                ip_flags(IpAddr::V4(ip)),
            );
        }
    }
    for m in V6.find_iter(t) {
        let s = m.as_str().trim_end_matches('.');
        if s.matches(':').count() < 2
            || claimed.iter().any(|&(a, b)| m.start() >= a && m.end() <= b)
        {
            continue;
        }
        if let Ok(ip) = s.parse::<Ipv6Addr>() {
            let (os, o, was) = orig(m.start(), m.start() + s.len());
            c.add(
                Kind::Ipv6,
                ip.to_string(),
                o,
                os,
                input,
                was,
                ip_flags(IpAddr::V6(ip)),
            );
        }
    }
    for m in HEX.find_iter(t) {
        // Only whole tokens: not inside a longer word or a dashed GUID.
        let before = t[..m.start()].chars().next_back();
        let after = t[m.end()..].chars().next();
        let edge = |c: Option<char>| {
            c.is_none_or(|c| !(c.is_ascii_alphanumeric() || c == '_' || c == '-'))
        };
        if !edge(before) || !edge(after) {
            continue;
        }
        let kind = match m.len() {
            32 => Kind::Md5,
            40 => Kind::Sha1,
            64 => Kind::Sha256,
            128 => Kind::Sha512,
            _ => continue,
        };
        let v = m.as_str();
        let mut flags = Vec::new();
        let digits = v.bytes().all(|b| b.is_ascii_digit());
        let letters = v.bytes().all(|b| b.is_ascii_alphabetic());
        if digits || letters {
            flags.push("weak candidate: all digits or all letters".into());
        }
        if kind == Kind::Md5 {
            flags.push("32 hex digits: MD5, or an undashed GUID/NTLM hash".into());
        }
        if kind == Kind::Sha1 {
            flags.push("40 hex digits: SHA-1, or another 160-bit value (e.g. a Git commit)".into());
        }
        let (os, o, was) = orig(m.start(), m.end());
        c.add(kind, v.to_ascii_lowercase(), o, os, input, was, flags);
    }

    c.out.sort_by(|a, b| {
        a.kind
            .cmp(&b.kind)
            .then(a.line.cmp(&b.line))
            .then(a.column.cmp(&b.column))
    });
    Extraction {
        iocs: c.out,
        truncated: c.truncated,
        error: None,
    }
}

/// Defang or refang free text (every recognizable indicator in place).
pub fn transform(input: &str, defang_out: bool) -> Result<String, String> {
    if input.len() > MAX_INPUT {
        return Err("input larger than 5 MB".into());
    }
    let r = refang(input);
    if !defang_out {
        return Ok(r.text);
    }
    let mut t = r.text;
    t = URL
        .replace_all(&t, |c: &regex::Captures| {
            let u = trim_url(&c[0]);
            format!("{}{}", defang(Kind::Url, u), &c[0][u.len()..])
        })
        .into_owned();
    t = EMAIL
        .replace_all(&t, |c: &regex::Captures| defang(Kind::Email, &c[0]))
        .into_owned();
    t = V4
        .replace_all(&t, |c: &regex::Captures| match c[0].parse::<Ipv4Addr>() {
            Ok(_) => defang(Kind::Ipv4, &c[0]),
            Err(_) => c[0].to_string(),
        })
        .into_owned();
    t = DOMAIN
        .replace_all(&t, |c: &regex::Captures| {
            let d = &c[0];
            if looks_like_domain(d.trim_end_matches('.')).is_some_and(|f| f.is_empty()) {
                defang(Kind::Domain, d)
            } else {
                d.to_string()
            }
        })
        .into_owned();
    Ok(t)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(e: &Extraction, k: Kind) -> Vec<String> {
        e.iocs
            .iter()
            .filter(|i| i.kind == k)
            .map(|i| i.value.clone())
            .collect()
    }

    #[test]
    fn extracts_and_refangs() {
        let text = "Beacon to hxxps://evil[.]example[.]com/a/b.php?id=1 and 198.51.100[.]7.\nMail from bad[at]phish.example.net, see https://example.org/x).\nHost 10.0.0.5 and 2001:db8::bad:1";
        let e = extract(text);
        assert_eq!(
            kinds(&e, Kind::Url),
            vec![
                "https://evil.example.com/a/b.php?id=1",
                "https://example.org/x"
            ]
        );
        assert!(kinds(&e, Kind::Domain).contains(&"evil.example.com".to_string()));
        assert!(kinds(&e, Kind::Domain).contains(&"example.org".to_string()));
        assert_eq!(kinds(&e, Kind::Email), vec!["bad@phish.example.net"]);
        assert_eq!(kinds(&e, Kind::Ipv4), vec!["198.51.100.7", "10.0.0.5"]);
        assert_eq!(kinds(&e, Kind::Ipv6), vec!["2001:db8::bad:1"]);
        let url = e.iocs.iter().find(|i| i.kind == Kind::Url).unwrap();
        assert_eq!((url.line, url.column), (1, 11));
        assert_eq!(url.original, "hxxps://evil[.]example[.]com/a/b.php?id=1");
        assert!(url.flags[0].contains("defanged"));
        assert_eq!(url.defanged, "hxxps://evil[.]example[.]com/a/b.php?id=1");
        let private = e.iocs.iter().find(|i| i.value == "10.0.0.5").unwrap();
        assert!(private.flags.iter().any(|f| f.contains("RFC 1918")));
        let doc = e.iocs.iter().find(|i| i.value == "198.51.100.7").unwrap();
        assert_eq!(doc.line, 1);
        assert!(doc.flags.iter().any(|f| f.contains("documentation")));
    }

    #[test]
    fn dedup_counts_and_files() {
        let e = extract(
            "evil.example.com evil.example.com EVIL.example.com\nrun svchost.exe and payload.dll from report.ts",
        );
        let d: Vec<&Ioc> = e.iocs.iter().filter(|i| i.kind == Kind::Domain).collect();
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].count, 3);
        assert!(
            kinds(&e, Kind::Domain)
                .iter()
                .all(|x| !x.ends_with(".exe") && !x.ends_with(".dll") && !x.ends_with(".ts"))
        );
    }

    #[test]
    fn hashes_are_candidates() {
        let md5 = "d41d8cd98f00b204e9800998ecf8427e";
        let sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let e = extract(&format!(
            "md5 {md5}\nsha256: {sha256}\nguid 550e8400-e29b-41d4-a716-446655440000\nlonger {sha256}ff\nnum {}",
            "1".repeat(32)
        ));
        assert_eq!(kinds(&e, Kind::Md5), vec![md5.to_string(), "1".repeat(32)]);
        assert_eq!(kinds(&e, Kind::Sha256), vec![sha256.to_string()]);
        let weak = e.iocs.iter().find(|i| i.value == "1".repeat(32)).unwrap();
        assert!(weak.flags.iter().any(|f| f.contains("weak")));
        assert!(e.iocs.iter().all(|i| !i.value.contains("446655440000")));
    }

    #[test]
    fn versions_oids_and_macs() {
        let e = extract("OID 1.3.6.1.2.1 version 2.4.1 mac 00:11:22:33:44:55 at 14:05:10");
        assert!(kinds(&e, Kind::Ipv4).is_empty());
        assert!(kinds(&e, Kind::Ipv6).is_empty());
    }

    #[test]
    fn defang_and_refang_text() {
        let t = "Go to https://evil.example.com/x and mail a@b.example.org from 203.0.113.9.";
        let d = transform(t, true).unwrap();
        assert_eq!(
            d,
            "Go to hxxps://evil[.]example[.]com/x and mail a[@]b[.]example[.]org from 203[.]0[.]113[.]9."
        );
        assert_eq!(transform(&d, false).unwrap(), t);
        assert!(transform(&"x".repeat(MAX_INPUT + 1), true).is_err());
    }

    #[test]
    fn hostile_input() {
        let e = extract(&"[.]".repeat(100_000));
        assert!(e.iocs.is_empty());
        let e = extract("é.example.com ünïcode hxxp://x[.]y\u{0}z [at][at][at]");
        assert!(e.error.is_none());
        let many: String = (0..2000)
            .map(|i| format!("10.0.{}.{}\n", i / 250, i % 250))
            .collect();
        assert_eq!(extract(&many).iocs.len(), 2000);
        assert!(extract(&"x".repeat(MAX_INPUT + 1)).error.is_some());
    }
}
