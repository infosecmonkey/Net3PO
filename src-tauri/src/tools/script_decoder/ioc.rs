//! Indicator extraction: URLs, domains, IPv4 addresses, emails, hashes and
//! file paths, with defanged forms for safe sharing. Domains are filtered by
//! TLD so Python attribute chains like `base64.b64decode` are not reported.

use std::collections::HashSet;
use std::sync::LazyLock;

use regex::Regex;
use serde::Serialize;

/// Most indicators reported.
pub const MAX_IOCS: usize = 2000;

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum IocKind {
    Url,
    Domain,
    Ipv4,
    Email,
    Md5,
    Sha1,
    Sha256,
    Path,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Ioc {
    pub kind: IocKind,
    pub value: String,
    /// Safe-to-paste form: hxxp, [.] and [@].
    pub defanged: String,
    /// Layer where it was first seen.
    pub layer: usize,
    /// Set for private, loopback and link-local addresses.
    pub private: bool,
}

static URL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)\b(?:https?|ftp)://[^\s'"<>()\[\]{}\\`]+"#).unwrap());
static IPV4: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\b").unwrap()
});
static DOMAIN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b").unwrap()
});
static EMAIL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,24}\b").unwrap()
});
static HASH: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\b[A-Fa-f0-9]{32,64}\b").unwrap());
static WIN_PATH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"\b[A-Za-z]:\\(?:[^\\\s'"<>|*?\r\n]+\\)*[^\\\s'"<>|*?\r\n]*"#).unwrap()
});
static UNIX_PATH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?:^|[\s'"(=,])((?:/(?:tmp|etc|var|dev/shm|usr|home|root|opt|bin|sbin|Library|Users|private|System)/|~/\.)[^\s'"<>()\]\[,;]*)"#).unwrap()
});

/// Generic and common TLDs accepted for bare domains. Two-letter country
/// codes are accepted too, except ones that are also common file extensions.
const TLDS: &[&str] = &[
    "com", "net", "org", "info", "biz", "edu", "gov", "mil", "int", "xyz", "top", "online", "site",
    "club", "app", "dev", "cloud", "live", "link", "click", "shop", "store", "tech", "space",
    "website", "icu", "vip", "work", "fun", "pro", "onion", "lol", "monster", "rest", "cyou",
    "buzz", "today", "life", "world", "email", "host", "network", "services", "support", "digital",
    "zip", "mov", "page", "run", "ninja", "agency", "help",
];
const CC_EXCLUDE: &[&str] = &[
    "py", "sh", "so", "pl", "rs", "md", "ps", "gz", "bz", "js", "cs", "hs", "ml", "rb", "go", "lo",
    "mo", "to", "is", "in", "as", "at", "it", "id", "do", "no", "me", "ok", "os", "pm",
];

fn domain_ok(d: &str) -> bool {
    let Some(tld) = d.rsplit('.').next() else {
        return false;
    };
    let tld = tld.to_ascii_lowercase();
    if TLDS.contains(&tld.as_str()) {
        return true;
    }
    tld.len() == 2
        && !CC_EXCLUDE.contains(&tld.as_str())
        && tld.chars().all(|c| c.is_ascii_alphabetic())
}

fn is_private(ip: &str) -> bool {
    let o: Vec<u8> = ip.split('.').filter_map(|p| p.parse().ok()).collect();
    matches!(
        o.as_slice(),
        [10, ..] | [127, ..] | [0, ..] | [169, 254, ..] | [192, 168, ..] | [100, 64..=127, ..]
    ) || matches!(o.as_slice(), [172, b, ..] if (16..=31).contains(b))
}

/// Defang an indicator for sharing.
pub fn defang(kind: IocKind, v: &str) -> String {
    match kind {
        IocKind::Url => {
            let (scheme, rest) = v.split_once("://").unwrap_or(("", v));
            let scheme = match scheme.to_ascii_lowercase().as_str() {
                "http" => "hxxp".to_string(),
                "https" => "hxxps".to_string(),
                "ftp" => "fxp".to_string(),
                s => s.to_string(),
            };
            let (host, path) = rest
                .split_once('/')
                .map(|(h, p)| (h, format!("/{p}")))
                .unwrap_or((rest, String::new()));
            format!("{scheme}://{}{path}", host.replace('.', "[.]"))
        }
        IocKind::Domain | IocKind::Ipv4 => v.replace('.', "[.]"),
        IocKind::Email => {
            let (user, host) = v.split_once('@').unwrap_or((v, ""));
            format!("{user}[@]{}", host.replace('.', "[.]"))
        }
        _ => v.to_string(),
    }
}

/// Collects unique indicators across layers.
#[derive(Default)]
pub struct Collector {
    seen: HashSet<(IocKind, String)>,
    pub iocs: Vec<Ioc>,
}

impl Collector {
    fn push(&mut self, kind: IocKind, value: &str, layer: usize) {
        if self.iocs.len() >= MAX_IOCS {
            return;
        }
        let value = value
            .trim_end_matches(['.', ',', ';', ':', ')'])
            .to_string();
        if value.is_empty() || !self.seen.insert((kind, value.to_ascii_lowercase())) {
            return;
        }
        let private = kind == IocKind::Ipv4 && is_private(&value);
        self.iocs.push(Ioc {
            kind,
            defanged: defang(kind, &value),
            value,
            layer,
            private,
        });
    }

    /// Scan one text for indicators.
    pub fn scan(&mut self, text: &str, layer: usize) {
        let mut url_hosts = Vec::new();
        for m in URL.find_iter(text) {
            self.push(IocKind::Url, m.as_str(), layer);
            if let Some(host) = m
                .as_str()
                .split_once("://")
                .map(|(_, r)| r.split(['/', ':', '?', '#']).next().unwrap_or(""))
            {
                url_hosts.push(host.to_string());
            }
        }
        for h in url_hosts {
            if IPV4.is_match(&h) {
                self.push(IocKind::Ipv4, &h, layer);
            } else if domain_ok(&h) {
                self.push(IocKind::Domain, &h, layer);
            }
        }
        for m in EMAIL.find_iter(text) {
            self.push(IocKind::Email, m.as_str(), layer);
        }
        for m in IPV4.find_iter(text) {
            self.push(IocKind::Ipv4, m.as_str(), layer);
        }
        for m in DOMAIN.find_iter(text) {
            let d = m.as_str();
            // Skip the domain half of an email, and IP-like runs.
            let before = text[..m.start()].chars().last();
            if before == Some('@') || d.chars().all(|c| c.is_ascii_digit() || c == '.') {
                continue;
            }
            // PascalCase labels are code (System.Net, Net.WebClient), not hosts.
            let code_like = d.split('.').any(|l| {
                let mut c = l.chars();
                c.next().is_some_and(|f| f.is_ascii_uppercase())
                    && c.any(|x| x.is_ascii_lowercase())
            });
            if domain_ok(d) && !code_like {
                self.push(IocKind::Domain, d, layer);
            }
        }
        for m in HASH.find_iter(text) {
            let kind = match m.as_str().len() {
                32 => IocKind::Md5,
                40 => IocKind::Sha1,
                64 => IocKind::Sha256,
                _ => continue,
            };
            // All-digit runs are more likely numbers than hashes.
            if m.as_str().bytes().any(|b| b.is_ascii_alphabetic()) {
                self.push(kind, m.as_str(), layer);
            }
        }
        for m in WIN_PATH.find_iter(text) {
            if m.as_str().len() > 3 {
                self.push(IocKind::Path, m.as_str(), layer);
            }
        }
        for c in UNIX_PATH.captures_iter(text) {
            if let Some(p) = c.get(1) {
                self.push(IocKind::Path, p.as_str(), layer);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan(s: &str) -> Vec<(IocKind, String)> {
        let mut c = Collector::default();
        c.scan(s, 0);
        c.iocs.into_iter().map(|i| (i.kind, i.value)).collect()
    }

    #[test]
    fn finds_url_and_its_host() {
        let got = scan("urlopen('http://evil.example.com/a.py').read()");
        assert!(got.contains(&(IocKind::Url, "http://evil.example.com/a.py".into())));
        assert!(got.contains(&(IocKind::Domain, "evil.example.com".into())));
    }

    #[test]
    fn python_attributes_are_not_domains() {
        let got = scan(
            "base64.b64decode(x); os.system(y); sys.argv; socket.socket(); payload.py; run.sh",
        );
        assert!(got.iter().all(|(k, _)| *k != IocKind::Domain), "{got:?}");
    }

    #[test]
    fn ips_emails_hashes_paths() {
        let got = scan(concat!(
            "s.connect(('203.0.113.7', 4444)) ",
            "mail to ops@example.org ",
            "d41d8cd98f00b204e9800998ecf8427e ",
            "open('/tmp/.x', 'w'); open('~/.ssh/id_rsa'); 'C:\\Users\\Public\\a.exe' ",
            "1.2.3"
        ));
        assert!(got.contains(&(IocKind::Ipv4, "203.0.113.7".into())));
        assert!(got.contains(&(IocKind::Email, "ops@example.org".into())));
        assert!(got.contains(&(IocKind::Md5, "d41d8cd98f00b204e9800998ecf8427e".into())));
        assert!(got.contains(&(IocKind::Path, "/tmp/.x".into())));
        assert!(got.contains(&(IocKind::Path, "~/.ssh/id_rsa".into())));
        assert!(got.contains(&(IocKind::Path, "C:\\Users\\Public\\a.exe".into())));
        // The email's domain is not listed separately.
        assert!(!got.contains(&(IocKind::Domain, "example.org".into())));
    }

    #[test]
    fn dotnet_names_are_not_domains() {
        let got =
            scan("using namespace System.Net; [System.Net.ServicePointManager]; Net.WebClient");
        assert!(got.iter().all(|(k, _)| *k != IocKind::Domain), "{got:?}");
        assert!(
            scan("IEX evil.example.net").contains(&(IocKind::Domain, "evil.example.net".into()))
        );
    }

    #[test]
    fn private_flag_and_dedupe() {
        let mut c = Collector::default();
        c.scan("10.0.0.5 10.0.0.5 8.8.8.8", 1);
        assert_eq!(c.iocs.len(), 2);
        assert!(c.iocs[0].private && !c.iocs[1].private);
        assert_eq!(c.iocs[0].layer, 1);
    }

    #[test]
    fn defanging() {
        assert_eq!(
            defang(IocKind::Url, "https://evil.com/x.y"),
            "hxxps://evil[.]com/x.y"
        );
        assert_eq!(defang(IocKind::Domain, "evil.com"), "evil[.]com");
        assert_eq!(defang(IocKind::Ipv4, "1.2.3.4"), "1[.]2[.]3[.]4");
        assert_eq!(defang(IocKind::Email, "a@b.com"), "a[@]b[.]com");
    }
}
