//! Report redaction: replace customer IPs, hostnames, usernames, email
//! addresses and detected secrets with consistent pseudonyms before a report
//! is written. The same original value always gets the same token within one
//! report (`[IP-1]`, `[HOST-2]`, `[USER-3]`, `[SECRET-1]`), so the report
//! still reads correctly. The mapping is returned for preview only; it is
//! never written into the exported report. Detection is heuristic and can
//! miss things; manual rules and exclusions cover the gaps.

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::LazyLock;

use regex::{Captures, Regex, RegexBuilder};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::core::{Block, Report};

/// Most manual rules accepted.
const MAX_RULES: usize = 200;
/// Most exclusions accepted.
const MAX_EXCLUSIONS: usize = 500;
/// Longest rule or exclusion text.
const MAX_RULE_LEN: usize = 500;
/// Compiled size cap for a user regex.
const RULE_REGEX_SIZE: usize = 1 << 20;
/// Most mapping entries returned for preview.
const MAX_PREVIEW: usize = 5000;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RedactError {
    #[error("too many rules (limit {MAX_RULES})")]
    TooManyRules,
    #[error("too many exclusions (limit {MAX_EXCLUSIONS})")]
    TooManyExclusions,
    #[error("rule {0} is longer than {MAX_RULE_LEN} characters")]
    RuleTooLong(usize),
    #[error("rule {0} is empty")]
    EmptyRule(usize),
    #[error("rule {0} is not a valid regular expression: {1}")]
    BadRegex(usize, String),
}

/// A manual find-and-replace rule.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", default)]
pub struct Rule {
    /// Text to find (case-insensitive), or a regular expression.
    pub find: String,
    /// Replacement; empty means a numbered `[CUSTOM-n]` token.
    pub replace: String,
    pub regex: bool,
}

/// What to redact.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", default)]
pub struct RedactOptions {
    pub ips: bool,
    pub hostnames: bool,
    pub emails: bool,
    pub usernames: bool,
    pub secrets: bool,
    pub rules: Vec<Rule>,
    /// Values never replaced, case-insensitive. A domain also covers its
    /// subdomains (`example.com` keeps `mx.example.com`); an IPv4 entry may
    /// be a CIDR (`192.0.2.0/24`).
    pub exclusions: Vec<String>,
}

impl Default for RedactOptions {
    fn default() -> Self {
        Self {
            ips: true,
            hostnames: true,
            emails: true,
            usernames: true,
            secrets: true,
            rules: Vec::new(),
            exclusions: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "camelCase")]
pub enum Kind {
    Custom,
    Secret,
    Ip,
    Host,
    User,
}

impl Kind {
    fn prefix(self) -> &'static str {
        match self {
            Self::Custom => "CUSTOM",
            Self::Secret => "SECRET",
            Self::Ip => "IP",
            Self::Host => "HOST",
            Self::User => "USER",
        }
    }
}

/// One original value and its replacement, for the preview.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MappingEntry {
    pub kind: Kind,
    pub original: String,
    pub token: String,
    pub count: usize,
}

/// Result of a redaction: the report to write plus what changed.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Redacted {
    pub report: Report,
    /// Shown in the preview only; never part of the report.
    pub mapping: Vec<MappingEntry>,
    pub mapping_truncated: bool,
    pub replacements: usize,
    pub emails: usize,
    pub private_keys: usize,
}

// ---------------------------------------------------------------- patterns

fn re(p: &str) -> Regex {
    // Patterns are constants, covered by tests.
    Regex::new(p).expect("valid built-in pattern")
}

static TOKEN: LazyLock<Regex> = LazyLock::new(|| re(r"^\[[A-Z]+-\d+\]$"));

static PRIVATE_KEY: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----",
    )
});

/// `password: x`, `api_key=x`, `community = "x"`: a keyword, a separator, a value.
static SECRET_KV: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r#"(?i)\b(password|passwd|pwd|passphrase|secret|psksecret|api[_-]?key|access[_-]?key|secret[_-]?key|client[_-]?secret|auth[_-]?token|access[_-]?token|token|community)(\s*[:=]\s*)("[^"\r\n]*"|'[^'\r\n]*'|[^\s,;]+)"#,
    )
});

/// Device config lines: FortiOS `set password ENC x`, Cisco `enable secret 5 x`,
/// `username u password 7 x`, `snmp-server community x RO`, `key-string 7 x`.
static SECRET_CONFIG: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"(?im)(\bset\s+(?:password|passwd|psksecret|secret|key|auth-pwd|priv-pwd|passphrase|pre-shared-key|private-key|password2|ppk-secret|auth-password|sso-password)|\benable\s+(?:secret|password)|\busername\s+\S+\s+(?:password|secret)|\bkey-string|\bsnmp-server\s+community|\bpre-shared-key|\bcrypto\s+isakmp\s+key)(\s+)((?:ENC\s+|[0-9]\s+)?)(\S+)",
    )
});

/// Recognizable credential formats that stand on their own.
static SECRET_STANDALONE: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"\b(?:AKIA[0-9A-Z]{16}|eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}|gh[pousr]_[A-Za-z0-9]{30,}|xox[abprs]-[A-Za-z0-9-]{10,}|sk-[A-Za-z0-9_-]{20,})\b|(?i:\bBearer\s+)[A-Za-z0-9._~+/=-]{16,}",
    )
});

static EMAIL: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"(?i)\b([a-z0-9][a-z0-9._%+-]{0,63})@([a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?)+)\b",
    )
});

/// A run of digits and dots; checked afterwards for exactly four octets, so
/// OIDs (1.3.6.1.2.1) and versions (1.2.3) are left alone.
static V4_RUN: LazyLock<Regex> = LazyLock::new(|| re(r"[0-9][0-9.]*[0-9]"));

/// Candidate IPv6 text; parsed afterwards. MACs and times do not parse.
static V6_RUN: LazyLock<Regex> = LazyLock::new(|| re(r"(?i)[0-9a-f:]*:[0-9a-f:]*[0-9a-f.]*"));

static HOSTNAME: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"(?i)\b[a-z0-9_](?:[a-z0-9_-]{0,62}[a-z0-9])?(?:\.[a-z0-9_](?:[a-z0-9_-]{0,62}[a-z0-9])?)+\.?\b",
    )
});

/// `user=alice`, `TargetUserName: alice`, `account name: alice`.
static USER_KV: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r#"(?i)\b(user(?:\s?name)?|account(?:\s?name)?|login(?:\s?name)?|logon\s?name|targetusername|subjectusername|samaccountname|user\s?id|uid)(\s*[:=]\s*)("[^"\r\n]*"|[^\s,;"]+)"#,
    )
});

/// `DOMAIN\user`, only after a start, space, quote or bracket so paths like
/// `C:\Windows\System32` are not taken.
static USER_DOMAIN: LazyLock<Regex> = LazyLock::new(|| {
    re(r#"(^|[\s"'(\[,=])([A-Za-z][A-Za-z0-9.-]{0,63})\\([A-Za-z0-9._$-]{1,64})"#)
});

static KEY_SECRET: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"(?i)^(password|passwd|passphrase|secret|psk|pre-?shared ?key|community|community string|api ?key|token|auth(entication)? (key|password)|priv(acy)? (key|password)|private key)$",
    )
});
static KEY_USER: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"(?i)^(user|username|user ?name|account|account ?name|login|logon ?name|targetusername|subjectusername|samaccountname|user ?id|uid|security name)$",
    )
});
static KEY_HOST: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"(?i)^(host|hostname|host ?name|computer|computer ?name|device|device ?name|sysname|system name|workstation|workstation ?name|server|server ?name)$",
    )
});

/// Common generic and internal top-level labels. Any other two-letter label
/// is taken as a country code unless it is a common file extension.
const TLDS: &[&str] = &[
    "com",
    "net",
    "org",
    "edu",
    "gov",
    "mil",
    "int",
    "info",
    "biz",
    "name",
    "pro",
    "aero",
    "coop",
    "museum",
    "mobi",
    "app",
    "dev",
    "cloud",
    "online",
    "site",
    "tech",
    "xyz",
    "store",
    "shop",
    "blog",
    "io",
    "ai",
    "email",
    "group",
    "solutions",
    "services",
    "systems",
    "network",
    "security",
    "digital",
    "global",
    "world",
    "company",
    "agency",
    "health",
    "bank",
    "insurance",
    "law",
    "media",
    "news",
    "live",
    "zone",
    "link",
    "page",
    "top",
    "club",
    "work",
    "one",
    "host",
    "website",
    "space",
    "today",
    "center",
    "support",
    "consulting",
    "microsoft",
    "google",
    "amazon",
    "local",
    "lan",
    "corp",
    "internal",
    "intranet",
    "home",
    "localdomain",
    "domain",
    "office",
    "priv",
    "private",
    "example",
    "test",
    "invalid",
    "localhost",
    "arpa",
    "onion",
];

/// Two-letter labels that are far more often file extensions than ccTLDs.
const FILE_EXT_2: &[&str] = &[
    "py", "rs", "ts", "js", "md", "sh", "pl", "rb", "cs", "ps", "db", "gz", "xz", "7z", "go", "hh",
    "cc",
];

/// Account names that identify no one.
const BUILTIN_USERS: &[&str] = &[
    "-",
    "system",
    "local service",
    "network service",
    "anonymous logon",
    "n/a",
    "none",
    "null",
    "nt authority",
    "localsystem",
];

fn looks_like_host(s: &str) -> bool {
    let s = s.trim_end_matches('.');
    let Some(tld) = s.rsplit('.').next() else {
        return false;
    };
    if !s.contains('.') || !tld.bytes().all(|b| b.is_ascii_alphabetic()) {
        return false;
    }
    let tld = tld.to_ascii_lowercase();
    if tld.len() == 2 {
        return !FILE_EXT_2.contains(&tld.as_str());
    }
    TLDS.contains(&tld.as_str())
}

fn is_mask(ip: Ipv4Addr) -> bool {
    let n = u32::from(ip);
    n != 0 && n.leading_ones() + n.trailing_zeros() == 32
}

fn keep_v4(ip: Ipv4Addr) -> bool {
    ip.is_unspecified() || ip.is_loopback() || ip.is_broadcast() || is_mask(ip)
}

fn keep_v6(ip: Ipv6Addr) -> bool {
    ip.is_unspecified() || ip.is_loopback()
}

// ---------------------------------------------------------------- engine

enum Exclusion {
    Text(String),
    V4Net(u32, u32),
}

fn parse_exclusion(s: &str) -> Option<Exclusion> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    if let Some((addr, len)) = s.split_once('/')
        && let (Ok(a), Ok(l)) = (addr.parse::<Ipv4Addr>(), len.parse::<u32>())
        && l <= 32
    {
        let mask = if l == 0 { 0 } else { u32::MAX << (32 - l) };
        return Some(Exclusion::V4Net(u32::from(a) & mask, mask));
    }
    Some(Exclusion::Text(s.trim_end_matches('.').to_lowercase()))
}

struct CompiledRule {
    re: Regex,
    replace: String,
}

struct Redactor<'a> {
    opts: &'a RedactOptions,
    rules: Vec<CompiledRule>,
    exclusions: Vec<Exclusion>,
    map: HashMap<(Kind, String), usize>,
    entries: Vec<MappingEntry>,
    counters: HashMap<Kind, usize>,
    replacements: usize,
    emails: usize,
    private_keys: usize,
}

impl<'a> Redactor<'a> {
    fn new(opts: &'a RedactOptions) -> Result<Self, RedactError> {
        if opts.rules.len() > MAX_RULES {
            return Err(RedactError::TooManyRules);
        }
        if opts.exclusions.len() > MAX_EXCLUSIONS {
            return Err(RedactError::TooManyExclusions);
        }
        let mut rules = Vec::new();
        for (i, r) in opts.rules.iter().enumerate() {
            let n = i + 1;
            if r.find.chars().count() > MAX_RULE_LEN || r.replace.chars().count() > MAX_RULE_LEN {
                return Err(RedactError::RuleTooLong(n));
            }
            if r.find.trim().is_empty() {
                return Err(RedactError::EmptyRule(n));
            }
            let pattern = if r.regex {
                r.find.clone()
            } else {
                regex::escape(r.find.trim())
            };
            let re = RegexBuilder::new(&pattern)
                .case_insensitive(true)
                .size_limit(RULE_REGEX_SIZE)
                .build()
                .map_err(|e| RedactError::BadRegex(n, e.to_string()))?;
            if re.is_match("") {
                return Err(RedactError::EmptyRule(n));
            }
            rules.push(CompiledRule {
                re,
                replace: r.replace.trim().to_string(),
            });
        }
        let exclusions = opts
            .exclusions
            .iter()
            .filter(|e| e.chars().count() <= MAX_RULE_LEN)
            .filter_map(|e| parse_exclusion(e))
            .collect();
        Ok(Self {
            opts,
            rules,
            exclusions,
            map: HashMap::new(),
            entries: Vec::new(),
            counters: HashMap::new(),
            replacements: 0,
            emails: 0,
            private_keys: 0,
        })
    }

    fn excluded(&self, kind: Kind, value: &str) -> bool {
        if kind == Kind::Secret || kind == Kind::Custom {
            return false;
        }
        let v = value.trim_end_matches('.').to_lowercase();
        let v4 = v.parse::<Ipv4Addr>().ok().map(u32::from);
        self.exclusions.iter().any(|e| match e {
            Exclusion::Text(t) => v == *t || (kind == Kind::Host && v.ends_with(&format!(".{t}"))),
            Exclusion::V4Net(net, mask) => v4.is_some_and(|a| a & mask == *net),
        })
    }

    /// The token for `original`, or None when it is excluded or already a token.
    fn token(&mut self, kind: Kind, original: &str) -> Option<String> {
        let original = original.trim();
        if original.is_empty() || TOKEN.is_match(original) || self.excluded(kind, original) {
            return None;
        }
        let key = match kind {
            Kind::Secret | Kind::Custom => original.to_string(),
            _ => original.trim_end_matches('.').to_lowercase(),
        };
        self.replacements += 1;
        if let Some(&i) = self.map.get(&(kind, key.clone())) {
            self.entries[i].count += 1;
            return Some(self.entries[i].token.clone());
        }
        let n = self.counters.entry(kind).or_insert(0);
        *n += 1;
        let token = format!("[{}-{}]", kind.prefix(), n);
        self.map.insert((kind, key), self.entries.len());
        self.entries.push(MappingEntry {
            kind,
            original: original.to_string(),
            token: token.clone(),
            count: 1,
        });
        Some(token)
    }

    fn token_or(&mut self, kind: Kind, original: &str) -> String {
        self.token(kind, original)
            .unwrap_or_else(|| original.to_string())
    }

    /// A manual rule with a fixed replacement still shows in the preview.
    fn fixed(&mut self, original: &str, replacement: &str) -> String {
        self.replacements += 1;
        let key = (Kind::Custom, format!("{original}\u{0}{replacement}"));
        if let Some(&i) = self.map.get(&key) {
            self.entries[i].count += 1;
        } else {
            self.map.insert(key, self.entries.len());
            self.entries.push(MappingEntry {
                kind: Kind::Custom,
                original: original.to_string(),
                token: replacement.to_string(),
                count: 1,
            });
        }
        replacement.to_string()
    }

    /// Redact a whole field whose label says what it holds.
    fn whole(&mut self, kind: Kind, value: &str) -> Option<String> {
        let v = value.trim();
        if v.is_empty() || v == "-" || TOKEN.is_match(v) {
            return None;
        }
        if kind == Kind::User && BUILTIN_USERS.contains(&v.to_lowercase().as_str()) {
            return None;
        }
        // A list ("a, b") is redacted item by item.
        if kind != Kind::Secret && v.contains(", ") {
            let parts: Vec<String> = v.split(", ").map(|p| self.token_or(kind, p)).collect();
            return Some(parts.join(", "));
        }
        self.token(kind, v)
    }

    fn text(&mut self, s: &str) -> String {
        if s.is_empty() {
            return String::new();
        }
        let mut out = s.to_string();

        for i in 0..self.rules.len() {
            let re = self.rules[i].re.clone();
            let replace = self.rules[i].replace.clone();
            out = re
                .replace_all(&out, |c: &Captures| {
                    let m = &c[0];
                    if replace.is_empty() {
                        self.token_or(Kind::Custom, m)
                    } else {
                        self.fixed(m, &replace)
                    }
                })
                .into_owned();
        }

        if self.opts.secrets {
            out = PRIVATE_KEY
                .replace_all(&out, |_: &Captures| {
                    self.private_keys += 1;
                    self.replacements += 1;
                    "[PRIVATE KEY REMOVED]".to_string()
                })
                .into_owned();
            out = SECRET_CONFIG
                .replace_all(&out, |c: &Captures| {
                    format!(
                        "{}{}{}{}",
                        &c[1],
                        &c[2],
                        &c[3],
                        self.token_or(Kind::Secret, &c[4])
                    )
                })
                .into_owned();
            out = SECRET_KV
                .replace_all(&out, |c: &Captures| {
                    let v = c[3].trim_matches(|ch| ch == '"' || ch == '\'');
                    if v.is_empty() {
                        return c[0].to_string();
                    }
                    format!("{}{}{}", &c[1], &c[2], self.token_or(Kind::Secret, v))
                })
                .into_owned();
            out = SECRET_STANDALONE
                .replace_all(&out, |c: &Captures| self.token_or(Kind::Secret, &c[0]))
                .into_owned();
        }

        if self.opts.emails {
            out = EMAIL
                .replace_all(&out, |c: &Captures| {
                    if self.excluded(Kind::Host, &c[2]) || self.excluded(Kind::User, &c[0]) {
                        return c[0].to_string();
                    }
                    self.emails += 1;
                    let user = self.token_or(Kind::User, &format!("{}@{}", &c[1], &c[2]));
                    let host = self.token_or(Kind::Host, &c[2]);
                    // The address as a whole maps to one user token; its domain
                    // keeps the same host token used elsewhere in the report.
                    format!("{user}@{host}")
                })
                .into_owned();
        }

        if self.opts.ips {
            out = V4_RUN
                .replace_all(&out, |c: &Captures| {
                    let m = &c[0];
                    match m.parse::<Ipv4Addr>() {
                        Ok(ip) if !keep_v4(ip) => self.token_or(Kind::Ip, m),
                        _ => m.to_string(),
                    }
                })
                .into_owned();
            out = V6_RUN
                .replace_all(&out, |c: &Captures| {
                    // A sentence may end right after the address.
                    let m = c[0].trim_end_matches('.');
                    let tail = &c[0][m.len()..];
                    if m.matches(':').count() < 2 {
                        return c[0].to_string();
                    }
                    match m.parse::<Ipv6Addr>() {
                        Ok(ip) if !keep_v6(ip) => {
                            format!("{}{tail}", self.token_or(Kind::Ip, &ip.to_string()))
                        }
                        _ => c[0].to_string(),
                    }
                })
                .into_owned();
        }

        if self.opts.usernames {
            out = USER_KV
                .replace_all(&out, |c: &Captures| {
                    let v = c[3].trim_matches('"');
                    match self.whole(Kind::User, v) {
                        Some(t) => format!("{}{}{}", &c[1], &c[2], t),
                        None => c[0].to_string(),
                    }
                })
                .into_owned();
            out = USER_DOMAIN
                .replace_all(&out, |c: &Captures| {
                    let full = format!("{}\\{}", &c[2], &c[3]);
                    if BUILTIN_USERS.contains(&c[3].to_lowercase().as_str())
                        || c[2].eq_ignore_ascii_case("nt authority")
                        || c[2].eq_ignore_ascii_case("authority")
                        || self.excluded(Kind::User, &full)
                    {
                        return c[0].to_string();
                    }
                    let domain = self.token_or(Kind::Host, &c[2]);
                    let user = self.token_or(Kind::User, &c[3]);
                    format!("{}{}\\{}", &c[1], domain, user)
                })
                .into_owned();
        }

        if self.opts.hostnames {
            out = HOSTNAME
                .replace_all(&out, |c: &Captures| {
                    let m = &c[0];
                    if looks_like_host(m) {
                        self.token_or(Kind::Host, m)
                    } else {
                        m.to_string()
                    }
                })
                .into_owned();
        }
        out
    }

    /// A value whose label (key or column header) says what it is.
    fn labelled(&mut self, label: &str, value: &str) -> String {
        let label = label.trim();
        let kind = if self.opts.secrets && KEY_SECRET.is_match(label) {
            Some(Kind::Secret)
        } else if self.opts.usernames && KEY_USER.is_match(label) {
            Some(Kind::User)
        } else if self.opts.hostnames && KEY_HOST.is_match(label) {
            Some(Kind::Host)
        } else {
            None
        };
        if let Some(kind) = kind {
            // IPs in a host column still get IP tokens.
            let is_ip = value.trim().parse::<std::net::IpAddr>().is_ok();
            if !is_ip && let Some(t) = self.whole(kind, value) {
                return t;
            }
        }
        self.text(value)
    }

    fn block(&mut self, b: &mut Block) {
        match b {
            Block::Paragraph { text } | Block::Code { text } => *text = self.text(text),
            Block::KeyValues { items } => {
                for kv in items {
                    kv.value = self.labelled(&kv.key, &kv.value);
                }
            }
            Block::Table { headers, rows } => {
                for row in rows {
                    for (i, cell) in row.iter_mut().enumerate() {
                        let header = headers.get(i).map(String::as_str).unwrap_or("");
                        *cell = self.labelled(header, cell);
                    }
                }
            }
            Block::Findings { items } => {
                for f in items {
                    f.title = self.text(&f.title);
                    f.detail = self.text(&f.detail);
                }
            }
            Block::Diff { lines } => {
                for l in lines {
                    l.text = self.text(&l.text);
                }
            }
        }
    }
}

/// Redact every value in `report`: title, subtitle, section headings and
/// all block content. Column headers, keys and the tool name are kept.
pub fn redact(report: &Report, opts: &RedactOptions) -> Result<Redacted, RedactError> {
    let mut r = Redactor::new(opts)?;
    let mut out = report.clone();
    out.title = r.text(&out.title);
    out.subtitle = r.text(&out.subtitle);
    for s in &mut out.sections {
        s.title = r.text(&s.title);
        s.subtitle = r.text(&s.subtitle);
        for b in &mut s.blocks {
            r.block(b);
        }
    }
    let mut mapping = r.entries;
    mapping.sort_by(|a, b| a.kind.cmp(&b.kind).then(b.count.cmp(&a.count)));
    let mapping_truncated = mapping.len() > MAX_PREVIEW;
    mapping.truncate(MAX_PREVIEW);
    Ok(Redacted {
        report: out,
        mapping,
        mapping_truncated,
        replacements: r.replacements,
        emails: r.emails,
        private_keys: r.private_keys,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::core::{Finding, KeyValue, Section, Severity};

    fn all() -> RedactOptions {
        RedactOptions::default()
    }

    fn one(s: &str) -> String {
        let opts = all();
        let mut r = Redactor::new(&opts).unwrap();
        r.text(s)
    }

    #[test]
    fn built_in_patterns_compile() {
        for p in [
            &*TOKEN,
            &*PRIVATE_KEY,
            &*SECRET_KV,
            &*SECRET_CONFIG,
            &*SECRET_STANDALONE,
            &*EMAIL,
            &*V4_RUN,
            &*V6_RUN,
            &*HOSTNAME,
            &*USER_KV,
            &*USER_DOMAIN,
            &*KEY_SECRET,
            &*KEY_USER,
            &*KEY_HOST,
        ] {
            assert!(!p.as_str().is_empty());
        }
    }

    #[test]
    fn ips_are_consistent_and_masks_kept() {
        let out = one(
            "10.1.1.5 talked to 10.1.1.6, then 10.1.1.5/24 again; mask 255.255.255.0, gw 0.0.0.0, lo 127.0.0.1",
        );
        assert_eq!(
            out,
            "[IP-1] talked to [IP-2], then [IP-1]/24 again; mask 255.255.255.0, gw 0.0.0.0, lo 127.0.0.1"
        );
        // OIDs, versions and sentence-ending dots.
        assert_eq!(
            one("OID 1.3.6.1.2.1.1.5.0 v1.2.3"),
            "OID 1.3.6.1.2.1.1.5.0 v1.2.3"
        );
        assert_eq!(one("from 192.0.2.7."), "from [IP-1].");
        assert_eq!(one("999.1.1.1"), "999.1.1.1");
    }

    #[test]
    fn ipv6_but_not_macs_or_times() {
        assert_eq!(
            one("src 2001:db8::1 and 2001:DB8:0::1"),
            "src [IP-1] and [IP-1]"
        );
        assert_eq!(
            one("mac 00:11:22:33:44:55 at 14:05:10"),
            "mac 00:11:22:33:44:55 at 14:05:10"
        );
        assert_eq!(one("listen :: and ::1"), "listen :: and ::1");
    }

    #[test]
    fn hostnames_but_not_files() {
        assert_eq!(
            one(
                "mail.corp.example.com and MAIL.corp.example.com. ran svchost.exe from report.ts on Node.js"
            ),
            "[HOST-1] and [HOST-1]. ran svchost.exe from report.ts on Node.js"
        );
        assert_eq!(one("dc01.acme.local"), "[HOST-1]");
        assert_eq!(one("e.g. this"), "e.g. this");
        assert_eq!(
            one("System.Security.Principal"),
            "System.Security.Principal"
        );
    }

    #[test]
    fn emails_share_the_domain_token() {
        let out = one("alice@acme.com wrote to bob@acme.com via mx.acme.com; alice@acme.com again");
        assert_eq!(
            out,
            "[USER-1]@[HOST-1] wrote to [USER-2]@[HOST-1] via [HOST-2]; [USER-1]@[HOST-1] again"
        );
    }

    #[test]
    fn secrets_in_config_and_kv() {
        assert_eq!(
            one("set password ENC SH2abcdef123"),
            "set password ENC [SECRET-1]"
        );
        assert_eq!(
            one("set psksecret ENC xyz=="),
            "set psksecret ENC [SECRET-1]"
        );
        assert_eq!(
            one("enable secret 5 $1$abc$def"),
            "enable secret 5 [SECRET-1]"
        );
        assert_eq!(
            one("username admin password 7 0822455D0A16"),
            "username admin password 7 [SECRET-1]"
        );
        assert_eq!(
            one("snmp-server community s3cret RO"),
            "snmp-server community [SECRET-1] RO"
        );
        assert_eq!(
            one("password=hunter2, token: \"abc def\""),
            "password=[SECRET-1], token: [SECRET-2]"
        );
        assert_eq!(one("the password policy"), "the password policy");
        let key =
            "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\nBBBB\n-----END OPENSSH PRIVATE KEY-----";
        assert_eq!(
            one(&format!("key:\n{key}\nend")),
            "key:\n[PRIVATE KEY REMOVED]\nend"
        );
        assert_eq!(one("AKIAABCDEFGHIJKLMNOP"), "[SECRET-1]");
        assert_eq!(
            one("Authorization: Bearer abcdefghijklmnop1234"),
            "Authorization: [SECRET-1]"
        );
    }

    #[test]
    fn usernames() {
        assert_eq!(one("TargetUserName: alice"), "TargetUserName: [USER-1]");
        assert_eq!(one("logon by ACME\\bob"), "logon by [HOST-1]\\[USER-1]");
        assert_eq!(
            one("C:\\Windows\\System32\\cmd.exe"),
            "C:\\Windows\\System32\\cmd.exe"
        );
        assert_eq!(one("NT AUTHORITY\\SYSTEM"), "NT AUTHORITY\\SYSTEM");
        assert_eq!(one("user=SYSTEM"), "user=SYSTEM");
    }

    #[test]
    fn rules_and_exclusions() {
        let opts = RedactOptions {
            rules: vec![
                Rule {
                    find: "Acme Widgets".into(),
                    replace: "Customer".into(),
                    regex: false,
                },
                Rule {
                    find: r"TICKET-\d+".into(),
                    replace: String::new(),
                    regex: true,
                },
            ],
            exclusions: vec!["example.net".into(), "192.0.2.0/24".into()],
            ..all()
        };
        let mut r = Redactor::new(&opts).unwrap();
        assert_eq!(
            r.text("ACME widgets ticket-42 ns1.example.net 192.0.2.9 198.51.100.1"),
            "Customer [CUSTOM-1] ns1.example.net 192.0.2.9 [IP-1]"
        );
        let bad = RedactOptions {
            rules: vec![Rule {
                find: "(".into(),
                replace: String::new(),
                regex: true,
            }],
            ..all()
        };
        assert!(matches!(
            Redactor::new(&bad),
            Err(RedactError::BadRegex(1, _))
        ));
        let empty = RedactOptions {
            rules: vec![Rule {
                find: "x*".into(),
                replace: String::new(),
                regex: true,
            }],
            ..all()
        };
        assert!(matches!(
            Redactor::new(&empty),
            Err(RedactError::EmptyRule(1))
        ));
    }

    #[test]
    fn categories_can_be_turned_off() {
        let opts = RedactOptions {
            hostnames: false,
            ips: false,
            ..all()
        };
        let mut r = Redactor::new(&opts).unwrap();
        assert_eq!(
            r.text("host.acme.com 10.0.0.1 password=x"),
            "host.acme.com 10.0.0.1 password=[SECRET-1]"
        );
    }

    #[test]
    fn whole_report_with_labels_and_mapping() {
        let report = Report {
            title: "Scan of fw1.acme.com".into(),
            subtitle: "10.9.9.1".into(),
            generated: "now".into(),
            tool: "Port Scanner".into(),
            sections: vec![Section {
                title: "Hosts".into(),
                blocks: vec![
                    Block::KeyValues {
                        items: vec![
                            KeyValue {
                                key: "Community".into(),
                                value: "public".into(),
                            },
                            KeyValue {
                                key: "Computer".into(),
                                value: "WS01".into(),
                            },
                            KeyValue {
                                key: "Target".into(),
                                value: "10.9.9.1".into(),
                            },
                        ],
                    },
                    Block::Table {
                        headers: vec!["User".into(), "Host".into()],
                        rows: vec![
                            vec!["alice".into(), "10.9.9.1".into()],
                            vec!["-".into(), "WS01, WS02".into()],
                        ],
                    },
                    Block::Findings {
                        items: vec![Finding {
                            severity: Severity::Warn,
                            category: String::new(),
                            title: "fw1.acme.com open".into(),
                            detail: String::new(),
                        }],
                    },
                ],
                ..Default::default()
            }],
        };
        let out = redact(&report, &all()).unwrap();
        assert_eq!(out.report.title, "Scan of [HOST-1]");
        assert_eq!(out.report.subtitle, "[IP-1]");
        let Block::KeyValues { items } = &out.report.sections[0].blocks[0] else {
            panic!()
        };
        assert_eq!(items[0].value, "[SECRET-1]");
        assert_eq!(items[1].value, "[HOST-2]");
        assert_eq!(items[2].value, "[IP-1]");
        let Block::Table { rows, .. } = &out.report.sections[0].blocks[1] else {
            panic!()
        };
        assert_eq!(rows[0], vec!["[USER-1]", "[IP-1]"]);
        assert_eq!(rows[1], vec!["-", "[HOST-2], [HOST-3]"]);
        let Block::Findings { items } = &out.report.sections[0].blocks[2] else {
            panic!()
        };
        assert_eq!(items[0].title, "[HOST-1] open");
        // The mapping is for preview; the report itself holds no originals.
        let json = serde_json::to_string(&out.report).unwrap();
        for m in &out.mapping {
            assert!(!json.contains(&m.original), "{} leaked", m.original);
        }
        assert_eq!(out.report.tool, "Port Scanner");
        let ip = out.mapping.iter().find(|m| m.token == "[IP-1]").unwrap();
        assert_eq!(ip.count, 3);
    }

    #[test]
    fn rendered_exports_hold_no_originals() {
        use crate::report::core::{Format, render};
        let report = Report {
            title: "Event log: dc01.acme.local".into(),
            subtitle: String::new(),
            generated: "now".into(),
            tool: "Windows Event Log".into(),
            sections: vec![Section {
                title: "Matching events".into(),
                blocks: vec![
                    Block::Table {
                        headers: vec!["Time".into(), "ID".into(), "Computer".into(), "Details".into()],
                        rows: vec![vec![
                            "2026-11-13 14:05:10 UTC".into(),
                            "4624".into(),
                            "DC01".into(),
                            "Logon: TargetUserName: jsmith, from 203.0.113.5 (ACME\\jsmith)".into(),
                        ]],
                    },
                    Block::Code {
                        text: "config system admin\n  edit admin\n    set password ENC SH2xyz\n  next\nend".into(),
                    },
                    Block::Paragraph { text: "Contact it@acme.com or 2001:db8:1::25.".into() },
                ],
                ..Default::default()
            }],
        };
        let out = redact(&report, &all()).unwrap();
        let originals = [
            "dc01.acme.local",
            "DC01",
            "jsmith",
            "203.0.113.5",
            "SH2xyz",
            "it@acme.com",
            "acme.com",
            "2001:db8:1::25",
            "ACME\\",
        ];
        for format in [Format::Html, Format::Markdown, Format::Text] {
            let text = String::from_utf8(render(&out.report, format).unwrap()).unwrap();
            for o in originals {
                assert!(!text.contains(o), "{o} leaked into {format:?}");
            }
            assert!(text.contains("[USER-1]") && text.contains("4624"));
        }
        assert!(!render(&out.report, Format::Pdf).unwrap().is_empty());
    }

    #[test]
    fn limits() {
        let many = RedactOptions {
            rules: vec![
                Rule {
                    find: "a".into(),
                    ..Default::default()
                };
                MAX_RULES + 1
            ],
            ..all()
        };
        assert!(matches!(
            Redactor::new(&many),
            Err(RedactError::TooManyRules)
        ));
        let long = RedactOptions {
            rules: vec![Rule {
                find: "a".repeat(MAX_RULE_LEN + 1),
                ..Default::default()
            }],
            ..all()
        };
        assert!(matches!(
            Redactor::new(&long),
            Err(RedactError::RuleTooLong(1))
        ));
    }
}
