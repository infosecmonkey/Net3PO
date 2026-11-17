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
use super::fake::{self, FakeKey};

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
/// Largest text accepted by `redact_text`.
pub const MAX_TEXT: usize = 5 * 1024 * 1024;
/// Most mapping entries carried by one text session.
pub const MAX_SESSION: usize = 200_000;

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
    #[error("the text is larger than {} MB", MAX_TEXT / (1024 * 1024))]
    TextTooLarge,
    #[error("the session holds too many values (limit {MAX_SESSION}); start a new session")]
    SessionFull,
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
    /// MAC addresses.
    pub macs: bool,
    /// Device serial numbers (Fortinet formats and `serial: x` fields).
    pub serials: bool,
    /// Remove certificate blocks (they name the organization).
    pub certificates: bool,
    /// Replace IPs and MACs with keyed fake addresses that keep subnets and
    /// vendor prefixes, instead of numbered tokens. Needs a session key.
    pub fake_addresses: bool,
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
            macs: false,
            serials: false,
            certificates: false,
            fake_addresses: false,
            exclusions: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "camelCase")]
pub enum Kind {
    Custom,
    Secret,
    Ip,
    Host,
    User,
    Mac,
    Serial,
}

impl Kind {
    fn prefix(self) -> &'static str {
        match self {
            Self::Custom => "CUSTOM",
            Self::Secret => "SECRET",
            Self::Ip => "IP",
            Self::Host => "HOST",
            Self::User => "USER",
            Self::Mac => "MAC",
            Self::Serial => "SERIAL",
        }
    }
}

/// One original value and its replacement, for the preview.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
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

/// Text that already holds a replacement somewhere inside.
static HAS_TOKEN: LazyLock<Regex> =
    LazyLock::new(|| re(r"\[[A-Z]+-\d+\]|\[(?:PRIVATE KEY|CERTIFICATE) REMOVED\]"));

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

static CERTIFICATE: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"-----BEGIN [A-Z0-9 ]*CERTIFICATE(?: REQUEST)?-----[\s\S]*?-----END [A-Z0-9 ]*CERTIFICATE(?: REQUEST)?-----",
    )
});

/// FortiOS shows every stored secret as `set <name> ENC <value>`.
static FORTI_ENC: LazyLock<Regex> =
    LazyLock::new(|| re(r#"(?m)(\bset\s+[a-z0-9-]+\s+ENC\s+)("[^"\r\n]*"|\S+)"#));

/// `set hostname "x"`, `hostname x`, `sysname x`, `Hostname: x`.
static HOST_CMD: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r#"(?im)^([ \t]*(?:(?:set[ \t]+)?host-?name|sysname|switchname)(?:[ \t]*[:=][ \t]*|[ \t]+))("[^"\r\n]+"|[^\s"]+)"#,
    )
});

/// Config lines that name an account: `set username x`, LDAP bind users.
static SET_USER: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r#"(?im)^([ \t]*set[ \t]+(?:username|admin-username|ldap-username|bind-user|sso-username)[ \t]+)("[^"\r\n]*"|\S+)"#,
    )
});

/// MAC addresses: `00:11:22:33:44:55`, `00-11-22-33-44-55`, `0011.2233.4455`.
pub(crate) static MAC: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"(?i)\b(?:[0-9a-f]{2}(?::[0-9a-f]{2}){5}|[0-9a-f]{2}(?:-[0-9a-f]{2}){5}|[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})\b",
    )
});

/// Fortinet serial numbers (`FGT60F...`, `FGVM...`, `FAP...`, FortiSwitch `S124...`).
static SERIAL: LazyLock<Regex> = LazyLock::new(|| {
    re(r"\b(?:F[A-Z][A-Z0-9]{6,14}[0-9]{6}|S[0-9]{3}[A-Z][A-Z0-9]{3,10}[0-9]{6})\b")
});

/// `Serial-Number: x`, `serial=x`, `S/N: x`.
static SERIAL_KV: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r#"(?i)\b(serial(?:[ _-]?(?:number|no|num))?|s/n)(\s*[:=]\s*)("[^"\r\n]*"|[A-Za-z0-9][A-Za-z0-9-]{4,63})"#,
    )
});

static EMAIL: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"(?i)\b([a-z0-9][a-z0-9._%+-]{0,63})@([a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?)+)\b",
    )
});

/// A run of digits and dots; checked afterwards for exactly four octets, so
/// OIDs (1.3.6.1.2.1) and versions (1.2.3) are left alone.
pub(crate) static V4_RUN: LazyLock<Regex> = LazyLock::new(|| re(r"[0-9][0-9.]*[0-9]"));

/// Candidate IPv6 text; parsed afterwards. MACs and times do not parse.
pub(crate) static V6_RUN: LazyLock<Regex> =
    LazyLock::new(|| re(r"(?i)[0-9a-f:]*:[0-9a-f:]*[0-9a-f.]*"));

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
    "admin",
    "root",
];

/// FortiOS sections whose `edit` names are accounts.
const USER_SECTIONS: &[&str] = &["system admin", "user local", "system snmp user"];

fn looks_like_host(s: &str) -> bool {
    let s = s.trim_end_matches('.');
    if MAC.is_match(s) && MAC.find(s).is_some_and(|m| m.len() == s.len()) {
        return false;
    }
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
    certificates: usize,
    /// Set for fake addresses.
    key: Option<FakeKey>,
}

/// The lookup key for an original value.
fn norm(kind: Kind, original: &str) -> String {
    match kind {
        Kind::Secret | Kind::Custom => original.to_string(),
        Kind::Mac => original
            .chars()
            .filter(char::is_ascii_hexdigit)
            .collect::<String>()
            .to_ascii_lowercase(),
        _ => original.trim_end_matches('.').to_lowercase(),
    }
}

fn fake_ip(key: &FakeKey, s: &str) -> Option<String> {
    if let Ok(v4) = s.parse::<Ipv4Addr>() {
        return Some(fake::fake_v4(key, v4).to_string());
    }
    s.parse::<Ipv6Addr>()
        .ok()
        .map(|v6| fake::fake_v6(key, v6).to_string())
}

/// Split a FortiOS value list (`"a" "b c" d`) keeping each item's quotes.
fn forti_items(rest: &str) -> Vec<(bool, &str)> {
    let mut out = Vec::new();
    let mut s = rest.trim();
    while !s.is_empty() {
        if let Some(r) = s.strip_prefix('"') {
            let end = r.find('"').unwrap_or(r.len());
            out.push((true, &r[..end]));
            s = r.get(end + 1..).unwrap_or("").trim_start();
        } else {
            let end = s.find(char::is_whitespace).unwrap_or(s.len());
            out.push((false, &s[..end]));
            s = s[end..].trim_start();
        }
    }
    out
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
            certificates: 0,
            key: None,
        })
    }

    /// Continue a text session: earlier values keep their replacements.
    fn seed(&mut self, entries: &[MappingEntry]) {
        for e in entries {
            let key = if e.kind == Kind::Custom && !TOKEN.is_match(&e.token) {
                format!("{}\u{0}{}", e.original, e.token)
            } else {
                norm(e.kind, &e.original)
            };
            if self.map.contains_key(&(e.kind, key.clone())) {
                continue;
            }
            if let Some(n) = e
                .token
                .strip_prefix(&format!("[{}-", e.kind.prefix()))
                .and_then(|t| t.strip_suffix(']'))
                .and_then(|t| t.parse::<usize>().ok())
            {
                let c = self.counters.entry(e.kind).or_insert(0);
                *c = (*c).max(n);
            }
            self.map.insert((e.kind, key), self.entries.len());
            self.entries.push(MappingEntry {
                count: 0,
                ..e.clone()
            });
        }
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
        if original.is_empty() || HAS_TOKEN.is_match(original) || self.excluded(kind, original) {
            return None;
        }
        let key = norm(kind, original);
        if let Some(&i) = self.map.get(&(kind, key.clone())) {
            self.replacements += 1;
            self.entries[i].count += 1;
            return Some(self.entries[i].token.clone());
        }
        let fake = match (kind, &self.key) {
            (Kind::Ip, Some(k)) => fake_ip(k, original),
            (Kind::Mac, Some(k)) => fake::fake_mac(k, original),
            _ => None,
        };
        let token = match fake {
            // Protocol constants and documentation addresses stay as they are.
            Some(f) if f.eq_ignore_ascii_case(original) => return None,
            Some(f) => f,
            None => {
                let n = self.counters.entry(kind).or_insert(0);
                *n += 1;
                format!("[{}-{}]", kind.prefix(), n)
            }
        };
        self.replacements += 1;
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
            out = FORTI_ENC
                .replace_all(&out, |c: &Captures| {
                    let v = c[2].trim_matches('"');
                    format!("{}{}", &c[1], self.token_or(Kind::Secret, v))
                })
                .into_owned();
            out = SECRET_CONFIG
                .replace_all(&out, |c: &Captures| {
                    // Already replaced (a removed key block or a token).
                    if c[4].trim_start_matches('"').starts_with('[') {
                        return c[0].to_string();
                    }
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

        if self.opts.certificates {
            out = CERTIFICATE
                .replace_all(&out, |_: &Captures| {
                    self.certificates += 1;
                    self.replacements += 1;
                    "[CERTIFICATE REMOVED]".to_string()
                })
                .into_owned();
        }

        out = self.forti_context(&out);

        if self.opts.usernames {
            out = SET_USER
                .replace_all(&out, |c: &Captures| {
                    let quoted = c[2].starts_with('"');
                    let v = c[2].trim_matches('"');
                    match self.whole(Kind::User, v) {
                        Some(t) if quoted => format!("{}\"{t}\"", &c[1]),
                        Some(t) => format!("{}{t}", &c[1]),
                        None => c[0].to_string(),
                    }
                })
                .into_owned();
        }

        if self.opts.hostnames {
            out = self.host_commands(&out);
        }

        if self.opts.serials {
            out = SERIAL_KV
                .replace_all(&out, |c: &Captures| {
                    let v = c[3].trim_matches('"');
                    if !v.bytes().any(|b| b.is_ascii_digit()) {
                        return c[0].to_string();
                    }
                    format!("{}{}{}", &c[1], &c[2], self.token_or(Kind::Serial, v))
                })
                .into_owned();
            out = SERIAL
                .replace_all(&out, |c: &Captures| self.token_or(Kind::Serial, &c[0]))
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

        if self.opts.macs {
            out = MAC
                .replace_all(&out, |c: &Captures| self.token_or(Kind::Mac, &c[0]))
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

    /// FortiOS config context: account names under `config system admin`
    /// and `config user local`, group members, SNMP community names.
    fn forti_context(&mut self, s: &str) -> String {
        if !(self.opts.usernames || self.opts.secrets) || !s.contains("config ") {
            return s.to_string();
        }
        let mut stack: Vec<String> = Vec::new();
        let mut out = String::with_capacity(s.len());
        for line in s.split_inclusive('\n') {
            let body = line.trim_end_matches(['\r', '\n']);
            let eol = &line[body.len()..];
            let t = body.trim_start();
            let indent = &body[..body.len() - t.len()];
            let lower = t.to_ascii_lowercase();
            let mut new = None;
            if let Some(rest) = lower.strip_prefix("config ") {
                stack.push(rest.split_whitespace().collect::<Vec<_>>().join(" "));
            } else if lower == "end" {
                stack.pop();
            } else if let Some(top) = stack.last() {
                let users = self.opts.usernames;
                if users && USER_SECTIONS.contains(&top.as_str()) && lower.starts_with("edit ") {
                    new = self.forti_values(indent, &t[..5], &t[5..], Kind::User);
                } else if users && top == "user group" && lower.starts_with("set member ") {
                    new = self.forti_values(indent, &t[..11], &t[11..], Kind::User);
                } else if self.opts.secrets
                    && top == "system snmp community"
                    && lower.starts_with("set name ")
                {
                    new = self.forti_values(indent, &t[..9], &t[9..], Kind::Secret);
                }
            }
            out.push_str(new.as_deref().unwrap_or(body));
            out.push_str(eol);
        }
        out
    }

    fn forti_values(&mut self, indent: &str, kw: &str, rest: &str, kind: Kind) -> Option<String> {
        let mut changed = false;
        let mut parts = Vec::new();
        for (quoted, v) in forti_items(rest) {
            let t = self.whole(kind, v);
            changed |= t.is_some();
            let v = t.unwrap_or_else(|| v.to_string());
            parts.push(if quoted { format!("\"{v}\"") } else { v });
        }
        changed.then(|| format!("{indent}{kw}{}", parts.join(" ")))
    }

    /// Device names from hostname commands, then every other place the same
    /// name appears (prompts, log prefixes).
    fn host_commands(&mut self, s: &str) -> String {
        let mut learned: Vec<(String, String)> = Vec::new();
        let out = HOST_CMD
            .replace_all(s, |c: &Captures| {
                let quoted = c[2].starts_with('"');
                let v = c[2].trim_matches('"');
                match self.whole(Kind::Host, v) {
                    Some(t) => {
                        learned.push((v.to_string(), t.clone()));
                        if quoted {
                            format!("{}\"{t}\"", &c[1])
                        } else {
                            format!("{}{t}", &c[1])
                        }
                    }
                    None => c[0].to_string(),
                }
            })
            .into_owned();
        let mut out = out;
        for (name, token) in learned {
            let edges = name.starts_with(|c: char| c.is_ascii_alphanumeric())
                && name.ends_with(|c: char| c.is_ascii_alphanumeric());
            if name.len() < 3 || !edges || name.bytes().all(|b| b.is_ascii_digit()) {
                continue;
            }
            let Ok(re) = RegexBuilder::new(&format!(r"\b{}\b", regex::escape(&name)))
                .case_insensitive(true)
                .build()
            else {
                continue;
            };
            out = re
                .replace_all(&out, |_: &Captures| {
                    self.token_or(Kind::Host, &name);
                    token.clone()
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
            Block::Notes { items } => {
                for n in items {
                    n.heading = self.text(&n.heading);
                    n.text = self.text(&n.text);
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

/// Result of redacting free text in a session.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RedactedText {
    pub text: String,
    /// The session key, new when none (or an invalid one) was given.
    pub key: String,
    /// Every value in the session, earlier ones included (count 0 when not
    /// seen this time). Stays in memory in the app; never written to disk.
    pub mapping: Vec<MappingEntry>,
    pub replacements: usize,
    pub emails: usize,
    pub private_keys: usize,
    pub certificates: usize,
}

/// Redact free text. `seed` carries the session so far, so values seen in
/// earlier pastes keep their replacements; `key` drives fake addresses.
pub fn redact_text(
    text: &str,
    opts: &RedactOptions,
    key: &str,
    seed: &[MappingEntry],
) -> Result<RedactedText, RedactError> {
    if text.len() > MAX_TEXT {
        return Err(RedactError::TextTooLarge);
    }
    if seed.len() > MAX_SESSION {
        return Err(RedactError::SessionFull);
    }
    let key = FakeKey::from_hex(key).unwrap_or_else(FakeKey::generate);
    let mut r = Redactor::new(opts)?;
    if opts.fake_addresses {
        r.key = Some(key.clone());
    }
    r.seed(seed);
    let out = r.text(text);
    if r.entries.len() > MAX_SESSION {
        return Err(RedactError::SessionFull);
    }
    Ok(RedactedText {
        text: out,
        key: key.to_hex(),
        mapping: r.entries,
        replacements: r.replacements,
        emails: r.emails,
        private_keys: r.private_keys,
        certificates: r.certificates,
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
            &*HAS_TOKEN,
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
        // An email in a user field keeps its email tokens.
        assert_eq!(one("user=alice@acme.com"), "user=[USER-1]@[HOST-1]");
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
    fn notes_are_redacted() {
        use crate::report::core::NoteEntry;
        let report = Report {
            title: "t".into(),
            subtitle: String::new(),
            generated: String::new(),
            tool: String::new(),
            sections: vec![Section {
                blocks: vec![Block::Notes {
                    items: vec![NoteEntry {
                        heading: "Nov 14, fw1.acme.com".into(),
                        text: "Called alice@acme.com; 10.2.3.4 still drops, password=hunter2"
                            .into(),
                    }],
                }],
                ..Default::default()
            }],
        };
        let out = redact(&report, &all()).unwrap();
        let Block::Notes { items } = &out.report.sections[0].blocks[0] else {
            panic!()
        };
        assert_eq!(items[0].heading, "Nov 14, [HOST-1]");
        assert!(
            !items[0].text.contains("acme")
                && !items[0].text.contains("10.2.3.4")
                && !items[0].text.contains("hunter2")
        );
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

    fn text_opts() -> RedactOptions {
        RedactOptions {
            macs: true,
            serials: true,
            certificates: true,
            fake_addresses: true,
            ..all()
        }
    }

    const KEY: &str = "0101010101010101010101010101010101010101010101010101010101010101";

    #[test]
    fn fortios_config_text() {
        let cfg = "\
FW-LAB01 # show full-configuration
config system global
    set hostname \"FW-LAB01\"
    set admin-sport 8443
end
config system admin
    edit \"admin\"
        set password ENC SH2aaaabbbbcccc
    next
    edit \"jdoe\"
        set password ENC SH2ddddeeeeffff
    next
end
config user local
    edit \"svc-backup\"
        set passwd ENC Zm9vYmFy
    next
end
config user group
    edit \"vpn-users\"
        set member \"svc-backup\" \"jdoe\"
    next
end
config system snmp community
    edit 1
        set name \"n0tpublic\"
    next
end
config vpn certificate local
    edit \"srv\"
        set private-key \"-----BEGIN ENCRYPTED PRIVATE KEY-----
QUJD
-----END ENCRYPTED PRIVATE KEY-----\"
        set certificate \"-----BEGIN CERTIFICATE-----
REVG
-----END CERTIFICATE-----\"
    next
end
Serial-Number: FGT60FTK21000123
config system interface
    edit \"port1\"
        set ip 10.20.30.1 255.255.255.0
        set macaddr 00:09:0f:aa:bb:cc
    next
end
";
        let r = redact_text(cfg, &text_opts(), KEY, &[]).unwrap();
        let out = &r.text;
        for leaked in [
            "FW-LAB01",
            "SH2aaaa",
            "SH2dddd",
            "jdoe",
            "svc-backup",
            "Zm9vYmFy",
            "n0tpublic",
            "QUJD",
            "REVG",
            "FGT60FTK21000123",
            "10.20.30.1",
            "aa:bb:cc",
        ] {
            assert!(!out.contains(leaked), "{leaked} leaked:\n{out}");
        }
        assert!(out.contains("[HOST-1] # show full-configuration"), "{out}");
        assert!(out.contains("set hostname \"[HOST-1]\""));
        assert!(out.contains("edit \"admin\""));
        assert!(out.contains("set password ENC [SECRET-1]"));
        assert!(
            out.contains("set member \"[USER-2]\" \"[USER-1]\""),
            "{out}"
        );
        assert!(out.contains("set name \"[SECRET-"));
        assert!(
            out.contains("set private-key \"[PRIVATE KEY REMOVED]\""),
            "{out}"
        );
        assert!(out.contains("[CERTIFICATE REMOVED]"));
        assert!(out.contains("Serial-Number: [SERIAL-1]"));
        assert!(out.contains("set ip 10.") && out.contains(".1 255.255.255.0"));
        assert!(out.contains("set macaddr 00:09:0f:"));
        assert!(out.contains("set admin-sport 8443"));
        assert_eq!(r.certificates, 1);
        assert_eq!(r.private_keys, 1);
        assert_eq!(r.key, KEY);
    }

    #[test]
    fn sessions_carry_over() {
        let a = redact_text(
            "ping 10.9.8.7 as alice@acme.com, password=x1",
            &text_opts(),
            "",
            &[],
        )
        .unwrap();
        assert_eq!(a.key.len(), 64);
        let b = redact_text(
            "10.9.8.7 again, bob@acme.com, password=x2",
            &text_opts(),
            &a.key,
            &a.mapping,
        )
        .unwrap();
        let fake = a.mapping.iter().find(|m| m.kind == Kind::Ip).unwrap();
        assert!(b.text.starts_with(&fake.token), "{}", b.text);
        assert!(b.text.contains("[USER-2]@[HOST-1]"), "{}", b.text);
        assert!(b.text.contains("password=[SECRET-2]"));
        // Earlier values stay in the mapping with a zero count this time.
        let x1 = b.mapping.iter().find(|m| m.original == "x1").unwrap();
        assert_eq!(x1.count, 0);
        // Tokens mode numbers addresses instead.
        let t = redact_text(
            "10.9.8.7 00:09:0f:aa:bb:cc",
            &RedactOptions {
                fake_addresses: false,
                ..text_opts()
            },
            "",
            &[],
        )
        .unwrap();
        assert_eq!(t.text, "[IP-1] [MAC-1]");
    }

    #[test]
    fn text_limits() {
        let big = "a".repeat(MAX_TEXT + 1);
        assert_eq!(
            redact_text(&big, &text_opts(), "", &[]).unwrap_err(),
            RedactError::TextTooLarge
        );
        // Report redaction keeps its old defaults.
        let d = RedactOptions::default();
        assert!(!d.macs && !d.serials && !d.certificates && !d.fake_addresses);
    }
}
