//! Pure email header and message analysis. Parsing is done by `mail-parser`;
//! this module turns the result into a triage view: addresses and their
//! domains, the Received chain in time order with delays and skew, the
//! authentication results that mail systems *claimed*, DKIM signature tags
//! and alignment, lookalike domains, attachments (listed, never opened) and
//! indicators. Nothing here touches the network, and no body content is
//! rendered or executed.

use std::net::IpAddr;

use mail_parser::{Host, MessageParser};
use serde::Serialize;
use thiserror::Error;

use super::domains::{
    self, aligned_relaxed, aligned_strict, is_non_public, of_address, org_domain,
};
use super::lookalike::{self, Lookalike};
use crate::tools::script_decoder::ioc::{Collector, Ioc};

/// Largest input accepted (a full .eml with attachments).
pub const MAX_INPUT: usize = 15 * 1024 * 1024;
/// Most header fields listed in the raw view.
pub const MAX_HEADERS: usize = 1000;
/// Longest header value shown; longer values are cut with a marker.
pub const MAX_VALUE: usize = 8 * 1024;
/// Most Received hops analyzed.
pub const MAX_HOPS: usize = 100;
/// Most text scanned per body part for indicators.
const MAX_SCAN: usize = 2 * 1024 * 1024;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum EmailError {
    #[error("paste email headers or open a .eml file")]
    Empty,
    #[error("input is too large ({0} bytes; limit {MAX_INPUT})")]
    TooLarge(usize),
    #[error(
        "no email header fields were found; paste the full header block, starting at the first header line"
    )]
    NoHeaders,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Sev {
    Pass,
    Info,
    Warn,
    Fail,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    pub severity: Sev,
    pub category: String,
    pub title: String,
    pub detail: String,
}

fn finding(
    severity: Sev,
    category: &str,
    title: impl Into<String>,
    detail: impl Into<String>,
) -> Finding {
    Finding {
        severity,
        category: category.to_string(),
        title: title.into(),
        detail: detail.into(),
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AddressRow {
    /// From, Sender, Reply-To, Return-Path, To, Cc.
    pub role: String,
    pub name: String,
    pub address: String,
    pub domain: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Hop {
    /// 1 is the earliest hop.
    pub index: usize,
    pub from_host: String,
    pub helo: String,
    pub from_ip: String,
    /// Reverse DNS name the receiving server recorded for `from_ip`.
    pub from_rdns: String,
    pub by_host: String,
    pub protocol: String,
    pub tls: String,
    pub id: String,
    pub for_addr: String,
    /// Unix seconds, when the date parsed.
    pub timestamp: Option<i64>,
    /// The hop's date as written.
    pub date: String,
    /// Seconds since the previous hop; negative means clock skew or a
    /// reordered or forged line.
    pub delay_secs: Option<i64>,
    pub non_public_ip: bool,
    pub parsed: bool,
    pub raw: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct OriginGuess {
    pub ip: String,
    pub host: String,
    pub hop: usize,
    /// "handoff" (entered the receiving organization) or "earliest" (first
    /// public address in the chain).
    pub basis: String,
    pub explanation: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AuthMethod {
    pub method: String,
    pub result: String,
    /// Properties such as smtp.mailfrom, header.d, header.from, reason.
    pub props: Vec<(String, String)>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AuthResults {
    /// Authentication-Results or ARC-Authentication-Results.
    pub header: String,
    /// The mail system that wrote the result (authserv-id).
    pub authserv_id: String,
    /// ARC instance number, for ARC-Authentication-Results.
    pub instance: Option<u32>,
    pub methods: Vec<AuthMethod>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DkimSig {
    pub domain: String,
    pub selector: String,
    pub algorithm: String,
    pub canonicalization: String,
    pub identity: String,
    pub signed_headers: Vec<String>,
    pub timestamp: Option<i64>,
    pub expires: Option<i64>,
    pub body_length: Option<u64>,
    /// "strict", "relaxed" or "none", against the From domain.
    pub alignment: String,
    /// `selector._domainkey.domain`, the DNS name holding the public key.
    pub key_name: String,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Attachment {
    pub name: String,
    pub content_type: String,
    /// Encoded size in the message, in bytes.
    pub size: usize,
    pub risky: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DomainRow {
    pub domain: String,
    /// Display form for internationalized names.
    pub unicode: String,
    pub roles: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EmailAnalysis {
    /// "headers" (no body) or "message".
    pub input_kind: String,
    pub subject: String,
    pub date: String,
    pub date_ts: Option<i64>,
    pub message_id: String,
    pub addresses: Vec<AddressRow>,
    pub domains: Vec<DomainRow>,
    pub hops: Vec<Hop>,
    pub origin: Vec<OriginGuess>,
    pub auth_results: Vec<AuthResults>,
    pub received_spf: Vec<String>,
    pub dkim: Vec<DkimSig>,
    pub arc_sets: usize,
    pub lookalikes: Vec<Lookalike>,
    pub attachments: Vec<Attachment>,
    pub text_parts: usize,
    pub html_parts: usize,
    pub iocs: Vec<Ioc>,
    pub notable_headers: Vec<(String, String)>,
    pub headers: Vec<(String, String)>,
    pub findings: Vec<Finding>,
}

/// Header names shown in the "notable" list when present.
const NOTABLE: &[&str] = &[
    "x-mailer",
    "user-agent",
    "x-originating-ip",
    "x-sender-ip",
    "x-spam-status",
    "x-spam-score",
    "x-spam-flag",
    "x-spam-level",
    "x-ms-exchange-organization-scl",
    "x-ms-exchange-organization-authas",
    "x-microsoft-antispam",
    "x-forefront-antispam-report",
    "x-ms-exchange-crosstenant-originalarrivaltime",
    "list-unsubscribe",
    "list-id",
    "precedence",
    "x-priority",
    "importance",
    "auto-submitted",
    "x-auto-response-suppress",
];

/// Attachment extensions that deserve a second look before anyone opens them.
const RISKY_EXT: &[&str] = &[
    "exe", "scr", "com", "pif", "bat", "cmd", "ps1", "vbs", "vbe", "js", "jse", "wsf", "wsh",
    "hta", "msi", "msix", "jar", "lnk", "iso", "img", "vhd", "vhdx", "one", "html", "htm", "svg",
    "docm", "xlsm", "pptm", "dotm", "xlam", "zip", "rar", "7z", "cab", "ace", "arj",
];

/// Unfold a raw header value and squeeze whitespace.
fn unfold(raw: &[u8]) -> String {
    let s = String::from_utf8_lossy(raw);
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn clip(s: String) -> String {
    if s.len() <= MAX_VALUE {
        return s;
    }
    let mut end = MAX_VALUE;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{} [cut at {MAX_VALUE} bytes]", &s[..end])
}

fn host_str(h: Option<Host<'_>>) -> String {
    match h {
        Some(Host::Name(n)) => n.to_string(),
        Some(Host::IpAddr(ip)) => ip.to_string(),
        None => String::new(),
    }
}

/// Remove RFC 5322 comments `( ... )`, honoring nesting and quoted strings.
pub fn strip_comments(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut depth = 0usize;
    let mut quoted = false;
    let mut escaped = false;
    for c in s.chars() {
        if escaped {
            if depth == 0 {
                out.push(c);
            }
            escaped = false;
            continue;
        }
        match c {
            '\\' => {
                escaped = true;
                if depth == 0 {
                    out.push(c);
                }
            }
            '"' if depth == 0 => {
                quoted = !quoted;
                out.push(c);
            }
            '(' if !quoted => depth += 1,
            ')' if !quoted && depth > 0 => depth -= 1,
            _ if depth == 0 => out.push(c),
            _ => {}
        }
    }
    out
}

/// Parse an Authentication-Results (or ARC-Authentication-Results) value.
pub fn parse_auth_results(header: &str, value: &str) -> AuthResults {
    let clean = strip_comments(value);
    let mut segments: Vec<&str> = clean
        .split(';')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    let mut instance = None;
    if let Some(first) = segments.first()
        && let Some(n) = first.strip_prefix("i=").and_then(|n| n.trim().parse().ok())
    {
        instance = Some(n);
        segments.remove(0);
    }
    // Microsoft 365 omits the authserv-id and starts with the first result.
    let has_id = segments
        .first()
        .and_then(|s| s.split_whitespace().next())
        .is_some_and(|t| !t.contains('='));
    let authserv_id = if has_id {
        segments[0]
            .split_whitespace()
            .next()
            .unwrap_or("")
            .to_ascii_lowercase()
    } else {
        String::new()
    };
    let mut methods = Vec::new();
    for seg in segments.iter().skip(usize::from(has_id)) {
        let mut tokens = seg.split_whitespace();
        let Some((method, result)) = tokens.next().and_then(|t| t.split_once('=')) else {
            continue;
        };
        let method = method
            .split('/')
            .next()
            .unwrap_or(method)
            .to_ascii_lowercase();
        let props = tokens
            .filter_map(|t| t.split_once('='))
            .map(|(k, v)| (k.to_ascii_lowercase(), v.trim_matches('"').to_string()))
            .collect();
        methods.push(AuthMethod {
            method,
            result: result.to_ascii_lowercase(),
            props,
        });
    }
    AuthResults {
        header: header.to_string(),
        authserv_id,
        instance,
        methods,
    }
}

/// Parse DKIM-Signature tags into a map, with whitespace removed from values
/// that may be folded (b, bh, h, z).
pub fn parse_tags(value: &str) -> Vec<(String, String)> {
    value
        .split(';')
        .filter_map(|t| t.split_once('='))
        .map(|(k, v)| {
            let k = k.trim().to_ascii_lowercase();
            let v: String = if matches!(k.as_str(), "b" | "bh" | "h" | "z") {
                v.chars().filter(|c| !c.is_whitespace()).collect()
            } else {
                v.trim().to_string()
            };
            (k, v)
        })
        .collect()
}

fn tag<'a>(tags: &'a [(String, String)], k: &str) -> Option<&'a str> {
    tags.iter()
        .find(|(key, _)| key == k)
        .map(|(_, v)| v.as_str())
}

/// Analyze one DKIM-Signature value against the From domain.
pub fn analyze_dkim(value: &str, from_domain: &str, message_ts: Option<i64>) -> DkimSig {
    let tags = parse_tags(value);
    let domain = domains::normalize(tag(&tags, "d").unwrap_or(""));
    let selector = tag(&tags, "s").unwrap_or("").trim().to_ascii_lowercase();
    let algorithm = tag(&tags, "a").unwrap_or("").to_ascii_lowercase();
    let signed_headers: Vec<String> = tag(&tags, "h")
        .unwrap_or("")
        .split(':')
        .filter(|h| !h.is_empty())
        .map(|h| h.to_ascii_lowercase())
        .collect();
    let timestamp = tag(&tags, "t").and_then(|t| t.parse().ok());
    let expires = tag(&tags, "x").and_then(|t| t.parse().ok());
    let body_length = tag(&tags, "l").and_then(|t| t.parse().ok());

    let alignment = if from_domain.is_empty() || domain.is_empty() {
        "none"
    } else if aligned_strict(&domain, from_domain) {
        "strict"
    } else if aligned_relaxed(&domain, from_domain) {
        "relaxed"
    } else {
        "none"
    };

    let mut notes = Vec::new();
    if domain.is_empty() || selector.is_empty() {
        notes.push("Missing d= or s= tag: the signature cannot be checked.".to_string());
    }
    if algorithm == "rsa-sha1" {
        notes.push(
            "rsa-sha1 is a legacy algorithm; RFC 8301 says verifiers should not accept it.".into(),
        );
    }
    if body_length.is_some() {
        notes.push("l= limits the signed body length, so text can be appended after signing without breaking the signature.".into());
    }
    if !signed_headers.iter().any(|h| h == "from") {
        notes.push("From is not in the signed header list (h=), which makes the signature invalid by RFC 6376.".into());
    }
    if let (Some(x), Some(t)) = (expires, message_ts)
        && x < t
    {
        notes.push("The signature had already expired (x=) at the message Date.".into());
    }
    if tag(&tags, "bh").is_none_or(str::is_empty) || tag(&tags, "b").is_none_or(str::is_empty) {
        notes.push("Body hash (bh=) or signature (b=) is missing or empty.".into());
    }

    DkimSig {
        key_name: if domain.is_empty() || selector.is_empty() {
            String::new()
        } else {
            format!("{selector}._domainkey.{domain}")
        },
        domain,
        selector,
        algorithm,
        canonicalization: tag(&tags, "c").unwrap_or("simple/simple").to_string(),
        identity: tag(&tags, "i").unwrap_or("").to_string(),
        signed_headers,
        timestamp,
        expires,
        body_length,
        alignment: alignment.to_string(),
        notes,
    }
}

/// Drop leading blank or indented lines some copy paths add, and normalize
/// line endings, so the header block starts at the first field.
fn tidy_input(raw: &[u8]) -> Vec<u8> {
    let text = String::from_utf8_lossy(raw);
    let mut lines = text.lines().skip_while(|l| l.trim().is_empty()).peekable();
    // Some web UIs indent every pasted line; strip a common leading indent.
    let indent = lines
        .peek()
        .map(|l| l.len() - l.trim_start().len())
        .unwrap_or(0);
    let mut out = String::with_capacity(text.len());
    for l in lines {
        let cut = if l.len() >= indent && l[..indent].trim().is_empty() {
            indent
        } else {
            0
        };
        out.push_str(&l[cut..]);
        out.push_str("\r\n");
    }
    out.into_bytes()
}

fn mailbox_rows(
    role: &str,
    list: Option<mail_parser::AddressList<'_>>,
    out: &mut Vec<AddressRow>,
    max: usize,
) {
    let Some(list) = list else { return };
    for m in list.mailboxes().take(max) {
        let address = m.address().unwrap_or("").to_string();
        out.push(AddressRow {
            role: role.to_string(),
            name: m.name().unwrap_or("").to_string(),
            domain: of_address(&address).unwrap_or_default(),
            address,
        });
    }
}

/// Analyze raw header text or a full message. `known` lists the customer's
/// genuine domains for the lookalike check.
pub fn analyze(raw: &[u8], known: &[String]) -> Result<EmailAnalysis, EmailError> {
    if raw.iter().all(|b| b.is_ascii_whitespace()) {
        return Err(EmailError::Empty);
    }
    if raw.len() > MAX_INPUT {
        return Err(EmailError::TooLarge(raw.len()));
    }
    let tidy = tidy_input(raw);
    let msg = MessageParser::new()
        .parse(&tidy)
        .ok_or(EmailError::NoHeaders)?;
    let headers = msg.headers();
    if headers.is_empty() || !headers.has_known() {
        return Err(EmailError::NoHeaders);
    }

    let mut findings = Vec::new();
    let date_ts = msg
        .date()
        .filter(|d| d.is_valid())
        .map(|d| d.to_timestamp());

    // Addresses.
    let mut addresses = Vec::new();
    mailbox_rows("From", msg.from(), &mut addresses, 5);
    mailbox_rows("Sender", msg.sender(), &mut addresses, 2);
    mailbox_rows("Reply-To", msg.reply_to(), &mut addresses, 5);
    if let Some(rp) = msg.return_address() {
        addresses.push(AddressRow {
            role: "Return-Path".into(),
            name: String::new(),
            domain: of_address(rp).unwrap_or_default(),
            address: rp.to_string(),
        });
    }
    mailbox_rows("To", msg.to(), &mut addresses, 10);
    mailbox_rows("Cc", msg.cc(), &mut addresses, 10);
    let first_domain = |role: &str| {
        addresses
            .iter()
            .find(|a| a.role == role && !a.domain.is_empty())
            .map(|a| a.domain.clone())
            .unwrap_or_default()
    };
    let from_domain = first_domain("From");
    let return_domain = first_domain("Return-Path");
    let reply_domain = first_domain("Reply-To");

    let from_count = headers.all("From").count();
    if from_count == 0 {
        findings.push(finding(
            Sev::Warn,
            "Sender",
            "No From header",
            "Every message must have one (RFC 5322).",
        ));
    } else if from_count > 1 {
        findings.push(finding(
            Sev::Fail,
            "Sender",
            format!("{from_count} From headers"),
            "Duplicate From headers are invalid and a known trick to show one sender while authenticating another.",
        ));
    }
    if let Some(a) = addresses.iter().find(|a| a.role == "From")
        && let Some(shown) = of_address(&a.name)
        && !a
            .name
            .to_ascii_lowercase()
            .contains(&a.address.to_ascii_lowercase())
    {
        findings.push(finding(
            Sev::Warn,
            "Sender",
            "Display name shows a different address",
            format!(
                "The name \"{}\" contains an address at {shown}, but the message is from {}.",
                a.name, a.address
            ),
        ));
    }
    if !reply_domain.is_empty()
        && !from_domain.is_empty()
        && !aligned_relaxed(&reply_domain, &from_domain)
    {
        findings.push(finding(
            Sev::Warn,
            "Sender",
            "Reply-To goes to a different domain",
            format!("Replies go to {reply_domain}, not {from_domain}. Normal for some mailing services; a common pattern in phishing and invoice fraud."),
        ));
    }
    if !return_domain.is_empty()
        && !from_domain.is_empty()
        && !aligned_relaxed(&return_domain, &from_domain)
    {
        findings.push(finding(
            Sev::Info,
            "Sender",
            "Return-Path domain differs from From",
            format!("Bounces go to {return_domain}. SPF checks that domain, so SPF cannot align with From ({from_domain}); DMARC then depends on an aligned DKIM signature."),
        ));
    }

    // Received chain, oldest first.
    let mut hops: Vec<Hop> = Vec::new();
    let received: Vec<_> = headers.all("Received").take(MAX_HOPS).collect();
    let total = received.len();
    for (doc_pos, h) in received.iter().enumerate() {
        let raw_line = clip(unfold(h.raw_value()));
        let date_raw = raw_line
            .rsplit_once(';')
            .map(|(_, d)| d.trim().to_string())
            .unwrap_or_default();
        let mut hop = Hop {
            index: total - doc_pos,
            from_host: String::new(),
            helo: String::new(),
            from_ip: String::new(),
            from_rdns: String::new(),
            by_host: String::new(),
            protocol: String::new(),
            tls: String::new(),
            id: String::new(),
            for_addr: String::new(),
            timestamp: None,
            date: date_raw,
            delay_secs: None,
            non_public_ip: false,
            parsed: false,
            raw: raw_line,
        };
        if let Some(r) = h.value().as_received() {
            hop.parsed = true;
            hop.from_host = host_str(r.from());
            hop.helo = host_str(r.helo());
            let ip = r.from_ip().or(match r.from() {
                Some(Host::IpAddr(ip)) => Some(ip),
                _ => None,
            });
            if let Some(ip) = ip {
                hop.non_public_ip = is_non_public(&ip);
                hop.from_ip = ip.to_string();
            }
            hop.from_rdns = r.from_iprev().unwrap_or("").to_string();
            hop.by_host = host_str(r.by());
            hop.protocol = r.with().map(|p| p.as_str().to_string()).unwrap_or_default();
            hop.tls = [
                r.tls_version().map(|v| v.as_str().to_string()),
                r.tls_cipher().map(str::to_string),
            ]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
            .join(" ");
            hop.id = r.id().unwrap_or("").to_string();
            hop.for_addr = r.for_().unwrap_or("").to_string();
            hop.timestamp = r.date().filter(|d| d.is_valid()).map(|d| d.to_timestamp());
        }
        hops.push(hop);
    }
    hops.reverse();
    let mut prev: Option<i64> = None;
    for hop in &mut hops {
        if let (Some(p), Some(t)) = (prev, hop.timestamp) {
            hop.delay_secs = Some(t - p);
        }
        if hop.timestamp.is_some() {
            prev = hop.timestamp;
        }
    }
    if hops.is_empty() {
        findings.push(finding(
            Sev::Info,
            "Route",
            "No Received headers",
            "Without them the delivery path cannot be traced. The header may be incomplete or copied from a client view that hides them.",
        ));
    }
    let skewed: Vec<usize> = hops
        .iter()
        .filter(|h| h.delay_secs.is_some_and(|d| d < -60))
        .map(|h| h.index)
        .collect();
    if !skewed.is_empty() {
        findings.push(finding(
            Sev::Warn,
            "Route",
            "Timestamps go backwards",
            format!("Hop {} is dated before the hop before it. Usually a server clock is wrong; it can also mean a Received line was added out of order or forged.", join_nums(&skewed)),
        ));
    }
    let slow: Vec<usize> = hops
        .iter()
        .filter(|h| h.delay_secs.is_some_and(|d| d > 3600))
        .map(|h| h.index)
        .collect();
    if !slow.is_empty() {
        findings.push(finding(
            Sev::Info,
            "Route",
            "Long delay between hops",
            format!("More than an hour passed before hop {}. Queueing, greylisting, a retry or clock skew can all cause this.", join_nums(&slow)),
        ));
    }
    let unparsed = hops.iter().filter(|h| !h.parsed).count();
    if unparsed > 0 {
        findings.push(finding(
            Sev::Info,
            "Route",
            format!(
                "{unparsed} Received line{} could not be parsed",
                if unparsed == 1 { "" } else { "s" }
            ),
            "They are shown as written.",
        ));
    }
    let origin = origin_guesses(&hops);

    // Authentication results as claimed by mail systems.
    let mut auth_results = Vec::new();
    for name in ["Authentication-Results", "ARC-Authentication-Results"] {
        for h in headers.all(name).take(50) {
            auth_results.push(parse_auth_results(name, &unfold(h.raw_value())));
        }
    }
    let received_spf: Vec<String> = headers
        .all("Received-SPF")
        .take(20)
        .map(|h| clip(unfold(h.raw_value())))
        .collect();
    if auth_results.is_empty() && received_spf.is_empty() {
        findings.push(finding(
            Sev::Info,
            "Authentication",
            "No authentication results in the header",
            "The receiving system did not record SPF, DKIM or DMARC results, or they were removed.",
        ));
    }
    let ids: Vec<&str> = {
        let mut v: Vec<&str> = auth_results
            .iter()
            .filter(|a| a.header == "Authentication-Results")
            .map(|a| a.authserv_id.as_str())
            .collect();
        v.dedup();
        v
    };
    if ids.len() > 1 {
        findings.push(finding(
            Sev::Info,
            "Authentication",
            "Results from more than one mail system",
            format!("Authentication-Results were written by {}. Trust only the ones from your own receiving system; anything else may have been added by the sender.", ids.join(", ")),
        ));
    }
    if let Some(top) = auth_results
        .iter()
        .find(|a| a.header == "Authentication-Results")
    {
        for m in &top.methods {
            if matches!(m.method.as_str(), "spf" | "dkim" | "dmarc")
                && matches!(m.result.as_str(), "fail" | "softfail" | "permerror")
            {
                findings.push(finding(
                    if m.method == "dmarc" {
                        Sev::Fail
                    } else {
                        Sev::Warn
                    },
                    "Authentication",
                    format!(
                        "{} reported {} by {}",
                        m.method.to_uppercase(),
                        m.result,
                        top.authserv_id
                    ),
                    "This is the receiving system's own verdict, recorded in the header.",
                ));
            }
        }
    }

    // DKIM signatures.
    let dkim: Vec<DkimSig> = headers
        .all("DKIM-Signature")
        .take(20)
        .map(|h| analyze_dkim(&unfold(h.raw_value()), &from_domain, date_ts))
        .collect();
    if dkim.is_empty() {
        findings.push(finding(
            Sev::Info,
            "DKIM",
            "No DKIM signature",
            "Without one, DMARC can pass only through aligned SPF.",
        ));
    } else if let Some(d) = dkim.iter().find(|d| d.alignment != "none") {
        findings.push(finding(
            Sev::Pass,
            "DKIM",
            format!("A DKIM signature aligns with From ({})", d.alignment),
            format!("Signed by {} with selector {}. Headers alone cannot prove the signature is valid; check the key in DNS and the receiver's Authentication-Results.", d.domain, d.selector),
        ));
    } else if !from_domain.is_empty() && !dkim.iter().any(|d| d.alignment != "none") {
        findings.push(finding(
            Sev::Warn,
            "DKIM",
            "No DKIM signature aligns with the From domain",
            format!("Signed by {}, but the message is from {from_domain}. Common with third-party senders that are not set up to sign for the customer's domain.", dkim.iter().map(|d| d.domain.as_str()).collect::<Vec<_>>().join(", ")),
        ));
    }
    let arc_sets = headers.all("ARC-Seal").count();

    // Domains and lookalikes.
    let mut domain_rows: Vec<DomainRow> = Vec::new();
    let mut add_domain = |d: &str, role: &str| {
        let d = domains::normalize(d);
        if d.is_empty() || !d.contains('.') || d.parse::<IpAddr>().is_ok() {
            return;
        }
        if let Some(row) = domain_rows.iter_mut().find(|r| r.domain == d) {
            if !row.roles.iter().any(|r| r == role) {
                row.roles.push(role.to_string());
            }
        } else {
            domain_rows.push(DomainRow {
                unicode: lookalike::unicode_form(&d).unwrap_or_default(),
                domain: d,
                roles: vec![role.to_string()],
            });
        }
    };
    for a in &addresses {
        if !matches!(a.role.as_str(), "To" | "Cc") {
            add_domain(&a.domain, &a.role);
        }
    }
    for d in &dkim {
        add_domain(&d.domain, "DKIM d=");
    }
    let message_id = msg.message_id().unwrap_or("").to_string();
    if let Some(d) = of_address(&message_id) {
        add_domain(&d, "Message-ID");
    }
    let pairs: Vec<(String, Vec<String>)> = domain_rows
        .iter()
        .map(|r| (r.domain.clone(), r.roles.clone()))
        .collect();
    let lookalikes = lookalike::check(&pairs, known);
    for l in &lookalikes {
        findings.push(finding(
            if l.against == "message" || l.against == "known" {
                Sev::Warn
            } else {
                Sev::Info
            },
            "Lookalike",
            format!("{} resembles {}", l.domain, l.resembles),
            format!(
                "{}. A similar name is not proof of impersonation; check who owns it.",
                capitalize(&l.reason)
            ),
        ));
    }

    // Body: listed and scanned for indicators, never rendered.
    let mut collector = Collector::default();
    let mut header_iocs = String::new();
    for a in &addresses {
        if !matches!(a.role.as_str(), "To" | "Cc") {
            header_iocs.push_str(&a.address);
            header_iocs.push(' ');
        }
    }
    for h in &hops {
        if !h.from_ip.is_empty() && !h.non_public_ip {
            header_iocs.push_str(&h.from_ip);
            header_iocs.push(' ');
        }
    }
    collector.scan(&header_iocs, 0);
    let text_parts = msg.text_body().count();
    let html_parts = msg.html_body().count();
    for t in msg.text_bodies().take(20) {
        collector.scan(cut(&t, MAX_SCAN), 1);
    }
    for h in msg.html_bodies().take(20) {
        let text = mail_parser::html_to_text(cut(&h, MAX_SCAN));
        collector.scan(&text, 1);
        // Link targets live in attributes that html_to_text drops.
        collector.scan(cut(&h, MAX_SCAN), 1);
    }
    let attachments: Vec<Attachment> = msg
        .attachments()
        .take(200)
        .map(|p| {
            let name = p.attachment_name().unwrap_or("").to_string();
            let content_type = p
                .content_type()
                .map(|c| match c.subtype() {
                    Some(s) => format!("{}/{s}", c.ctype()),
                    None => c.ctype().to_string(),
                })
                .unwrap_or_default();
            let ext = name
                .rsplit_once('.')
                .map(|(_, e)| e.to_ascii_lowercase())
                .unwrap_or_default();
            Attachment {
                risky: RISKY_EXT.contains(&ext.as_str()),
                name,
                content_type,
                size: p.raw_body().len(),
            }
        })
        .collect();
    let risky: Vec<&str> = attachments
        .iter()
        .filter(|a| a.risky)
        .map(|a| a.name.as_str())
        .collect();
    if !risky.is_empty() {
        findings.push(finding(
            Sev::Warn,
            "Attachments",
            "Attachment types often used to deliver malware",
            format!("{}. Do not open them outside a sandbox.", risky.join(", ")),
        ));
    }

    let notable_headers: Vec<(String, String)> = headers
        .iter()
        .filter(|h| NOTABLE.contains(&h.raw_name().to_ascii_lowercase().as_str()))
        .take(50)
        .map(|h| (h.raw_name().to_string(), clip(unfold(h.raw_value()))))
        .collect();
    let all_headers: Vec<(String, String)> = headers
        .iter()
        .take(MAX_HEADERS)
        .map(|h| (h.raw_name().to_string(), clip(unfold(h.raw_value()))))
        .collect();
    if msg.message_id().is_none() {
        findings.push(finding(
            Sev::Info,
            "Headers",
            "No Message-ID",
            "Most legitimate mail systems add one.",
        ));
    }
    if date_ts.is_none() {
        findings.push(finding(
            Sev::Info,
            "Headers",
            "No valid Date header",
            "Required by RFC 5322.",
        ));
    }

    findings.sort_by_key(|f| std::cmp::Reverse(f.severity));
    let has_body = !msg
        .root_part()
        .raw_body()
        .iter()
        .all(|b| b.is_ascii_whitespace());
    Ok(EmailAnalysis {
        input_kind: if has_body { "message" } else { "headers" }.into(),
        subject: msg.subject().unwrap_or("").to_string(),
        date: headers
            .get("Date")
            .map(|h| unfold(h.raw_value()))
            .unwrap_or_default(),
        date_ts,
        message_id,
        addresses,
        domains: domain_rows,
        hops,
        origin,
        auth_results,
        received_spf,
        dkim,
        arc_sets,
        lookalikes,
        attachments,
        text_parts,
        html_parts,
        iocs: collector.iocs,
        notable_headers,
        headers: all_headers,
        findings,
    })
}

/// Best guesses at the sending server, with their basis. The handoff into
/// the receiving organization is recorded by the receiver and is the most
/// reliable; the earliest public address can be forged by the sender.
pub fn origin_guesses(hops: &[Hop]) -> Vec<OriginGuess> {
    let mut out = Vec::new();
    // Newest hop first: the receiving organization is the newest `by` host.
    let newest: Vec<&Hop> = hops.iter().rev().collect();
    if let Some(top) = newest.first()
        && !top.by_host.is_empty()
    {
        let receiver = org_domain(&top.by_host);
        // Walk down while the receiver's own servers recorded the hop; the
        // last such hop's `from` is who handed the message over.
        let mut handoff = None;
        for h in &newest {
            if org_domain(&h.by_host) != receiver {
                break;
            }
            let from_org = if h.from_rdns.is_empty() {
                org_domain(&h.from_host)
            } else {
                org_domain(&h.from_rdns)
            };
            if !h.from_ip.is_empty() && !h.non_public_ip && from_org != receiver {
                handoff = Some(*h);
                break;
            }
        }
        if let Some(h) = handoff {
            out.push(OriginGuess {
                ip: h.from_ip.clone(),
                host: if h.from_rdns.is_empty() { h.from_host.clone() } else { h.from_rdns.clone() },
                hop: h.index,
                basis: "handoff".into(),
                explanation: format!("The server that handed the message to {receiver}, as recorded by {receiver}'s own mail servers. This is the most reliable sending address in the header."),
            });
        }
    }
    if let Some(h) = hops
        .iter()
        .find(|h| !h.from_ip.is_empty() && !h.non_public_ip)
        && !out.iter().any(|o| o.ip == h.from_ip)
    {
        out.push(OriginGuess {
            ip: h.from_ip.clone(),
            host: if h.from_rdns.is_empty() { h.from_host.clone() } else { h.from_rdns.clone() },
            hop: h.index,
            basis: "earliest".into(),
            explanation: "The first public address in the Received chain. Lines this early are written by servers outside the receiver's control and can be forged.".into(),
        });
    }
    out
}

fn cut(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
        None => String::new(),
    }
}

fn join_nums(v: &[usize]) -> String {
    v.iter()
        .map(|n| n.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Synthetic phishing-style header: a forged earliest hop, a handoff to
    /// the customer's MX, a lookalike signing domain and a spoofed name.
    const HEADER: &str = "\
Received: from mx.customer.example (mx.customer.example [10.0.0.5])
\tby mailbox.customer.example with LMTP; Fri, 13 Nov 2026 14:05:12 +0000
Received: from mail-out.paypa1.com (mail-out.paypa1.com [209.85.220.41])
\tby mx.customer.example (Postfix) with ESMTPS id 4AbC123
\tfor <bob@customer.example>; Fri, 13 Nov 2026 14:05:10 +0000
Received: from workstation (unknown [45.33.32.156])
\tby mail-out.paypa1.com with ESMTPSA id xyz; Fri, 13 Nov 2026 15:04:58 +0000
Authentication-Results: mx.customer.example; spf=pass (sender ok) smtp.mailfrom=bounce.paypa1.com;
 dkim=pass header.d=paypa1.com header.s=s1; dmarc=pass (p=none) header.from=paypa1.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=paypa1.com; s=s1;
 h=from:to:subject:date; bh=abc=; b=de
 f=
From: \"PayPal Support <service@paypal.com>\" <support@paypa1.com>
Reply-To: billing@collect-payments.example
Return-Path: <bounce@bounce.paypa1.com>
To: bob@customer.example
Subject: =?utf-8?B?WW91ciBhY2NvdW50IGlzIGxvY2tlZA==?=
Date: Fri, 13 Nov 2026 14:04:55 +0000
Message-ID: <abc@smtp.paypa1.com>
X-Mailer: Example Mailer 1.0
";

    fn analysis() -> EmailAnalysis {
        analyze(HEADER.as_bytes(), &[]).unwrap()
    }

    #[test]
    fn addresses_and_subject() {
        let a = analysis();
        assert_eq!(a.input_kind, "headers");
        assert_eq!(a.subject, "Your account is locked");
        let role = |r: &str| a.addresses.iter().find(|x| x.role == r).unwrap();
        assert_eq!(role("From").address, "support@paypa1.com");
        assert_eq!(role("From").domain, "paypa1.com");
        assert_eq!(role("Reply-To").domain, "collect-payments.example");
        assert_eq!(role("Return-Path").domain, "bounce.paypa1.com");
        assert_eq!(a.message_id, "abc@smtp.paypa1.com");
        assert_eq!(
            a.notable_headers,
            vec![("X-Mailer".to_string(), "Example Mailer 1.0".to_string())]
        );
    }

    #[test]
    fn sender_findings() {
        let a = analysis();
        let titles: Vec<&str> = a.findings.iter().map(|f| f.title.as_str()).collect();
        assert!(
            titles.contains(&"Display name shows a different address"),
            "{titles:?}"
        );
        assert!(titles.contains(&"Reply-To goes to a different domain"));
        // Return-Path is a subdomain of From: aligned, so no finding.
        assert!(!titles.contains(&"Return-Path domain differs from From"));
        assert!(
            a.findings
                .windows(2)
                .all(|w| w[0].severity >= w[1].severity)
        );
    }

    #[test]
    fn hops_in_time_order_with_skew() {
        let a = analysis();
        assert_eq!(a.hops.len(), 3);
        assert_eq!(a.hops[0].index, 1);
        assert_eq!(a.hops[0].from_ip, "45.33.32.156");
        assert_eq!(a.hops[0].by_host, "mail-out.paypa1.com");
        assert_eq!(a.hops[1].from_ip, "209.85.220.41");
        assert_eq!(a.hops[1].protocol, "ESMTPS");
        assert_eq!(a.hops[1].for_addr, "bob@customer.example");
        assert!(a.hops[2].non_public_ip);
        // Hop 1 is dated an hour after hop 2: clock skew or a forged line.
        assert_eq!(a.hops[1].delay_secs, Some(-3588));
        assert_eq!(a.hops[2].delay_secs, Some(2));
        assert!(
            a.findings
                .iter()
                .any(|f| f.title == "Timestamps go backwards" && f.detail.contains("Hop 2"))
        );
    }

    #[test]
    fn origin_prefers_the_receivers_handoff() {
        let a = analysis();
        assert_eq!(a.origin[0].basis, "handoff");
        assert_eq!(a.origin[0].ip, "209.85.220.41");
        assert_eq!(a.origin[0].hop, 2);
        assert_eq!(a.origin[1].basis, "earliest");
        assert_eq!(a.origin[1].ip, "45.33.32.156");
    }

    #[test]
    fn authentication_results_are_parsed_as_claims() {
        let a = analysis();
        let ar = &a.auth_results[0];
        assert_eq!(ar.authserv_id, "mx.customer.example");
        let m = |name: &str| ar.methods.iter().find(|m| m.method == name).unwrap();
        assert_eq!(m("spf").result, "pass");
        assert!(
            m("spf")
                .props
                .contains(&("smtp.mailfrom".into(), "bounce.paypa1.com".into()))
        );
        assert!(m("dkim").props.contains(&("header.s".into(), "s1".into())));
        assert_eq!(m("dmarc").result, "pass");
    }

    #[test]
    fn dkim_tags_and_alignment() {
        let a = analysis();
        let d = &a.dkim[0];
        assert_eq!(d.domain, "paypa1.com");
        assert_eq!(d.selector, "s1");
        assert_eq!(d.alignment, "strict");
        assert_eq!(d.key_name, "s1._domainkey.paypa1.com");
        assert_eq!(d.signed_headers, ["from", "to", "subject", "date"]);
        assert!(d.notes.is_empty(), "{:?}", d.notes);

        let weak = analyze_dkim(
            "v=1; a=rsa-sha1; d=mail.example.com; s=k; l=100; h=to:subject; bh=x; b=y",
            "example.com",
            None,
        );
        assert_eq!(weak.alignment, "relaxed");
        assert_eq!(weak.notes.len(), 3, "{:?}", weak.notes);
        assert_eq!(
            analyze_dkim("d=other.net; s=k", "example.com", None).alignment,
            "none"
        );
    }

    #[test]
    fn lookalike_domains_are_flagged() {
        let a = analysis();
        assert!(
            a.lookalikes
                .iter()
                .any(|l| l.domain == "paypa1.com" && l.resembles == "paypal.com")
        );
        assert!(
            a.domains
                .iter()
                .any(|d| d.domain == "paypa1.com" && d.roles.contains(&"DKIM d=".to_string()))
        );
    }

    #[test]
    fn auth_results_parsing_edge_cases() {
        let arc = parse_auth_results(
            "ARC-Authentication-Results",
            "i=2; mx.google.com; dkim=pass (2048-bit key) header.i=@example.com; spf=softfail (domain of transitioning x) smtp.mailfrom=x@example.net",
        );
        assert_eq!(arc.instance, Some(2));
        assert_eq!(arc.authserv_id, "mx.google.com");
        assert_eq!(arc.methods[1].result, "softfail");
        let none = parse_auth_results("Authentication-Results", "example.com 1; none");
        assert_eq!(none.authserv_id, "example.com");
        assert!(none.methods.is_empty());
        // Microsoft 365 style: no authserv-id.
        let ms = parse_auth_results(
            "Authentication-Results",
            "spf=pass (sender IP is 209.85.160.171) smtp.mailfrom=gmail.com; dkim=pass (signature was verified) header.d=gmail.com;dmarc=pass action=none header.from=gmail.com;compauth=pass reason=100",
        );
        assert_eq!(ms.authserv_id, "");
        assert_eq!(ms.methods.len(), 4);
        assert_eq!(ms.methods[0].method, "spf");
        assert!(
            ms.methods[0]
                .props
                .contains(&("smtp.mailfrom".into(), "gmail.com".into()))
        );
        assert_eq!(
            strip_comments("a (b (c) d) e \"(kept)\""),
            "a  e \"(kept)\""
        );
    }

    #[test]
    fn duplicate_from_and_missing_fields() {
        let raw = "From: a@example.com\nFrom: b@example.org\nSubject: x\n";
        let a = analyze(raw.as_bytes(), &[]).unwrap();
        assert!(
            a.findings
                .iter()
                .any(|f| f.severity == Sev::Fail && f.title == "2 From headers")
        );
        assert!(a.findings.iter().any(|f| f.title == "No Message-ID"));
        assert!(a.findings.iter().any(|f| f.title == "No Received headers"));
    }

    #[test]
    fn pasted_text_is_tidied() {
        let raw =
            "\n\n    From: a@example.com\n    Subject: indented\n    Message-ID: <1@example.com>\n";
        let a = analyze(raw.as_bytes(), &[]).unwrap();
        assert_eq!(a.subject, "indented");
    }

    #[test]
    fn bad_input() {
        assert_eq!(analyze(b"  \n ", &[]), Err(EmailError::Empty));
        assert_eq!(
            analyze(b"this is not an email at all", &[]),
            Err(EmailError::NoHeaders)
        );
        let big = vec![b'a'; MAX_INPUT + 1];
        assert_eq!(analyze(&big, &[]), Err(EmailError::TooLarge(MAX_INPUT + 1)));
    }

    #[test]
    fn full_message_attachments_and_links() {
        let eml = "\
From: billing@example.com
To: bob@customer.example
Subject: Invoice
Message-ID: <2@example.com>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary=\"b1\"

--b1
Content-Type: text/html; charset=utf-8

<p>Pay here: <a href=\"https://pay.evil.example/login?x=1\">invoice</a></p>
--b1
Content-Type: application/octet-stream
Content-Disposition: attachment; filename=\"invoice.pdf.exe\"
Content-Transfer-Encoding: base64

TVqQAAMAAAAEAAAA
--b1--
";
        let a = analyze(eml.as_bytes(), &[]).unwrap();
        assert_eq!(a.input_kind, "message");
        assert_eq!(a.html_parts, 1);
        assert_eq!(a.attachments.len(), 1);
        assert!(a.attachments[0].risky);
        assert_eq!(a.attachments[0].name, "invoice.pdf.exe");
        assert!(
            a.iocs
                .iter()
                .any(|i| i.value == "https://pay.evil.example/login?x=1"),
            "{:?}",
            a.iocs
        );
        assert!(a.findings.iter().any(|f| f.category == "Attachments"));
    }

    #[test]
    fn hostile_header_values_are_bounded() {
        let long = format!(
            "From: a@example.com\nSubject: s\nX-Junk: {}\n",
            "A".repeat(100_000)
        );
        let a = analyze(long.as_bytes(), &[]).unwrap();
        let junk = &a.headers.iter().find(|(n, _)| n == "X-Junk").unwrap().1;
        assert!(junk.len() < MAX_VALUE + 64);
        assert!(junk.ends_with("bytes]"));
        let many: String = (0..2000)
            .map(|i| format!("Received: from h{i} by x; Fri, 13 Nov 2026 14:00:00 +0000\n"))
            .collect();
        let a = analyze(format!("From: a@example.com\n{many}").as_bytes(), &[]).unwrap();
        assert_eq!(a.hops.len(), MAX_HOPS);
    }
}
