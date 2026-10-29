//! Pure DNS-posture analysis: parsing and scoring for SPF, DMARC, DKIM, MX,
//! DNSSEC, and NS health. Everything here takes already-fetched record strings, so
//! it is deterministic and unit tested. The network orchestration lives in
//! `commands.rs`.

use serde::Serialize;

/// Severity of a finding. Declaration order is the ranking used for rollups.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Pass,
    Info,
    Warn,
    Fail,
}

/// A single observation about one check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    pub severity: Severity,
    pub message: String,
}

impl Finding {
    pub fn new(severity: Severity, message: impl Into<String>) -> Self {
        Finding {
            severity,
            message: message.into(),
        }
    }
}

/// Overall status of a section: Fail if any failure, else Warn if any warning,
/// else Pass. Info-only findings do not lower the status.
pub fn section_status(findings: &[Finding]) -> Severity {
    if findings.iter().any(|f| f.severity == Severity::Fail) {
        Severity::Fail
    } else if findings.iter().any(|f| f.severity == Severity::Warn) {
        Severity::Warn
    } else {
        Severity::Pass
    }
}

/// Split a `k=v; k=v` tag string into trimmed, lowercased-key pairs.
pub fn parse_tags(s: &str) -> Vec<(String, String)> {
    s.split(';')
        .filter_map(|part| {
            let part = part.trim();
            if part.is_empty() {
                return None;
            }
            part.split_once('=')
                .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
        })
        .collect()
}

// --- SPF ------------------------------------------------------------------

/// Parsed SPF record, enough to evaluate posture and drive lookup counting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Spf {
    /// Qualifier on the `all` mechanism, e.g. '-', '~', '?', '+'.
    pub all_qualifier: Option<char>,
    /// Targets of `include:` mechanisms (each recurses).
    pub includes: Vec<String>,
    /// Target of a `redirect=` modifier, if present (recurses).
    pub redirect: Option<String>,
    /// Count of non-recursing lookup mechanisms: a, mx, ptr, exists.
    pub direct_lookups: u32,
    /// True when the deprecated `ptr` mechanism appears.
    pub uses_ptr: bool,
}

/// Does this TXT record look like an SPF record?
pub fn is_spf(txt: &str) -> bool {
    txt.trim_start().to_ascii_lowercase().starts_with("v=spf1")
}

/// Parse an SPF record string.
pub fn parse_spf(txt: &str) -> Option<Spf> {
    if !is_spf(txt) {
        return None;
    }
    let mut spf = Spf {
        all_qualifier: None,
        includes: Vec::new(),
        redirect: None,
        direct_lookups: 0,
        uses_ptr: false,
    };
    for term in txt.split_whitespace().skip(1) {
        // redirect=example.com is a modifier, not a qualified mechanism.
        if let Some(target) = term.strip_prefix("redirect=") {
            spf.redirect = Some(target.to_string());
            continue;
        }
        let (qualifier, rest) = match term.chars().next() {
            Some(q @ ('+' | '-' | '~' | '?')) => (Some(q), &term[1..]),
            _ => (None, term),
        };
        let name = rest
            .split([':', '='])
            .next()
            .unwrap_or("")
            .to_ascii_lowercase();
        match name.as_str() {
            "all" => spf.all_qualifier = qualifier.or(Some('+')),
            "include" => {
                if let Some((_, target)) = rest.split_once(':') {
                    spf.includes.push(target.to_string());
                }
            }
            "ptr" => {
                spf.direct_lookups += 1;
                spf.uses_ptr = true;
            }
            "a" | "mx" | "exists" => spf.direct_lookups += 1,
            _ => {}
        }
    }
    Some(spf)
}

/// Findings for the set of TXT records at the domain root (record count and the
/// `all` qualifier). Lookup-count findings are added separately once the
/// recursive total is known.
pub fn spf_record_findings(txt_records: &[String]) -> Vec<Finding> {
    let spf_records: Vec<&String> = txt_records.iter().filter(|r| is_spf(r)).collect();
    match spf_records.len() {
        0 => vec![Finding::new(
            Severity::Fail,
            "No SPF record found. Mail from this domain is easier to spoof.",
        )],
        1 => {
            let spf = parse_spf(spf_records[0]).unwrap();
            let mut findings = vec![Finding::new(Severity::Pass, "One SPF record present.")];
            match spf.all_qualifier {
                Some('-') => findings.push(Finding::new(Severity::Pass, "Ends with -all (fail).")),
                Some('~') => {
                    findings.push(Finding::new(Severity::Info, "Ends with ~all (softfail)."))
                }
                Some('?') => findings.push(Finding::new(
                    Severity::Warn,
                    "Ends with ?all (neutral); provides little protection.",
                )),
                Some('+') => findings.push(Finding::new(
                    Severity::Fail,
                    "Ends with +all (pass all); this authorizes any sender.",
                )),
                _ => findings.push(Finding::new(
                    Severity::Warn,
                    "No 'all' mechanism; the record is effectively neutral.",
                )),
            }
            findings
        }
        n => vec![Finding::new(
            Severity::Fail,
            format!("{n} SPF records found; exactly one is allowed (permerror)."),
        )],
    }
}

/// Finding for the recursive SPF DNS-lookup total against the limit of 10.
pub fn spf_lookup_finding(total: u32, capped: bool) -> Finding {
    if capped {
        Finding::new(
            Severity::Fail,
            format!("SPF requires more than {total} DNS lookups (limit is 10); permerror."),
        )
    } else if total > 10 {
        Finding::new(
            Severity::Fail,
            format!("SPF uses {total} DNS lookups; the limit is 10 (permerror)."),
        )
    } else if total >= 8 {
        Finding::new(
            Severity::Warn,
            format!("SPF uses {total} of 10 allowed DNS lookups; close to the limit."),
        )
    } else {
        Finding::new(
            Severity::Pass,
            format!("SPF uses {total} of 10 allowed DNS lookups."),
        )
    }
}

/// Longest SPF record before older resolvers risk truncating the response.
pub const SPF_LONG_RECORD: usize = 450;

/// Findings for void lookups (include or redirect targets with no SPF
/// record), the deprecated `ptr` mechanism, and record length.
pub fn spf_extra_findings(voids: &[String], uses_ptr: bool, record_len: usize) -> Vec<Finding> {
    let mut f = Vec::new();
    let n = voids.len();
    let list = voids.join(", ");
    if n > 2 {
        f.push(Finding::new(
            Severity::Fail,
            format!("{n} void lookups ({list}): include or redirect targets with no SPF record. More than 2 is a permerror (RFC 7208 4.6.4)."),
        ));
    } else if n > 0 {
        f.push(Finding::new(
            Severity::Warn,
            format!("{n} void lookup{} ({list}): no SPF record at that include or redirect target. Fix or remove it.", if n == 1 { "" } else { "s" }),
        ));
    }
    if uses_ptr {
        f.push(Finding::new(
            Severity::Warn,
            "Uses the ptr mechanism, which is deprecated, slow and unreliable (RFC 7208 5.5). Replace it with ip4, ip6 or include.",
        ));
    }
    if record_len > SPF_LONG_RECORD {
        f.push(Finding::new(
            Severity::Warn,
            format!(
                "SPF record is {record_len} characters; long records risk truncated UDP responses."
            ),
        ));
    }
    f
}

// --- DMARC ----------------------------------------------------------------

pub fn is_dmarc(txt: &str) -> bool {
    txt.trim_start()
        .to_ascii_lowercase()
        .starts_with("v=dmarc1")
}

/// Findings for the `_dmarc` TXT records.
pub fn dmarc_findings(txt_records: &[String]) -> Vec<Finding> {
    let records: Vec<&String> = txt_records.iter().filter(|r| is_dmarc(r)).collect();
    if records.is_empty() {
        return vec![Finding::new(
            Severity::Fail,
            "No DMARC record found. Receivers have no policy to apply.",
        )];
    }
    if records.len() > 1 {
        return vec![Finding::new(
            Severity::Fail,
            "Multiple DMARC records found; exactly one is allowed.",
        )];
    }

    let tags = parse_tags(records[0]);
    let get = |k: &str| tags.iter().find(|(tk, _)| tk == k).map(|(_, v)| v.as_str());

    let mut findings = Vec::new();
    match get("p").map(|p| p.to_ascii_lowercase()) {
        Some(p) if p == "reject" => {
            findings.push(Finding::new(Severity::Pass, "Policy p=reject (enforcing)."))
        }
        Some(p) if p == "quarantine" => findings.push(Finding::new(
            Severity::Warn,
            "Policy p=quarantine; stronger than none but not full enforcement.",
        )),
        Some(p) if p == "none" => findings.push(Finding::new(
            Severity::Warn,
            "Policy p=none (monitor only); does not block spoofed mail.",
        )),
        Some(other) => findings.push(Finding::new(
            Severity::Fail,
            format!("Unknown DMARC policy p={other}."),
        )),
        None => findings.push(Finding::new(
            Severity::Fail,
            "DMARC record has no p= policy tag.",
        )),
    }

    match get("rua") {
        Some(_) => findings.push(Finding::new(
            Severity::Pass,
            "Aggregate reporting (rua) is configured.",
        )),
        None => findings.push(Finding::new(
            Severity::Warn,
            "No aggregate reporting (rua); you will not receive DMARC reports.",
        )),
    }

    if let Some(pct) = get("pct")
        && pct != "100"
    {
        findings.push(Finding::new(
            Severity::Info,
            format!("Policy applies to only {pct}% of mail (pct={pct})."),
        ));
    }

    findings
}

// --- DKIM -----------------------------------------------------------------

pub fn is_dkim(txt: &str) -> bool {
    let lower = txt.trim_start().to_ascii_lowercase();
    lower.starts_with("v=dkim1") || lower.contains("p=")
}

/// Findings for one DKIM selector's record.
pub fn dkim_findings(selector: &str, txt: &str) -> Vec<Finding> {
    let tags = parse_tags(txt);
    let tag = |k: &str| tags.iter().find(|(t, _)| t == k).map(|(_, v)| v.as_str());
    let key_type = tag("k").unwrap_or("rsa").to_ascii_lowercase();
    let testing =
        tag("t").is_some_and(|t| t.split(':').any(|f| f.trim().eq_ignore_ascii_case("y")));

    let mut f = match tag("p").map(|p| p.split_whitespace().collect::<String>()) {
        None => vec![Finding::new(
            Severity::Warn,
            format!("Selector '{selector}' record has no p= public key."),
        )],
        Some(p) if p.is_empty() => vec![Finding::new(
            Severity::Warn,
            format!(
                "Selector '{selector}' exists but the key is revoked (empty p=). Remove it if unused."
            ),
        )],
        Some(p) => match dkim_key(&key_type, &p) {
            DkimKey::Rsa(bits) if bits < 1024 => vec![Finding::new(
                Severity::Fail,
                format!(
                    "Selector '{selector}' has a {bits}-bit RSA key; major receivers reject keys under 1024 bits. Rotate to 2048."
                ),
            )],
            DkimKey::Rsa(bits) if bits < 2048 => vec![Finding::new(
                Severity::Warn,
                format!(
                    "Selector '{selector}' has a {bits}-bit RSA key, considered weak. Rotate to 2048."
                ),
            )],
            DkimKey::Rsa(bits) => vec![Finding::new(
                Severity::Pass,
                format!("Selector '{selector}' has a {bits}-bit RSA key."),
            )],
            DkimKey::Ed25519 => vec![Finding::new(
                Severity::Pass,
                format!(
                    "Selector '{selector}' has an Ed25519 key. Not every receiver verifies Ed25519 yet; pair it with an RSA selector."
                ),
            )],
            DkimKey::Invalid => vec![Finding::new(
                Severity::Fail,
                format!("Selector '{selector}' public key is not a valid {key_type} key."),
            )],
        },
    };
    if testing {
        f.push(Finding::new(
            Severity::Info,
            format!("Selector '{selector}' has the testing flag (t=y); receivers treat its signatures as unsigned."),
        ));
    }
    f
}

/// Finding for a wildcard `*._domainkey` record, which answers every
/// selector the same way so individual selectors cannot be told apart.
pub fn dkim_wildcard_finding(record: &str) -> Finding {
    let revoked = parse_tags(record)
        .iter()
        .any(|(k, v)| k == "p" && v.trim().is_empty());
    if revoked {
        Finding::new(
            Severity::Info,
            "A wildcard *._domainkey record answers every selector with a revoked key (empty p=), the usual way to say the domain sends no signed mail. Supplied selectors are checked only where they differ.",
        )
    } else {
        Finding::new(
            Severity::Warn,
            "A wildcard *._domainkey record answers every selector with the same key, so selector probing is meaningless. Publish keys per selector instead.",
        )
    }
}

/// A parsed DKIM public key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DkimKey {
    /// RSA, by modulus size in bits.
    Rsa(u32),
    Ed25519,
    Invalid,
}

/// Parse a DKIM `p=` value for key type `k=` (rsa or ed25519).
pub fn dkim_key(key_type: &str, p: &str) -> DkimKey {
    use base64::Engine as _;
    let Ok(der) = base64::engine::general_purpose::STANDARD.decode(p) else {
        return DkimKey::Invalid;
    };
    if key_type == "ed25519" {
        // RFC 8463: the raw 32-byte public key.
        return if der.len() == 32 {
            DkimKey::Ed25519
        } else {
            DkimKey::Invalid
        };
    }
    rsa_modulus_bits(&der)
        .map(DkimKey::Rsa)
        .unwrap_or(DkimKey::Invalid)
}

/// One DER tag-length-value at `pos`: (tag, contents, next position).
fn der_tlv(b: &[u8], pos: usize) -> Option<(u8, &[u8], usize)> {
    let tag = *b.get(pos)?;
    let first = *b.get(pos + 1)? as usize;
    let (len, hdr) = if first < 0x80 {
        (first, 2)
    } else {
        let n = first & 0x7f;
        if n == 0 || n > 4 {
            return None;
        }
        let mut len = 0usize;
        for k in 0..n {
            len = (len << 8) | *b.get(pos + 2 + k)? as usize;
        }
        (len, 2 + n)
    };
    let start = pos + hdr;
    let end = start.checked_add(len)?;
    Some((tag, b.get(start..end)?, end))
}

/// RSA modulus size from a SubjectPublicKeyInfo or a bare PKCS#1
/// RSAPublicKey, as DKIM records may carry either.
pub fn rsa_modulus_bits(der: &[u8]) -> Option<u32> {
    let (tag, outer, _) = der_tlv(der, 0)?;
    if tag != 0x30 {
        return None;
    }
    let (t1, c1, next) = der_tlv(outer, 0)?;
    let modulus = match t1 {
        // PKCS#1: SEQUENCE { INTEGER n, INTEGER e }
        0x02 => c1,
        // SPKI: SEQUENCE { AlgorithmIdentifier, BIT STRING { RSAPublicKey } }
        0x30 => {
            let (t2, bits, _) = der_tlv(outer, next)?;
            if t2 != 0x03 || bits.first() != Some(&0) {
                return None;
            }
            let (t3, rsa, _) = der_tlv(&bits[1..], 0)?;
            if t3 != 0x30 {
                return None;
            }
            let (t4, n, _) = der_tlv(rsa, 0)?;
            if t4 != 0x02 {
                return None;
            }
            n
        }
        _ => return None,
    };
    let n: &[u8] = {
        let skip = modulus.iter().take_while(|b| **b == 0).count();
        &modulus[skip..]
    };
    let first = *n.first()?;
    Some(n.len() as u32 * 8 - first.leading_zeros())
}

/// Common DKIM selectors to probe when the user does not supply one:
/// Google, Microsoft 365, Fastmail, Proton, Zoho, iCloud, SendGrid, Mailgun,
/// Mailchimp/Mandrill, Postmark, Amazon SES custom, and generic names.
pub const COMMON_SELECTORS: &[&str] = &[
    "google",
    "selector1",
    "selector2",
    "default",
    "dkim",
    "mail",
    "k1",
    "k2",
    "k3",
    "s1",
    "s2",
    "smtp",
    "mx",
    "mta",
    "key1",
    "key2",
    "sig1",
    "fm1",
    "fm2",
    "fm3",
    "protonmail",
    "protonmail2",
    "protonmail3",
    "zoho",
    "zmail",
    "mandrill",
    "mailjet",
    "pm",
    "krs",
    "everlytickey1",
    "everlytickey2",
    "dkim1",
    "dkim2",
    "email",
    "mxvault",
    "turbo-smtp",
    "cm",
];

// --- MX -------------------------------------------------------------------

/// One MX record and the addresses its exchanger resolved to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MxEntry {
    pub preference: u16,
    /// Exchanger host, without the trailing dot; "." or empty for a Null MX.
    pub host: String,
    pub addresses: Vec<String>,
}

impl MxEntry {
    /// RFC 7505 Null MX: preference 0 and exchanger ".".
    pub fn is_null(&self) -> bool {
        self.preference == 0 && (self.host == "." || self.host.is_empty())
    }
}

/// Findings for the MX set. `apex` holds the domain's own A/AAAA addresses,
/// which senders fall back to when no MX exists.
pub fn mx_findings(entries: &[MxEntry], apex: &[String]) -> Vec<Finding> {
    let mut f = Vec::new();
    if entries.is_empty() {
        if apex.is_empty() {
            f.push(Finding::new(
                Severity::Info,
                "No MX records and no A/AAAA at the apex, so the domain cannot receive mail. Publish a Null MX (0 .) to say so explicitly.",
            ));
        } else {
            f.push(Finding::new(
                Severity::Warn,
                format!(
                    "No MX records. Senders fall back to the apex address ({}). Publish MX records, or a Null MX if the domain should not receive mail.",
                    apex.join(", ")
                ),
            ));
        }
        return f;
    }
    if entries.len() == 1 && entries[0].is_null() {
        f.push(Finding::new(
            Severity::Info,
            "Null MX published (RFC 7505): the domain does not accept mail.",
        ));
        return f;
    }
    if entries.iter().any(MxEntry::is_null) {
        f.push(Finding::new(
            Severity::Fail,
            "A Null MX (0 .) is mixed with real MX records; it must be the only MX.",
        ));
    }
    let real: Vec<&MxEntry> = entries.iter().filter(|e| !e.is_null()).collect();
    f.push(Finding::new(
        Severity::Pass,
        format!(
            "{} MX record{}.",
            real.len(),
            if real.len() == 1 { "" } else { "s" }
        ),
    ));
    for e in &real {
        if e.host
            .trim_end_matches('.')
            .parse::<std::net::IpAddr>()
            .is_ok()
        {
            f.push(Finding::new(
                Severity::Fail,
                format!(
                    "MX {} is an IP address; exchangers must be hostnames.",
                    e.host
                ),
            ));
        } else if e.addresses.is_empty() {
            f.push(Finding::new(
                Severity::Fail,
                format!(
                    "MX {} does not resolve (no A or AAAA); mail to it cannot be delivered.",
                    e.host
                ),
            ));
        }
    }
    let mut prefs: Vec<u16> = real.iter().map(|e| e.preference).collect();
    prefs.sort_unstable();
    if real.len() > 1 && prefs.windows(2).any(|w| w[0] == w[1]) {
        f.push(Finding::new(
            Severity::Info,
            "Several MX records share a preference; senders load-balance between them.",
        ));
    }
    if real.len() == 1 {
        f.push(Finding::new(
            Severity::Info,
            "Only one MX; there is no backup exchanger.",
        ));
    }
    f
}

// --- DNSSEC ---------------------------------------------------------------

/// Findings from DS (at the parent) and DNSKEY (in the zone) presence.
pub fn dnssec_findings(has_ds: bool, has_dnskey: bool) -> Vec<Finding> {
    match (has_ds, has_dnskey) {
        (true, true) => vec![Finding::new(
            Severity::Pass,
            "Zone is signed: DS at the parent and DNSKEY in the zone.",
        )],
        (false, false) => vec![Finding::new(
            Severity::Info,
            "Zone is not signed with DNSSEC.",
        )],
        (true, false) => vec![Finding::new(
            Severity::Fail,
            "DS exists at the parent but no DNSKEY in the zone; the chain is broken.",
        )],
        (false, true) => vec![Finding::new(
            Severity::Warn,
            "Zone has DNSKEY but no DS at the parent; it is not in the validation chain.",
        )],
    }
}

// --- NS consistency -------------------------------------------------------

/// Findings for the NS set and per-server SOA serial agreement. Each entry is
/// (ns name, serial or None if the server did not answer).
pub fn ns_findings(serials: &[(String, Option<u32>)]) -> Vec<Finding> {
    let mut findings = Vec::new();
    if serials.len() < 2 {
        findings.push(Finding::new(
            Severity::Warn,
            format!(
                "Only {} nameserver(s); at least 2 are recommended.",
                serials.len()
            ),
        ));
    } else {
        findings.push(Finding::new(
            Severity::Pass,
            format!("{} nameservers listed.", serials.len()),
        ));
    }

    let unreachable: Vec<&String> = serials
        .iter()
        .filter(|(_, s)| s.is_none())
        .map(|(n, _)| n)
        .collect();
    if !unreachable.is_empty() {
        findings.push(Finding::new(
            Severity::Warn,
            format!(
                "No SOA answer from: {}.",
                unreachable
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        ));
    }

    let present: Vec<u32> = serials.iter().filter_map(|(_, s)| *s).collect();
    if present.len() >= 2 {
        let all_equal = present.iter().all(|s| *s == present[0]);
        if all_equal {
            findings.push(Finding::new(
                Severity::Pass,
                format!(
                    "All answering nameservers agree on SOA serial {}.",
                    present[0]
                ),
            ));
        } else {
            findings.push(Finding::new(
                Severity::Fail,
                "Nameservers disagree on the SOA serial; the zone is out of sync.",
            ));
        }
    }

    findings
}

/// Findings about nameserver hosts themselves: whether each resolves, IPv6
/// reachability, and provider diversity. Each entry is (host, addresses).
pub fn ns_host_findings(hosts: &[(String, Vec<String>)]) -> Vec<Finding> {
    let mut f = Vec::new();
    for (host, addrs) in hosts {
        if addrs.is_empty() {
            f.push(Finding::new(
                Severity::Warn,
                format!("Nameserver {host} does not resolve (no A or AAAA); lame delegation risk."),
            ));
        }
    }
    let resolved: Vec<&(String, Vec<String>)> =
        hosts.iter().filter(|(_, a)| !a.is_empty()).collect();
    if !resolved.is_empty() {
        if resolved
            .iter()
            .any(|(_, a)| a.iter().any(|ip| ip.contains(':')))
        {
            f.push(Finding::new(
                Severity::Pass,
                "At least one nameserver is reachable over IPv6.",
            ));
        } else {
            f.push(Finding::new(
                Severity::Info,
                "No nameserver has an IPv6 (AAAA) address.",
            ));
        }
    }
    if hosts.len() >= 2 {
        let providers: std::collections::HashSet<String> =
            hosts.iter().map(|(h, _)| parent_domain(h)).collect();
        if providers.len() == 1 {
            let p = providers.into_iter().next().unwrap_or_default();
            f.push(Finding::new(
                Severity::Info,
                format!("All nameservers are under {p}: normal for managed DNS, but no provider diversity."),
            ));
        }
    }
    f
}

/// The last two labels of a host name, a rough provider key.
fn parent_domain(host: &str) -> String {
    let labels: Vec<&str> = host.trim_end_matches('.').split('.').collect();
    labels[labels.len().saturating_sub(2)..]
        .join(".")
        .to_ascii_lowercase()
}

// --- Report model ---------------------------------------------------------

/// One check's results: a rolled-up status, its findings, and the raw records
/// observed.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Section {
    pub name: String,
    pub status: Severity,
    pub findings: Vec<Finding>,
    pub records: Vec<String>,
}

impl Section {
    pub fn new(name: &str, findings: Vec<Finding>, records: Vec<String>) -> Self {
        Section {
            status: section_status(&findings),
            name: name.to_string(),
            findings,
            records,
        }
    }
}

/// The full analysis across all checks.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AnalysisReport {
    pub domain: String,
    pub server: String,
    pub sections: Vec<Section>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_tags() {
        let t = parse_tags("v=DMARC1; p=reject; rua=mailto:x@y ");
        assert_eq!(t[0], ("v".into(), "DMARC1".into()));
        assert_eq!(t[1], ("p".into(), "reject".into()));
        assert_eq!(t[2], ("rua".into(), "mailto:x@y".into()));
    }

    #[test]
    fn section_status_rollup() {
        let f = |s| Finding::new(s, "x");
        assert_eq!(section_status(&[f(Severity::Pass)]), Severity::Pass);
        assert_eq!(
            section_status(&[f(Severity::Pass), f(Severity::Warn)]),
            Severity::Warn
        );
        assert_eq!(
            section_status(&[f(Severity::Warn), f(Severity::Fail)]),
            Severity::Fail
        );
        // Info alone does not lower status below Pass.
        assert_eq!(section_status(&[f(Severity::Info)]), Severity::Pass);
    }

    #[test]
    fn spf_parse_basic() {
        let spf = parse_spf("v=spf1 ip4:1.2.3.0/24 a mx include:_spf.google.com -all").unwrap();
        assert_eq!(spf.all_qualifier, Some('-'));
        assert_eq!(spf.direct_lookups, 2); // a, mx
        assert_eq!(spf.includes, vec!["_spf.google.com".to_string()]);
        assert_eq!(spf.redirect, None);
    }

    #[test]
    fn spf_parse_redirect() {
        let spf = parse_spf("v=spf1 redirect=_spf.example.com").unwrap();
        assert_eq!(spf.redirect.as_deref(), Some("_spf.example.com"));
        assert_eq!(spf.all_qualifier, None);
    }

    #[test]
    fn spf_not_spf() {
        assert!(parse_spf("some other txt").is_none());
        assert!(is_spf("v=spf1 -all"));
    }

    #[test]
    fn spf_record_findings_cases() {
        assert_eq!(
            spf_record_findings(&[]).first().unwrap().severity,
            Severity::Fail
        );
        let plus = spf_record_findings(&["v=spf1 +all".to_string()]);
        assert!(plus.iter().any(|f| f.severity == Severity::Fail));
        let two = spf_record_findings(&["v=spf1 -all".into(), "v=spf1 ~all".into()]);
        assert_eq!(two[0].severity, Severity::Fail);
        let good = spf_record_findings(&["v=spf1 include:a -all".into()]);
        assert_eq!(section_status(&good), Severity::Pass);
    }

    #[test]
    fn spf_lookup_findings() {
        assert_eq!(spf_lookup_finding(5, false).severity, Severity::Pass);
        assert_eq!(spf_lookup_finding(9, false).severity, Severity::Warn);
        assert_eq!(spf_lookup_finding(12, false).severity, Severity::Fail);
        assert_eq!(spf_lookup_finding(10, true).severity, Severity::Fail);
    }

    #[test]
    fn dmarc_reject_with_rua() {
        let f = dmarc_findings(&["v=DMARC1; p=reject; rua=mailto:r@x".into()]);
        assert_eq!(section_status(&f), Severity::Pass);
    }

    #[test]
    fn dmarc_none_is_warn() {
        let f = dmarc_findings(&["v=DMARC1; p=none".into()]);
        assert_eq!(section_status(&f), Severity::Warn);
    }

    #[test]
    fn dmarc_missing_is_fail() {
        let f = dmarc_findings(&[]);
        assert_eq!(f[0].severity, Severity::Fail);
    }

    #[test]
    fn dmarc_pct_partial() {
        let f = dmarc_findings(&["v=DMARC1; p=reject; rua=mailto:r@x; pct=50".into()]);
        assert!(f.iter().any(|x| x.severity == Severity::Info));
    }

    /// DER for a length.
    fn der_len(n: usize) -> Vec<u8> {
        if n < 0x80 {
            vec![n as u8]
        } else if n < 0x100 {
            vec![0x81, n as u8]
        } else {
            vec![0x82, (n >> 8) as u8, n as u8]
        }
    }

    fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut v = vec![tag];
        v.extend(der_len(body.len()));
        v.extend_from_slice(body);
        v
    }

    /// A syntactically valid RSA key of `bits` (contents are not a real key).
    fn rsa_pkcs1(bits: usize) -> Vec<u8> {
        let mut n = vec![0x00, 0xc0];
        n.extend(vec![0x11; bits / 8 - 1]);
        let mut body = tlv(0x02, &n);
        body.extend(tlv(0x02, &[0x01, 0x00, 0x01]));
        tlv(0x30, &body)
    }

    fn rsa_spki(bits: usize) -> Vec<u8> {
        let alg = tlv(
            0x30,
            &[
                0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
            ],
        );
        let mut bit_string = vec![0x00];
        bit_string.extend(rsa_pkcs1(bits));
        let mut body = alg;
        body.extend(tlv(0x03, &bit_string));
        tlv(0x30, &body)
    }

    fn b64(b: &[u8]) -> String {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(b)
    }

    #[test]
    fn rsa_key_sizes() {
        assert_eq!(rsa_modulus_bits(&rsa_spki(2048)), Some(2048));
        assert_eq!(rsa_modulus_bits(&rsa_spki(1024)), Some(1024));
        assert_eq!(rsa_modulus_bits(&rsa_pkcs1(4096)), Some(4096));
        assert_eq!(rsa_modulus_bits(&[0x30, 0x05, 0x02]), None);
        assert_eq!(rsa_modulus_bits(&[]), None);
    }

    #[test]
    fn dkim_cases() {
        let rec = |bits: usize| format!("v=DKIM1; k=rsa; p={}", b64(&rsa_spki(bits)));
        assert_eq!(dkim_findings("s", &rec(2048))[0].severity, Severity::Pass);
        assert_eq!(dkim_findings("s", &rec(1024))[0].severity, Severity::Warn);
        assert_eq!(dkim_findings("s", &rec(512))[0].severity, Severity::Fail);
        assert!(
            dkim_findings("s", &rec(2048))[0]
                .message
                .contains("2048-bit")
        );
        assert_eq!(
            dkim_findings("s", "v=DKIM1; k=rsa; p=")[0].severity,
            Severity::Warn
        );
        assert_eq!(
            dkim_findings("s", "v=DKIM1; k=rsa; p=MIGf...")[0].severity,
            Severity::Fail
        );
        let ed = format!("v=DKIM1; k=ed25519; p={}", b64(&[7u8; 32]));
        assert_eq!(dkim_findings("s", &ed)[0].severity, Severity::Pass);
        let testing = format!("{}; t=y", rec(2048));
        let f = dkim_findings("s", &testing);
        assert_eq!(f.len(), 2);
        assert_eq!(f[1].severity, Severity::Info);
        // Whitespace inside p= is allowed.
        let spaced = rec(2048).replacen("p=", "p=  ", 1);
        assert_eq!(dkim_findings("s", &spaced)[0].severity, Severity::Pass);
    }

    #[test]
    fn dkim_wildcard() {
        assert_eq!(
            dkim_wildcard_finding("v=DKIM1; p=").severity,
            Severity::Info
        );
        assert_eq!(
            dkim_wildcard_finding("v=DKIM1; p=MIIB").severity,
            Severity::Warn
        );
    }

    #[test]
    fn spf_ptr_voids_and_length() {
        let spf = parse_spf("v=spf1 ptr include:x.example -all").unwrap();
        assert!(spf.uses_ptr);
        let v = |n: usize| (0..n).map(|i| format!("v{i}.example")).collect::<Vec<_>>();
        assert!(spf_extra_findings(&v(0), false, 100).is_empty());
        let one = spf_extra_findings(&v(1), false, 100);
        assert_eq!(one[0].severity, Severity::Warn);
        assert!(one[0].message.contains("v0.example"));
        assert_eq!(
            spf_extra_findings(&v(3), false, 100)[0].severity,
            Severity::Fail
        );
        assert_eq!(
            spf_extra_findings(&v(0), true, 100)[0].severity,
            Severity::Warn
        );
        assert_eq!(
            spf_extra_findings(&v(0), false, 500)[0].severity,
            Severity::Warn
        );
    }

    fn mx(pref: u16, host: &str, addrs: &[&str]) -> MxEntry {
        MxEntry {
            preference: pref,
            host: host.to_string(),
            addresses: addrs.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn mx_cases() {
        let ok = mx_findings(
            &[
                mx(10, "mx1.example.com", &["192.0.2.1"]),
                mx(20, "mx2.example.com", &["192.0.2.2"]),
            ],
            &[],
        );
        assert_eq!(section_status(&ok), Severity::Pass);

        let null = mx_findings(&[mx(0, ".", &[])], &[]);
        assert_eq!(null.len(), 1);
        assert!(null[0].message.contains("Null MX"));

        let mixed = mx_findings(
            &[mx(0, ".", &[]), mx(10, "mx.example.com", &["192.0.2.1"])],
            &[],
        );
        assert_eq!(section_status(&mixed), Severity::Fail);

        let dead = mx_findings(&[mx(10, "gone.example.com", &[])], &[]);
        assert_eq!(section_status(&dead), Severity::Fail);

        let ip = mx_findings(&[mx(10, "192.0.2.9", &["192.0.2.9"])], &[]);
        assert!(ip.iter().any(|f| f.message.contains("IP address")));

        let none_fallback = mx_findings(&[], &["192.0.2.5".to_string()]);
        assert_eq!(none_fallback[0].severity, Severity::Warn);
        let none = mx_findings(&[], &[]);
        assert_eq!(none[0].severity, Severity::Info);

        let dup = mx_findings(
            &[
                mx(10, "a.example.com", &["1"]),
                mx(10, "b.example.com", &["2"]),
            ],
            &[],
        );
        assert!(dup.iter().any(|f| f.message.contains("share a preference")));
    }

    #[test]
    fn ns_host_cases() {
        let v6 = ns_host_findings(&[
            (
                "ns1.p.net".into(),
                vec!["192.0.2.1".into(), "2001:db8::1".into()],
            ),
            ("ns2.p.net".into(), vec!["192.0.2.2".into()]),
        ]);
        assert!(
            v6.iter()
                .any(|f| f.severity == Severity::Pass && f.message.contains("IPv6"))
        );
        assert!(v6.iter().any(|f| f.message.contains("under p.net")));

        let lame = ns_host_findings(&[
            ("ns1.a.net".into(), vec!["192.0.2.1".into()]),
            ("ns.b.org".into(), vec![]),
        ]);
        assert_eq!(section_status(&lame), Severity::Warn);
        assert!(
            lame.iter()
                .any(|f| f.message.contains("No nameserver has an IPv6"))
        );
        assert!(!lame.iter().any(|f| f.message.contains("diversity")));
    }

    #[test]
    fn dnssec_cases() {
        assert_eq!(dnssec_findings(true, true)[0].severity, Severity::Pass);
        assert_eq!(dnssec_findings(false, false)[0].severity, Severity::Info);
        assert_eq!(dnssec_findings(true, false)[0].severity, Severity::Fail);
        assert_eq!(dnssec_findings(false, true)[0].severity, Severity::Warn);
    }

    #[test]
    fn ns_agreement() {
        let ok = ns_findings(&[("a".into(), Some(5)), ("b".into(), Some(5))]);
        assert_eq!(section_status(&ok), Severity::Pass);
        let drift = ns_findings(&[("a".into(), Some(5)), ("b".into(), Some(6))]);
        assert_eq!(section_status(&drift), Severity::Fail);
        let one = ns_findings(&[("a".into(), Some(5))]);
        assert_eq!(section_status(&one), Severity::Warn);
    }
}
