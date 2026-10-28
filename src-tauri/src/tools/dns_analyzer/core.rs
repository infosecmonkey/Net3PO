//! Pure DNS-posture analysis: parsing and scoring for SPF, DMARC, DKIM, DNSSEC,
//! and NS consistency. Everything here takes already-fetched record strings, so
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
            "a" | "mx" | "ptr" | "exists" => spf.direct_lookups += 1,
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
    let p = tags.iter().find(|(k, _)| k == "p").map(|(_, v)| v.as_str());
    match p {
        Some("") => vec![Finding::new(
            Severity::Warn,
            format!("Selector '{selector}' exists but the key is revoked (empty p=)."),
        )],
        Some(_) => vec![Finding::new(
            Severity::Pass,
            format!("Selector '{selector}' has a published key."),
        )],
        None => vec![Finding::new(
            Severity::Warn,
            format!("Selector '{selector}' record has no p= public key."),
        )],
    }
}

/// Common DKIM selectors to probe when the user does not supply one.
pub const COMMON_SELECTORS: [&str; 12] = [
    "google",
    "default",
    "selector1",
    "selector2",
    "k1",
    "k2",
    "s1",
    "s2",
    "mail",
    "dkim",
    "mandrill",
    "fm1",
];

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

    #[test]
    fn dkim_cases() {
        assert_eq!(
            dkim_findings("google", "v=DKIM1; k=rsa; p=MIGf...")[0].severity,
            Severity::Pass
        );
        assert_eq!(
            dkim_findings("google", "v=DKIM1; k=rsa; p=")[0].severity,
            Severity::Warn
        );
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
