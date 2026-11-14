//! Offline lookalike-domain heuristics. Compares the domains in a message
//! with each other, with domains the user says are genuine, and with a short
//! list of commonly impersonated brands. Findings are prompts for review:
//! a similar name is not proof of impersonation.

use serde::Serialize;

use super::domains::{normalize, org_domain};

/// Brands often imitated in phishing. Exact matches are never flagged.
pub const COMMON_BRANDS: &[&str] = &[
    "microsoft.com",
    "office.com",
    "office365.com",
    "outlook.com",
    "live.com",
    "google.com",
    "gmail.com",
    "apple.com",
    "icloud.com",
    "amazon.com",
    "paypal.com",
    "docusign.com",
    "dropbox.com",
    "adobe.com",
    "linkedin.com",
    "facebook.com",
    "instagram.com",
    "netflix.com",
    "fortinet.com",
    "zoom.us",
    "slack.com",
    "salesforce.com",
    "intuit.com",
    "wellsfargo.com",
    "chase.com",
    "bankofamerica.com",
    "americanexpress.com",
    "fedex.com",
    "ups.com",
    "usps.com",
    "dhl.com",
    "irs.gov",
];

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Lookalike {
    /// The domain found in the message.
    pub domain: String,
    /// What it resembles.
    pub resembles: String,
    /// "message" (another domain in this message), "known" (user list) or
    /// "brand" (built-in list).
    pub against: String,
    pub reason: String,
}

/// Unicode form of an IDN, when it decodes.
pub fn unicode_form(domain: &str) -> Option<String> {
    if !domain.split('.').any(|l| l.starts_with("xn--")) {
        return None;
    }
    let (u, res) = idna::domain_to_unicode(domain);
    res.ok().map(|_| u)
}

/// Map look-alike characters to a plain ASCII skeleton so `paypa1.com`,
/// `pаypal.com` (Cyrillic а) and `rnicrosoft.com` collapse to the same
/// string as the genuine name.
pub fn skeleton(domain: &str) -> String {
    let lower = domain.to_lowercase();
    let mut s = String::with_capacity(lower.len());
    for c in lower.chars() {
        let mapped = match c {
            // Cyrillic
            'а' => 'a',
            'е' => 'e',
            'о' => 'o',
            'р' => 'p',
            'с' => 'c',
            'у' => 'y',
            'х' => 'x',
            'і' => 'i',
            'ј' => 'j',
            'ѕ' => 's',
            'һ' => 'h',
            'ԁ' => 'd',
            'ԛ' => 'q',
            'ԝ' => 'w',
            'ӏ' => 'l',
            'к' => 'k',
            'м' => 'm',
            'т' => 't',
            'в' => 'b',
            'н' => 'h',
            // Greek
            'α' => 'a',
            'ο' => 'o',
            'ρ' => 'p',
            'ν' => 'v',
            'ι' => 'i',
            'κ' => 'k',
            'τ' => 't',
            'χ' => 'x',
            'υ' => 'u',
            'ε' => 'e',
            // Latin look-alikes and digits
            'ı' => 'i',
            'ł' => 'l',
            'ɡ' => 'g',
            'ɑ' => 'a',
            'ⅼ' => 'l',
            '0' => 'o',
            '1' => 'l',
            '3' => 'e',
            '5' => 's',
            '8' => 'b',
            other => other,
        };
        s.push(mapped);
    }
    // Multi-character tricks, applied after the single-character map.
    s.replace("rn", "m")
        .replace("vv", "w")
        .replace("cl", "d")
        .replace('i', "l")
}

/// Optimal string alignment distance (Damerau-Levenshtein with adjacent
/// transpositions), on characters.
pub fn edit_distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let (n, m) = (a.len(), b.len());
    let mut d = vec![vec![0usize; m + 1]; n + 1];
    for (i, row) in d.iter_mut().enumerate() {
        row[0] = i;
    }
    for (j, cell) in d[0].iter_mut().enumerate() {
        *cell = j;
    }
    for i in 1..=n {
        for j in 1..=m {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            d[i][j] = (d[i - 1][j] + 1)
                .min(d[i][j - 1] + 1)
                .min(d[i - 1][j - 1] + cost);
            if i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                d[i][j] = d[i][j].min(d[i - 2][j - 2] + 1);
            }
        }
    }
    d[n][m]
}

/// Split an organizational domain into (name, suffix): `example.co.uk` ->
/// (`example`, `co.uk`).
fn split_org(org: &str) -> (&str, &str) {
    match org.split_once('.') {
        Some((name, suffix)) => (name, suffix),
        None => (org, ""),
    }
}

/// Why `candidate` resembles `genuine`, if it does. Both are organizational
/// domains, in their display (Unicode) form.
pub fn resemblance(candidate: &str, genuine: &str) -> Option<String> {
    if candidate == genuine {
        return None;
    }
    let (cn, cs) = split_org(candidate);
    let (gn, gs) = split_org(genuine);
    if skeleton(candidate) == skeleton(genuine) {
        return Some("uses look-alike characters".into());
    }
    if cn == gn && cs != gs {
        return Some(format!(
            "same name with a different ending (.{cs} instead of .{gs})"
        ));
    }
    if gn.chars().count() >= 4 && cs == gs {
        let dist = edit_distance(cn, gn);
        if dist == 1 {
            return Some("one character added, removed, swapped or changed".into());
        }
        if dist == 2 && gn.chars().count() >= 8 {
            return Some("two characters different".into());
        }
    }
    if gn.chars().count() >= 4 {
        let parts: Vec<&str> = cn.split('-').collect();
        if parts.len() > 1 && parts.contains(&gn) {
            return Some(format!("contains \"{gn}\" with extra words"));
        }
    }
    None
}

/// Run every comparison. `message` is each domain in the message with the
/// roles it plays (From, Reply-To, ...); `known` is the user's list.
pub fn check(message: &[(String, Vec<String>)], known: &[String]) -> Vec<Lookalike> {
    let display = |d: &str| unicode_form(d).unwrap_or_else(|| d.to_string());
    let orgs: Vec<(String, String)> = message
        .iter()
        .map(|(d, _)| {
            let org = org_domain(d);
            (org.clone(), display(&org))
        })
        .collect();
    let known: Vec<String> = known
        .iter()
        .map(|k| org_domain(&normalize(k)))
        .filter(|k| !k.is_empty())
        .collect();

    let mut out: Vec<Lookalike> = Vec::new();
    let mut push = |l: Lookalike| {
        if !out
            .iter()
            .any(|x| x.domain == l.domain && x.resembles == l.resembles)
        {
            out.push(l);
        }
    };

    for (i, (org, shown)) in orgs.iter().enumerate() {
        if let Some(u) = unicode_form(org) {
            let non_ascii = !u.is_ascii();
            if non_ascii {
                push(Lookalike {
                    domain: org.clone(),
                    resembles: u.clone(),
                    against: "message".into(),
                    reason: format!("internationalized domain; it displays as \"{u}\""),
                });
            }
        }
        // Other domains in the same message.
        for (j, (other, other_shown)) in orgs.iter().enumerate() {
            if i == j || org == other {
                continue;
            }
            if let Some(reason) = resemblance(shown, other_shown) {
                push(Lookalike {
                    domain: org.clone(),
                    resembles: other.clone(),
                    against: "message".into(),
                    reason,
                });
            }
        }
        for k in &known {
            if let Some(reason) = resemblance(shown, &display(k)) {
                push(Lookalike {
                    domain: org.clone(),
                    resembles: k.clone(),
                    against: "known".into(),
                    reason,
                });
            }
        }
        for b in COMMON_BRANDS {
            if known.iter().any(|k| k == b) {
                continue;
            }
            if let Some(reason) = resemblance(shown, b) {
                push(Lookalike {
                    domain: org.clone(),
                    resembles: (*b).to_string(),
                    against: "brand".into(),
                    reason,
                });
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roles(list: &[&str]) -> Vec<(String, Vec<String>)> {
        list.iter()
            .map(|d| (d.to_string(), vec!["From".to_string()]))
            .collect()
    }

    #[test]
    fn skeletons() {
        assert_eq!(skeleton("paypa1.com"), skeleton("paypal.com"));
        assert_eq!(skeleton("rnicrosoft.com"), skeleton("microsoft.com"));
        assert_eq!(skeleton("pаypal.com"), skeleton("paypal.com"));
        assert_ne!(skeleton("example.com"), skeleton("sample.com"));
    }

    #[test]
    fn distances() {
        assert_eq!(edit_distance("paypal", "paypal"), 0);
        assert_eq!(edit_distance("paypal", "paypall"), 1);
        assert_eq!(edit_distance("paypal", "papyal"), 1);
        assert_eq!(edit_distance("fortinet", "fortniet"), 1);
        assert_eq!(edit_distance("abc", ""), 3);
    }

    #[test]
    fn resemblances() {
        assert!(
            resemblance("paypa1.com", "paypal.com")
                .unwrap()
                .contains("look-alike")
        );
        assert!(
            resemblance("paypal.net", "paypal.com")
                .unwrap()
                .contains("different ending")
        );
        assert!(resemblance("fortniet.com", "fortinet.com").is_some());
        assert!(
            resemblance("paypal-secure.com", "paypal.com")
                .unwrap()
                .contains("extra words")
        );
        assert_eq!(resemblance("paypal.com", "paypal.com"), None);
        assert_eq!(
            resemblance("ups.com", "ubs.com"),
            None,
            "short names are too noisy"
        );
        assert_eq!(resemblance("example.com", "sample.org"), None);
    }

    #[test]
    fn message_and_brand_checks() {
        let found = check(&roles(&["mail.paypa1.com", "paypal.com"]), &[]);
        assert!(found.iter().any(|l| l.domain == "paypa1.com"
            && l.resembles == "paypal.com"
            && l.against == "message"));
        // One finding per pair: the in-message comparison wins over the brand list.
        let pairs = found
            .iter()
            .filter(|l| l.domain == "paypa1.com" && l.resembles == "paypal.com")
            .count();
        assert_eq!(pairs, 1);
        let alone = check(&roles(&["paypa1.com"]), &[]);
        assert!(
            alone
                .iter()
                .any(|l| l.resembles == "paypal.com" && l.against == "brand")
        );
        // The genuine brand itself is never flagged against the brand list.
        assert!(
            !found
                .iter()
                .any(|l| l.domain == "paypal.com" && l.against == "brand")
        );
    }

    #[test]
    fn known_list_and_idn() {
        let found = check(&roles(&["acrne-corp.com"]), &["acme-corp.com".to_string()]);
        assert!(found.iter().any(|l| l.against == "known"));
        // "pаypal.com" with a Cyrillic а.
        let puny = idna::domain_to_ascii("p\u{0430}ypal.com").unwrap();
        assert!(puny.starts_with("xn--"));
        let idn = check(&roles(&[puny.as_str()]), &[]);
        assert!(
            idn.iter().any(|l| l.reason.contains("internationalized")),
            "{idn:?}"
        );
        assert!(idn.iter().any(|l| l.resembles == "paypal.com"), "{idn:?}");
    }

    #[test]
    fn unrelated_domains_are_quiet() {
        assert!(
            check(
                &roles(&["example.com", "mailchimp.com", "sendgrid.net"]),
                &[]
            )
            .is_empty()
        );
        // Same name on another suffix is worth a look.
        assert_eq!(
            check(&roles(&["example.com", "example.org.uk"]), &[]).len(),
            2
        );
    }
}
