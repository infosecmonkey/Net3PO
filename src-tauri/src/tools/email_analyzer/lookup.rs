//! Pure helpers for the explicit online checks: building the DNS names for
//! Team Cymru's IP-to-ASN service and DNS blocklists, and interpreting their
//! answers. The queries themselves are made in `commands`.

use std::net::{IpAddr, Ipv4Addr};

use serde::Serialize;

/// A DNS blocklist the user can pick.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Blocklist {
    pub zone: &'static str,
    pub name: &'static str,
    pub note: &'static str,
}

pub const BLOCKLISTS: &[Blocklist] = &[
    Blocklist {
        zone: "zen.spamhaus.org",
        name: "Spamhaus ZEN",
        note: "SBL, CSS, XBL and PBL combined. Refuses queries sent through large public resolvers (8.8.8.8, 1.1.1.1). Free for low-volume, non-commercial use.",
    },
    Blocklist {
        zone: "bl.spamcop.net",
        name: "SpamCop",
        note: "Short-lived listings driven by user spam reports.",
    },
    Blocklist {
        zone: "b.barracudacentral.org",
        name: "Barracuda",
        note: "Needs a free registration of the resolver's IP; unregistered queries may go unanswered.",
    },
    Blocklist {
        zone: "psbl.surriel.com",
        name: "PSBL",
        note: "Passive Spam Block List, fed by spam traps.",
    },
    Blocklist {
        zone: "bl.mailspike.net",
        name: "Mailspike",
        note: "Reputation list; codes 127.0.0.10 to 14 rate the IP from worst to poor.",
    },
];

/// IPv4 octets reversed, as DNSBLs and Cymru expect: 1.2.3.4 -> 4.3.2.1.
pub fn reversed_v4(ip: Ipv4Addr) -> String {
    let o = ip.octets();
    format!("{}.{}.{}.{}", o[3], o[2], o[1], o[0])
}

/// Team Cymru origin query name for an address.
pub fn cymru_origin_name(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => format!("{}.origin.asn.cymru.com", reversed_v4(v4)),
        IpAddr::V6(v6) => {
            let nibbles: String = v6
                .octets()
                .iter()
                .rev()
                .flat_map(|b| [b & 0x0f, b >> 4])
                .map(|n| format!("{n:x}."))
                .collect();
            format!("{nibbles}origin6.asn.cymru.com")
        }
    }
}

/// Parsed Team Cymru origin answer: `15169 | 8.8.8.0/24 | US | arin | 2023-12-28`.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CymruOrigin {
    /// Every ASN announcing the prefix (usually one).
    pub asns: Vec<u32>,
    pub prefix: String,
    pub country: String,
    pub registry: String,
    pub allocated: String,
}

pub fn parse_cymru_origin(txt: &str) -> Option<CymruOrigin> {
    let f: Vec<&str> = txt.split('|').map(str::trim).collect();
    if f.len() < 3 {
        return None;
    }
    let asns: Vec<u32> = f[0]
        .split_whitespace()
        .filter_map(|a| a.parse().ok())
        .collect();
    if asns.is_empty() {
        return None;
    }
    Some(CymruOrigin {
        asns,
        prefix: f[1].to_string(),
        country: f[2].to_string(),
        registry: f.get(3).map(|s| s.to_string()).unwrap_or_default(),
        allocated: f.get(4).map(|s| s.to_string()).unwrap_or_default(),
    })
}

/// The AS name from `15169 | US | arin | 2000-03-30 | GOOGLE, US`.
pub fn parse_cymru_as_name(txt: &str) -> Option<String> {
    let name = txt.split('|').nth(4)?.trim();
    (!name.is_empty()).then(|| name.to_string())
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum ListingStatus {
    /// The list returned a listing code.
    Listed,
    /// NXDOMAIN: not on the list.
    NotListed,
    /// The list refused to answer (for example a public-resolver block).
    Refused,
    /// Timeout, SERVFAIL or an answer that makes no sense.
    Error,
}

/// Interpret a DNSBL A-record answer. `answers` empty means NXDOMAIN.
pub fn interpret_dnsbl(zone: &str, answers: &[Ipv4Addr]) -> (ListingStatus, String) {
    if answers.is_empty() {
        return (ListingStatus::NotListed, "Not listed".into());
    }
    if answers.iter().any(|a| a.octets()[0] != 127) {
        return (
            ListingStatus::Error,
            format!(
                "Unexpected answer {}; the resolver may be rewriting failed lookups",
                answers
                    .iter()
                    .map(|a| a.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        );
    }
    if zone.ends_with("spamhaus.org") {
        // Error codes in 127.255.255.0/24 are refusals, not listings.
        if let Some(code) = answers.iter().find(|a| a.octets()[1..3] == [255, 255]) {
            let why = match code.octets()[3] {
                252 => "query was malformed",
                254 => {
                    "queries through public or open resolvers are refused; use your own resolver or Spamhaus DQS"
                }
                255 => "query volume limit exceeded",
                _ => "query refused",
            };
            return (ListingStatus::Refused, format!("Spamhaus {code}: {why}"));
        }
        let meaning: Vec<&str> = answers
            .iter()
            .map(|a| match a.octets()[3] {
                2 => "SBL (spam source)",
                3 => "SBL CSS (snowshoe spam)",
                4..=7 => "XBL (compromised or exploited host)",
                9 => "DROP (hijacked or criminal network)",
                10 | 11 => "PBL (end-user range not meant to send mail directly)",
                _ => "listed",
            })
            .collect();
        return (ListingStatus::Listed, meaning.join("; "));
    }
    if zone == "bl.mailspike.net" {
        let worst = answers.iter().map(|a| a.octets()[3]).min().unwrap_or(0);
        if (15..=20).contains(&worst) {
            return (
                ListingStatus::NotListed,
                format!("Not listed (reputation code 127.0.0.{worst}, neutral to good)"),
            );
        }
    }
    (
        ListingStatus::Listed,
        format!(
            "Listed ({})",
            answers
                .iter()
                .map(|a| a.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        ),
    )
}

/// A blocklist zone name: the built-in ones, or any plain DNS name.
pub fn valid_zone(zone: &str) -> bool {
    let z = zone.trim().trim_end_matches('.');
    z.len() <= 200
        && z.contains('.')
        && z.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                && !l.starts_with('-')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_names() {
        assert_eq!(
            reversed_v4(Ipv4Addr::new(209, 85, 220, 41)),
            "41.220.85.209"
        );
        assert_eq!(
            cymru_origin_name("209.85.220.41".parse().unwrap()),
            "41.220.85.209.origin.asn.cymru.com"
        );
        let v6 = cymru_origin_name("2001:4860::8888".parse().unwrap());
        assert!(
            v6.ends_with("0.6.8.4.1.0.0.2.origin6.asn.cymru.com"),
            "{v6}"
        );
        assert!(v6.starts_with("8.8.8.8.0.0.0.0."), "{v6}");
    }

    #[test]
    fn cymru_answers() {
        let o = parse_cymru_origin("15169 | 8.8.8.0/24 | US | arin | 2023-12-28").unwrap();
        assert_eq!(o.asns, vec![15169]);
        assert_eq!(o.prefix, "8.8.8.0/24");
        assert_eq!(o.registry, "arin");
        let multi = parse_cymru_origin("23028 3356 | 1.2.3.0/24 | US | arin |").unwrap();
        assert_eq!(multi.asns, vec![23028, 3356]);
        assert_eq!(parse_cymru_origin("garbage"), None);
        assert_eq!(
            parse_cymru_as_name("15169 | US | arin | 2000-03-30 | GOOGLE, US").as_deref(),
            Some("GOOGLE, US")
        );
        assert_eq!(parse_cymru_as_name("15169 | US"), None);
    }

    #[test]
    fn dnsbl_answers() {
        let a = |s: &str| s.parse::<Ipv4Addr>().unwrap();
        assert_eq!(
            interpret_dnsbl("bl.spamcop.net", &[]).0,
            ListingStatus::NotListed
        );
        assert_eq!(
            interpret_dnsbl("bl.spamcop.net", &[a("127.0.0.2")]).0,
            ListingStatus::Listed
        );
        let (s, why) = interpret_dnsbl("zen.spamhaus.org", &[a("127.255.255.254")]);
        assert_eq!(s, ListingStatus::Refused);
        assert!(why.contains("public"));
        let (s, why) = interpret_dnsbl("zen.spamhaus.org", &[a("127.0.0.4"), a("127.0.0.10")]);
        assert_eq!(s, ListingStatus::Listed);
        assert!(why.contains("XBL") && why.contains("PBL"));
        assert_eq!(
            interpret_dnsbl("psbl.surriel.com", &[a("23.1.2.3")]).0,
            ListingStatus::Error
        );
        assert_eq!(
            interpret_dnsbl("bl.mailspike.net", &[a("127.0.0.18")]).0,
            ListingStatus::NotListed
        );
        assert_eq!(
            interpret_dnsbl("bl.mailspike.net", &[a("127.0.0.11")]).0,
            ListingStatus::Listed
        );
    }

    #[test]
    fn zones() {
        assert!(valid_zone("zen.spamhaus.org"));
        assert!(valid_zone("dnsbl.example.net."));
        assert!(!valid_zone("localhost"));
        assert!(!valid_zone("bad zone.org"));
        assert!(!valid_zone("x;rm.org"));
    }
}
