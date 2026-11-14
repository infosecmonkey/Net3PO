//! Domain helpers: an approximate organizational domain (for DMARC-style
//! alignment) and address-literal checks. There is no full Public Suffix
//! List here, so the organizational domain is labeled approximate in the UI.

use std::net::IpAddr;

/// Common public suffixes with more than one label. Not exhaustive.
const MULTI_LABEL_SUFFIXES: &[&str] = &[
    "co.uk", "org.uk", "ac.uk", "gov.uk", "ltd.uk", "plc.uk", "me.uk", "net.uk", "com.au",
    "net.au", "org.au", "edu.au", "gov.au", "asn.au", "id.au", "co.nz", "org.nz", "net.nz",
    "govt.nz", "ac.nz", "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp", "co.kr", "or.kr", "ac.kr",
    "go.kr", "com.br", "net.br", "org.br", "gov.br", "com.mx", "org.mx", "gob.mx", "com.ar",
    "com.co", "com.pe", "com.ve", "com.ec", "com.uy", "co.za", "org.za", "gov.za", "co.in",
    "net.in", "org.in", "gov.in", "ac.in", "firm.in", "com.cn", "net.cn", "org.cn", "gov.cn",
    "edu.cn", "com.hk", "org.hk", "net.hk", "com.tw", "org.tw", "com.sg", "org.sg", "edu.sg",
    "com.my", "org.my", "com.ph", "com.vn", "co.th", "or.th", "co.id", "or.id", "com.tr", "org.tr",
    "gov.tr", "com.sa", "com.eg", "co.il", "org.il", "ac.il", "com.pl", "net.pl", "org.pl",
    "co.at", "or.at", "com.es", "org.es", "com.pt", "com.gr", "com.ua", "org.ua", "com.ru",
    "org.ru",
];

/// Lowercase, trim, and drop a trailing dot and surrounding brackets.
pub fn normalize(domain: &str) -> String {
    domain
        .trim()
        .trim_matches(|c| c == '<' || c == '>' || c == '[' || c == ']')
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

/// The domain part of an address, if any.
pub fn of_address(addr: &str) -> Option<String> {
    let at = addr.rfind('@')?;
    let d = normalize(&addr[at + 1..]);
    (!d.is_empty() && d.contains('.')).then_some(d)
}

/// Approximate organizational domain: the registrable part, using a short
/// list of multi-label suffixes. `mail.corp.example.co.uk` -> `example.co.uk`.
pub fn org_domain(domain: &str) -> String {
    let d = normalize(domain);
    if d.parse::<IpAddr>().is_ok() {
        return d;
    }
    let labels: Vec<&str> = d.split('.').filter(|l| !l.is_empty()).collect();
    if labels.len() <= 2 {
        return labels.join(".");
    }
    let last_two = labels[labels.len() - 2..].join(".");
    let keep = if MULTI_LABEL_SUFFIXES.contains(&last_two.as_str()) {
        3
    } else {
        2
    };
    labels[labels.len().saturating_sub(keep)..].join(".")
}

/// Relaxed alignment: same organizational domain.
pub fn aligned_relaxed(a: &str, b: &str) -> bool {
    !a.is_empty() && !b.is_empty() && org_domain(a) == org_domain(b)
}

/// Strict alignment: exactly the same domain.
pub fn aligned_strict(a: &str, b: &str) -> bool {
    !a.is_empty() && normalize(a) == normalize(b)
}

/// True for addresses that cannot be an internet sender: private, loopback,
/// link-local, CGNAT, documentation, multicast and unspecified ranges.
pub fn is_non_public(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.is_documentation()
                || (o[0] == 100 && (64..128).contains(&o[1]))
                || o[0] == 0
                || o[0] >= 240
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00
                || (s[0] & 0xffc0) == 0xfe80
                || (s[0] == 0x2001 && s[1] == 0x0db8)
                || v6
                    .to_ipv4_mapped()
                    .is_some_and(|v4| is_non_public(&IpAddr::V4(v4)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn org_domains() {
        assert_eq!(org_domain("mail.Example.com."), "example.com");
        assert_eq!(org_domain("example.com"), "example.com");
        assert_eq!(org_domain("a.b.example.co.uk"), "example.co.uk");
        assert_eq!(org_domain("example.co.uk"), "example.co.uk");
        assert_eq!(org_domain("localhost"), "localhost");
        assert_eq!(org_domain("10.1.1.1"), "10.1.1.1");
    }

    #[test]
    fn alignment() {
        assert!(aligned_relaxed("mail.example.com", "example.com"));
        assert!(!aligned_strict("mail.example.com", "example.com"));
        assert!(aligned_strict("Example.COM", "example.com"));
        assert!(!aligned_relaxed("example.com", "example.net"));
        assert!(!aligned_relaxed("", ""));
    }

    #[test]
    fn addresses() {
        assert_eq!(
            of_address("Ann@Mail.Example.com").as_deref(),
            Some("mail.example.com")
        );
        assert_eq!(
            of_address("<bounce@example.org>").as_deref(),
            Some("example.org")
        );
        assert_eq!(of_address("no-domain"), None);
        assert_eq!(of_address("x@localhost"), None);
    }

    #[test]
    fn public_ranges() {
        for ip in [
            "10.0.0.1",
            "192.168.1.1",
            "172.16.0.1",
            "127.0.0.1",
            "100.64.1.1",
            "169.254.1.1",
            "192.0.2.5",
            "::1",
            "fe80::1",
            "fd00::1",
            "2001:db8::1",
            "::ffff:10.0.0.1",
        ] {
            assert!(is_non_public(&ip.parse().unwrap()), "{ip}");
        }
        for ip in ["8.8.8.8", "203.1.113.1", "2607:f8b0::1"] {
            assert!(!is_non_public(&ip.parse().unwrap()), "{ip}");
        }
    }
}
