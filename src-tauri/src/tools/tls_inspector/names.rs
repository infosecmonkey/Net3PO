//! Names for algorithm OIDs, and RFC 6125 hostname matching against a
//! certificate's subject alternative names.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const OID_ED25519: &str = "1.3.101.112";
pub const OID_ED448: &str = "1.3.101.113";

pub fn key_algorithm(oid: &str) -> &str {
    match oid {
        "1.2.840.113549.1.1.1" => "RSA",
        "1.2.840.113549.1.1.10" => "RSA-PSS",
        "1.2.840.10045.2.1" => "EC",
        "1.2.840.10040.4.1" => "DSA",
        OID_ED25519 => "Ed25519",
        OID_ED448 => "Ed448",
        other => other,
    }
}

pub fn curve(oid: &str) -> &str {
    match oid {
        "1.2.840.10045.3.1.7" => "P-256",
        "1.3.132.0.34" => "P-384",
        "1.3.132.0.35" => "P-521",
        "1.3.132.0.10" => "secp256k1",
        other => other,
    }
}

pub fn signature_algorithm(oid: &str) -> String {
    match oid {
        "1.2.840.113549.1.1.4" => "RSA with MD5",
        "1.2.840.113549.1.1.5" => "RSA with SHA-1",
        "1.2.840.113549.1.1.11" => "RSA with SHA-256",
        "1.2.840.113549.1.1.12" => "RSA with SHA-384",
        "1.2.840.113549.1.1.13" => "RSA with SHA-512",
        "1.2.840.113549.1.1.10" => "RSA-PSS",
        "1.2.840.10045.4.1" => "ECDSA with SHA-1",
        "1.2.840.10045.4.3.2" => "ECDSA with SHA-256",
        "1.2.840.10045.4.3.3" => "ECDSA with SHA-384",
        "1.2.840.10045.4.3.4" => "ECDSA with SHA-512",
        OID_ED25519 => "Ed25519",
        OID_ED448 => "Ed448",
        other => return other.to_string(),
    }
    .to_string()
}

/// An IP address SAN as text (4 or 16 bytes; anything else as hex).
pub fn ip_bytes(b: &[u8]) -> String {
    match b.len() {
        4 => Ipv4Addr::new(b[0], b[1], b[2], b[3]).to_string(),
        16 => {
            let mut a = [0u8; 16];
            a.copy_from_slice(b);
            Ipv6Addr::from(a).to_string()
        }
        _ => b.iter().map(|x| format!("{x:02x}")).collect(),
    }
}

/// One DNS SAN against a hostname. A wildcard covers exactly one leftmost
/// label (`*.example.com` matches `a.example.com`, not `example.com` or
/// `a.b.example.com`), and never a public suffix like `*.com`.
fn dns_matches(pattern: &str, host: &str) -> bool {
    let p = pattern.trim_end_matches('.').to_ascii_lowercase();
    let h = host.trim_end_matches('.').to_ascii_lowercase();
    if let Some(rest) = p.strip_prefix("*.") {
        if !rest.contains('.') {
            return false;
        }
        return match h.split_once('.') {
            Some((first, tail)) => !first.is_empty() && tail == rest,
            None => false,
        };
    }
    p == h
}

/// Which SAN, if any, covers `host`. IP literals match only IP SANs.
pub fn matching_name(dns: &[String], ips: &[String], host: &str) -> Option<String> {
    if let Ok(ip) = host
        .trim_matches(|c| c == '[' || c == ']')
        .parse::<IpAddr>()
    {
        return ips
            .iter()
            .find(|s| s.parse::<IpAddr>().is_ok_and(|a| a == ip))
            .cloned();
    }
    dns.iter().find(|p| dns_matches(p, host)).cloned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcard_rules() {
        assert!(dns_matches("*.example.com", "www.example.com"));
        assert!(dns_matches("*.EXAMPLE.com", "WWW.example.com."));
        assert!(!dns_matches("*.example.com", "example.com"));
        assert!(!dns_matches("*.example.com", "a.b.example.com"));
        assert!(!dns_matches("*.com", "example.com"));
        assert!(dns_matches("www.example.com", "www.example.com"));
        assert!(!dns_matches("www.example.com", "mail.example.com"));
    }

    #[test]
    fn matching() {
        let dns = vec![
            "www.example.com".to_string(),
            "*.api.example.com".to_string(),
        ];
        let ips = vec!["192.0.2.10".to_string(), "2001:db8::1".to_string()];
        assert_eq!(
            matching_name(&dns, &ips, "v1.api.example.com").as_deref(),
            Some("*.api.example.com")
        );
        assert_eq!(
            matching_name(&dns, &ips, "192.0.2.10").as_deref(),
            Some("192.0.2.10")
        );
        assert_eq!(
            matching_name(&dns, &ips, "[2001:db8::1]").as_deref(),
            Some("2001:db8::1")
        );
        assert_eq!(matching_name(&dns, &ips, "192.0.2.11"), None);
        assert_eq!(matching_name(&dns, &ips, "example.com"), None);
    }

    #[test]
    fn ip_san_text() {
        assert_eq!(ip_bytes(&[192, 0, 2, 1]), "192.0.2.1");
        assert_eq!(
            ip_bytes(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
            "2001:db8::1"
        );
        assert_eq!(ip_bytes(&[1, 2]), "0102");
    }
}
