//! Pure FortiOS CLI command builders. Each builder takes form input, validates
//! every field, and returns the command text; nothing here touches the
//! network. Validation is the point: a value that reaches the command is a
//! well-formed address, port, number, or name, never free text that could
//! break the line or smuggle a second command.

pub mod flow;
pub mod ping;
pub mod session;
pub mod sniffer;
pub mod traceroute;

use std::net::{IpAddr, Ipv4Addr};

use serde::Serialize;
use thiserror::Error;

use crate::tools::mac_vendor::core::parse_mac;

/// A validation failure tied to the form field that caused it.
#[derive(Debug, Clone, Error, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
#[error("{field}: {message}")]
pub struct BuildError {
    pub field: String,
    pub message: String,
}

pub type BuildResult<T> = Result<T, BuildError>;

fn err<T>(field: &str, message: impl Into<String>) -> BuildResult<T> {
    Err(BuildError {
        field: field.to_string(),
        message: message.into(),
    })
}

/// Trimmed value, or None when blank.
fn present(s: &str) -> Option<&str> {
    let t = s.trim();
    (!t.is_empty()).then_some(t)
}

/// Optional IPv4 address.
pub fn opt_ipv4(field: &str, s: &str) -> BuildResult<Option<Ipv4Addr>> {
    match present(s) {
        None => Ok(None),
        Some(t) => t
            .parse::<Ipv4Addr>()
            .map(Some)
            .or_else(|_| err(field, format!("'{t}' is not an IPv4 address"))),
    }
}

/// Optional IPv4 or IPv6 address.
pub fn opt_ip(field: &str, s: &str) -> BuildResult<Option<IpAddr>> {
    match present(s) {
        None => Ok(None),
        Some(t) => t
            .parse::<IpAddr>()
            .map(Some)
            .or_else(|_| err(field, format!("'{t}' is not an IP address"))),
    }
}

/// Optional network in CIDR form (or a bare address), normalized.
pub fn opt_cidr(field: &str, s: &str) -> BuildResult<Option<String>> {
    let Some(t) = present(s) else {
        return Ok(None);
    };
    let (addr, prefix) = match t.split_once('/') {
        Some((a, p)) => (a, Some(p)),
        None => (t, None),
    };
    let Ok(ip) = addr.parse::<IpAddr>() else {
        return err(
            field,
            format!("'{t}' is not a network (use e.g. 10.0.0.0/24)"),
        );
    };
    let max = if ip.is_ipv4() { 32 } else { 128 };
    match prefix {
        None => Ok(Some(ip.to_string())),
        Some(p) => match p.parse::<u8>() {
            Ok(n) if n <= max => Ok(Some(format!("{ip}/{n}"))),
            _ => err(field, format!("prefix length must be 0 to {max}")),
        },
    }
}

/// Optional TCP/UDP port, 1 to 65535.
pub fn opt_port(field: &str, s: &str) -> BuildResult<Option<u16>> {
    match present(s) {
        None => Ok(None),
        Some(t) => match t.parse::<u16>() {
            Ok(p) if p > 0 => Ok(Some(p)),
            _ => err(field, format!("'{t}' is not a port (1 to 65535)")),
        },
    }
}

/// Comma-separated ports; empty yields an empty list.
pub fn port_list(field: &str, s: &str) -> BuildResult<Vec<u16>> {
    s.split(',')
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .map(|p| opt_port(field, p).map(|v| v.unwrap_or_default()))
        .collect()
}

/// Optional integer within `[min, max]`.
pub fn opt_int(field: &str, s: &str, min: u64, max: u64) -> BuildResult<Option<u64>> {
    match present(s) {
        None => Ok(None),
        Some(t) => match t.parse::<u64>() {
            Ok(n) if (min..=max).contains(&n) => Ok(Some(n)),
            _ => err(
                field,
                format!("'{t}' must be a whole number from {min} to {max}"),
            ),
        },
    }
}

/// Optional VDOM index. FortiOS session and flow filters take the numeric
/// index shown by `diagnose sys vd list`, not the VDOM name.
pub fn opt_vdom_index(field: &str, s: &str) -> BuildResult<Option<u64>> {
    match present(s) {
        Some(t) if t.parse::<u64>().is_err() => err(
            field,
            "use the VDOM index number (see diagnose sys vd list), not its name",
        ),
        _ => opt_int(field, s, 0, 65_535),
    }
}

/// A FortiOS interface name: letters, digits, and `. _ - :`, at most 35
/// characters (VLAN and zone names can exceed the 15-character port limit).
pub fn interface_name(field: &str, s: &str) -> BuildResult<String> {
    let t = s.trim();
    if t.is_empty() {
        return err(field, "enter an interface name or 'any'");
    }
    if t.len() > 35 {
        return err(field, "interface names are at most 35 characters");
    }
    if let Some(c) = t
        .chars()
        .find(|c| !(c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | ':')))
    {
        return err(field, format!("'{c}' is not allowed in an interface name"));
    }
    Ok(t.to_string())
}

/// Required ping/traceroute target: an IPv4 address or a DNS hostname
/// (letters, digits, hyphens, dots; labels up to 63, name up to 253).
pub fn target_host(field: &str, s: &str) -> BuildResult<String> {
    let t = s.trim().trim_end_matches('.');
    if t.is_empty() {
        return err(field, "enter a destination IP or hostname");
    }
    if t.parse::<Ipv4Addr>().is_ok() {
        return Ok(t.to_string());
    }
    let label_ok = |l: &str| {
        !l.is_empty()
            && l.len() <= 63
            && !l.starts_with('-')
            && !l.ends_with('-')
            && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    };
    // A name made only of digits and dots is a malformed IP, not a hostname.
    let all_numeric = t.chars().all(|c| c.is_ascii_digit() || c == '.');
    if t.len() <= 253 && !all_numeric && t.split('.').all(label_ok) {
        Ok(t.to_string())
    } else {
        err(
            field,
            format!("'{}' is not an IPv4 address or hostname", s.trim()),
        )
    }
}

/// Optional source address for ping/traceroute options: IPv4 or `auto`.
pub fn opt_source(field: &str, s: &str) -> BuildResult<Option<String>> {
    match present(s) {
        None => Ok(None),
        Some(t) if t.eq_ignore_ascii_case("auto") => Ok(Some("auto".to_string())),
        Some(t) => t
            .parse::<Ipv4Addr>()
            .map(|ip| Some(ip.to_string()))
            .or_else(|_| err(field, format!("'{t}' must be an IPv4 address or 'auto'"))),
    }
}

/// Optional interface name.
pub fn opt_interface(field: &str, s: &str) -> BuildResult<Option<String>> {
    match present(s) {
        None => Ok(None),
        Some(_) => interface_name(field, s).map(Some),
    }
}

/// Optional 6-octet MAC, normalized to lowercase colon form for BPF.
pub fn opt_mac(field: &str, s: &str) -> BuildResult<Option<String>> {
    let Some(t) = present(s) else {
        return Ok(None);
    };
    match parse_mac(t) {
        Ok(b) if b.len() == 6 => Ok(Some(
            b.iter()
                .map(|x| format!("{x:02x}"))
                .collect::<Vec<_>>()
                .join(":"),
        )),
        Ok(_) => err(field, "a MAC address has 6 octets"),
        Err(e) => err(field, e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_validation() {
        assert_eq!(opt_ipv4("src", "  ").unwrap(), None);
        assert_eq!(
            opt_ipv4("src", " 10.1.1.10 ").unwrap(),
            Some(Ipv4Addr::new(10, 1, 1, 10))
        );
        let e = opt_ipv4("src", "10.1.1.10; diagnose sys reboot").unwrap_err();
        assert_eq!(e.field, "src");
        assert!(opt_ipv4("src", "10.1.1").is_err());
    }

    #[test]
    fn cidr_validation_and_normalization() {
        assert_eq!(
            opt_cidr("net", "10.0.0.0/24").unwrap().as_deref(),
            Some("10.0.0.0/24")
        );
        assert_eq!(
            opt_cidr("net", "10.0.0.1").unwrap().as_deref(),
            Some("10.0.0.1")
        );
        assert_eq!(
            opt_cidr("net", "2001:DB8::/32").unwrap().as_deref(),
            Some("2001:db8::/32")
        );
        assert!(opt_cidr("net", "10.0.0.0/33").is_err());
        assert!(opt_cidr("net", "10.0.0.0/x").is_err());
        assert!(opt_cidr("net", "lan").is_err());
    }

    #[test]
    fn ports() {
        assert_eq!(opt_port("p", "443").unwrap(), Some(443));
        assert!(opt_port("p", "0").is_err());
        assert!(opt_port("p", "65536").is_err());
        assert!(opt_port("p", "http").is_err());
        assert_eq!(
            port_list("p", "80, 443,,8443").unwrap(),
            vec![80, 443, 8443]
        );
        assert!(port_list("p", "80,abc").is_err());
    }

    #[test]
    fn vdom_must_be_index() {
        assert_eq!(opt_vdom_index("vdom", "3").unwrap(), Some(3));
        let e = opt_vdom_index("vdom", "root").unwrap_err();
        assert!(e.message.contains("index"));
    }

    #[test]
    fn interface_names() {
        for ok in ["any", "port1", "port1.20", "vlan-100", "guest_wifi", "wan1"] {
            assert_eq!(interface_name("iface", ok).unwrap(), ok);
        }
        for bad in ["", "port1 port2", "a'b", "x;y", &"p".repeat(36)] {
            assert!(interface_name("iface", bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn mac_normalized_for_bpf() {
        assert_eq!(
            opt_mac("mac", "00-1B-44-11-3A-B7").unwrap().as_deref(),
            Some("00:1b:44:11:3a:b7")
        );
        assert_eq!(
            opt_mac("mac", "001b.4411.3ab7").unwrap().as_deref(),
            Some("00:1b:44:11:3a:b7")
        );
        assert!(opt_mac("mac", "00:1b:44").is_err());
        assert!(opt_mac("mac", "zz:1b:44:11:3a:b7").is_err());
    }

    #[test]
    fn targets() {
        for ok in [
            "8.8.8.8",
            "fortinet.com",
            "fw-01.lab.example.net",
            "fortinet.com.",
        ] {
            assert!(target_host("target", ok).is_ok(), "{ok}");
        }
        for bad in [
            "",
            "8.8.8",
            "999.1.1.1",
            "a b.com",
            "-bad.com",
            "host;reboot",
            &"a".repeat(64),
        ] {
            assert!(target_host("target", bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn sources() {
        assert_eq!(
            opt_source("source", "AUTO").unwrap().as_deref(),
            Some("auto")
        );
        assert_eq!(
            opt_source("source", "10.0.0.1").unwrap().as_deref(),
            Some("10.0.0.1")
        );
        assert!(opt_source("source", "port1").is_err());
        assert_eq!(opt_source("source", " ").unwrap(), None);
    }

    #[test]
    fn int_range() {
        assert_eq!(opt_int("count", "1000", 1, 100_000).unwrap(), Some(1000));
        assert!(opt_int("count", "0", 1, 100_000).is_err());
        assert!(opt_int("count", "-5", 1, 100_000).is_err());
    }
}
