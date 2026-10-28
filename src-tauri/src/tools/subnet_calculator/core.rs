//! Pure subnet-calculator logic. No Tauri types here so it can be unit tested
//! in isolation. Covers IPv4 and IPv6 analysis plus subnet splitting.

use std::net::{Ipv4Addr, Ipv6Addr};

use serde::Serialize;
use thiserror::Error;

/// Hard cap on how many subnets a split will enumerate. Splitting a /8 into
/// /32s would be billions of entries, so we bound the list and report the real
/// total separately. Keeps the UI responsive and memory bounded.
pub const SPLIT_LIMIT: usize = 4096;

/// Errors returned by the subnet calculator core. Mapped to plain strings at
/// the command boundary so the UI can show them directly.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum SubnetError {
    #[error("enter an address, for example 10.1.1.0/24 or 2001:db8::/48")]
    Empty,
    #[error("could not parse '{0}' as an IPv4 or IPv6 address")]
    BadAddress(String),
    #[error("could not parse '{0}' as a prefix length or netmask")]
    BadPrefix(String),
    #[error("prefix /{0} is out of range for IPv4 (0 to 32)")]
    PrefixRangeV4(u32),
    #[error("prefix /{0} is out of range for IPv6 (0 to 128)")]
    PrefixRangeV6(u32),
    #[error("'{0}' is not a valid IPv4 netmask (bits must be contiguous)")]
    BadNetmask(String),
    #[error("new prefix /{new} must be larger than the current prefix /{current}")]
    SplitTooSmall { current: u32, new: u32 },
}

/// A parsed network, either IPv4 or IPv6, together with its prefix length.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Network {
    V4 { addr: Ipv4Addr, prefix: u32 },
    V6 { addr: Ipv6Addr, prefix: u32 },
}

/// The analysis result for one network. Tagged enum so the UI can switch on
/// `version`.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(tag = "version")]
pub enum SubnetReport {
    #[serde(rename = "ipv4")]
    V4(Ipv4Report),
    #[serde(rename = "ipv6")]
    V6(Ipv6Report),
}

/// sipcalc-style breakdown of an IPv4 network.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Ipv4Report {
    pub address: String,
    pub prefix: u32,
    pub cidr: String,
    pub netmask: String,
    pub netmask_hex: String,
    pub wildcard: String,
    pub network: String,
    pub broadcast: String,
    pub host_min: String,
    pub host_max: String,
    /// Total addresses in the block, including network and broadcast.
    pub total_addresses: u64,
    /// Addresses assignable to hosts.
    pub usable_hosts: u64,
    pub network_class: String,
    pub address_type: String,
    pub address_binary: String,
    pub netmask_binary: String,
    pub network_binary: String,
}

/// sipcalc-style breakdown of an IPv6 network.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Ipv6Report {
    pub address_compressed: String,
    pub address_expanded: String,
    pub prefix: u32,
    pub cidr: String,
    pub network_compressed: String,
    pub network_expanded: String,
    pub host_min: String,
    pub host_max: String,
    /// Decimal string because the count can be up to 2^128.
    pub total_addresses: String,
    pub address_type: String,
}

/// One subnet produced by a split.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SubnetEntry {
    pub cidr: String,
    pub network: String,
    pub broadcast: String,
    pub host_min: String,
    pub host_max: String,
    pub usable_hosts: String,
}

/// Result of splitting a network into smaller prefixes.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SplitResult {
    pub parent_cidr: String,
    pub new_prefix: u32,
    /// Real number of subnets, as a decimal string (can exceed u64 for IPv6).
    pub total_subnets: String,
    /// True when `subnets` was truncated to `SPLIT_LIMIT`.
    pub truncated: bool,
    pub subnets: Vec<SubnetEntry>,
}

/// Parse user input like `10.1.1.0/24`, `10.0.0.0/255.255.255.0`,
/// `2001:db8::/48`, or a bare address (defaults to /32 or /128).
pub fn parse_network(input: &str) -> Result<Network, SubnetError> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(SubnetError::Empty);
    }

    let (addr_part, prefix_part) = match trimmed.split_once('/') {
        Some((a, p)) => (a.trim(), Some(p.trim())),
        None => (trimmed, None),
    };

    if let Ok(v4) = addr_part.parse::<Ipv4Addr>() {
        let prefix = match prefix_part {
            None => 32,
            Some(p) => parse_ipv4_prefix(p)?,
        };
        if prefix > 32 {
            return Err(SubnetError::PrefixRangeV4(prefix));
        }
        return Ok(Network::V4 { addr: v4, prefix });
    }

    if let Ok(v6) = addr_part.parse::<Ipv6Addr>() {
        let prefix = match prefix_part {
            None => 128,
            Some(p) => p
                .parse::<u32>()
                .map_err(|_| SubnetError::BadPrefix(p.to_string()))?,
        };
        if prefix > 128 {
            return Err(SubnetError::PrefixRangeV6(prefix));
        }
        return Ok(Network::V6 { addr: v6, prefix });
    }

    Err(SubnetError::BadAddress(addr_part.to_string()))
}

/// Accept either a plain prefix length (`24`) or a dotted netmask
/// (`255.255.255.0`) for IPv4.
fn parse_ipv4_prefix(p: &str) -> Result<u32, SubnetError> {
    if let Ok(n) = p.parse::<u32>() {
        return Ok(n);
    }
    if let Ok(mask) = p.parse::<Ipv4Addr>() {
        return netmask_to_prefix(mask).ok_or_else(|| SubnetError::BadNetmask(p.to_string()));
    }
    Err(SubnetError::BadPrefix(p.to_string()))
}

/// Convert a dotted netmask to a prefix length, rejecting non-contiguous masks.
fn netmask_to_prefix(mask: Ipv4Addr) -> Option<u32> {
    let bits = u32::from(mask);
    let ones = bits.leading_ones();
    // A valid mask is `ones` leading 1s followed by all 0s.
    let expected = if ones == 0 {
        0
    } else {
        u32::MAX << (32 - ones)
    };
    if bits == expected { Some(ones) } else { None }
}

/// Analyze a parsed network into a full report.
pub fn analyze(net: &Network) -> SubnetReport {
    match net {
        Network::V4 { addr, prefix } => SubnetReport::V4(analyze_ipv4(*addr, *prefix)),
        Network::V6 { addr, prefix } => SubnetReport::V6(analyze_ipv6(*addr, *prefix)),
    }
}

fn ipv4_mask(prefix: u32) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

fn analyze_ipv4(addr: Ipv4Addr, prefix: u32) -> Ipv4Report {
    let a = u32::from(addr);
    let mask = ipv4_mask(prefix);
    let wildcard = !mask;
    let network = a & mask;
    let broadcast = network | wildcard;

    let total_addresses: u64 = 1u64 << (32 - prefix);

    // RFC 3021 (/31) and single host (/32) are special cases.
    let (host_min, host_max, usable_hosts) = match prefix {
        32 => (network, network, 1u64),
        31 => (network, broadcast, 2u64),
        _ => (
            network.wrapping_add(1),
            broadcast.wrapping_sub(1),
            total_addresses - 2,
        ),
    };

    Ipv4Report {
        address: addr.to_string(),
        prefix,
        cidr: format!("{}/{}", Ipv4Addr::from(network), prefix),
        netmask: Ipv4Addr::from(mask).to_string(),
        netmask_hex: format!("0x{mask:08x}"),
        wildcard: Ipv4Addr::from(wildcard).to_string(),
        network: Ipv4Addr::from(network).to_string(),
        broadcast: Ipv4Addr::from(broadcast).to_string(),
        host_min: Ipv4Addr::from(host_min).to_string(),
        host_max: Ipv4Addr::from(host_max).to_string(),
        total_addresses,
        usable_hosts,
        network_class: ipv4_class(addr).to_string(),
        address_type: ipv4_type(addr).to_string(),
        address_binary: ipv4_binary(a),
        netmask_binary: ipv4_binary(mask),
        network_binary: ipv4_binary(network),
    }
}

/// Classful network letter, kept for reference only.
fn ipv4_class(addr: Ipv4Addr) -> &'static str {
    match addr.octets()[0] {
        0..=127 => "A",
        128..=191 => "B",
        192..=223 => "C",
        224..=239 => "D (multicast)",
        _ => "E (reserved)",
    }
}

/// Classify an IPv4 address by its registered use.
fn ipv4_type(addr: Ipv4Addr) -> &'static str {
    let o = addr.octets();
    if addr.is_unspecified() {
        "Unspecified"
    } else if addr == Ipv4Addr::BROADCAST {
        "Limited broadcast"
    } else if addr.is_loopback() {
        "Loopback"
    } else if addr.is_link_local() {
        "Link-local (APIPA)"
    } else if addr.is_private() {
        "Private (RFC 1918)"
    } else if o[0] == 100 && (64..=127).contains(&o[1]) {
        "Shared / CGN (RFC 6598)"
    } else if addr.is_multicast() {
        "Multicast"
    } else if o[0] >= 240 {
        "Reserved (RFC 1112)"
    } else if (o[0] == 192 && o[1] == 0 && o[2] == 2)
        || (o[0] == 198 && o[1] == 51 && o[2] == 100)
        || (o[0] == 203 && o[1] == 0 && o[2] == 113)
    {
        "Documentation (RFC 5737)"
    } else {
        "Public"
    }
}

fn ipv4_binary(v: u32) -> String {
    let o = v.to_be_bytes();
    format!("{:08b}.{:08b}.{:08b}.{:08b}", o[0], o[1], o[2], o[3])
}

fn ipv6_mask(prefix: u32) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    }
}

fn analyze_ipv6(addr: Ipv6Addr, prefix: u32) -> Ipv6Report {
    let a = u128::from(addr);
    let mask = ipv6_mask(prefix);
    let network = a & mask;
    let last = network | !mask;

    Ipv6Report {
        address_compressed: addr.to_string(),
        address_expanded: ipv6_expanded(addr),
        prefix,
        cidr: format!("{}/{}", Ipv6Addr::from(network), prefix),
        network_compressed: Ipv6Addr::from(network).to_string(),
        network_expanded: ipv6_expanded(Ipv6Addr::from(network)),
        host_min: ipv6_expanded(Ipv6Addr::from(network)),
        host_max: ipv6_expanded(Ipv6Addr::from(last)),
        total_addresses: pow2_string(128 - prefix),
        address_type: ipv6_type(addr).to_string(),
    }
}

/// Full, non-compressed IPv6 form, for example 2001:0db8:0000:...:0001.
fn ipv6_expanded(addr: Ipv6Addr) -> String {
    let s = addr.segments();
    s.iter()
        .map(|seg| format!("{seg:04x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Classify an IPv6 address by its address block.
fn ipv6_type(addr: Ipv6Addr) -> &'static str {
    if addr.is_unspecified() {
        "Unspecified"
    } else if addr.is_loopback() {
        "Loopback"
    } else if addr.is_multicast() {
        "Multicast"
    } else {
        let first = addr.segments()[0];
        if (first & 0xffc0) == 0xfe80 {
            "Link-local (fe80::/10)"
        } else if (first & 0xfe00) == 0xfc00 {
            "Unique local (fc00::/7)"
        } else if (first & 0xe000) == 0x2000 {
            "Global unicast"
        } else {
            "Reserved"
        }
    }
}

/// Compute 2^exp as a decimal string, for exponents up to 128.
fn pow2_string(exp: u32) -> String {
    if exp < 128 {
        return (1u128 << exp).to_string();
    }
    // Only 2^128 reaches here; one grade-school doubling from 2^127.
    let mut digits = vec![1u8];
    for _ in 0..exp {
        let mut carry = 0u8;
        for d in digits.iter_mut() {
            let v = *d * 2 + carry;
            *d = v % 10;
            carry = v / 10;
        }
        if carry > 0 {
            digits.push(carry);
        }
    }
    digits.iter().rev().map(|d| (b'0' + d) as char).collect()
}

/// Split a network into subnets of `new_prefix`. Returns up to [`SPLIT_LIMIT`]
/// entries plus the true total.
pub fn split(net: &Network, new_prefix: u32) -> Result<SplitResult, SubnetError> {
    match net {
        Network::V4 { addr, prefix } => split_ipv4(*addr, *prefix, new_prefix),
        Network::V6 { addr, prefix } => split_ipv6(*addr, *prefix, new_prefix),
    }
}

fn split_ipv4(addr: Ipv4Addr, prefix: u32, new_prefix: u32) -> Result<SplitResult, SubnetError> {
    if new_prefix > 32 {
        return Err(SubnetError::PrefixRangeV4(new_prefix));
    }
    if new_prefix <= prefix {
        return Err(SubnetError::SplitTooSmall {
            current: prefix,
            new: new_prefix,
        });
    }

    let parent_mask = ipv4_mask(prefix);
    let base = u32::from(addr) & parent_mask;
    let total: u64 = 1u64 << (new_prefix - prefix);
    let step: u64 = 1u64 << (32 - new_prefix);

    let shown = total.min(SPLIT_LIMIT as u64);
    let mut subnets = Vec::with_capacity(shown as usize);
    for i in 0..shown {
        let net_addr = (base as u64 + i * step) as u32;
        let report = analyze_ipv4(Ipv4Addr::from(net_addr), new_prefix);
        subnets.push(SubnetEntry {
            cidr: report.cidr,
            network: report.network,
            broadcast: report.broadcast,
            host_min: report.host_min,
            host_max: report.host_max,
            usable_hosts: report.usable_hosts.to_string(),
        });
    }

    Ok(SplitResult {
        parent_cidr: format!("{}/{}", Ipv4Addr::from(base), prefix),
        new_prefix,
        total_subnets: total.to_string(),
        truncated: total > shown,
        subnets,
    })
}

fn split_ipv6(addr: Ipv6Addr, prefix: u32, new_prefix: u32) -> Result<SplitResult, SubnetError> {
    if new_prefix > 128 {
        return Err(SubnetError::PrefixRangeV6(new_prefix));
    }
    if new_prefix <= prefix {
        return Err(SubnetError::SplitTooSmall {
            current: prefix,
            new: new_prefix,
        });
    }

    let parent_mask = ipv6_mask(prefix);
    let base = u128::from(addr) & parent_mask;
    let diff = new_prefix - prefix;
    let total_str = pow2_string(diff);
    let step: u128 = if new_prefix == 128 {
        1
    } else {
        1u128 << (128 - new_prefix)
    };

    // Enumerate at most SPLIT_LIMIT regardless of how large the true total is.
    let shown: u128 = if diff >= 64 {
        SPLIT_LIMIT as u128
    } else {
        (1u128 << diff).min(SPLIT_LIMIT as u128)
    };

    let mut subnets = Vec::with_capacity(shown as usize);
    for i in 0..shown {
        let net_addr = base + i * step;
        let report = analyze_ipv6(Ipv6Addr::from(net_addr), new_prefix);
        subnets.push(SubnetEntry {
            cidr: report.cidr,
            network: report.network_compressed,
            broadcast: report.host_max.clone(),
            host_min: report.host_min,
            host_max: report.host_max,
            usable_hosts: report.total_addresses,
        });
    }

    let truncated = diff >= 64 || (1u128 << diff) > shown;
    Ok(SplitResult {
        parent_cidr: format!("{}/{}", Ipv6Addr::from(base), prefix),
        new_prefix,
        total_subnets: total_str,
        truncated,
        subnets,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(input: &str) -> Ipv4Report {
        match analyze(&parse_network(input).unwrap()) {
            SubnetReport::V4(r) => r,
            _ => panic!("expected ipv4"),
        }
    }

    fn v6(input: &str) -> Ipv6Report {
        match analyze(&parse_network(input).unwrap()) {
            SubnetReport::V6(r) => r,
            _ => panic!("expected ipv6"),
        }
    }

    #[test]
    fn parses_cidr() {
        assert_eq!(
            parse_network("10.1.1.0/24").unwrap(),
            Network::V4 {
                addr: "10.1.1.0".parse().unwrap(),
                prefix: 24
            }
        );
    }

    #[test]
    fn parses_dotted_netmask() {
        let n = parse_network("10.0.0.0/255.255.255.0").unwrap();
        assert_eq!(
            n,
            Network::V4 {
                addr: "10.0.0.0".parse().unwrap(),
                prefix: 24
            }
        );
    }

    #[test]
    fn rejects_noncontiguous_netmask() {
        let err = parse_network("10.0.0.0/255.0.255.0").unwrap_err();
        assert!(matches!(err, SubnetError::BadNetmask(_)));
    }

    #[test]
    fn bare_address_defaults_to_host() {
        assert_eq!(
            parse_network("192.168.1.5").unwrap(),
            Network::V4 {
                addr: "192.168.1.5".parse().unwrap(),
                prefix: 32
            }
        );
    }

    #[test]
    fn empty_input_errors() {
        assert_eq!(parse_network("   ").unwrap_err(), SubnetError::Empty);
    }

    #[test]
    fn prefix_out_of_range() {
        assert!(matches!(
            parse_network("10.0.0.0/33").unwrap_err(),
            SubnetError::PrefixRangeV4(33)
        ));
    }

    #[test]
    fn ipv4_slash24() {
        let r = v4("10.1.1.37/24");
        assert_eq!(r.network, "10.1.1.0");
        assert_eq!(r.broadcast, "10.1.1.255");
        assert_eq!(r.netmask, "255.255.255.0");
        assert_eq!(r.wildcard, "0.0.0.255");
        assert_eq!(r.host_min, "10.1.1.1");
        assert_eq!(r.host_max, "10.1.1.254");
        assert_eq!(r.total_addresses, 256);
        assert_eq!(r.usable_hosts, 254);
        assert_eq!(r.network_class, "A");
        assert_eq!(r.address_type, "Private (RFC 1918)");
        assert_eq!(r.netmask_hex, "0xffffff00");
    }

    #[test]
    fn ipv4_slash31_point_to_point() {
        let r = v4("192.168.1.0/31");
        assert_eq!(r.usable_hosts, 2);
        assert_eq!(r.host_min, "192.168.1.0");
        assert_eq!(r.host_max, "192.168.1.1");
        assert_eq!(r.total_addresses, 2);
    }

    #[test]
    fn ipv4_slash32_single_host() {
        let r = v4("8.8.8.8/32");
        assert_eq!(r.usable_hosts, 1);
        assert_eq!(r.host_min, "8.8.8.8");
        assert_eq!(r.host_max, "8.8.8.8");
        assert_eq!(r.address_type, "Public");
    }

    #[test]
    fn ipv4_slash0() {
        let r = v4("0.0.0.0/0");
        assert_eq!(r.total_addresses, 4_294_967_296);
        assert_eq!(r.usable_hosts, 4_294_967_294);
        assert_eq!(r.netmask, "0.0.0.0");
    }

    #[test]
    fn ipv4_binary_format() {
        let r = v4("192.168.1.0/24");
        assert_eq!(r.address_binary, "11000000.10101000.00000001.00000000");
        assert_eq!(r.netmask_binary, "11111111.11111111.11111111.00000000");
    }

    #[test]
    fn ipv4_types() {
        assert_eq!(v4("127.0.0.1/8").address_type, "Loopback");
        assert_eq!(v4("169.254.1.1/16").address_type, "Link-local (APIPA)");
        assert_eq!(v4("172.16.5.4/12").address_type, "Private (RFC 1918)");
        assert_eq!(v4("100.64.0.1/10").address_type, "Shared / CGN (RFC 6598)");
        assert_eq!(v4("224.0.0.1/4").address_type, "Multicast");
        assert_eq!(v4("192.0.2.1/24").address_type, "Documentation (RFC 5737)");
    }

    #[test]
    fn ipv6_basic() {
        let r = v6("2001:db8::1/48");
        assert_eq!(r.prefix, 48);
        assert_eq!(r.network_compressed, "2001:db8::");
        assert_eq!(
            r.address_expanded,
            "2001:0db8:0000:0000:0000:0000:0000:0001"
        );
        assert_eq!(r.address_type, "Global unicast");
    }

    #[test]
    fn ipv6_counts() {
        // /64 holds 2^64 addresses.
        let r = v6("2001:db8::/64");
        assert_eq!(r.total_addresses, "18446744073709551616");
        // /0 holds 2^128.
        let r0 = v6("::/0");
        assert_eq!(
            r0.total_addresses,
            "340282366920938463463374607431768211456"
        );
    }

    #[test]
    fn ipv6_types() {
        assert_eq!(v6("fe80::1/10").address_type, "Link-local (fe80::/10)");
        assert_eq!(v6("fc00::1/7").address_type, "Unique local (fc00::/7)");
        assert_eq!(v6("ff02::1/8").address_type, "Multicast");
        assert_eq!(v6("::1/128").address_type, "Loopback");
    }

    #[test]
    fn split_v4_24_into_28s() {
        let net = parse_network("10.1.1.0/24").unwrap();
        let r = split(&net, 28).unwrap();
        assert_eq!(r.total_subnets, "16");
        assert!(!r.truncated);
        assert_eq!(r.subnets.len(), 16);
        assert_eq!(r.subnets[0].cidr, "10.1.1.0/28");
        assert_eq!(r.subnets[0].broadcast, "10.1.1.15");
        assert_eq!(r.subnets[1].cidr, "10.1.1.16/28");
        assert_eq!(r.subnets[15].cidr, "10.1.1.240/28");
        assert_eq!(r.subnets[15].broadcast, "10.1.1.255");
        assert_eq!(r.subnets[0].usable_hosts, "14");
    }

    #[test]
    fn split_rejects_equal_or_smaller_prefix() {
        let net = parse_network("10.1.1.0/24").unwrap();
        assert!(matches!(
            split(&net, 24).unwrap_err(),
            SubnetError::SplitTooSmall {
                current: 24,
                new: 24
            }
        ));
        assert!(matches!(
            split(&net, 16).unwrap_err(),
            SubnetError::SplitTooSmall { .. }
        ));
    }

    #[test]
    fn split_v4_truncates_large_lists() {
        // /8 into /24s is 65536 subnets, well over the cap.
        let net = parse_network("10.0.0.0/8").unwrap();
        let r = split(&net, 24).unwrap();
        assert_eq!(r.total_subnets, "65536");
        assert!(r.truncated);
        assert_eq!(r.subnets.len(), SPLIT_LIMIT);
        assert_eq!(r.subnets[0].cidr, "10.0.0.0/24");
    }

    #[test]
    fn split_v6_48_into_64s() {
        let net = parse_network("2001:db8::/48").unwrap();
        let r = split(&net, 64).unwrap();
        assert_eq!(r.total_subnets, "65536");
        assert!(r.truncated);
        assert_eq!(r.subnets.len(), SPLIT_LIMIT);
        assert_eq!(r.subnets[0].cidr, "2001:db8::/64");
        assert_eq!(r.subnets[1].cidr, "2001:db8:0:1::/64");
    }
}
