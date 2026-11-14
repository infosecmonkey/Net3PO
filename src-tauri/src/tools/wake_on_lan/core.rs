//! Pure Wake-on-LAN logic: MAC and SecureOn password parsing, magic packet
//! construction, and classifying the destination address so the UI can
//! explain how the packet will travel. No sockets or Tauri types here.

use std::net::Ipv4Addr;

use serde::Serialize;
use thiserror::Error;

/// Magic packet: 6 bytes of 0xFF, then the target MAC 16 times.
pub const MAGIC_LEN: usize = 6 + 16 * 6;
/// Most packets sent per wake request.
pub const MAX_REPEATS: u8 = 10;
/// Longest destination host name accepted.
const MAX_HOST: usize = 253;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum WolError {
    #[error("enter a MAC address")]
    NoMac,
    #[error(
        "'{0}' is not a MAC address (use aa:bb:cc:dd:ee:ff, aa-bb-..., aabb.ccdd.eeff or 12 hex digits)"
    )]
    BadMac(String),
    #[error("{0} is a multicast or broadcast MAC; Wake-on-LAN needs the NIC's unicast address")]
    GroupMac(String),
    #[error("00:00:00:00:00:00 is not a valid NIC address")]
    ZeroMac,
    #[error("SecureOn password must be 4 bytes (a.b.c.d) or 6 bytes (MAC format)")]
    BadPassword,
    #[error("enter a destination: a broadcast address, IPv4 address or host name")]
    NoDestination,
    #[error("'{0}' is not a valid IPv4 address or host name")]
    BadDestination(String),
    #[error("port must be 1 to 65535")]
    BadPort,
    #[error("repeat count must be 1 to {MAX_REPEATS}")]
    BadRepeats,
}

/// Parse a MAC in colon, dash, Cisco dot or bare hex form.
pub fn parse_mac(input: &str) -> Result<[u8; 6], WolError> {
    let s = input.trim();
    if s.is_empty() {
        return Err(WolError::NoMac);
    }
    let hex: String = s
        .chars()
        .filter(|c| !matches!(c, ':' | '-' | '.'))
        .collect();
    let seps_ok = {
        let parts: Vec<&str> = s.split([':', '-']).collect();
        let dots: Vec<&str> = s.split('.').collect();
        (parts.len() == 6 && parts.iter().all(|p| p.len() == 2))
            || (dots.len() == 3 && dots.iter().all(|p| p.len() == 4))
            || (parts.len() == 1 && dots.len() == 1)
    };
    if !seps_ok || hex.len() != 12 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(WolError::BadMac(s.to_string()));
    }
    let mut mac = [0u8; 6];
    for (i, byte) in mac.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .map_err(|_| WolError::BadMac(s.to_string()))?;
    }
    if mac == [0; 6] {
        return Err(WolError::ZeroMac);
    }
    if mac[0] & 1 == 1 {
        return Err(WolError::GroupMac(format_mac(&mac)));
    }
    Ok(mac)
}

/// `aa:bb:cc:dd:ee:ff`.
pub fn format_mac(mac: &[u8; 6]) -> String {
    mac.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Optional SecureOn password: empty, 4 bytes in dotted decimal, or 6 bytes
/// in any MAC notation.
pub fn parse_password(input: &str) -> Result<Vec<u8>, WolError> {
    let s = input.trim();
    if s.is_empty() {
        return Ok(Vec::new());
    }
    if let Ok(v4) = s.parse::<Ipv4Addr>() {
        return Ok(v4.octets().to_vec());
    }
    // Reuse MAC parsing for the hex form, but any byte values are allowed.
    let hex: String = s
        .chars()
        .filter(|c| !matches!(c, ':' | '-' | '.'))
        .collect();
    if hex.len() == 12 && hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return (0..6)
            .map(|i| {
                u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).map_err(|_| WolError::BadPassword)
            })
            .collect();
    }
    Err(WolError::BadPassword)
}

/// Build the magic packet, with the SecureOn password appended if given.
pub fn magic_packet(mac: &[u8; 6], password: &[u8]) -> Vec<u8> {
    let mut p = Vec::with_capacity(MAGIC_LEN + password.len());
    p.extend_from_slice(&[0xff; 6]);
    for _ in 0..16 {
        p.extend_from_slice(mac);
    }
    p.extend_from_slice(password);
    p
}

/// A destination as typed: an IPv4 literal or a host name to resolve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Destination {
    Ip(Ipv4Addr),
    Host(String),
}

pub fn parse_destination(input: &str) -> Result<Destination, WolError> {
    let s = input.trim();
    if s.is_empty() {
        return Err(WolError::NoDestination);
    }
    if let Ok(ip) = s.parse::<Ipv4Addr>() {
        return Ok(Destination::Ip(ip));
    }
    let name = s.trim_end_matches('.');
    let label_ok = |l: &str| {
        !l.is_empty()
            && l.len() <= 63
            && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            && !l.starts_with('-')
            && !l.ends_with('-')
    };
    // A bare dotted-number string that failed IPv4 parsing is a typo, not a name.
    let numeric = name.bytes().all(|b| b.is_ascii_digit() || b == b'.');
    if name.len() > MAX_HOST || numeric || !name.split('.').all(label_ok) {
        return Err(WolError::BadDestination(s.to_string()));
    }
    Ok(Destination::Host(name.to_ascii_lowercase()))
}

pub fn validate_port(port: u32) -> Result<u16, WolError> {
    u16::try_from(port)
        .ok()
        .filter(|p| *p != 0)
        .ok_or(WolError::BadPort)
}

pub fn validate_repeats(n: u32) -> Result<u8, WolError> {
    u8::try_from(n)
        .ok()
        .filter(|n| (1..=MAX_REPEATS).contains(n))
        .ok_or(WolError::BadRepeats)
}

/// Subnet-directed broadcast for an interface address and prefix length.
pub fn directed_broadcast(ip: Ipv4Addr, prefix: u8) -> Ipv4Addr {
    if prefix >= 32 {
        return ip;
    }
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    Ipv4Addr::from(u32::from(ip) | !mask)
}

/// How the packet will be delivered, for the explanation shown with results.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum DeliveryKind {
    /// 255.255.255.255: stays on the local segment of the sending interface.
    LimitedBroadcast,
    /// Broadcast address of a local interface's subnet: stays on that segment.
    LocalBroadcast,
    /// Looks like a broadcast address of a remote subnet; routers forward it
    /// only if directed broadcast is enabled for that subnet.
    RemoteBroadcast,
    /// A single host address: reaches a sleeping NIC only if the switch still
    /// knows its port and something answers ARP (a static ARP entry or a
    /// router feature).
    Unicast,
}

/// Classify `dest` against the local interfaces (`ip`, `prefix`).
pub fn classify(dest: Ipv4Addr, interfaces: &[(Ipv4Addr, u8)]) -> DeliveryKind {
    if dest == Ipv4Addr::BROADCAST {
        return DeliveryKind::LimitedBroadcast;
    }
    if interfaces
        .iter()
        .any(|(ip, p)| *p < 31 && directed_broadcast(*ip, *p) == dest)
    {
        return DeliveryKind::LocalBroadcast;
    }
    // Ends in .255 and is not on a local subnet: most likely a remote /24
    // broadcast. Other prefixes cannot be told apart from host addresses.
    let on_local = interfaces.iter().any(|(ip, p)| {
        let mask = if *p == 0 {
            0
        } else {
            u32::MAX << (32 - u32::from((*p).min(32)))
        };
        u32::from(*ip) & mask == u32::from(dest) & mask
    });
    if dest.octets()[3] == 255 && !on_local {
        return DeliveryKind::RemoteBroadcast;
    }
    DeliveryKind::Unicast
}

/// Ports tried by the optional reachability check when the user gives none.
pub const DEFAULT_CHECK_PORTS: &[u16] = &[22, 3389, 445, 80, 443];

/// Parse a comma or space separated list of TCP ports for the reachability
/// check; empty means the defaults. At most 8 ports.
pub fn parse_check_ports(input: &str) -> Result<Vec<u16>, WolError> {
    let s = input.trim();
    if s.is_empty() {
        return Ok(DEFAULT_CHECK_PORTS.to_vec());
    }
    let mut out = Vec::new();
    for part in s.split([',', ' ']).filter(|p| !p.is_empty()) {
        let port: u32 = part.parse().map_err(|_| WolError::BadPort)?;
        let port = validate_port(port)?;
        if !out.contains(&port) {
            out.push(port);
        }
    }
    if out.is_empty() || out.len() > 8 {
        return Err(WolError::BadPort);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_formats() {
        let want = [0x00, 0x11, 0x22, 0xaa, 0xbb, 0xcc];
        for s in [
            "00:11:22:aa:bb:cc",
            "00-11-22-AA-BB-CC",
            "0011.22aa.bbcc",
            "001122aabbcc",
            "  00:11:22:aa:bb:cc  ",
        ] {
            assert_eq!(parse_mac(s).unwrap(), want, "{s}");
        }
        assert_eq!(format_mac(&want), "00:11:22:aa:bb:cc");
    }

    #[test]
    fn mac_rejects() {
        assert_eq!(parse_mac(""), Err(WolError::NoMac));
        for bad in [
            "00:11:22:aa:bb",
            "00:11:22:aa:bb:cc:dd",
            "0:11:22:aa:bb:cc",
            "00:11:22:aa:bb:zz",
            "0011.22aa.bbc",
            "00:11-22:aa:bb:cc:",
            "001122aabbccdd",
        ] {
            assert!(matches!(parse_mac(bad), Err(WolError::BadMac(_))), "{bad}");
        }
        assert_eq!(parse_mac("00:00:00:00:00:00"), Err(WolError::ZeroMac));
        assert!(matches!(
            parse_mac("ff:ff:ff:ff:ff:ff"),
            Err(WolError::GroupMac(_))
        ));
        assert!(matches!(
            parse_mac("01:00:5e:00:00:01"),
            Err(WolError::GroupMac(_))
        ));
    }

    #[test]
    fn packet_layout() {
        let mac = [1u8, 2, 3, 4, 5, 6];
        let p = magic_packet(&[0x02, 2, 3, 4, 5, 6], &[]);
        assert_eq!(p.len(), MAGIC_LEN);
        assert_eq!(&p[..6], &[0xff; 6]);
        for i in 0..16 {
            assert_eq!(&p[6 + i * 6..12 + i * 6], &[0x02, 2, 3, 4, 5, 6]);
        }
        let p = magic_packet(&mac, &[9, 9, 9, 9]);
        assert_eq!(p.len(), MAGIC_LEN + 4);
        assert_eq!(&p[MAGIC_LEN..], &[9, 9, 9, 9]);
    }

    #[test]
    fn passwords() {
        assert_eq!(parse_password("").unwrap(), Vec::<u8>::new());
        assert_eq!(parse_password("192.168.1.2").unwrap(), vec![192, 168, 1, 2]);
        assert_eq!(
            parse_password("ff:ee:dd:cc:bb:aa").unwrap(),
            vec![0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa]
        );
        assert_eq!(parse_password("abc"), Err(WolError::BadPassword));
        assert_eq!(parse_password("1.2.3"), Err(WolError::BadPassword));
    }

    #[test]
    fn destinations() {
        assert_eq!(
            parse_destination("10.1.1.255").unwrap(),
            Destination::Ip(Ipv4Addr::new(10, 1, 1, 255))
        );
        assert_eq!(
            parse_destination("PC-01.Corp.Example.").unwrap(),
            Destination::Host("pc-01.corp.example".into())
        );
        assert_eq!(parse_destination(" "), Err(WolError::NoDestination));
        for bad in [
            "10.1.1.256",
            "10.1.1",
            "a b",
            "-x.example",
            "host;rm",
            "2001:db8::1",
        ] {
            assert!(
                matches!(parse_destination(bad), Err(WolError::BadDestination(_))),
                "{bad}"
            );
        }
    }

    #[test]
    fn ports_and_repeats() {
        assert_eq!(validate_port(9).unwrap(), 9);
        assert_eq!(validate_port(0), Err(WolError::BadPort));
        assert_eq!(validate_port(70_000), Err(WolError::BadPort));
        assert_eq!(validate_repeats(3).unwrap(), 3);
        assert_eq!(validate_repeats(0), Err(WolError::BadRepeats));
        assert_eq!(validate_repeats(11), Err(WolError::BadRepeats));
        assert_eq!(parse_check_ports("").unwrap(), DEFAULT_CHECK_PORTS);
        assert_eq!(parse_check_ports("22, 3389 22").unwrap(), vec![22, 3389]);
        assert_eq!(parse_check_ports("22,x"), Err(WolError::BadPort));
        assert_eq!(
            parse_check_ports("1,2,3,4,5,6,7,8,9"),
            Err(WolError::BadPort)
        );
    }

    #[test]
    fn broadcast_math() {
        let ip = Ipv4Addr::new(10, 1, 1, 20);
        assert_eq!(directed_broadcast(ip, 24), Ipv4Addr::new(10, 1, 1, 255));
        assert_eq!(directed_broadcast(ip, 22), Ipv4Addr::new(10, 1, 3, 255));
        assert_eq!(directed_broadcast(ip, 32), ip);
        assert_eq!(directed_broadcast(ip, 0), Ipv4Addr::BROADCAST);
    }

    #[test]
    fn delivery_classes() {
        let ifs = [
            (Ipv4Addr::new(10, 1, 1, 20), 24),
            (Ipv4Addr::new(192, 168, 8, 5), 22),
        ];
        assert_eq!(
            classify(Ipv4Addr::BROADCAST, &ifs),
            DeliveryKind::LimitedBroadcast
        );
        assert_eq!(
            classify(Ipv4Addr::new(10, 1, 1, 255), &ifs),
            DeliveryKind::LocalBroadcast
        );
        assert_eq!(
            classify(Ipv4Addr::new(192, 168, 11, 255), &ifs),
            DeliveryKind::LocalBroadcast
        );
        assert_eq!(
            classify(Ipv4Addr::new(10, 9, 9, 255), &ifs),
            DeliveryKind::RemoteBroadcast
        );
        assert_eq!(
            classify(Ipv4Addr::new(10, 1, 1, 50), &ifs),
            DeliveryKind::Unicast
        );
        // .255 inside a local /22 is a host address there, not a broadcast.
        assert_eq!(
            classify(Ipv4Addr::new(192, 168, 9, 255), &ifs),
            DeliveryKind::Unicast
        );
    }
}
