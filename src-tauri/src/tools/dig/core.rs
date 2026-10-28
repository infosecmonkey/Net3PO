//! Pure DNS lookup helpers: parsing user input, building query names (including
//! reverse lookups), and formatting records. The network query itself lives in
//! `commands.rs`; everything here is deterministic and unit tested.

use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

use hickory_client::proto::op::ResponseCode;
use hickory_client::proto::rr::{Name, Record, RecordType};
use serde::Serialize;
use thiserror::Error;

/// Default DNS port when the user gives a bare server IP.
pub const DNS_PORT: u16 = 53;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DigError {
    #[error("enter a name or IP to look up")]
    EmptyName,
    #[error("'{0}' is not a valid DNS name")]
    BadName(String),
    #[error("server '{0}' must be an IP address, optionally with :port")]
    BadServer(String),
    #[error("unknown record type '{0}'")]
    BadType(String),
}

/// One resource record, flattened for the UI.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DnsRecord {
    pub name: String,
    pub ttl: u32,
    pub rtype: String,
    pub data: String,
}

/// A dig-style response: the sections plus header metadata.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DigResponse {
    pub server: String,
    pub protocol: String,
    pub rcode: String,
    pub flags: Vec<String>,
    pub query_time_ms: u64,
    pub question: String,
    pub answers: Vec<DnsRecord>,
    pub authority: Vec<DnsRecord>,
    pub additional: Vec<DnsRecord>,
}

/// Record types offered as buttons in the UI.
pub const SUPPORTED_TYPES: [&str; 10] = [
    "A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA", "PTR", "SRV", "CAA",
];

/// Parse a record type name (case-insensitive) limited to the supported set.
pub fn parse_record_type(s: &str) -> Result<RecordType, DigError> {
    let upper = s.trim().to_ascii_uppercase();
    if !SUPPORTED_TYPES.contains(&upper.as_str()) {
        return Err(DigError::BadType(s.to_string()));
    }
    RecordType::from_str(&upper).map_err(|_| DigError::BadType(s.to_string()))
}

/// Parse a server as `IP` or `IP:port` (IPv6 in brackets for the port form).
pub fn parse_server(s: &str) -> Result<SocketAddr, DigError> {
    let s = s.trim();
    if let Ok(sock) = s.parse::<SocketAddr>() {
        return Ok(sock);
    }
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, DNS_PORT));
    }
    Err(DigError::BadServer(s.to_string()))
}

/// Build the query name. For a PTR lookup of an IP address, construct the
/// reverse DNS name; otherwise parse the input as a domain name.
pub fn query_name(input: &str, rtype: RecordType) -> Result<Name, DigError> {
    let input = input.trim();
    if input.is_empty() {
        return Err(DigError::EmptyName);
    }
    if rtype == RecordType::PTR
        && let Ok(ip) = input.parse::<IpAddr>()
    {
        let rev = reverse_name(ip);
        return Name::from_str(&rev).map_err(|_| DigError::BadName(rev));
    }
    Name::from_str(input).map_err(|_| DigError::BadName(input.to_string()))
}

/// Reverse DNS name for an IP, e.g. 10.1.2.3 -> "3.2.1.10.in-addr.arpa.".
pub fn reverse_name(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}.{}.in-addr.arpa.", o[3], o[2], o[1], o[0])
        }
        IpAddr::V6(v6) => {
            let mut s = String::with_capacity(72);
            for octet in v6.octets().iter().rev() {
                // Low nibble first, then high nibble (reversed order overall).
                s.push_str(&format!("{:x}.", octet & 0x0f));
                s.push_str(&format!("{:x}.", octet >> 4));
            }
            s.push_str("ip6.arpa.");
            s
        }
    }
}

/// Flatten a hickory record for the UI. `data` uses hickory's rdata Display,
/// which matches dig's zone-file style.
pub fn to_record(r: &Record) -> DnsRecord {
    DnsRecord {
        name: r.name().to_string(),
        ttl: r.ttl(),
        rtype: r.record_type().to_string(),
        data: r.data().map(|d| d.to_string()).unwrap_or_default(),
    }
}

/// dig-style response code token.
pub fn rcode_str(rc: ResponseCode) -> String {
    match rc {
        ResponseCode::NoError => "NOERROR".to_string(),
        ResponseCode::FormErr => "FORMERR".to_string(),
        ResponseCode::ServFail => "SERVFAIL".to_string(),
        ResponseCode::NXDomain => "NXDOMAIN".to_string(),
        ResponseCode::NotImp => "NOTIMP".to_string(),
        ResponseCode::Refused => "REFUSED".to_string(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn parses_record_types() {
        assert_eq!(parse_record_type("a").unwrap(), RecordType::A);
        assert_eq!(parse_record_type("AAAA").unwrap(), RecordType::AAAA);
        assert_eq!(parse_record_type("Mx").unwrap(), RecordType::MX);
        assert_eq!(parse_record_type("caa").unwrap(), RecordType::CAA);
    }

    #[test]
    fn rejects_unknown_record_type() {
        assert!(matches!(
            parse_record_type("ANY").unwrap_err(),
            DigError::BadType(_)
        ));
    }

    #[test]
    fn parses_server_forms() {
        assert_eq!(
            parse_server("1.1.1.1").unwrap(),
            "1.1.1.1:53".parse().unwrap()
        );
        assert_eq!(
            parse_server("8.8.8.8:5353").unwrap(),
            "8.8.8.8:5353".parse().unwrap()
        );
        assert_eq!(
            parse_server("2606:4700:4700::1111").unwrap(),
            SocketAddr::new("2606:4700:4700::1111".parse().unwrap(), 53)
        );
        assert_eq!(
            parse_server("[2606:4700:4700::1111]:53").unwrap(),
            "[2606:4700:4700::1111]:53".parse().unwrap()
        );
    }

    #[test]
    fn rejects_hostname_server() {
        assert!(matches!(
            parse_server("dns.google").unwrap_err(),
            DigError::BadServer(_)
        ));
    }

    #[test]
    fn reverse_name_ipv4() {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3));
        assert_eq!(reverse_name(ip), "3.2.1.10.in-addr.arpa.");
    }

    #[test]
    fn reverse_name_ipv6() {
        let ip = IpAddr::V6(Ipv6Addr::from_str("2001:db8::1").unwrap());
        // Nibble-reversed, low nibble first.
        assert_eq!(
            reverse_name(ip),
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa."
        );
    }

    #[test]
    fn ptr_query_uses_reverse_name() {
        let name = query_name("10.1.2.3", RecordType::PTR).unwrap();
        assert_eq!(name.to_string(), "3.2.1.10.in-addr.arpa.");
    }

    #[test]
    fn a_query_parses_domain() {
        // hickory parses this as a non-FQDN name, so Display has no root dot.
        // It still encodes correctly on the wire.
        let name = query_name("example.com", RecordType::A).unwrap();
        assert_eq!(name.to_string(), "example.com");
    }

    #[test]
    fn empty_name_errors() {
        assert_eq!(
            query_name("  ", RecordType::A).unwrap_err(),
            DigError::EmptyName
        );
    }

    #[test]
    fn rcode_tokens() {
        assert_eq!(rcode_str(ResponseCode::NoError), "NOERROR");
        assert_eq!(rcode_str(ResponseCode::NXDomain), "NXDOMAIN");
    }
}
