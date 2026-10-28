//! Pure port-scanner helpers: port-spec parsing, the common-port list, service
//! names, and speed presets. No network here, so it is unit tested directly.
//! The scanning loop and streaming live in `commands.rs`.

use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PortError {
    #[error("no ports to scan")]
    Empty,
    #[error("'{0}' is not a valid port or range")]
    BadToken(String),
    #[error("port {0} is out of range (1-65535)")]
    OutOfRange(u32),
    #[error("range {0}-{1} is backwards")]
    BackwardsRange(u16, u16),
}

/// Speed preset: simultaneous connections and per-connection timeout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScanParams {
    pub concurrency: usize,
    pub timeout_ms: u64,
}

/// Map a preset name to its parameters. Unknown names fall back to Normal.
pub fn preset_params(name: &str) -> ScanParams {
    match name.trim().to_ascii_lowercase().as_str() {
        "polite" => ScanParams {
            concurrency: 32,
            timeout_ms: 1500,
        },
        "aggressive" => ScanParams {
            concurrency: 512,
            timeout_ms: 600,
        },
        _ => ScanParams {
            concurrency: 128,
            timeout_ms: 1000,
        },
    }
}

/// Resolve a port specification into a sorted, de-duplicated list.
/// Accepts `common` (the default set), `all`/`*` (1-65535), or a
/// comma-separated list of ports and `A-B` ranges.
pub fn resolve_ports(spec: &str) -> Result<Vec<u16>, PortError> {
    let s = spec.trim();
    if s.is_empty() || s.eq_ignore_ascii_case("common") {
        return Ok(COMMON_PORTS.to_vec());
    }
    if s.eq_ignore_ascii_case("all") || s == "*" {
        return Ok((1..=65535).collect());
    }
    parse_ports(s)
}

/// Parse an explicit list like `22,80,443,8000-8100`.
pub fn parse_ports(spec: &str) -> Result<Vec<u16>, PortError> {
    let mut ports: Vec<u16> = Vec::new();
    for token in spec.split(',') {
        let token = token.trim();
        if token.is_empty() {
            continue;
        }
        match token.split_once('-') {
            Some((a, b)) => {
                let start = parse_one(a.trim())?;
                let end = parse_one(b.trim())?;
                if start > end {
                    return Err(PortError::BackwardsRange(start, end));
                }
                ports.extend(start..=end);
            }
            None => ports.push(parse_one(token)?),
        }
    }
    if ports.is_empty() {
        return Err(PortError::Empty);
    }
    ports.sort_unstable();
    ports.dedup();
    Ok(ports)
}

fn parse_one(s: &str) -> Result<u16, PortError> {
    let n: u32 = s.parse().map_err(|_| PortError::BadToken(s.to_string()))?;
    if n == 0 || n > 65535 {
        return Err(PortError::OutOfRange(n));
    }
    Ok(n as u16)
}

/// Best-effort service name for a well-known port.
pub fn service_name(port: u16) -> Option<&'static str> {
    let name = match port {
        21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 => "smtp",
        53 => "domain",
        67..=68 => "dhcp",
        69 => "tftp",
        80 => "http",
        110 => "pop3",
        111 => "rpcbind",
        123 => "ntp",
        135 => "msrpc",
        137..=139 => "netbios",
        143 => "imap",
        161..=162 => "snmp",
        179 => "bgp",
        389 => "ldap",
        443 => "https",
        445 => "microsoft-ds",
        465 => "smtps",
        514 => "syslog",
        587 => "submission",
        593 => "http-rpc-epmap",
        623 => "ipmi",
        636 => "ldaps",
        873 => "rsync",
        902 => "vmware",
        989..=990 => "ftps",
        993 => "imaps",
        995 => "pop3s",
        1433..=1434 => "mssql",
        1521 => "oracle",
        1723 => "pptp",
        1883 => "mqtt",
        2049 => "nfs",
        2181 => "zookeeper",
        2375..=2376 => "docker",
        3128 => "squid-http",
        3268 => "globalcat-ldap",
        3306 => "mysql",
        3389 => "ms-wbt-rdp",
        5060..=5061 => "sip",
        5432 => "postgresql",
        5601 => "kibana",
        5672 => "amqp",
        5900 => "vnc",
        5985..=5986 => "winrm",
        6379 => "redis",
        6443 => "kube-apiserver",
        8000 | 8008 | 8080 | 8081 | 8088 => "http-alt",
        8443 => "https-alt",
        9090 => "prometheus",
        9092 => "kafka",
        9200 | 9300 => "elasticsearch",
        11211 => "memcached",
        27017..=27018 => "mongodb",
        _ => return None,
    };
    Some(name)
}

/// Curated set of commonly interesting TCP ports, the default scan.
pub const COMMON_PORTS: &[u16] = &[
    21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 111, 123, 135, 137, 138, 139, 143, 161, 162, 179, 389,
    443, 445, 465, 500, 514, 515, 520, 523, 543, 544, 548, 554, 587, 593, 623, 631, 636, 660, 666,
    873, 902, 989, 990, 993, 995, 1025, 1080, 1194, 1433, 1434, 1521, 1701, 1723, 1812, 1883, 2000,
    2049, 2082, 2083, 2086, 2087, 2095, 2096, 2181, 2222, 2375, 2376, 3000, 3128, 3268, 3306, 3389,
    3478, 3690, 4433, 4444, 4500, 4786, 5000, 5060, 5061, 5222, 5432, 5555, 5601, 5672, 5900, 5985,
    5986, 6379, 6443, 6666, 7001, 7070, 8000, 8008, 8080, 8081, 8088, 8443, 8888, 9000, 9090, 9092,
    9200, 9300, 9418, 9999,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn presets() {
        assert_eq!(preset_params("polite").concurrency, 32);
        assert_eq!(preset_params("normal").concurrency, 128);
        assert_eq!(preset_params("aggressive").concurrency, 512);
        // Unknown falls back to Normal.
        assert_eq!(preset_params("whatever").concurrency, 128);
    }

    #[test]
    fn parse_list_and_ranges() {
        assert_eq!(parse_ports("80").unwrap(), vec![80]);
        assert_eq!(parse_ports("22,80,443").unwrap(), vec![22, 80, 443]);
        assert_eq!(parse_ports("80-83").unwrap(), vec![80, 81, 82, 83]);
        // Sorted and de-duplicated across tokens.
        assert_eq!(parse_ports("443,80,80,22").unwrap(), vec![22, 80, 443]);
        assert_eq!(parse_ports("10-12,11-13").unwrap(), vec![10, 11, 12, 13]);
    }

    #[test]
    fn parse_errors() {
        assert!(matches!(
            parse_ports("abc").unwrap_err(),
            PortError::BadToken(_)
        ));
        assert!(matches!(
            parse_ports("0").unwrap_err(),
            PortError::OutOfRange(0)
        ));
        assert!(matches!(
            parse_ports("70000").unwrap_err(),
            PortError::OutOfRange(70000)
        ));
        assert!(matches!(
            parse_ports("100-50").unwrap_err(),
            PortError::BackwardsRange(100, 50)
        ));
        assert_eq!(parse_ports("  ").unwrap_err(), PortError::Empty);
    }

    #[test]
    fn resolve_special_specs() {
        assert_eq!(resolve_ports("").unwrap(), COMMON_PORTS.to_vec());
        assert_eq!(resolve_ports("common").unwrap(), COMMON_PORTS.to_vec());
        assert_eq!(resolve_ports("all").unwrap().len(), 65535);
        assert_eq!(resolve_ports("*").unwrap().len(), 65535);
        assert_eq!(resolve_ports("22,80").unwrap(), vec![22, 80]);
    }

    #[test]
    fn services() {
        assert_eq!(service_name(22), Some("ssh"));
        assert_eq!(service_name(443), Some("https"));
        assert_eq!(service_name(3306), Some("mysql"));
        assert_eq!(service_name(65000), None);
    }

    #[test]
    fn common_ports_sorted_and_unique() {
        let mut sorted = COMMON_PORTS.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(
            sorted.len(),
            COMMON_PORTS.len(),
            "common ports must be unique"
        );
        assert_eq!(sorted, COMMON_PORTS.to_vec(), "common ports must be sorted");
    }
}
