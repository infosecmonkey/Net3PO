//! `diagnose sniffer packet` builder, plus the BPF snippet builder used for
//! custom filters. The command is
//! `diagnose sniffer packet <iface> '<filter|none>' <verbose> [count] [a|l]`.

use serde::Deserialize;

use super::{
    BuildResult, err, interface_name, opt_cidr, opt_int, opt_ip, opt_mac, port_list, present,
};

/// Longest custom BPF filter accepted.
pub const MAX_FILTER_LEN: usize = 1024;

/// Protocol keywords offered by the simple filter and the BPF builder.
pub const PROTOCOLS: &[&str] = &[
    "tcp", "udp", "icmp", "icmp6", "arp", "ip", "ip6", "esp", "gre",
];

/// Traffic direction for host, net, and port primitives.
#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum Dir {
    #[default]
    Any,
    Src,
    Dst,
}

impl Dir {
    fn prefix(self, primitive: &str) -> String {
        match self {
            Dir::Any => primitive.to_string(),
            Dir::Src => format!("src {primitive}"),
            Dir::Dst => format!("dst {primitive}"),
        }
    }
}

/// Timestamp column format.
#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum Timestamp {
    Relative,
    Utc,
    #[default]
    Local,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SnifferInput {
    pub interface: String,
    /// Use `custom_filter` verbatim (after validation) instead of the simple
    /// host/net/port/protocol fields.
    pub use_custom_filter: bool,
    pub custom_filter: String,
    pub host: String,
    pub host_dir: Dir,
    pub net: String,
    pub net_dir: Dir,
    pub ports: String,
    pub port_dir: Dir,
    /// Protocol keyword, or empty for any.
    pub proto: String,
    pub verbose: u8,
    pub count: String,
    pub timestamp: Timestamp,
}

impl Default for SnifferInput {
    fn default() -> Self {
        SnifferInput {
            interface: "any".to_string(),
            use_custom_filter: false,
            custom_filter: String::new(),
            host: String::new(),
            host_dir: Dir::Any,
            net: String::new(),
            net_dir: Dir::Any,
            ports: String::new(),
            port_dir: Dir::Any,
            proto: String::new(),
            verbose: 4,
            count: String::new(),
            timestamp: Timestamp::Local,
        }
    }
}

/// Validate a free-form BPF filter. It sits inside single quotes on the
/// FortiGate CLI, so a quote or a line break would end it early.
pub fn custom_filter(field: &str, s: &str) -> BuildResult<String> {
    let t = s.trim();
    if t.len() > MAX_FILTER_LEN {
        return err(
            field,
            format!("filter is longer than {MAX_FILTER_LEN} characters"),
        );
    }
    if t.contains('\'') {
        return err(
            field,
            "single quotes are not allowed; the filter is already quoted",
        );
    }
    if t.chars().any(char::is_control) {
        return err(field, "line breaks and control characters are not allowed");
    }
    Ok(t.to_string())
}

fn protocol(field: &str, s: &str) -> BuildResult<Option<&'static str>> {
    match present(s) {
        None => Ok(None),
        Some(t) => match PROTOCOLS.iter().find(|p| p.eq_ignore_ascii_case(t)) {
            Some(p) => Ok(Some(p)),
            None => err(field, format!("unknown protocol '{t}'")),
        },
    }
}

/// `port 80`, or `(port 80 or port 443)` for a list.
fn ports_expr(dir: Dir, ports: &[u16]) -> Option<String> {
    let prefix = dir.prefix("port");
    match ports {
        [] => None,
        [p] => Some(format!("{prefix} {p}")),
        many => Some(format!(
            "({})",
            many.iter()
                .map(|p| format!("{prefix} {p}"))
                .collect::<Vec<_>>()
                .join(" or ")
        )),
    }
}

/// The filter expression from the simple fields: protocol, host, net, ports,
/// joined with `and`.
fn simple_filter(i: &SnifferInput) -> BuildResult<String> {
    let mut terms = Vec::new();
    if let Some(p) = protocol("proto", &i.proto)? {
        terms.push(p.to_string());
    }
    if let Some(ip) = opt_ip("host", &i.host)? {
        terms.push(format!("{} {ip}", i.host_dir.prefix("host")));
    }
    if let Some(net) = opt_cidr("net", &i.net)? {
        terms.push(format!("{} {net}", i.net_dir.prefix("net")));
    }
    if let Some(expr) = ports_expr(i.port_dir, &port_list("ports", &i.ports)?) {
        terms.push(expr);
    }
    Ok(terms.join(" and "))
}

/// Build the sniffer command.
pub fn build(i: &SnifferInput) -> BuildResult<String> {
    let iface = if i.interface.trim().is_empty() {
        "any".to_string()
    } else {
        interface_name("interface", &i.interface)?
    };
    let filter = if i.use_custom_filter {
        custom_filter("customFilter", &i.custom_filter)?
    } else {
        simple_filter(i)?
    };
    if !(1..=6).contains(&i.verbose) {
        return err("verbose", "verbosity must be 1 to 6");
    }
    let count = opt_int("count", &i.count, 0, 10_000_000)?;
    let ts = match i.timestamp {
        Timestamp::Relative => None,
        Timestamp::Utc => Some("a"),
        Timestamp::Local => Some("l"),
    };

    let filter_arg = if filter.is_empty() {
        "'none'".to_string()
    } else {
        format!("'{filter}'")
    };
    let mut parts = vec![
        "diagnose sniffer packet".to_string(),
        iface,
        filter_arg,
        i.verbose.to_string(),
    ];
    // The timestamp flag is positional after the count; 0 means unlimited.
    match (count, ts) {
        (Some(c), t) => {
            parts.push(c.to_string());
            parts.extend(t.map(str::to_string));
        }
        (None, Some(t)) => {
            parts.push("0".to_string());
            parts.push(t.to_string());
        }
        (None, None) => {}
    }
    Ok(parts.join(" "))
}

/// Policy snippet that disables NPU/ASIC offload so the CPU sniffer sees every
/// packet of a session.
pub const OFFLOAD_DISABLE: &str = "config firewall policy\n    edit <policy-id>\n        set auto-asic-offload disable\n    next\nend";

/// TCP flags offered by the BPF builder.
const TCP_FLAGS: &[&str] = &["syn", "ack", "fin", "rst", "push", "urg"];

/// ICMP message types offered by the BPF builder.
const ICMP_TYPES: &[&str] = &[
    "echo",
    "echoreply",
    "unreach",
    "redirect",
    "timxceed",
    "sourcequench",
];

/// One BPF primitive from the snippet builder.
#[derive(Debug, Clone, Deserialize)]
#[serde(
    tag = "type",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum Snippet {
    Host {
        ip: String,
        dir: Dir,
    },
    Network {
        cidr: String,
        dir: Dir,
    },
    Ports {
        list: String,
        dir: Dir,
    },
    Protocol {
        name: String,
    },
    EtherHost {
        mac: String,
        dir: Dir,
    },
    /// VLAN, optionally a specific ID.
    Vlan {
        id: String,
    },
    /// Flags by name; `exact` requires all of them, otherwise any of them.
    TcpFlags {
        flags: Vec<String>,
        exact: bool,
    },
    IcmpType {
        kind: String,
    },
    EtherBroadcast,
    EtherMulticast,
    IpVersion {
        v6: bool,
    },
    EtherProto {
        number: String,
    },
    IpProto {
        number: String,
    },
}

/// Parse a number given in decimal or `0x` hex.
fn number(field: &str, s: &str, max: u64) -> BuildResult<u64> {
    let t = s.trim();
    let parsed = match t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        Some(hex) => u64::from_str_radix(hex, 16),
        None => t.parse::<u64>(),
    };
    match parsed {
        Ok(n) if n <= max => Ok(n),
        _ => err(
            field,
            format!("enter a number from 0 to {max} (decimal or 0x hex)"),
        ),
    }
}

/// Render one snippet as a BPF expression.
pub fn render_snippet(s: &Snippet) -> BuildResult<String> {
    let missing = |f: &str| err(f, "required");
    Ok(match s {
        Snippet::Host { ip, dir } => match opt_ip("ip", ip)? {
            Some(a) => format!("{} {a}", dir.prefix("host")),
            None => return missing("ip"),
        },
        Snippet::Network { cidr, dir } => match opt_cidr("cidr", cidr)? {
            Some(n) => format!("{} {n}", dir.prefix("net")),
            None => return missing("cidr"),
        },
        Snippet::Ports { list, dir } => match ports_expr(*dir, &port_list("list", list)?) {
            Some(e) => e,
            None => return missing("list"),
        },
        Snippet::Protocol { name } => match protocol("name", name)? {
            Some(p) => p.to_string(),
            None => return missing("name"),
        },
        Snippet::EtherHost { mac, dir } => match opt_mac("mac", mac)? {
            Some(m) => {
                let prefix = match dir {
                    Dir::Any => "ether host",
                    Dir::Src => "ether src",
                    Dir::Dst => "ether dst",
                };
                format!("{prefix} {m}")
            }
            None => return missing("mac"),
        },
        Snippet::Vlan { id } => match opt_int("id", id, 1, 4094)? {
            Some(v) => format!("vlan {v}"),
            None => "vlan".to_string(),
        },
        Snippet::TcpFlags { flags, exact } => {
            let mut chosen = Vec::new();
            for f in TCP_FLAGS {
                if flags.iter().any(|x| x.eq_ignore_ascii_case(f)) {
                    chosen.push(format!("tcp-{f}"));
                }
            }
            if let Some(bad) = flags
                .iter()
                .find(|x| !TCP_FLAGS.iter().any(|f| f.eq_ignore_ascii_case(x)))
            {
                return err("flags", format!("unknown TCP flag '{bad}'"));
            }
            if chosen.is_empty() {
                return err("flags", "choose at least one flag");
            }
            let joined = chosen.join("|");
            let mask = if chosen.len() > 1 {
                format!("({joined})")
            } else {
                joined
            };
            if *exact {
                format!("tcp[tcpflags] & {mask} == {mask}")
            } else {
                format!("tcp[tcpflags] & {mask} != 0")
            }
        }
        Snippet::IcmpType { kind } => match ICMP_TYPES.iter().find(|k| **k == kind.as_str()) {
            Some(k) => format!("icmp[icmptype] == icmp-{k}"),
            None => return err("kind", format!("unknown ICMP type '{kind}'")),
        },
        Snippet::EtherBroadcast => "ether broadcast".to_string(),
        Snippet::EtherMulticast => "ether multicast".to_string(),
        Snippet::IpVersion { v6 } => (if *v6 { "ip6" } else { "ip" }).to_string(),
        Snippet::EtherProto { number: n } => {
            if n.trim().is_empty() {
                return missing("number");
            }
            let v = number("number", n, 0xffff)?;
            format!("ether proto 0x{v:04x}")
        }
        Snippet::IpProto { number: n } => {
            if n.trim().is_empty() {
                return missing("number");
            }
            format!("ip proto {}", number("number", n, 255)?)
        }
    })
}

/// Apply NOT / parentheses to a rendered snippet. NOT always parenthesizes.
pub fn decorate(raw: &str, negate: bool, wrap: bool) -> String {
    if negate {
        format!("not ({raw})")
    } else if wrap {
        format!("({raw})")
    } else {
        raw.to_string()
    }
}

/// Append a piece to an existing filter with `and` / `or`.
pub fn append(existing: &str, piece: &str, or: bool) -> String {
    let e = existing.trim();
    if e.is_empty() {
        piece.to_string()
    } else {
        format!("{e} {} {piece}", if or { "or" } else { "and" })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_command() {
        assert_eq!(
            build(&SnifferInput::default()).unwrap(),
            "diagnose sniffer packet any 'none' 4 0 l"
        );
    }

    #[test]
    fn simple_filter_matches_swift() {
        let i = SnifferInput {
            interface: "port1".into(),
            host: "10.0.0.1".into(),
            host_dir: Dir::Src,
            net: "192.168.1.0/24".into(),
            ports: "80, 443".into(),
            port_dir: Dir::Dst,
            proto: "tcp".into(),
            verbose: 6,
            count: "100".into(),
            timestamp: Timestamp::Utc,
            ..Default::default()
        };
        assert_eq!(
            build(&i).unwrap(),
            "diagnose sniffer packet port1 'tcp and src host 10.0.0.1 and net 192.168.1.0/24 and (dst port 80 or dst port 443)' 6 100 a"
        );
    }

    #[test]
    fn count_and_timestamp_positions() {
        let base = SnifferInput::default();
        let rel = SnifferInput {
            timestamp: Timestamp::Relative,
            ..base.clone()
        };
        assert_eq!(build(&rel).unwrap(), "diagnose sniffer packet any 'none' 4");
        let rel_count = SnifferInput {
            timestamp: Timestamp::Relative,
            count: "10".into(),
            ..base
        };
        assert_eq!(
            build(&rel_count).unwrap(),
            "diagnose sniffer packet any 'none' 4 10"
        );
    }

    #[test]
    fn custom_filter_rules() {
        let ok = SnifferInput {
            use_custom_filter: true,
            custom_filter: "(tcp[tcpflags] & tcp-syn != 0) and not port 22".into(),
            ..Default::default()
        };
        assert!(
            build(&ok)
                .unwrap()
                .contains("'(tcp[tcpflags] & tcp-syn != 0) and not port 22'")
        );
        for bad in [
            "host 1.1.1.1' ; diagnose sys reboot '",
            "port 80\nexec reboot",
        ] {
            let i = SnifferInput {
                use_custom_filter: true,
                custom_filter: bad.into(),
                ..Default::default()
            };
            assert_eq!(build(&i).unwrap_err().field, "customFilter");
        }
        let long = SnifferInput {
            use_custom_filter: true,
            custom_filter: "a".repeat(MAX_FILTER_LEN + 1),
            ..Default::default()
        };
        assert!(build(&long).is_err());
    }

    #[test]
    fn rejects_bad_simple_fields() {
        let cases = [
            (
                SnifferInput {
                    interface: "port1;x".into(),
                    ..Default::default()
                },
                "interface",
            ),
            (
                SnifferInput {
                    verbose: 7,
                    ..Default::default()
                },
                "verbose",
            ),
            (
                SnifferInput {
                    proto: "sctp".into(),
                    ..Default::default()
                },
                "proto",
            ),
            (
                SnifferInput {
                    host: "fw01".into(),
                    ..Default::default()
                },
                "host",
            ),
            (
                SnifferInput {
                    ports: "80,0".into(),
                    ..Default::default()
                },
                "ports",
            ),
        ];
        for (i, field) in cases {
            assert_eq!(build(&i).unwrap_err().field, field);
        }
    }

    #[test]
    fn snippets_render_like_swift() {
        let cases: Vec<(Snippet, &str)> = vec![
            (
                Snippet::Host {
                    ip: "10.0.0.1".into(),
                    dir: Dir::Any,
                },
                "host 10.0.0.1",
            ),
            (
                Snippet::Network {
                    cidr: "10.0.0.0/8".into(),
                    dir: Dir::Dst,
                },
                "dst net 10.0.0.0/8",
            ),
            (
                Snippet::Ports {
                    list: "53,123".into(),
                    dir: Dir::Src,
                },
                "(src port 53 or src port 123)",
            ),
            (Snippet::Protocol { name: "ARP".into() }, "arp"),
            (
                Snippet::EtherHost {
                    mac: "00-1B-44-11-3A-B7".into(),
                    dir: Dir::Src,
                },
                "ether src 00:1b:44:11:3a:b7",
            ),
            (Snippet::Vlan { id: "".into() }, "vlan"),
            (Snippet::Vlan { id: "100".into() }, "vlan 100"),
            (
                Snippet::TcpFlags {
                    flags: vec!["syn".into()],
                    exact: false,
                },
                "tcp[tcpflags] & tcp-syn != 0",
            ),
            (
                Snippet::TcpFlags {
                    flags: vec!["ack".into(), "syn".into()],
                    exact: true,
                },
                "tcp[tcpflags] & (tcp-syn|tcp-ack) == (tcp-syn|tcp-ack)",
            ),
            (
                Snippet::IcmpType {
                    kind: "timxceed".into(),
                },
                "icmp[icmptype] == icmp-timxceed",
            ),
            (Snippet::EtherBroadcast, "ether broadcast"),
            (Snippet::EtherMulticast, "ether multicast"),
            (Snippet::IpVersion { v6: true }, "ip6"),
            (
                Snippet::EtherProto {
                    number: "0x806".into(),
                },
                "ether proto 0x0806",
            ),
            (
                Snippet::EtherProto {
                    number: "2054".into(),
                },
                "ether proto 0x0806",
            ),
            (
                Snippet::IpProto {
                    number: "47".into(),
                },
                "ip proto 47",
            ),
        ];
        for (s, want) in cases {
            assert_eq!(render_snippet(&s).unwrap(), want);
        }
    }

    #[test]
    fn snippet_errors() {
        assert!(
            render_snippet(&Snippet::Host {
                ip: "".into(),
                dir: Dir::Any
            })
            .is_err()
        );
        assert!(render_snippet(&Snippet::Vlan { id: "4095".into() }).is_err());
        assert!(
            render_snippet(&Snippet::TcpFlags {
                flags: vec![],
                exact: false
            })
            .is_err()
        );
        assert!(
            render_snippet(&Snippet::TcpFlags {
                flags: vec!["xmas".into()],
                exact: false
            })
            .is_err()
        );
        assert!(
            render_snippet(&Snippet::IcmpType {
                kind: "echo; reboot".into()
            })
            .is_err()
        );
        assert!(
            render_snippet(&Snippet::IpProto {
                number: "256".into()
            })
            .is_err()
        );
    }

    #[test]
    fn decorate_and_append() {
        assert_eq!(decorate("arp", true, false), "not (arp)");
        assert_eq!(decorate("arp", false, true), "(arp)");
        assert_eq!(decorate("arp", false, false), "arp");
        assert_eq!(append("", "(arp)", false), "(arp)");
        assert_eq!(append("(arp) ", "(ip6)", true), "(arp) or (ip6)");
    }
}
