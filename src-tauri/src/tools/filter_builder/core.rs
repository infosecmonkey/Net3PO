//! Capture and display filter builder. One structured description (groups
//! of terms: AND inside a group, OR between groups) is rendered separately
//! as a BPF capture filter, a Wireshark display filter and a FortiGate
//! sniffer command. The languages are never mixed. No filter engine is
//! bundled, so outputs are generated from validated terms, not compiled.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

const MAX_GROUPS: usize = 20;
const MAX_TERMS: usize = 20;

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Dir {
    #[default]
    Any,
    Src,
    Dst,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum L4 {
    #[default]
    Any,
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(
    tag = "type",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum TermKind {
    Host {
        addr: String,
        #[serde(default)]
        dir: Dir,
    },
    Net {
        cidr: String,
        #[serde(default)]
        dir: Dir,
    },
    /// Ports and ranges: "53", "80,443", "1000-2000".
    Port {
        ports: String,
        #[serde(default)]
        dir: Dir,
        #[serde(default)]
        l4: L4,
    },
    Proto {
        name: String,
    },
    /// Flags among syn, ack, fin, rst, psh, urg. `exact`: these set and the
    /// other four of SYN/ACK/FIN/RST/PSH/URG clear.
    TcpFlags {
        flags: Vec<String>,
        #[serde(default)]
        exact: bool,
    },
    Vlan {
        #[serde(default)]
        id: Option<u16>,
    },
    Mac {
        addr: String,
        #[serde(default)]
        dir: Dir,
    },
    /// A Wireshark-only expression (from a scenario), e.g. retransmissions.
    DisplayOnly {
        expr: String,
        label: String,
    },
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Term {
    #[serde(flatten)]
    pub kind: TermKind,
    #[serde(default)]
    pub negate: bool,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct Group {
    pub terms: Vec<Term>,
}

#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Output {
    pub text: String,
    /// Why this language cannot express the filter, when it cannot.
    pub error: Option<String>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Filters {
    pub bpf: Output,
    pub wireshark: Output,
    pub fortigate: Output,
    /// Plain-language reading of the filter.
    pub explanation: String,
    /// Input problems; when set, no filter is produced.
    pub errors: Vec<String>,
}

const PROTOS: &[&str] = &[
    "tcp", "udp", "icmp", "icmp6", "arp", "ip", "ip6", "esp", "gre", "sctp",
];
const FLAGS: &[(&str, u8)] = &[
    ("fin", 0x01),
    ("syn", 0x02),
    ("rst", 0x04),
    ("psh", 0x08),
    ("ack", 0x10),
    ("urg", 0x20),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PortSpec {
    One(u16),
    Range(u16, u16),
}

fn parse_ports(s: &str) -> Result<Vec<PortSpec>, String> {
    let mut out = Vec::new();
    for p in s.split([',', ' ']).map(str::trim).filter(|p| !p.is_empty()) {
        if let Some((a, b)) = p.split_once('-') {
            let a: u16 = a
                .trim()
                .parse()
                .map_err(|_| format!("bad port range {p}"))?;
            let b: u16 = b
                .trim()
                .parse()
                .map_err(|_| format!("bad port range {p}"))?;
            if a > b {
                return Err(format!("port range {p} is reversed"));
            }
            out.push(if a == b {
                PortSpec::One(a)
            } else {
                PortSpec::Range(a, b)
            });
        } else {
            out.push(PortSpec::One(
                p.parse().map_err(|_| format!("bad port {p}"))?,
            ));
        }
        if out.len() > 50 {
            return Err("more than 50 ports in one term".into());
        }
    }
    if out.is_empty() {
        return Err("enter at least one port".into());
    }
    Ok(out)
}

fn parse_cidr(s: &str) -> Result<(IpAddr, u8), String> {
    let (a, l) = s
        .trim()
        .split_once('/')
        .ok_or_else(|| format!("{s}: use address/prefix, e.g. 10.0.0.0/8"))?;
    let ip: IpAddr = a.parse().map_err(|_| format!("{a} is not an IP address"))?;
    let max = if ip.is_ipv4() { 32 } else { 128 };
    let len: u8 = l
        .parse()
        .ok()
        .filter(|&n| n <= max)
        .ok_or_else(|| format!("bad prefix length /{l}"))?;
    Ok((ip, len))
}

fn parse_mac(s: &str) -> Result<String, String> {
    let hex: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if hex.len() != 12
        || s.chars()
            .any(|c| !(c.is_ascii_hexdigit() || ":-.".contains(c)))
    {
        return Err(format!("{s} is not a MAC address"));
    }
    let h = hex.to_ascii_lowercase();
    Ok((0..6)
        .map(|i| &h[i * 2..i * 2 + 2])
        .collect::<Vec<_>>()
        .join(":"))
}

fn flag_mask(flags: &[String]) -> Result<u8, String> {
    let mut m = 0;
    for f in flags {
        let f = f.trim().to_ascii_lowercase();
        m |= FLAGS
            .iter()
            .find(|(n, _)| *n == f)
            .map(|(_, v)| *v)
            .ok_or_else(|| format!("unknown TCP flag {f}"))?;
    }
    if m == 0 {
        return Err("choose at least one TCP flag".into());
    }
    Ok(m)
}

fn flag_names(m: u8, sep: &str, prefix: &str) -> String {
    FLAGS
        .iter()
        .filter(|(_, v)| m & v != 0)
        .map(|(n, _)| format!("{prefix}{n}"))
        .collect::<Vec<_>>()
        .join(sep)
}

/// One validated term rendered in each language plus English.
struct Rendered {
    bpf: Option<String>,
    ws: String,
    english: String,
    bpf_note: Option<String>,
}

fn dir_word(d: Dir) -> &'static str {
    match d {
        Dir::Any => "to or from",
        Dir::Src => "from",
        Dir::Dst => "to",
    }
}

fn render(t: &TermKind) -> Result<Rendered, String> {
    Ok(match t {
        TermKind::Host { addr, dir } => {
            let ip: IpAddr = addr
                .trim()
                .parse()
                .map_err(|_| format!("{addr} is not an IP address"))?;
            let field = if ip.is_ipv4() { "ip" } else { "ipv6" };
            let ws_dir = match dir {
                Dir::Any => "addr",
                Dir::Src => "src",
                Dir::Dst => "dst",
            };
            let bpf_dir = match dir {
                Dir::Any => "",
                Dir::Src => "src ",
                Dir::Dst => "dst ",
            };
            Rendered {
                bpf: Some(format!("{bpf_dir}host {ip}")),
                ws: format!("{field}.{ws_dir} == {ip}"),
                english: format!("traffic {} {ip}", dir_word(*dir)),
                bpf_note: None,
            }
        }
        TermKind::Net { cidr, dir } => {
            let (ip, len) = parse_cidr(cidr)?;
            let field = if ip.is_ipv4() { "ip" } else { "ipv6" };
            let ws_dir = match dir {
                Dir::Any => "addr",
                Dir::Src => "src",
                Dir::Dst => "dst",
            };
            let bpf_dir = match dir {
                Dir::Any => "",
                Dir::Src => "src ",
                Dir::Dst => "dst ",
            };
            Rendered {
                bpf: Some(format!("{bpf_dir}net {ip}/{len}")),
                ws: format!("{field}.{ws_dir} == {ip}/{len}"),
                english: format!("traffic {} {ip}/{len}", dir_word(*dir)),
                bpf_note: None,
            }
        }
        TermKind::Port { ports, dir, l4 } => {
            let list = parse_ports(ports)?;
            let bpf_l4 = match l4 {
                L4::Any => "",
                L4::Tcp => "tcp ",
                L4::Udp => "udp ",
            };
            let bpf_dir = match dir {
                Dir::Any => "",
                Dir::Src => "src ",
                Dir::Dst => "dst ",
            };
            let bpf_parts: Vec<String> = list
                .iter()
                .map(|p| match p {
                    PortSpec::One(n) => format!("{bpf_l4}{bpf_dir}port {n}"),
                    PortSpec::Range(a, b) => format!("{bpf_l4}{bpf_dir}portrange {a}-{b}"),
                })
                .collect();
            let bpf = if bpf_parts.len() == 1 {
                bpf_parts[0].clone()
            } else {
                format!("({})", bpf_parts.join(" or "))
            };
            let set: Vec<String> = list
                .iter()
                .map(|p| match p {
                    PortSpec::One(n) => n.to_string(),
                    PortSpec::Range(a, b) => format!("{a}..{b}"),
                })
                .collect();
            let field = match dir {
                Dir::Any => "port",
                Dir::Src => "srcport",
                Dir::Dst => "dstport",
            };
            let cond = |proto: &str| {
                if list.len() == 1 && matches!(list[0], PortSpec::One(_)) {
                    format!("{proto}.{field} == {}", set[0])
                } else {
                    format!("{proto}.{field} in {{{}}}", set.join(" "))
                }
            };
            let ws = match l4 {
                L4::Tcp => cond("tcp"),
                L4::Udp => cond("udp"),
                L4::Any => format!("({} || {})", cond("tcp"), cond("udp")),
            };
            let proto_word = match l4 {
                L4::Any => "TCP or UDP",
                L4::Tcp => "TCP",
                L4::Udp => "UDP",
            };
            let dir_word = match dir {
                Dir::Any => "",
                Dir::Src => "source ",
                Dir::Dst => "destination ",
            };
            Rendered {
                bpf: Some(bpf),
                ws,
                english: format!(
                    "{proto_word} {dir_word}port {}",
                    set.join(", ").replace("..", "-")
                ),
                bpf_note: None,
            }
        }
        TermKind::Proto { name } => {
            let n = name.trim().to_ascii_lowercase();
            if !PROTOS.contains(&n.as_str()) {
                return Err(format!("unknown protocol {name}"));
            }
            let ws = match n.as_str() {
                "icmp6" => "icmpv6",
                "ip6" => "ipv6",
                other => other,
            }
            .to_string();
            Rendered {
                english: format!("{} packets", n.to_uppercase()),
                bpf: Some(n),
                ws,
                bpf_note: None,
            }
        }
        TermKind::TcpFlags { flags, exact } => {
            let m = flag_mask(flags)?;
            let names = flag_names(m, "|", "tcp-");
            let bpf = if *exact {
                format!("tcp[tcpflags] & 0x3f == {m:#04x}")
            } else {
                format!("tcp[tcpflags] & ({names}) == ({names})")
            };
            let ws = if *exact {
                format!("tcp.flags & 0x3f == {m:#05x}")
            } else {
                FLAGS
                    .iter()
                    .filter(|(_, v)| m & v != 0)
                    .map(|(n, _)| format!("tcp.flags.{n} == 1"))
                    .collect::<Vec<_>>()
                    .join(" && ")
            };
            let english = format!(
                "TCP with {}{}",
                flag_names(m, "+", "").to_uppercase(),
                if *exact { " only" } else { " set" }
            );
            Rendered { bpf: Some(bpf), ws, english, bpf_note: Some("tcp[tcpflags] reads the TCP header at a fixed IPv4 offset; it does not match TCP over IPv6".into()) }
        }
        TermKind::Vlan { id } => {
            if id.is_some_and(|v| v == 0 || v > 4094) {
                return Err("VLAN ID must be 1 to 4094".into());
            }
            let (bpf, ws, english) = match id {
                Some(v) => (
                    format!("vlan {v}"),
                    format!("vlan.id == {v}"),
                    format!("VLAN {v}"),
                ),
                None => ("vlan".into(), "vlan".into(), "802.1Q-tagged frames".into()),
            };
            Rendered { bpf: Some(bpf), ws, english, bpf_note: Some("in BPF, \"vlan\" shifts the offsets of everything after it; keep it first in its group".into()) }
        }
        TermKind::Mac { addr, dir } => {
            let m = parse_mac(addr)?;
            let ws_dir = match dir {
                Dir::Any => "addr",
                Dir::Src => "src",
                Dir::Dst => "dst",
            };
            let bpf_dir = match dir {
                Dir::Any => "ether host",
                Dir::Src => "ether src",
                Dir::Dst => "ether dst",
            };
            Rendered {
                bpf: Some(format!("{bpf_dir} {m}")),
                ws: format!("eth.{ws_dir} == {m}"),
                english: format!("frames {} MAC {m}", dir_word(*dir)),
                bpf_note: None,
            }
        }
        TermKind::DisplayOnly { expr, label } => {
            let e = expr.trim();
            if e.is_empty() || e.len() > 200 || e.contains(['\n', '\r']) {
                return Err("bad display expression".into());
            }
            Rendered {
                bpf: None,
                ws: e.to_string(),
                english: label.clone(),
                bpf_note: None,
            }
        }
    })
}

/// True when the whole string is one parenthesized expression.
fn wrapped(s: &str) -> bool {
    if !s.starts_with('(') || !s.ends_with(')') {
        return false;
    }
    let mut depth = 0i32;
    for (i, c) in s.char_indices() {
        match c {
            '(' => depth += 1,
            ')' => depth -= 1,
            _ => {}
        }
        if depth == 0 && i < s.len() - 1 {
            return false;
        }
    }
    true
}

fn wrap_neg(s: &str, neg: bool, not: &str) -> String {
    match (neg, wrapped(s)) {
        (false, _) => s.to_string(),
        (true, true) => format!("{not}{s}"),
        (true, false) => format!("{not}({s})"),
    }
}

/// Render all outputs for `groups`.
pub fn build(groups: &[Group], interface: &str) -> Filters {
    let mut f = Filters::default();
    if groups.len() > MAX_GROUPS || groups.iter().any(|g| g.terms.len() > MAX_TERMS) {
        f.errors
            .push(format!("at most {MAX_GROUPS} groups of {MAX_TERMS} terms"));
        return f;
    }
    let groups: Vec<&Group> = groups.iter().filter(|g| !g.terms.is_empty()).collect();
    if groups.is_empty() {
        f.errors.push("add at least one condition".into());
        return f;
    }
    let iface = interface.trim();
    if iface.is_empty()
        || iface.len() > 32
        || !iface
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c))
    {
        f.errors
            .push("interface name may use letters, digits, - _ and .".into());
        return f;
    }

    let mut bpf_groups = Vec::new();
    let mut ws_groups = Vec::new();
    let mut en_groups = Vec::new();
    let mut bpf_impossible: Vec<String> = Vec::new();
    let mut bpf_notes: Vec<String> = Vec::new();
    for (gi, g) in groups.iter().enumerate() {
        let (mut b, mut w, mut e) = (Vec::new(), Vec::new(), Vec::new());
        for (ti, t) in g.terms.iter().enumerate() {
            match render(&t.kind) {
                Ok(r) => {
                    match r.bpf {
                        Some(x) => b.push(wrap_neg(&x, t.negate, "not ")),
                        None => bpf_impossible.push(r.english.clone()),
                    }
                    if let Some(n) = r.bpf_note
                        && !bpf_notes.contains(&n)
                    {
                        bpf_notes.push(n);
                    }
                    w.push(wrap_neg(&r.ws, t.negate, "!"));
                    e.push(if t.negate {
                        format!("not {}", r.english)
                    } else {
                        r.english
                    });
                }
                Err(msg) => f
                    .errors
                    .push(format!("group {}, condition {}: {msg}", gi + 1, ti + 1)),
            }
        }
        let join = |v: &[String], op: &str, many: bool| {
            let s = v.join(op);
            if many && v.len() > 1 {
                format!("({s})")
            } else {
                s
            }
        };
        let many = groups.len() > 1;
        bpf_groups.push(join(&b, " and ", many));
        ws_groups.push(join(&w, " && ", many));
        en_groups.push(e.join(" and "));
    }
    if !f.errors.is_empty() {
        return f;
    }

    f.explanation = if en_groups.len() == 1 {
        format!("Matches {}.", en_groups[0])
    } else {
        format!(
            "Matches any of: {}.",
            en_groups
                .iter()
                .map(|g| format!("({g})"))
                .collect::<Vec<_>>()
                .join(" or ")
        )
    };
    f.wireshark = Output {
        text: ws_groups.join(" || "),
        error: None,
        notes: vec!["Not validated by Wireshark here; paste it into the display filter bar, which turns green when the syntax is valid.".into()],
    };
    if bpf_impossible.is_empty() {
        let bpf = bpf_groups.join(" or ");
        let mut notes = bpf_notes.clone();
        notes.push(
            "Not compiled here (no libpcap bundled); `tcpdump -d '<filter>'` checks it.".into(),
        );
        f.bpf = Output {
            text: bpf.clone(),
            error: None,
            notes,
        };
        let mut fnotes = bpf_notes;
        fnotes.push("Same BPF syntax as the Fortinet Command Builder's sniffer; verbose 4 shows interface names, count 0 runs until Ctrl+C, l prints local time.".into());
        if bpf.contains('\'') || bpf.len() > 1024 {
            f.fortigate = Output {
                error: Some("filter too long or contains a quote for the FortiGate CLI".into()),
                ..Default::default()
            };
        } else {
            f.fortigate = Output {
                text: format!("diagnose sniffer packet {iface} '{bpf}' 4 0 l"),
                error: None,
                notes: fnotes,
            };
        }
    } else {
        let why = format!(
            "A capture filter cannot express: {}. Capture more broadly and use the display filter.",
            bpf_impossible.join(", ")
        );
        f.bpf = Output {
            error: Some(why.clone()),
            ..Default::default()
        };
        f.fortigate = Output {
            error: Some(why),
            ..Default::default()
        };
    }
    f
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(kind: TermKind) -> Term {
        Term {
            kind,
            negate: false,
        }
    }

    fn g(terms: Vec<Term>) -> Group {
        Group { terms }
    }

    #[test]
    fn ui_json_shape() {
        let json = r#"[{"terms":[{"type":"host","addr":"10.0.0.1","dir":"src","negate":true},{"type":"port","ports":"443","l4":"tcp"},{"type":"tcpFlags","flags":["syn"],"exact":true},{"type":"displayOnly","expr":"dns","label":"DNS"}]}]"#;
        let groups: Vec<Group> = serde_json::from_str(json).unwrap();
        assert_eq!(groups[0].terms.len(), 4);
        assert!(groups[0].terms[0].negate);
        assert_eq!(
            groups[0].terms[0].kind,
            TermKind::Host {
                addr: "10.0.0.1".into(),
                dir: Dir::Src
            }
        );
    }

    #[test]
    fn single_host_and_port() {
        let f = build(
            &[g(vec![
                t(TermKind::Host {
                    addr: "10.1.1.10".into(),
                    dir: Dir::Any,
                }),
                t(TermKind::Port {
                    ports: "443".into(),
                    dir: Dir::Any,
                    l4: L4::Tcp,
                }),
            ])],
            "any",
        );
        assert!(f.errors.is_empty(), "{:?}", f.errors);
        assert_eq!(f.bpf.text, "host 10.1.1.10 and tcp port 443");
        assert_eq!(f.wireshark.text, "ip.addr == 10.1.1.10 && tcp.port == 443");
        assert_eq!(
            f.fortigate.text,
            "diagnose sniffer packet any 'host 10.1.1.10 and tcp port 443' 4 0 l"
        );
        assert_eq!(
            f.explanation,
            "Matches traffic to or from 10.1.1.10 and TCP port 443."
        );
    }

    #[test]
    fn or_groups_negation_and_ipv6() {
        let f = build(
            &[
                g(vec![
                    t(TermKind::Net {
                        cidr: "2001:db8::/32".into(),
                        dir: Dir::Src,
                    }),
                    Term {
                        kind: TermKind::Port {
                            ports: "22".into(),
                            dir: Dir::Any,
                            l4: L4::Any,
                        },
                        negate: true,
                    },
                ]),
                g(vec![t(TermKind::Proto {
                    name: "icmp6".into(),
                })]),
            ],
            "port1",
        );
        assert_eq!(
            f.bpf.text,
            "(src net 2001:db8::/32 and not (port 22)) or icmp6"
        );
        assert_eq!(
            f.wireshark.text,
            "(ipv6.src == 2001:db8::/32 && !(tcp.port == 22 || udp.port == 22)) || icmpv6"
        );
        assert!(
            f.fortigate
                .text
                .starts_with("diagnose sniffer packet port1 '")
        );
    }

    #[test]
    fn port_lists_and_ranges() {
        let f = build(
            &[g(vec![t(TermKind::Port {
                ports: "53, 67-68".into(),
                dir: Dir::Dst,
                l4: L4::Udp,
            })])],
            "any",
        );
        assert_eq!(f.bpf.text, "(udp dst port 53 or udp dst portrange 67-68)");
        assert_eq!(f.wireshark.text, "udp.dstport in {53 67..68}");
    }

    #[test]
    fn tcp_flags() {
        let f = build(
            &[g(vec![t(TermKind::TcpFlags {
                flags: vec!["syn".into()],
                exact: true,
            })])],
            "any",
        );
        assert_eq!(f.bpf.text, "tcp[tcpflags] & 0x3f == 0x02");
        assert_eq!(f.wireshark.text, "tcp.flags & 0x3f == 0x002");
        assert!(f.bpf.notes.iter().any(|n| n.contains("IPv6")));
        let f = build(
            &[g(vec![t(TermKind::TcpFlags {
                flags: vec!["rst".into(), "ack".into()],
                exact: false,
            })])],
            "any",
        );
        assert_eq!(
            f.bpf.text,
            "tcp[tcpflags] & (tcp-rst|tcp-ack) == (tcp-rst|tcp-ack)"
        );
        assert_eq!(f.wireshark.text, "tcp.flags.rst == 1 && tcp.flags.ack == 1");
    }

    #[test]
    fn display_only_blocks_capture() {
        let f = build(
            &[g(vec![t(TermKind::DisplayOnly {
                expr: "tcp.analysis.retransmission".into(),
                label: "TCP retransmissions".into(),
            })])],
            "any",
        );
        assert_eq!(f.wireshark.text, "tcp.analysis.retransmission");
        assert!(f.bpf.error.as_ref().unwrap().contains("retransmissions"));
        assert!(f.fortigate.error.is_some() && f.bpf.text.is_empty());
    }

    #[test]
    fn mac_vlan_and_errors() {
        let f = build(
            &[g(vec![
                t(TermKind::Vlan { id: Some(100) }),
                t(TermKind::Mac {
                    addr: "00-11-22-AA-BB-CC".into(),
                    dir: Dir::Src,
                }),
            ])],
            "any",
        );
        assert_eq!(f.bpf.text, "vlan 100 and ether src 00:11:22:aa:bb:cc");
        assert_eq!(
            f.wireshark.text,
            "vlan.id == 100 && eth.src == 00:11:22:aa:bb:cc"
        );
        for bad in [
            TermKind::Host {
                addr: "10.1.1".into(),
                dir: Dir::Any,
            },
            TermKind::Net {
                cidr: "10.0.0.0/33".into(),
                dir: Dir::Any,
            },
            TermKind::Port {
                ports: "70000".into(),
                dir: Dir::Any,
                l4: L4::Any,
            },
            TermKind::Port {
                ports: "20-10".into(),
                dir: Dir::Any,
                l4: L4::Any,
            },
            TermKind::Proto {
                name: "smtp; rm".into(),
            },
            TermKind::TcpFlags {
                flags: vec![],
                exact: false,
            },
            TermKind::Vlan { id: Some(5000) },
            TermKind::Mac {
                addr: "zz:11".into(),
                dir: Dir::Any,
            },
        ] {
            let f = build(&[g(vec![t(bad)])], "any");
            assert!(!f.errors.is_empty() && f.bpf.text.is_empty());
        }
        assert!(!build(&[], "any").errors.is_empty());
        assert!(
            !build(
                &[g(vec![t(TermKind::Proto { name: "tcp".into() })])],
                "bad iface'"
            )
            .errors
            .is_empty()
        );
    }
}
