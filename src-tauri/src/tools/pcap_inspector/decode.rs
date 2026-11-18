//! Decode one captured frame into a summary line and, on request, a field
//! list. L2 to L4 come from etherparse's tolerant slicer, so truncated
//! captures still decode as far as the bytes go. Encrypted payloads are
//! labelled, never guessed at. Every read is bounds-checked.

use std::net::{IpAddr, Ipv4Addr};

use etherparse::{
    EtherType, LaxLinkExtSlice, LaxNetSlice, LaxSlicedPacket, LinkSlice, TransportSlice,
};
use serde::Serialize;

/// Link types this inspector decodes.
pub fn link_name(lt: i32) -> Option<&'static str> {
    Some(match lt {
        0 => "BSD loopback",
        1 => "Ethernet",
        12 | 14 | 101 => "Raw IP",
        108 => "OpenBSD loopback",
        113 => "Linux cooked (SLL)",
        228 => "Raw IPv4",
        229 => "Raw IPv6",
        276 => "Linux cooked v2 (SLL2)",
        _ => return None,
    })
}

#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Field {
    pub layer: String,
    pub name: String,
    pub value: String,
}

/// What one frame boils down to.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Decoded {
    pub src: String,
    pub dst: String,
    pub proto: String,
    pub info: String,
    pub ips: Option<(IpAddr, IpAddr)>,
    /// (IP protocol number, source port, destination port).
    pub l4: Option<(u8, u16, u16)>,
    pub tcp_flags: u8,
    pub malformed: Option<String>,
    pub encrypted: bool,
    pub dns: Option<DnsInfo>,
    pub fields: Vec<Field>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DnsInfo {
    pub response: bool,
    pub rcode: String,
    pub questions: Vec<(String, String)>,
    pub answers: usize,
}

fn mac(b: [u8; 6]) -> String {
    b.iter()
        .map(|x| format!("{x:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn port_name(p: u16, udp: bool) -> Option<&'static str> {
    Some(match (p, udp) {
        (20 | 21, false) => "FTP",
        (22, false) => "SSH",
        (23, false) => "Telnet",
        (25 | 587 | 465, false) => "SMTP",
        (53, _) => "DNS",
        (67 | 68, true) => "DHCP",
        (69, true) => "TFTP",
        (80 | 8080, false) => "HTTP",
        (88, _) => "Kerberos",
        (110, false) => "POP3",
        (123, true) => "NTP",
        (137..=139, _) => "NetBIOS",
        (143, false) => "IMAP",
        (161 | 162, true) => "SNMP",
        (179, false) => "BGP",
        (389, _) => "LDAP",
        (443 | 8443, false) => "HTTPS",
        (443, true) => "QUIC",
        (445, false) => "SMB",
        (500, true) => "IKE",
        (514, _) => "Syslog",
        (546 | 547, true) => "DHCPv6",
        (636, false) => "LDAPS",
        (853, _) => "DNS over TLS",
        (1812 | 1813, true) => "RADIUS",
        (1900, true) => "SSDP",
        (3389, _) => "RDP",
        (4500, true) => "IPsec NAT-T",
        (5060 | 5061, _) => "SIP",
        (5353, true) => "mDNS",
        _ => return None,
    })
}

fn tcp_flag_text(f: u8) -> String {
    let names = [
        (0x02, "SYN"),
        (0x10, "ACK"),
        (0x01, "FIN"),
        (0x04, "RST"),
        (0x08, "PSH"),
        (0x20, "URG"),
    ];
    names
        .iter()
        .filter(|(b, _)| f & b != 0)
        .map(|(_, n)| *n)
        .collect::<Vec<_>>()
        .join(",")
}

/// SNI from a TLS ClientHello, if this is one. Bounded parse.
fn tls_sni(p: &[u8]) -> Option<String> {
    // Record header (5) + handshake header (4) + version (2) + random (32).
    if p.len() < 43 || p[0] != 0x16 || p[5] != 0x01 {
        return None;
    }
    let mut i = 43;
    let sid = *p.get(i)? as usize;
    i += 1 + sid;
    let cs = u16::from_be_bytes([*p.get(i)?, *p.get(i + 1)?]) as usize;
    i += 2 + cs;
    let comp = *p.get(i)? as usize;
    i += 1 + comp;
    let ext_total = u16::from_be_bytes([*p.get(i)?, *p.get(i + 1)?]) as usize;
    i += 2;
    let end = (i + ext_total).min(p.len());
    while i + 4 <= end {
        let et = u16::from_be_bytes([p[i], p[i + 1]]);
        let el = u16::from_be_bytes([p[i + 2], p[i + 3]]) as usize;
        let body = p.get(i + 4..i + 4 + el)?;
        if et == 0 && body.len() >= 5 && body[2] == 0 {
            let nl = u16::from_be_bytes([body[3], body[4]]) as usize;
            let name = body.get(5..5 + nl)?;
            let s = std::str::from_utf8(name).ok()?;
            if s.len() <= 255 && s.bytes().all(|b| b.is_ascii_graphic()) {
                return Some(s.to_string());
            }
            return None;
        }
        i += 4 + el;
    }
    None
}

fn tls_label(p: &[u8]) -> Option<(String, bool)> {
    if p.len() < 5 || !(20..=23).contains(&p[0]) || p[1] != 3 {
        return None;
    }
    Some(match p[0] {
        22 => match (p.get(5), tls_sni(p)) {
            (Some(1), Some(sni)) => (format!("TLS ClientHello, SNI {sni}"), false),
            (Some(1), None) => ("TLS ClientHello".into(), false),
            (Some(2), _) => ("TLS ServerHello".into(), false),
            _ => ("TLS handshake (encrypted after hello)".into(), true),
        },
        23 => ("TLS application data (encrypted)".into(), true),
        21 => ("TLS alert".into(), true),
        _ => ("TLS change cipher spec".into(), false),
    })
}

fn http_line(p: &[u8]) -> Option<String> {
    let line = p.split(|&b| b == b'\r' || b == b'\n').next()?;
    let s = std::str::from_utf8(line).ok()?;
    let methods = [
        "GET ", "POST ", "PUT ", "HEAD ", "DELETE ", "OPTIONS ", "PATCH ", "CONNECT ", "HTTP/1.",
    ];
    methods
        .iter()
        .any(|m| s.starts_with(m))
        .then(|| s.chars().take(120).collect())
}

pub fn dns(payload: &[u8]) -> Option<DnsInfo> {
    let m = hickory_proto::op::Message::from_vec(payload).ok()?;
    let questions = m
        .queries
        .iter()
        .take(10)
        .map(|q| {
            (
                q.name().to_utf8().trim_end_matches('.').to_string(),
                q.query_type().to_string(),
            )
        })
        .collect();
    Some(DnsInfo {
        response: m.message_type == hickory_proto::op::MessageType::Response,
        rcode: m.response_code.to_string(),
        questions,
        answers: m.answers.len(),
    })
}

fn icmp4_text(t: u8, c: u8) -> String {
    match t {
        0 => "echo reply".into(),
        3 => format!(
            "destination unreachable ({})",
            match c {
                0 => "network",
                1 => "host",
                3 => "port",
                4 => "fragmentation needed",
                13 => "administratively prohibited",
                _ => "other",
            }
        ),
        5 => "redirect".into(),
        8 => "echo request".into(),
        11 => "time exceeded".into(),
        _ => format!("type {t} code {c}"),
    }
}

fn icmp6_text(t: u8, c: u8) -> String {
    match t {
        1 => format!("destination unreachable (code {c})"),
        2 => "packet too big".into(),
        3 => "time exceeded".into(),
        128 => "echo request".into(),
        129 => "echo reply".into(),
        133 => "router solicitation".into(),
        134 => "router advertisement".into(),
        135 => "neighbor solicitation".into(),
        136 => "neighbor advertisement".into(),
        _ => format!("type {t} code {c}"),
    }
}

fn arp(p: &[u8], d: &mut Decoded) {
    if p.len() < 28 || p[4] != 6 || p[5] != 4 {
        d.proto = "ARP".into();
        d.info = "ARP (non-Ethernet/IPv4 or truncated)".into();
        return;
    }
    let op = u16::from_be_bytes([p[6], p[7]]);
    let spa = Ipv4Addr::new(p[14], p[15], p[16], p[17]);
    let tpa = Ipv4Addr::new(p[24], p[25], p[26], p[27]);
    let sha = mac([p[8], p[9], p[10], p[11], p[12], p[13]]);
    d.proto = "ARP".into();
    d.info = match op {
        1 if spa == tpa => format!("Gratuitous ARP for {spa}"),
        1 => format!("Who has {tpa}? Tell {spa}"),
        2 => format!("{spa} is at {sha}"),
        _ => format!("ARP operation {op}"),
    };
}

pub(crate) fn slice<'a>(lt: i32, data: &'a [u8]) -> Result<LaxSlicedPacket<'a>, String> {
    let ip = |b: &'a [u8]| LaxSlicedPacket::from_ip(b).map_err(|e| format!("IP header: {e}"));
    match lt {
        1 => LaxSlicedPacket::from_ethernet(data).map_err(|e| format!("Ethernet header: {e}")),
        12 | 14 | 101 | 228 | 229 => ip(data),
        0 | 108 => {
            let fam = data.get(..4).ok_or("loopback header truncated")?;
            let le = u32::from_le_bytes([fam[0], fam[1], fam[2], fam[3]]);
            let be = u32::from_be_bytes([fam[0], fam[1], fam[2], fam[3]]);
            if [2, 24, 28, 30].contains(&le) || [2, 24, 28, 30].contains(&be) {
                ip(&data[4..])
            } else {
                Err(format!("loopback family {le} not decoded"))
            }
        }
        113 => {
            let proto = data.get(14..16).ok_or("SLL header truncated")?;
            Ok(LaxSlicedPacket::from_ether_type(
                EtherType(u16::from_be_bytes([proto[0], proto[1]])),
                &data[16..],
            ))
        }
        276 => {
            let proto = data.get(0..2).ok_or("SLL2 header truncated")?;
            let body = data.get(20..).ok_or("SLL2 header truncated")?;
            Ok(LaxSlicedPacket::from_ether_type(
                EtherType(u16::from_be_bytes([proto[0], proto[1]])),
                body,
            ))
        }
        other => Err(format!("link type {other} is not decoded")),
    }
}

fn f(out: &mut Vec<Field>, want: bool, layer: &str, name: &str, value: impl ToString) {
    if want {
        out.push(Field {
            layer: layer.into(),
            name: name.into(),
            value: value.to_string(),
        });
    }
}

/// Decode a frame. `detail` also fills the field list.
pub fn decode(lt: i32, data: &[u8], detail: bool) -> Decoded {
    let mut d = Decoded::default();
    let pkt = match slice(lt, data) {
        Ok(p) => p,
        Err(e) => {
            d.proto = link_name(lt)
                .map(|n| format!("{n}?"))
                .unwrap_or_else(|| format!("linktype {lt}"));
            d.info = e.clone();
            d.malformed = Some(e);
            return d;
        }
    };
    let fl = &mut d.fields;
    if let Some(LinkSlice::Ethernet2(e)) = &pkt.link {
        d.src = mac(e.source());
        d.dst = mac(e.destination());
        f(fl, detail, "Ethernet", "Source", mac(e.source()));
        f(fl, detail, "Ethernet", "Destination", mac(e.destination()));
        f(
            fl,
            detail,
            "Ethernet",
            "Type",
            format!("0x{:04x}", e.ether_type().0),
        );
    }
    for ext in &pkt.link_exts {
        if let LaxLinkExtSlice::Vlan(v) = ext {
            f(fl, detail, "802.1Q", "VLAN", v.vlan_identifier().value());
        }
    }
    let mut ether_type = match &pkt.link {
        Some(LinkSlice::Ethernet2(e)) => Some(e.ether_type().0),
        _ => None,
    };
    if let Some(LaxLinkExtSlice::Vlan(v)) = pkt.link_exts.last() {
        ether_type = Some(v.ether_type().0);
    }

    let ip_payload: Option<(u8, &[u8], bool)>;
    match &pkt.net {
        Some(LaxNetSlice::Ipv4(v4)) => {
            let h = v4.header();
            let (s, t) = (h.source_addr(), h.destination_addr());
            d.src = s.to_string();
            d.dst = t.to_string();
            d.ips = Some((IpAddr::V4(s), IpAddr::V4(t)));
            d.proto = "IPv4".into();
            let p = v4.payload();
            ip_payload = Some((p.ip_number.0, p.payload, p.fragmented));
            f(fl, detail, "IPv4", "Source", s);
            f(fl, detail, "IPv4", "Destination", t);
            f(fl, detail, "IPv4", "TTL", h.ttl());
            f(fl, detail, "IPv4", "Protocol", p.ip_number.0);
            f(fl, detail, "IPv4", "Total length", h.total_len());
            f(fl, detail, "IPv4", "Identification", h.identification());
            f(
                fl,
                detail,
                "IPv4",
                "Flags",
                format!(
                    "{}{}",
                    if h.dont_fragment() { "DF " } else { "" },
                    if h.more_fragments() { "MF" } else { "" }
                )
                .trim()
                .to_string(),
            );
            if p.fragmented {
                f(
                    fl,
                    detail,
                    "IPv4",
                    "Fragment offset",
                    h.fragments_offset().value(),
                );
            }
            if p.incomplete {
                d.malformed =
                    Some("IPv4 payload shorter than the header says (capture truncated?)".into());
            }
        }
        Some(LaxNetSlice::Ipv6(v6)) => {
            let h = v6.header();
            let (s, t) = (h.source_addr(), h.destination_addr());
            d.src = s.to_string();
            d.dst = t.to_string();
            d.ips = Some((IpAddr::V6(s), IpAddr::V6(t)));
            d.proto = "IPv6".into();
            let p = v6.payload();
            ip_payload = Some((p.ip_number.0, p.payload, p.fragmented));
            f(fl, detail, "IPv6", "Source", s);
            f(fl, detail, "IPv6", "Destination", t);
            f(fl, detail, "IPv6", "Hop limit", h.hop_limit());
            f(fl, detail, "IPv6", "Next header", p.ip_number.0);
        }
        Some(LaxNetSlice::Arp(a)) => {
            arp(a.slice(), &mut d);
            return d;
        }
        None => {
            // Not IP: name the EtherType when we know it.
            let (name, info) = match ether_type {
                Some(0x88cc) => ("LLDP", "LLDP (not decoded here)"),
                Some(0x8100) | Some(0x88a8) => ("VLAN", "VLAN-tagged frame"),
                Some(0x888e) => ("EAPOL", "802.1X EAPOL (not decoded here)"),
                Some(0x8809) => ("LACP", "Slow protocols / LACP (not decoded here)"),
                Some(0x8863) | Some(0x8864) => ("PPPoE", "PPPoE (not decoded here)"),
                Some(0x8847) | Some(0x8848) => ("MPLS", "MPLS (not decoded here)"),
                Some(t) if t < 0x0600 => (
                    "802.3",
                    "802.3 frame with length field (LLC, STP, CDP: not decoded here)",
                ),
                _ => ("Ethernet", "unsupported EtherType (not decoded here)"),
            };
            d.proto = name.into();
            d.info = match ether_type {
                Some(t) => format!("{info}, 0x{t:04x}"),
                None => info.into(),
            };
            if let Some((e, _)) = &pkt.stop_err {
                d.malformed = Some(e.to_string());
            }
            return d;
        }
    }

    let Some((ipn, payload, fragmented)) = ip_payload else {
        return d;
    };
    match &pkt.transport {
        Some(TransportSlice::Tcp(t)) => {
            let (sp, dp) = (t.source_port(), t.destination_port());
            let mut flags = 0u8;
            for (on, b) in [
                (t.fin(), 0x01),
                (t.syn(), 0x02),
                (t.rst(), 0x04),
                (t.psh(), 0x08),
                (t.ack(), 0x10),
                (t.urg(), 0x20),
            ] {
                if on {
                    flags |= b;
                }
            }
            d.tcp_flags = flags;
            d.l4 = Some((6, sp, dp));
            let pl = t.payload();
            let app = port_name(dp, false).or_else(|| port_name(sp, false));
            d.proto = app.map(str::to_string).unwrap_or_else(|| "TCP".into());
            d.info = format!(
                "{sp} > {dp} [{}] seq={} ack={} win={} len={}",
                tcp_flag_text(flags),
                t.sequence_number(),
                t.acknowledgment_number(),
                t.window_size(),
                pl.len()
            );
            if let Some((label, enc)) = tls_label(pl) {
                d.proto = "TLS".into();
                d.info = format!("{label}  ({sp} > {dp})");
                d.encrypted = enc;
            } else if let Some(line) = http_line(pl) {
                d.proto = "HTTP".into();
                d.info = line;
            } else if (sp == 53 || dp == 53) && pl.len() > 2 {
                d.dns = dns(&pl[2..]);
            } else if matches!(app, Some("SSH" | "RDP" | "LDAPS" | "DNS over TLS"))
                && !pl.is_empty()
            {
                d.encrypted = true;
            }
            f(fl, detail, "TCP", "Source port", sp);
            f(fl, detail, "TCP", "Destination port", dp);
            f(fl, detail, "TCP", "Flags", tcp_flag_text(flags));
            f(fl, detail, "TCP", "Sequence", t.sequence_number());
            f(
                fl,
                detail,
                "TCP",
                "Acknowledgment",
                t.acknowledgment_number(),
            );
            f(fl, detail, "TCP", "Window", t.window_size());
            f(fl, detail, "TCP", "Payload length", pl.len());
        }
        Some(TransportSlice::Udp(u)) => {
            let (sp, dp) = (u.source_port(), u.destination_port());
            d.l4 = Some((17, sp, dp));
            let pl = u.payload();
            let app = port_name(dp, true).or_else(|| port_name(sp, true));
            d.proto = app.map(str::to_string).unwrap_or_else(|| "UDP".into());
            d.info = format!("{sp} > {dp} len={}", pl.len());
            if matches!(app, Some("DNS" | "mDNS")) {
                d.dns = dns(pl);
            } else if app == Some("QUIC") {
                d.info = format!("QUIC (encrypted)  {sp} > {dp} len={}", pl.len());
                d.encrypted = true;
            } else if app == Some("IPsec NAT-T") && pl.len() > 4 && pl[..4] != [0, 0, 0, 0] {
                d.info = format!("ESP in UDP (encrypted)  {sp} > {dp}");
                d.encrypted = true;
            }
            f(fl, detail, "UDP", "Source port", sp);
            f(fl, detail, "UDP", "Destination port", dp);
            f(fl, detail, "UDP", "Payload length", pl.len());
        }
        Some(TransportSlice::Icmpv4(i)) => {
            d.proto = "ICMP".into();
            d.info = icmp4_text(i.type_u8(), i.code_u8());
            d.l4 = Some((1, 0, 0));
            f(fl, detail, "ICMP", "Type", i.type_u8());
            f(fl, detail, "ICMP", "Code", i.code_u8());
        }
        Some(TransportSlice::Icmpv6(i)) => {
            d.proto = "ICMPv6".into();
            d.info = icmp6_text(i.type_u8(), i.code_u8());
            d.l4 = Some((58, 0, 0));
            f(fl, detail, "ICMPv6", "Type", i.type_u8());
            f(fl, detail, "ICMPv6", "Code", i.code_u8());
        }
        _ => {
            d.l4 = Some((ipn, 0, 0));
            let (name, info, enc) = match ipn {
                50 => ("ESP", "IPsec ESP (encrypted)", true),
                51 => ("AH", "IPsec AH", false),
                47 => ("GRE", "GRE (inner packet not decoded here)", false),
                89 => ("OSPF", "OSPF (not decoded here)", false),
                112 => ("VRRP", "VRRP (not decoded here)", false),
                2 => ("IGMP", "IGMP", false),
                132 => ("SCTP", "SCTP (not decoded here)", false),
                _ => ("IP", "IP protocol not decoded here", false),
            };
            d.proto = name.into();
            d.info = if fragmented {
                format!("{info}, fragment")
            } else {
                format!("{info} (protocol {ipn})")
            };
            d.encrypted = enc;
            if ipn == 6 || ipn == 17 {
                d.info = format!(
                    "{} segment, too short or fragmented to decode",
                    if ipn == 6 { "TCP" } else { "UDP" }
                );
            }
        }
    }
    if let Some(info) = &d.dns {
        let q = info
            .questions
            .first()
            .map(|(n, t)| format!("{t} {n}"))
            .unwrap_or_default();
        d.proto = "DNS".into();
        d.info = if info.response {
            format!("response {q} {} ({} answers)", info.rcode, info.answers)
        } else {
            format!("query {q}")
        };
    }
    if d.malformed.is_none()
        && let Some((e, _)) = &pkt.stop_err
    {
        d.malformed = Some(e.to_string());
    }
    let _ = payload;
    d
}

/// Hex dump: offset, 16 bytes, ASCII.
pub fn hexdump(b: &[u8]) -> String {
    b.chunks(16)
        .enumerate()
        .map(|(i, c)| {
            let h: Vec<String> = c.iter().map(|x| format!("{x:02x}")).collect();
            let a: String = c
                .iter()
                .map(|&x| {
                    if (0x20..0x7f).contains(&x) {
                        x as char
                    } else {
                        '.'
                    }
                })
                .collect();
            format!("{:04x}  {:<47}  {a}", i * 16, h.join(" "))
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use etherparse::PacketBuilder;

    #[test]
    fn arp_icmp6_vlan_and_encrypted() {
        // ARP request.
        let mut f = vec![0xffu8; 6];
        f.extend_from_slice(&[0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x08, 0x06]);
        f.extend_from_slice(&[
            0, 1, 8, 0, 6, 4, 0, 1, 0, 0x11, 0x22, 0x33, 0x44, 0x55, 10, 0, 0, 1, 0, 0, 0, 0, 0, 0,
            10, 0, 0, 9,
        ]);
        let d = decode(1, &f, false);
        assert_eq!(d.proto, "ARP");
        assert_eq!(d.info, "Who has 10.0.0.9? Tell 10.0.0.1");
        // ICMPv6 echo over IPv6.
        let mut v6 = Vec::new();
        PacketBuilder::ethernet2([1; 6], [2; 6])
            .ipv6(
                [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
                64,
            )
            .icmpv6_echo_request(1, 1)
            .write(&mut v6, b"ping")
            .unwrap();
        let d = decode(1, &v6, true);
        assert_eq!(
            (d.proto.as_str(), d.info.as_str()),
            ("ICMPv6", "echo request")
        );
        assert_eq!(d.src, "2001:db8::1");
        // VLAN-tagged UDP.
        let mut tagged = Vec::new();
        PacketBuilder::ethernet2([1; 6], [2; 6])
            .single_vlan(etherparse::VlanId::try_new(42).unwrap())
            .ipv4([10, 0, 0, 1], [10, 0, 0, 2], 64)
            .udp(500, 500)
            .write(&mut tagged, b"ike")
            .unwrap();
        let d = decode(1, &tagged, true);
        assert_eq!(d.proto, "IKE");
        assert!(
            d.fields
                .iter()
                .any(|f| f.layer == "802.1Q" && f.value == "42")
        );
        // QUIC and ESP are labelled encrypted.
        let mut q = Vec::new();
        PacketBuilder::ethernet2([1; 6], [2; 6])
            .ipv4([10, 0, 0, 1], [10, 0, 0, 2], 64)
            .udp(55555, 443)
            .write(&mut q, &[0xc0; 40])
            .unwrap();
        assert!(decode(1, &q, false).encrypted);
    }

    #[test]
    fn raw_ip_and_unknown_links() {
        let mut ip = Vec::new();
        PacketBuilder::ipv4([10, 0, 0, 1], [10, 0, 0, 2], 64)
            .udp(123, 123)
            .write(&mut ip, &[0u8; 48])
            .unwrap();
        assert_eq!(decode(101, &ip, false).proto, "NTP");
        let mut lo = 2u32.to_le_bytes().to_vec();
        lo.extend_from_slice(&ip);
        assert_eq!(decode(0, &lo, false).proto, "NTP");
        let d = decode(147, &ip, false);
        assert!(d.malformed.is_some() && d.info.contains("not decoded"));
        assert!(decode(1, &[1, 2, 3], false).malformed.is_some());
    }

    #[test]
    fn hostile_tls_does_not_panic() {
        let mut p = vec![22, 3, 1, 0xff, 0xff, 1];
        p.extend_from_slice(&[0xff; 60]);
        assert!(tls_sni(&p).is_none());
        for n in 0..60 {
            let _ = tls_sni(&p[..n]);
            let _ = tls_label(&p[..n]);
        }
    }
}
