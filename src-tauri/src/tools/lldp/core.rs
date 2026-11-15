//! LLDP (IEEE 802.1AB) and CDP decoding: find the discovery frame in an
//! Ethernet or Linux cooked capture frame, read its TLVs into a neighbor
//! record, and merge repeated announcements. Pure logic, no I/O except the
//! capture file reader, which streams with a bounded buffer.
//!
//! All input is hostile: every read is bounds-checked, strings are capped,
//! and list fields have a maximum length.

use std::collections::HashMap;
use std::io::Read;
use std::net::{Ipv4Addr, Ipv6Addr};

use pcap_parser::{Block, PcapBlockOwned, PcapError, create_reader};
use serde::Serialize;

/// LLDP EtherType.
pub const ETH_LLDP: u16 = 0x88cc;
/// CDP destination MAC (Cisco multicast).
pub const CDP_MAC: [u8; 6] = [0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcc];
/// LLC/SNAP header in front of a CDP payload: DSAP, SSAP, control, OUI, PID.
const CDP_SNAP: [u8; 8] = [0xaa, 0xaa, 0x03, 0x00, 0x00, 0x0c, 0x20, 0x00];

/// Longest string kept from any TLV, in characters.
const MAX_STR: usize = 512;
/// Most entries kept in list fields (VLANs, addresses, notes).
const MAX_LIST: usize = 64;
/// Most distinct neighbors tracked; more are counted, not stored.
pub const MAX_NEIGHBORS: usize = 256;

/// Link types the decoder understands.
pub const LINK_ETHERNET: i32 = 1;
pub const LINK_SLL: i32 = 113;
pub const LINK_SLL2: i32 = 276;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Protocol {
    #[serde(rename = "LLDP")]
    Lldp,
    #[serde(rename = "CDP")]
    Cdp,
}

/// One neighbor as announced: what the switch (or phone, AP, router) says
/// about itself and the port it sent from.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Neighbor {
    pub protocol: Option<Protocol>,
    /// Source MAC of the frame.
    pub source_mac: String,
    pub chassis_id: String,
    pub chassis_id_type: String,
    pub port_id: String,
    pub port_id_type: String,
    pub port_description: String,
    pub system_name: String,
    pub system_description: String,
    /// Capabilities the device has, and those enabled (LLDP) or advertised (CDP).
    pub capabilities: Vec<String>,
    pub enabled_capabilities: Vec<String>,
    pub management: Vec<String>,
    /// Hold time, seconds.
    pub ttl: Option<u16>,
    /// Untagged VLAN for this port (802.1 PVID, or CDP native VLAN).
    pub port_vlan: Option<u16>,
    /// VLAN names (802.1 TLV): id and name.
    pub vlans: Vec<VlanName>,
    /// Voice VLAN (LLDP-MED network policy, or CDP appliance VLAN).
    pub voice_vlan: Option<u16>,
    /// Voice VLAN detail: tagged, 802.1p priority, DSCP.
    pub voice_policy: String,
    /// Maximum frame size (802.3) or CDP MTU.
    pub mtu: Option<u32>,
    /// Speed/duplex and autonegotiation (802.3 MAC/PHY, or CDP duplex).
    pub link: String,
    /// Power over Ethernet summary.
    pub poe: String,
    pub platform: String,
    /// LLDP-MED inventory and CDP software version, as label/value pairs.
    pub inventory: Vec<Field>,
    /// TLVs that were malformed or not decoded.
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VlanName {
    pub id: u16,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Field {
    pub label: String,
    pub value: String,
}

impl Neighbor {
    /// Identity used to merge repeated announcements.
    pub fn key(&self) -> String {
        format!(
            "{:?}|{}|{}|{}",
            self.protocol, self.chassis_id, self.port_id, self.source_mac
        )
    }

    fn note(&mut self, s: impl Into<String>) {
        if self.notes.len() < MAX_LIST {
            self.notes.push(s.into());
        }
    }
}

/// A discovery payload found in a frame.
#[derive(Debug, PartialEq, Eq)]
pub struct Found<'a> {
    pub protocol: Protocol,
    pub source_mac: [u8; 6],
    pub payload: &'a [u8],
}

fn u16_at(b: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(i)?, *b.get(i + 1)?]))
}

fn u32_at(b: &[u8], i: usize) -> Option<u32> {
    Some(u32::from_be_bytes(b.get(i..i + 4)?.try_into().ok()?))
}

fn mac6(b: &[u8]) -> Option<[u8; 6]> {
    b.get(..6)?.try_into().ok()
}

pub fn fmt_mac(m: &[u8]) -> String {
    m.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Printable text from a TLV value, capped and stripped of control characters.
fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b)
        .chars()
        .map(|c| if c.is_control() && c != '\n' { ' ' } else { c })
        .take(MAX_STR)
        .collect::<String>()
        .trim()
        .to_string()
}

/// Find an LLDP or CDP payload in a captured frame of the given link type.
pub fn find(link: i32, frame: &[u8]) -> Option<Found<'_>> {
    match link {
        LINK_ETHERNET => find_ethernet(frame),
        LINK_SLL => {
            // 16 bytes: packet type, ARPHRD, address length, address (8), protocol.
            let alen = u16_at(frame, 4)? as usize;
            let src = if alen == 6 {
                mac6(frame.get(6..)?)?
            } else {
                [0; 6]
            };
            let proto = u16_at(frame, 14)?;
            payload_after(proto, src, frame.get(16..)?)
        }
        LINK_SLL2 => {
            // 20 bytes: protocol, reserved, ifindex, ARPHRD, packet type,
            // address length, address (8).
            let proto = u16_at(frame, 0)?;
            let alen = *frame.get(11)? as usize;
            let src = if alen == 6 {
                mac6(frame.get(12..)?)?
            } else {
                [0; 6]
            };
            payload_after(proto, src, frame.get(20..)?)
        }
        _ => None,
    }
}

/// After a cooked header: LLDP by EtherType, CDP as an 802.2 LLC frame
/// (protocol 0x0004) carrying the Cisco SNAP header.
fn payload_after(proto: u16, src: [u8; 6], rest: &[u8]) -> Option<Found<'_>> {
    match proto {
        ETH_LLDP => Some(Found {
            protocol: Protocol::Lldp,
            source_mac: src,
            payload: rest,
        }),
        0x0004 if rest.starts_with(&CDP_SNAP) => Some(Found {
            protocol: Protocol::Cdp,
            source_mac: src,
            payload: &rest[CDP_SNAP.len()..],
        }),
        _ => None,
    }
}

fn find_ethernet(frame: &[u8]) -> Option<Found<'_>> {
    let dst = mac6(frame)?;
    let src = mac6(frame.get(6..)?)?;
    let mut off = 12;
    let mut tl = u16_at(frame, off)?;
    // Skip up to two VLAN tags (802.1Q, 802.1ad).
    for _ in 0..2 {
        if tl == 0x8100 || tl == 0x88a8 {
            off += 4;
            tl = u16_at(frame, off)?;
        }
    }
    let body = frame.get(off + 2..)?;
    if tl == ETH_LLDP {
        return Some(Found {
            protocol: Protocol::Lldp,
            source_mac: src,
            payload: body,
        });
    }
    // 802.3 length field, then LLC/SNAP for CDP.
    if tl <= 1500 && dst == CDP_MAC && body.starts_with(&CDP_SNAP) {
        let end = (tl as usize).min(body.len());
        return Some(Found {
            protocol: Protocol::Cdp,
            source_mac: src,
            payload: body.get(CDP_SNAP.len()..end)?,
        });
    }
    None
}

/// Decode a discovery payload into a neighbor.
pub fn decode(f: &Found<'_>) -> Neighbor {
    let mut n = Neighbor {
        protocol: Some(f.protocol),
        source_mac: fmt_mac(&f.source_mac),
        ..Default::default()
    };
    match f.protocol {
        Protocol::Lldp => decode_lldp(f.payload, &mut n),
        Protocol::Cdp => decode_cdp(f.payload, &mut n),
    }
    n
}

const LLDP_CAPS: [(u16, &str); 11] = [
    (0x0001, "Other"),
    (0x0002, "Repeater"),
    (0x0004, "Bridge"),
    (0x0008, "WLAN AP"),
    (0x0010, "Router"),
    (0x0020, "Telephone"),
    (0x0040, "DOCSIS"),
    (0x0080, "Station"),
    (0x0100, "C-VLAN"),
    (0x0200, "S-VLAN"),
    (0x0400, "TPMR"),
];

fn cap_names<T: Copy + Into<u32>>(bits: T, table: &[(T, &str)]) -> Vec<String> {
    let b: u32 = bits.into();
    table
        .iter()
        .filter(|(m, _)| b & (*m).into() != 0)
        .map(|(_, s)| s.to_string())
        .collect()
}

/// An address with an IANA address family number (LLDP management address,
/// network-address chassis/port IDs).
fn family_addr(af: u8, b: &[u8]) -> String {
    match (af, b.len()) {
        (1, 4) => Ipv4Addr::new(b[0], b[1], b[2], b[3]).to_string(),
        (2, 16) => {
            let a: [u8; 16] = b.try_into().unwrap_or([0; 16]);
            Ipv6Addr::from(a).to_string()
        }
        (6, 6) => fmt_mac(b),
        _ => format!("family {af}: {}", fmt_mac(b)),
    }
}

fn chassis_or_port_id(kind: &str, sub: u8, v: &[u8]) -> (String, String) {
    // Chassis subtypes: 1 chassis component, 2 interface alias, 3 port
    // component, 4 MAC, 5 network address, 6 interface name, 7 local.
    // Port subtypes: 1 interface alias, 2 port component, 3 MAC, 4 network
    // address, 5 interface name, 6 agent circuit ID, 7 local.
    let (mac, net) = if kind == "chassis" { (4, 5) } else { (3, 4) };
    let label = match (kind, sub) {
        ("chassis", 1) => "chassis component",
        ("chassis", 2) | ("port", 1) => "interface alias",
        ("chassis", 3) | ("port", 2) => "port component",
        ("chassis", 6) | ("port", 5) => "interface name",
        ("port", 6) => "agent circuit ID",
        (_, 7) => "locally assigned",
        _ if sub == mac => "MAC address",
        _ if sub == net => "network address",
        _ => "unknown subtype",
    };
    let value = if sub == mac && v.len() == 6 {
        fmt_mac(v)
    } else if sub == net && !v.is_empty() {
        family_addr(v[0], &v[1..])
    } else {
        text(v)
    };
    (value, label.to_string())
}

fn decode_lldp(p: &[u8], n: &mut Neighbor) {
    let mut i = 0usize;
    while i + 2 <= p.len() {
        let h = u16_at(p, i).unwrap_or(0);
        let ty = (h >> 9) as u8;
        let len = (h & 0x01ff) as usize;
        i += 2;
        let Some(v) = p.get(i..i + len) else {
            n.note(format!("TLV {ty} truncated"));
            return;
        };
        i += len;
        match ty {
            0 => return,
            1 if !v.is_empty() => {
                (n.chassis_id, n.chassis_id_type) = chassis_or_port_id("chassis", v[0], &v[1..]);
            }
            2 if !v.is_empty() => {
                (n.port_id, n.port_id_type) = chassis_or_port_id("port", v[0], &v[1..]);
            }
            3 => n.ttl = u16_at(v, 0),
            4 => n.port_description = text(v),
            5 => n.system_name = text(v),
            6 => n.system_description = text(v),
            7 => {
                if let (Some(sup), Some(en)) = (u16_at(v, 0), u16_at(v, 2)) {
                    n.capabilities = cap_names(sup, &LLDP_CAPS);
                    n.enabled_capabilities = cap_names(en, &LLDP_CAPS);
                }
            }
            8 => {
                // Length of (subtype + address), subtype, address, ...
                let alen = *v.first().unwrap_or(&0) as usize;
                if alen >= 2
                    && let Some(a) = v.get(2..1 + alen)
                    && n.management.len() < MAX_LIST
                {
                    n.management.push(family_addr(v[1], a));
                }
            }
            127 if v.len() >= 4 => decode_org(&v[..3], v[3], &v[4..], n),
            _ => {}
        }
    }
}

fn decode_org(oui: &[u8], sub: u8, v: &[u8], n: &mut Neighbor) {
    match (oui, sub) {
        // IEEE 802.1
        ([0x00, 0x80, 0xc2], 1) => n.port_vlan = u16_at(v, 0).filter(|&x| x != 0),
        ([0x00, 0x80, 0xc2], 3) => {
            if let (Some(id), Some(&l)) = (u16_at(v, 0), v.get(2))
                && let Some(name) = v.get(3..3 + l as usize)
                && n.vlans.len() < MAX_LIST
            {
                n.vlans.push(VlanName {
                    id,
                    name: text(name),
                });
            }
        }
        // IEEE 802.3
        ([0x00, 0x12, 0x0f], 1) => {
            if let (Some(&an), Some(mau)) = (v.first(), u16_at(v, 3)) {
                let auto = match (an & 1 != 0, an & 2 != 0) {
                    (_, true) => "autoneg on",
                    (true, false) => "autoneg supported, off",
                    _ => "autoneg not supported",
                };
                n.link = format!("{}, {auto}", mau_name(mau));
            }
        }
        ([0x00, 0x12, 0x0f], 2) => n.poe = poe_8023(v),
        ([0x00, 0x12, 0x0f], 4) => n.mtu = u16_at(v, 0).map(u32::from),
        // TIA LLDP-MED
        ([0x00, 0x12, 0xbb], 2) => {
            // Application type, then U/T/X flags, 12-bit VLAN, priority, DSCP.
            if let (Some(&app), Some(bits)) = (v.first(), v.get(1..4)) {
                let w = u32::from_be_bytes([0, bits[0], bits[1], bits[2]]);
                let unknown = w & 0x80_0000 != 0;
                let tagged = w & 0x40_0000 != 0;
                let vlan = ((w >> 9) & 0x0fff) as u16;
                let prio = (w >> 6) & 0x7;
                let dscp = w & 0x3f;
                if app == 1 && !unknown {
                    n.voice_vlan = Some(vlan);
                    n.voice_policy = format!(
                        "{}, priority {prio}, DSCP {dscp}",
                        if tagged { "tagged" } else { "untagged" }
                    );
                }
            }
        }
        ([0x00, 0x12, 0xbb], 4) => {
            // Extended power: type/source/priority, then power in 0.1 W.
            if let Some(p) = u16_at(v, 1)
                && n.poe.is_empty()
            {
                n.poe = format!("LLDP-MED: {:.1} W", p as f64 / 10.0);
            }
        }
        ([0x00, 0x12, 0xbb], s @ 5..=11) => {
            let label = match s {
                5 => "Hardware revision",
                6 => "Firmware revision",
                7 => "Software revision",
                8 => "Serial number",
                9 => "Manufacturer",
                10 => "Model",
                _ => "Asset ID",
            };
            let value = text(v);
            if !value.is_empty() && n.inventory.len() < MAX_LIST {
                n.inventory.push(Field {
                    label: label.into(),
                    value,
                });
            }
        }
        _ => {}
    }
}

/// Common ifMauType values (RFC 4836). Others are shown by number.
fn mau_name(m: u16) -> String {
    match m {
        10 => "10BASE-T half duplex".into(),
        11 => "10BASE-T full duplex".into(),
        15 => "100BASE-TX half duplex".into(),
        16 => "100BASE-TX full duplex".into(),
        29 => "1000BASE-T half duplex".into(),
        30 => "1000BASE-T full duplex".into(),
        0 => "MAU type not given".into(),
        other => format!("MAU type {other}"),
    }
}

fn poe_8023(v: &[u8]) -> String {
    let Some(&mdi) = v.first() else {
        return String::new();
    };
    let class = v.get(2).map(|c| c.saturating_sub(1));
    let mut s = format!(
        "{}{}",
        if mdi & 0x01 != 0 { "PSE" } else { "PD" },
        if mdi & 0x04 != 0 {
            ", enabled"
        } else {
            ", disabled"
        }
    );
    if let Some(c) = class {
        s.push_str(&format!(", class {c}"));
    }
    // 802.3at extension: type/source/priority, requested and allocated power
    // in 0.1 W.
    if let (Some(req), Some(alloc)) = (u16_at(v, 4), u16_at(v, 6)) {
        s.push_str(&format!(
            ", requested {:.1} W, allocated {:.1} W",
            req as f64 / 10.0,
            alloc as f64 / 10.0
        ));
    }
    s
}

const CDP_CAPS: [(u32, &str); 11] = [
    (0x001, "Router"),
    (0x002, "Transparent bridge"),
    (0x004, "Source-route bridge"),
    (0x008, "Switch"),
    (0x010, "Host"),
    (0x020, "IGMP"),
    (0x040, "Repeater"),
    (0x080, "Phone"),
    (0x100, "Remotely managed"),
    (0x200, "CVTA"),
    (0x400, "Two-port MAC relay"),
];

/// CDP address list: count, then (protocol type, protocol length, protocol,
/// address length, address) entries.
fn cdp_addresses(v: &[u8], out: &mut Vec<String>) {
    let Some(count) = u32_at(v, 0) else { return };
    let mut i = 4usize;
    for _ in 0..count.min(MAX_LIST as u32) {
        let (Some(&pt), Some(&pl)) = (v.get(i), v.get(i + 1)) else {
            return;
        };
        let proto = v.get(i + 2..i + 2 + pl as usize);
        i += 2 + pl as usize;
        let Some(al) = u16_at(v, i) else { return };
        i += 2;
        let Some(addr) = v.get(i..i + al as usize) else {
            return;
        };
        i += al as usize;
        let s = match (pt, proto, addr.len()) {
            (1, Some([0xcc]), 4) => Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]).to_string(),
            (2, Some([.., 0x86, 0xdd]), 16) => {
                let a: [u8; 16] = addr.try_into().unwrap_or([0; 16]);
                Ipv6Addr::from(a).to_string()
            }
            _ => continue,
        };
        if out.len() < MAX_LIST && !out.contains(&s) {
            out.push(s);
        }
    }
}

fn decode_cdp(p: &[u8], n: &mut Neighbor) {
    // Version, TTL, checksum, then TLVs (type, length including header).
    let (Some(&ver), Some(&ttl)) = (p.first(), p.get(1)) else {
        n.note("CDP header truncated");
        return;
    };
    if ver != 1 && ver != 2 {
        n.note(format!("CDP version {ver}"));
    }
    n.ttl = Some(ttl as u16);
    n.chassis_id_type = "device ID".into();
    n.port_id_type = "interface name".into();
    let mut i = 4usize;
    while i + 4 <= p.len() {
        let ty = u16_at(p, i).unwrap_or(0);
        let len = u16_at(p, i + 2).unwrap_or(0) as usize;
        if len < 4 {
            n.note(format!("CDP TLV {ty:#06x} has bad length {len}"));
            return;
        }
        let Some(v) = p.get(i + 4..i + len) else {
            n.note(format!("CDP TLV {ty:#06x} truncated"));
            return;
        };
        i += len;
        match ty {
            0x0001 => n.chassis_id = text(v),
            0x0002 | 0x0016 => cdp_addresses(v, &mut n.management),
            0x0003 => n.port_id = text(v),
            0x0004 => {
                if let Some(c) = u32_at(v, 0) {
                    n.capabilities = cap_names(c, &CDP_CAPS);
                    n.enabled_capabilities = n.capabilities.clone();
                }
            }
            0x0005 => {
                let s = text(v);
                if n.system_description.is_empty() {
                    n.system_description = s.clone();
                }
                if let Some(first) = s.lines().next()
                    && n.inventory.len() < MAX_LIST
                {
                    n.inventory.push(Field {
                        label: "Software".into(),
                        value: first.trim().to_string(),
                    });
                }
            }
            0x0006 => n.platform = text(v),
            0x0009 => {
                let s = text(v);
                if !s.is_empty() && n.inventory.len() < MAX_LIST {
                    n.inventory.push(Field {
                        label: "VTP domain".into(),
                        value: s,
                    });
                }
            }
            0x000a => n.port_vlan = u16_at(v, 0),
            0x000b => {
                n.link = match v.first() {
                    Some(1) => "full duplex".into(),
                    Some(0) => "half duplex".into(),
                    _ => String::new(),
                }
            }
            0x000e => n.voice_vlan = u16_at(v, 1),
            0x0010 => {
                if let Some(mw) = u16_at(v, 0) {
                    n.poe = format!("{:.1} W", mw as f64 / 1000.0);
                }
            }
            0x0011 => n.mtu = u32_at(v, 0),
            0x0014 => n.system_name = text(v),
            _ => {}
        }
    }
}

/// Neighbors seen so far, in first-seen order, with repeat counts.
#[derive(Debug, Default)]
pub struct Tracker {
    order: Vec<String>,
    seen: HashMap<String, Seen>,
    /// Frames from neighbors beyond the cap.
    pub dropped: u64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Seen {
    pub neighbor: Neighbor,
    pub first_ms: i64,
    pub last_ms: i64,
    pub count: u64,
}

impl Tracker {
    /// Record an announcement. Returns the updated entry, or None when the
    /// neighbor cap is reached.
    pub fn record(&mut self, n: Neighbor, at_ms: i64) -> Option<&Seen> {
        let key = n.key();
        if !self.seen.contains_key(&key) {
            if self.order.len() >= MAX_NEIGHBORS {
                self.dropped += 1;
                return None;
            }
            self.order.push(key.clone());
        }
        let e = self.seen.entry(key).or_insert_with(|| Seen {
            neighbor: n.clone(),
            first_ms: at_ms,
            last_ms: at_ms,
            count: 0,
        });
        e.neighbor = n;
        e.last_ms = at_ms;
        e.count += 1;
        Some(e)
    }

    pub fn list(&self) -> Vec<Seen> {
        self.order
            .iter()
            .filter_map(|k| self.seen.get(k).cloned())
            .collect()
    }
}

/// Result of reading a capture file.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FileResult {
    pub format: String,
    pub packets: u64,
    pub frames: u64,
    pub neighbors: Vec<Seen>,
    pub warnings: Vec<String>,
}

/// Scan a PCAP or PCAPNG stream for LLDP and CDP frames.
pub fn read_capture<R: Read + Send>(input: R) -> Result<FileResult, String> {
    let mut reader = create_reader(1 << 20, input).map_err(|e| match e {
        PcapError::HeaderNotRecognized => "not a PCAP or PCAPNG file".to_string(),
        other => format!("could not read the capture: {other:?}"),
    })?;
    let mut tracker = Tracker::default();
    let mut format = "PCAP".to_string();
    let mut legacy_link = LINK_ETHERNET;
    let mut legacy_ns = false;
    let mut iface_links: Vec<(i32, u64)> = Vec::new();
    let mut packets = 0u64;
    let mut frames = 0u64;
    let mut other_links: Vec<i32> = Vec::new();
    let mut warnings = Vec::new();
    loop {
        match reader.next() {
            Ok((len, block)) => {
                let pkt: Option<(i32, i64, &[u8])> = match &block {
                    PcapBlockOwned::LegacyHeader(h) => {
                        legacy_link = h.network.0;
                        legacy_ns = h.is_nanosecond_precision();
                        None
                    }
                    PcapBlockOwned::Legacy(b) => {
                        let sub = if legacy_ns {
                            b.ts_usec as i64 / 1_000_000
                        } else {
                            b.ts_usec as i64 / 1000
                        };
                        Some((legacy_link, b.ts_sec as i64 * 1000 + sub, b.data))
                    }
                    PcapBlockOwned::NG(Block::SectionHeader(_)) => {
                        format = "PCAPNG".into();
                        iface_links.clear();
                        None
                    }
                    PcapBlockOwned::NG(Block::InterfaceDescription(idb)) => {
                        let res = idb.ts_resolution().unwrap_or(1_000_000).max(1);
                        iface_links.push((idb.linktype.0, res));
                        None
                    }
                    PcapBlockOwned::NG(Block::EnhancedPacket(epb)) => {
                        iface_links.get(epb.if_id as usize).map(|&(link, res)| {
                            let units = ((epb.ts_high as u128) << 32) | epb.ts_low as u128;
                            let ms = (units * 1000 / res as u128) as i64;
                            (link, ms, epb.data)
                        })
                    }
                    PcapBlockOwned::NG(Block::SimplePacket(spb)) => {
                        iface_links.first().map(|&(link, _)| (link, 0, spb.data))
                    }
                    _ => None,
                };
                if let Some((link, ms, data)) = pkt {
                    packets += 1;
                    if !matches!(link, LINK_ETHERNET | LINK_SLL | LINK_SLL2) {
                        if !other_links.contains(&link) && other_links.len() < 8 {
                            other_links.push(link);
                        }
                    } else if let Some(f) = find(link, data) {
                        frames += 1;
                        tracker.record(decode(&f), ms);
                    }
                }
                reader.consume(len);
            }
            Err(PcapError::Eof) => break,
            Err(PcapError::Incomplete(_)) => {
                if reader.refill().is_err() {
                    warnings.push("the file ends in the middle of a packet".into());
                    break;
                }
            }
            Err(e) => {
                warnings.push(format!("stopped reading: {e:?}"));
                break;
            }
        }
    }
    if !other_links.is_empty() {
        warnings.push(format!(
            "packets with link types {other_links:?} were skipped (only Ethernet and Linux cooked captures are decoded)"
        ));
    }
    if tracker.dropped > 0 {
        warnings.push(format!(
            "more than {MAX_NEIGHBORS} neighbors; {} frames from others were not shown",
            tracker.dropped
        ));
    }
    Ok(FileResult {
        format,
        packets,
        frames,
        neighbors: tracker.list(),
        warnings,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// One LLDP TLV.
    fn tlv(ty: u8, v: &[u8]) -> Vec<u8> {
        let h = ((ty as u16) << 9) | v.len() as u16;
        let mut out = h.to_be_bytes().to_vec();
        out.extend_from_slice(v);
        out
    }

    fn org(oui: [u8; 3], sub: u8, v: &[u8]) -> Vec<u8> {
        let mut b = oui.to_vec();
        b.push(sub);
        b.extend_from_slice(v);
        tlv(127, &b)
    }

    const SRC: [u8; 6] = [0x00, 0x00, 0x5e, 0x00, 0x53, 0x01];

    /// A switch port announcement: documentation MAC and addresses only.
    pub(crate) fn lldp_frame(vlan_tag: bool) -> Vec<u8> {
        let mut f = vec![0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e];
        f.extend_from_slice(&SRC);
        if vlan_tag {
            f.extend_from_slice(&[0x81, 0x00, 0x00, 0x0a]);
        }
        f.extend_from_slice(&ETH_LLDP.to_be_bytes());
        let mut chassis = vec![4];
        chassis.extend_from_slice(&SRC);
        f.extend(tlv(1, &chassis));
        f.extend(tlv(2, b"\x05GigabitEthernet1/0/12"));
        f.extend(tlv(3, &120u16.to_be_bytes()));
        f.extend(tlv(4, b"Desk 4B"));
        f.extend(tlv(5, b"access-sw1.example.net"));
        f.extend(tlv(6, b"Example switch OS 17.9"));
        f.extend(tlv(7, &[0x00, 0x14, 0x00, 0x04])); // Bridge+Router, Bridge on
        f.extend(tlv(8, &[5, 1, 192, 0, 2, 10, 2, 0, 0, 0, 12, 0]));
        f.extend(org([0x00, 0x80, 0xc2], 1, &20u16.to_be_bytes()));
        f.extend(org([0x00, 0x80, 0xc2], 3, b"\x00\x14\x05USERS"));
        f.extend(org([0x00, 0x12, 0x0f], 1, &[0x03, 0x6c, 0x01, 0x00, 30]));
        f.extend(org([0x00, 0x12, 0x0f], 4, &9216u16.to_be_bytes()));
        f.extend(org(
            [0x00, 0x12, 0x0f],
            2,
            &[0x0f, 0x01, 0x05, 0x51, 0x00, 0x82, 0x00, 0x82],
        ));
        // Voice: app 1, tagged, VLAN 30, priority 5, DSCP 46.
        let w: u32 = (1 << 22) | (30 << 9) | (5 << 6) | 46;
        let b = w.to_be_bytes();
        f.extend(org([0x00, 0x12, 0xbb], 2, &[1, b[1], b[2], b[3]]));
        f.extend(org([0x00, 0x12, 0xbb], 10, b"Model X"));
        f.extend(tlv(0, &[]));
        f
    }

    pub(crate) fn cdp_frame() -> Vec<u8> {
        let mut body = CDP_SNAP.to_vec();
        body.extend_from_slice(&[2, 180, 0, 0]);
        let t = |ty: u16, v: &[u8]| {
            let mut o = ty.to_be_bytes().to_vec();
            o.extend_from_slice(&((v.len() + 4) as u16).to_be_bytes());
            o.extend_from_slice(v);
            o
        };
        body.extend(t(0x0001, b"core-sw2.example.net"));
        let mut addrs = 1u32.to_be_bytes().to_vec();
        addrs.extend_from_slice(&[1, 1, 0xcc, 0, 4, 198, 51, 100, 7]);
        body.extend(t(0x0002, &addrs));
        body.extend(t(0x0003, b"TenGigabitEthernet1/1/1"));
        body.extend(t(0x0004, &0x28u32.to_be_bytes()));
        body.extend(t(0x0005, b"Example IOS Software, Version 17.9\nCopyright"));
        body.extend(t(0x0006, b"cisco WS-C0000"));
        body.extend(t(0x000a, &1u16.to_be_bytes()));
        body.extend(t(0x000b, &[1]));
        body.extend(t(0x000e, &[1, 0, 40]));
        let mut f = CDP_MAC.to_vec();
        f.extend_from_slice(&SRC);
        f.extend_from_slice(&(body.len() as u16).to_be_bytes());
        f.extend(body);
        f
    }

    #[test]
    fn decodes_lldp_switch_port() {
        for tagged in [false, true] {
            let frame = lldp_frame(tagged);
            let found = find(LINK_ETHERNET, &frame).expect("LLDP found");
            assert_eq!(found.protocol, Protocol::Lldp);
            let n = decode(&found);
            assert_eq!(n.chassis_id, "00:00:5e:00:53:01");
            assert_eq!(n.chassis_id_type, "MAC address");
            assert_eq!(n.port_id, "GigabitEthernet1/0/12");
            assert_eq!(n.port_id_type, "interface name");
            assert_eq!(n.ttl, Some(120));
            assert_eq!(n.port_description, "Desk 4B");
            assert_eq!(n.system_name, "access-sw1.example.net");
            assert_eq!(n.capabilities, vec!["Bridge", "Router"]);
            assert_eq!(n.enabled_capabilities, vec!["Bridge"]);
            assert_eq!(n.management, vec!["192.0.2.10"]);
            assert_eq!(n.port_vlan, Some(20));
            assert_eq!(
                n.vlans,
                vec![VlanName {
                    id: 20,
                    name: "USERS".into()
                }]
            );
            assert_eq!(n.link, "1000BASE-T full duplex, autoneg on");
            assert_eq!(n.mtu, Some(9216));
            assert!(n.poe.contains("allocated 13.0 W"), "{}", n.poe);
            assert_eq!(n.voice_vlan, Some(30));
            assert_eq!(n.voice_policy, "tagged, priority 5, DSCP 46");
            assert_eq!(n.inventory[0].value, "Model X");
            assert!(n.notes.is_empty(), "{:?}", n.notes);
        }
    }

    #[test]
    fn decodes_cdp() {
        let frame = cdp_frame();
        let found = find(LINK_ETHERNET, &frame).expect("CDP found");
        assert_eq!(found.protocol, Protocol::Cdp);
        let n = decode(&found);
        assert_eq!(n.chassis_id, "core-sw2.example.net");
        assert_eq!(n.port_id, "TenGigabitEthernet1/1/1");
        assert_eq!(n.management, vec!["198.51.100.7"]);
        assert_eq!(n.capabilities, vec!["Switch", "IGMP"]);
        assert_eq!(n.platform, "cisco WS-C0000");
        assert_eq!(n.port_vlan, Some(1));
        assert_eq!(n.voice_vlan, Some(40));
        assert_eq!(n.link, "full duplex");
        assert_eq!(n.ttl, Some(180));
        assert_eq!(n.inventory[0].value, "Example IOS Software, Version 17.9");
    }

    #[test]
    fn decodes_linux_cooked() {
        let eth = lldp_frame(false);
        let mut sll = vec![0, 2, 0, 1, 0, 6];
        sll.extend_from_slice(&SRC);
        sll.extend_from_slice(&[0, 0]);
        sll.extend_from_slice(&ETH_LLDP.to_be_bytes());
        sll.extend_from_slice(&eth[14..]);
        let n = decode(&find(LINK_SLL, &sll).unwrap());
        assert_eq!(n.system_name, "access-sw1.example.net");
        assert_eq!(n.source_mac, "00:00:5e:00:53:01");
    }

    #[test]
    fn ignores_other_traffic() {
        let mut ip = vec![0u8; 12];
        ip.extend_from_slice(&[0x08, 0x00]);
        ip.extend_from_slice(&[0x45; 40]);
        assert!(find(LINK_ETHERNET, &ip).is_none());
        assert!(find(LINK_ETHERNET, &[]).is_none());
        assert!(find(105, &lldp_frame(false)).is_none());
    }

    #[test]
    fn hostile_frames_do_not_panic() {
        let base = lldp_frame(false);
        for cut in 0..base.len() {
            if let Some(f) = find(LINK_ETHERNET, &base[..cut]) {
                let _ = decode(&f);
            }
        }
        let cdp = cdp_frame();
        for cut in 0..cdp.len() {
            if let Some(f) = find(LINK_ETHERNET, &cdp[..cut]) {
                let _ = decode(&f);
            }
        }
        // A TLV claiming more bytes than exist is noted, not read.
        let mut f = base[..14].to_vec();
        f.extend_from_slice(&[0x0a, 0xff, b'x']);
        let n = decode(&find(LINK_ETHERNET, &f).unwrap());
        assert_eq!(n.notes.len(), 1);
        // CDP TLV with a zero length stops instead of looping.
        let mut c = CDP_MAC.to_vec();
        c.extend_from_slice(&SRC);
        let mut body = CDP_SNAP.to_vec();
        body.extend_from_slice(&[2, 180, 0, 0, 0, 1, 0, 0, 0, 0]);
        c.extend_from_slice(&(body.len() as u16).to_be_bytes());
        c.extend(body);
        let n = decode(&find(LINK_ETHERNET, &c).unwrap());
        assert!(n.notes[0].contains("bad length"));
    }

    #[test]
    fn tracker_merges_and_caps() {
        let n = decode(&find(LINK_ETHERNET, &lldp_frame(false)).unwrap());
        let mut t = Tracker::default();
        t.record(n.clone(), 1);
        let e = t.record(n.clone(), 5).unwrap();
        assert_eq!((e.count, e.first_ms, e.last_ms), (2, 1, 5));
        for i in 0..MAX_NEIGHBORS + 3 {
            let mut m = n.clone();
            m.port_id = format!("port {i}");
            t.record(m, 9);
        }
        assert_eq!(t.list().len(), MAX_NEIGHBORS);
        assert!(t.dropped > 0);
    }

    /// Classic PCAP file bytes holding the given Ethernet frames.
    pub(crate) fn pcap_file(frames: &[Vec<u8>]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes());
        out.extend_from_slice(&2u16.to_le_bytes());
        out.extend_from_slice(&4u16.to_le_bytes());
        out.extend_from_slice(&[0; 8]);
        out.extend_from_slice(&65535u32.to_le_bytes());
        out.extend_from_slice(&1u32.to_le_bytes());
        for (i, f) in frames.iter().enumerate() {
            out.extend_from_slice(&(1_700_000_000u32 + i as u32 * 30).to_le_bytes());
            out.extend_from_slice(&0u32.to_le_bytes());
            out.extend_from_slice(&(f.len() as u32).to_le_bytes());
            out.extend_from_slice(&(f.len() as u32).to_le_bytes());
            out.extend_from_slice(f);
        }
        out
    }

    #[test]
    fn reads_capture_file() {
        let mut other = vec![0u8; 12];
        other.extend_from_slice(&[0x08, 0x00, 0x45, 0]);
        let file = pcap_file(&[lldp_frame(false), other, cdp_frame(), lldp_frame(false)]);
        let r = read_capture(&file[..]).unwrap();
        assert_eq!(r.format, "PCAP");
        assert_eq!(r.packets, 4);
        assert_eq!(r.frames, 3);
        assert_eq!(r.neighbors.len(), 2);
        assert_eq!(r.neighbors[0].count, 2);
        assert_eq!(r.neighbors[0].first_ms, 1_700_000_000_000);
        assert_eq!(r.neighbors[1].neighbor.protocol, Some(Protocol::Cdp));
        assert!(read_capture(&b"not a capture file at all"[..]).is_err());
    }
}
