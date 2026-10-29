//! Pure switch port mapping logic. SNMP table rows arrive as (index suffix,
//! value) pairs; this module decodes the table indexes (MACs, VLANs, IPs),
//! joins the bridge forwarding database to interfaces, and builds the port and
//! MAC views. No network here; the SNMP I/O is in `commands.rs`.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::net::Ipv4Addr;

use serde::Serialize;

/// Column OIDs read by the mapper. Each is walked; rows are keyed by the
/// index suffix after the column OID.
pub mod oids {
    pub const SYSTEM: &[u32] = &[1, 3, 6, 1, 2, 1, 1];
    pub const IF_DESCR: &[u32] = &[1, 3, 6, 1, 2, 1, 2, 2, 1, 2];
    pub const IF_TYPE: &[u32] = &[1, 3, 6, 1, 2, 1, 2, 2, 1, 3];
    pub const IF_SPEED: &[u32] = &[1, 3, 6, 1, 2, 1, 2, 2, 1, 5];
    pub const IF_ADMIN_STATUS: &[u32] = &[1, 3, 6, 1, 2, 1, 2, 2, 1, 7];
    pub const IF_OPER_STATUS: &[u32] = &[1, 3, 6, 1, 2, 1, 2, 2, 1, 8];
    pub const IF_NAME: &[u32] = &[1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 1];
    pub const IF_HIGH_SPEED: &[u32] = &[1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 15];
    pub const IF_ALIAS: &[u32] = &[1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 18];
    /// BRIDGE-MIB dot1dBasePortIfIndex: bridge port -> ifIndex.
    pub const BASE_PORT_IF_INDEX: &[u32] = &[1, 3, 6, 1, 2, 1, 17, 1, 4, 1, 2];
    /// BRIDGE-MIB dot1dTpFdbPort / Status, indexed by MAC.
    pub const TP_FDB_PORT: &[u32] = &[1, 3, 6, 1, 2, 1, 17, 4, 3, 1, 2];
    pub const TP_FDB_STATUS: &[u32] = &[1, 3, 6, 1, 2, 1, 17, 4, 3, 1, 3];
    /// Q-BRIDGE-MIB dot1qTpFdbPort / Status, indexed by FDB id + MAC.
    pub const Q_FDB_PORT: &[u32] = &[1, 3, 6, 1, 2, 1, 17, 7, 1, 2, 2, 1, 2];
    pub const Q_FDB_STATUS: &[u32] = &[1, 3, 6, 1, 2, 1, 17, 7, 1, 2, 2, 1, 3];
    /// Q-BRIDGE-MIB dot1qVlanFdbId: (timeMark, VLAN) -> FDB id.
    pub const Q_VLAN_FDB_ID: &[u32] = &[1, 3, 6, 1, 2, 1, 17, 7, 1, 4, 2, 1, 3];
    /// Q-BRIDGE-MIB dot1qPvid: bridge port -> native/access VLAN.
    pub const Q_PVID: &[u32] = &[1, 3, 6, 1, 2, 1, 17, 7, 1, 4, 5, 1, 1];
    /// IP-MIB ipNetToMediaPhysAddress, indexed by ifIndex + IPv4.
    pub const ARP_PHYS: &[u32] = &[1, 3, 6, 1, 2, 1, 4, 22, 1, 2];
    /// CISCO-VTP-MIB vtpVlanState, indexed by domain + VLAN.
    pub const CISCO_VTP_VLAN_STATE: &[u32] = &[1, 3, 6, 1, 4, 1, 9, 9, 46, 1, 3, 1, 1, 2];
}

/// Ports with at least this many learned MACs are flagged as likely uplinks.
pub const UPLINK_MAC_THRESHOLD: usize = 10;

/// Hard cap on MAC rows kept in a result.
pub const MAX_MACS: usize = 50_000;

/// An owned SNMP value, detached from the PDU buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RawValue {
    Int(i64),
    Bytes(Vec<u8>),
    Text(String),
}

impl RawValue {
    /// The numeric value, if this is an integer-like type.
    pub fn as_int(&self) -> Option<i64> {
        match self {
            RawValue::Int(n) => Some(*n),
            _ => None,
        }
    }

    /// Display text: octet strings decode as UTF-8 (lossy), others as-is.
    pub fn as_text(&self) -> String {
        match self {
            RawValue::Int(n) => n.to_string(),
            RawValue::Bytes(b) => String::from_utf8_lossy(b).trim().to_string(),
            RawValue::Text(t) => t.clone(),
        }
    }
}

/// Table rows as (index suffix, value).
pub type Rows = Vec<(Vec<u32>, RawValue)>;

/// A 6-octet MAC address.
pub type Mac = [u8; 6];

/// Decode a MAC from the last six index arcs. Every arc must be an octet.
pub fn mac_from_arcs(arcs: &[u32]) -> Option<Mac> {
    if arcs.len() < 6 {
        return None;
    }
    let tail = &arcs[arcs.len() - 6..];
    let mut mac = [0u8; 6];
    for (slot, arc) in mac.iter_mut().zip(tail) {
        *slot = u8::try_from(*arc).ok()?;
    }
    Some(mac)
}

/// Uppercase colon form, e.g. `00:1B:44:11:3A:B7`.
pub fn format_mac(mac: &Mac) -> String {
    mac.iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Collect a single-arc-indexed integer column into ifIndex/port -> value.
pub fn index_ints(rows: &Rows) -> HashMap<u32, i64> {
    rows.iter()
        .filter_map(|(idx, v)| match idx.as_slice() {
            [i] => v.as_int().map(|n| (*i, n)),
            _ => None,
        })
        .collect()
}

/// Collect a single-arc-indexed text column into ifIndex -> text.
pub fn index_text(rows: &Rows) -> HashMap<u32, String> {
    rows.iter()
        .filter_map(|(idx, v)| match idx.as_slice() {
            [i] => Some((*i, v.as_text())),
            _ => None,
        })
        .collect()
}

/// Pull sysDescr.0 and sysName.0 out of a walk of the system group
/// (suffixes relative to `oids::SYSTEM`). Returns (sysName, sysDescr).
pub fn system_identity(rows: &Rows) -> (String, String) {
    let mut name = String::new();
    let mut descr = String::new();
    for (idx, v) in rows {
        match idx.as_slice() {
            [1, 0] => descr = v.as_text(),
            [5, 0] => name = v.as_text(),
            _ => {}
        }
    }
    (name, descr)
}

/// One forwarding-database entry before bridge port resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawFdb {
    pub mac: Mac,
    pub vlan: Option<u32>,
    pub bridge_port: u32,
    pub status: Option<i64>,
}

/// Map Q-BRIDGE FDB ids to VLAN ids from dot1qVlanFdbId rows
/// (index: timeMark, VLAN; value: FDB id). The lowest VLAN wins when several
/// share one FDB (shared VLAN learning).
pub fn parse_vlan_fdb_map(rows: &Rows) -> HashMap<u32, u32> {
    let mut map: HashMap<u32, u32> = HashMap::new();
    for (idx, v) in rows {
        let ([_, vlan], Some(fdb)) = (idx.as_slice(), v.as_int()) else {
            continue;
        };
        let Ok(fdb) = u32::try_from(fdb) else {
            continue;
        };
        map.entry(fdb)
            .and_modify(|cur| *cur = (*cur).min(*vlan))
            .or_insert(*vlan);
    }
    map
}

/// Parse Q-BRIDGE dot1qTpFdbPort rows (index: FDB id + 6 MAC arcs) with their
/// status. FDB ids translate to VLANs via `fdb_to_vlan`, falling back to the
/// FDB id itself, which equals the VLAN on most switches.
pub fn parse_qbridge_fdb(
    ports: &Rows,
    status: &Rows,
    fdb_to_vlan: &HashMap<u32, u32>,
) -> Vec<RawFdb> {
    let status_by_idx: HashMap<&[u32], i64> = status
        .iter()
        .filter_map(|(idx, v)| v.as_int().map(|n| (idx.as_slice(), n)))
        .collect();
    ports
        .iter()
        .filter_map(|(idx, v)| {
            if idx.len() != 7 {
                return None;
            }
            let fdb = idx[0];
            let mac = mac_from_arcs(idx)?;
            let bridge_port = u32::try_from(v.as_int()?).ok()?;
            Some(RawFdb {
                mac,
                vlan: Some(*fdb_to_vlan.get(&fdb).unwrap_or(&fdb)),
                bridge_port,
                status: status_by_idx.get(idx.as_slice()).copied(),
            })
        })
        .collect()
}

/// Parse BRIDGE-MIB dot1dTpFdbPort rows (index: 6 MAC arcs) with their status.
/// `vlan` is set when the rows came from a per-VLAN context (Cisco).
pub fn parse_bridge_fdb(ports: &Rows, status: &Rows, vlan: Option<u32>) -> Vec<RawFdb> {
    let status_by_idx: HashMap<&[u32], i64> = status
        .iter()
        .filter_map(|(idx, v)| v.as_int().map(|n| (idx.as_slice(), n)))
        .collect();
    ports
        .iter()
        .filter_map(|(idx, v)| {
            if idx.len() != 6 {
                return None;
            }
            Some(RawFdb {
                mac: mac_from_arcs(idx)?,
                vlan,
                bridge_port: u32::try_from(v.as_int()?).ok()?,
                status: status_by_idx.get(idx.as_slice()).copied(),
            })
        })
        .collect()
}

/// Operational Cisco VLANs from vtpVlanState rows (index: domain, VLAN;
/// value 1 = operational). The reserved FDDI/Token Ring VLANs 1002-1005 are
/// skipped. Sorted and deduplicated.
pub fn parse_vtp_vlans(rows: &Rows) -> Vec<u32> {
    let set: BTreeSet<u32> = rows
        .iter()
        .filter_map(|(idx, v)| match (idx.as_slice(), v.as_int()) {
            ([_, vlan], Some(1)) if !(1002..=1005).contains(vlan) => Some(*vlan),
            _ => None,
        })
        .collect();
    set.into_iter().collect()
}

/// Parse ipNetToMediaPhysAddress rows (index: ifIndex + 4 IPv4 arcs; value:
/// MAC octets) into MAC -> IPs.
pub fn parse_arp(rows: &Rows) -> HashMap<Mac, BTreeSet<Ipv4Addr>> {
    let mut map: HashMap<Mac, BTreeSet<Ipv4Addr>> = HashMap::new();
    for (idx, v) in rows {
        let RawValue::Bytes(bytes) = v else { continue };
        let Ok(mac) = <Mac>::try_from(bytes.as_slice()) else {
            continue;
        };
        if idx.len() != 5 || mac == [0; 6] {
            continue;
        }
        let octets: Option<Vec<u8>> = idx[1..].iter().map(|a| u8::try_from(*a).ok()).collect();
        let Some(o) = octets else { continue };
        map.entry(mac)
            .or_default()
            .insert(Ipv4Addr::new(o[0], o[1], o[2], o[3]));
    }
    map
}

/// An FDB entry resolved to an interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FdbEntry {
    pub mac: Mac,
    pub vlan: Option<u32>,
    /// None when the bridge port has no known ifIndex.
    pub if_index: Option<u32>,
}

/// Resolve bridge ports to ifIndex and drop entries that are not learned
/// station addresses: status invalid(2) or self(4), and bridge port 0 (which
/// means the port is unknown). When `base_ports` is empty, the bridge port is
/// assumed to equal the ifIndex, as on some small switches.
pub fn resolve_fdb(entries: Vec<RawFdb>, base_ports: &HashMap<u32, i64>) -> Vec<FdbEntry> {
    entries
        .into_iter()
        .filter(|e| e.bridge_port != 0 && !matches!(e.status, Some(2) | Some(4)))
        .map(|e| {
            let if_index = if base_ports.is_empty() {
                Some(e.bridge_port)
            } else {
                base_ports
                    .get(&e.bridge_port)
                    .and_then(|i| u32::try_from(*i).ok())
            };
            FdbEntry {
                mac: e.mac,
                vlan: e.vlan,
                if_index,
            }
        })
        .collect()
}

/// Raw per-interface columns, keyed by ifIndex.
#[derive(Debug, Default)]
pub struct InterfaceColumns {
    pub descr: HashMap<u32, String>,
    pub name: HashMap<u32, String>,
    pub alias: HashMap<u32, String>,
    pub if_type: HashMap<u32, i64>,
    pub speed: HashMap<u32, i64>,
    pub high_speed: HashMap<u32, i64>,
    pub admin: HashMap<u32, i64>,
    pub oper: HashMap<u32, i64>,
}

/// Everything the mapper needs to build a result.
#[derive(Debug, Default)]
pub struct MapInput {
    pub sys_name: String,
    pub sys_descr: String,
    pub interfaces: InterfaceColumns,
    /// Bridge port -> ifIndex (from the default context).
    pub base_ports: HashMap<u32, i64>,
    /// Bridge port -> PVID.
    pub pvid: HashMap<u32, i64>,
    pub fdb: Vec<FdbEntry>,
    pub arp: HashMap<Mac, BTreeSet<Ipv4Addr>>,
    pub source: String,
    pub warnings: Vec<String>,
}

/// One interface in the port view.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PortRow {
    pub if_index: u32,
    pub name: String,
    pub descr: String,
    pub alias: String,
    pub admin_status: String,
    pub oper_status: String,
    pub speed: String,
    pub pvid: Option<u32>,
    pub vlans: Vec<u32>,
    pub mac_count: usize,
    /// Ethernet-like interface (as opposed to VLAN SVIs, loopbacks, tunnels).
    pub physical: bool,
    /// Many MACs learned here, so probably an uplink or trunk.
    pub uplink: bool,
}

/// One learned MAC in the MAC view.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MacRow {
    pub mac: String,
    pub vendor: Option<String>,
    pub vlan: Option<u32>,
    pub if_index: Option<u32>,
    pub port: String,
    pub ips: Vec<String>,
    /// The MAC was learned on a port flagged as an uplink.
    pub on_uplink: bool,
}

/// The finished map.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PortMap {
    pub sys_name: String,
    pub sys_descr: String,
    pub source: String,
    pub ports: Vec<PortRow>,
    pub macs: Vec<MacRow>,
    pub warnings: Vec<String>,
    pub truncated: bool,
}

/// ifType values treated as physical Ethernet ports.
pub fn is_physical(if_type: i64) -> bool {
    // ethernetCsmacd, fastEther, fastEtherFX, gigabitEthernet
    matches!(if_type, 6 | 62 | 69 | 117)
}

/// ifAdminStatus / ifOperStatus value names.
pub fn status_name(v: Option<i64>) -> String {
    match v {
        Some(1) => "up",
        Some(2) => "down",
        Some(3) => "testing",
        Some(4) => "unknown",
        Some(5) => "dormant",
        Some(6) => "notPresent",
        Some(7) => "lowerLayerDown",
        _ => "",
    }
    .to_string()
}

/// Human speed from ifHighSpeed (Mbps) when set, else ifSpeed (bps).
pub fn format_speed(if_speed_bps: Option<i64>, high_speed_mbps: Option<i64>) -> String {
    let mbps = match (high_speed_mbps, if_speed_bps) {
        (Some(h), _) if h > 0 => h as f64,
        (_, Some(s)) if s > 0 => s as f64 / 1_000_000.0,
        _ => return String::new(),
    };
    if mbps >= 1000.0 {
        trim_float(mbps / 1000.0) + "G"
    } else {
        trim_float(mbps) + "M"
    }
}

fn trim_float(v: f64) -> String {
    let s = format!("{v:.1}");
    s.strip_suffix(".0").map(str::to_string).unwrap_or(s)
}

/// Build the port and MAC views. `vendor` looks up a MAC's OUI owner.
pub fn build_map(input: MapInput, vendor: impl Fn(&Mac) -> Option<String>) -> PortMap {
    let cols = &input.interfaces;
    let mut indexes: BTreeSet<u32> = cols.descr.keys().copied().collect();
    indexes.extend(cols.name.keys().copied());

    // PVID is keyed by bridge port; move it to ifIndex.
    let pvid_by_if: HashMap<u32, u32> = input
        .pvid
        .iter()
        .filter_map(|(bp, vlan)| {
            let if_index = match input.base_ports.get(bp) {
                Some(i) => u32::try_from(*i).ok()?,
                None if input.base_ports.is_empty() => *bp,
                None => return None,
            };
            Some((if_index, u32::try_from(*vlan).ok()?))
        })
        .collect();

    // Deduplicate on (MAC, VLAN, ifIndex) and cap the size.
    let mut seen = HashSet::new();
    let mut fdb: Vec<&FdbEntry> = Vec::new();
    let mut truncated = false;
    for e in &input.fdb {
        if seen.insert((e.mac, e.vlan, e.if_index)) {
            if fdb.len() >= MAX_MACS {
                truncated = true;
                break;
            }
            fdb.push(e);
        }
    }

    let mut count_by_if: HashMap<u32, usize> = HashMap::new();
    let mut vlans_by_if: HashMap<u32, BTreeSet<u32>> = HashMap::new();
    for e in &fdb {
        if let Some(i) = e.if_index {
            *count_by_if.entry(i).or_default() += 1;
            if let Some(v) = e.vlan {
                vlans_by_if.entry(i).or_default().insert(v);
            }
        }
    }

    let ports: Vec<PortRow> = indexes
        .iter()
        .map(|&i| {
            let mac_count = count_by_if.get(&i).copied().unwrap_or(0);
            let descr = cols.descr.get(&i).cloned().unwrap_or_default();
            let name = cols
                .name
                .get(&i)
                .filter(|n| !n.is_empty())
                .cloned()
                .unwrap_or_else(|| descr.clone());
            PortRow {
                if_index: i,
                name,
                descr,
                alias: cols.alias.get(&i).cloned().unwrap_or_default(),
                admin_status: status_name(cols.admin.get(&i).copied()),
                oper_status: status_name(cols.oper.get(&i).copied()),
                speed: format_speed(
                    cols.speed.get(&i).copied(),
                    cols.high_speed.get(&i).copied(),
                ),
                pvid: pvid_by_if.get(&i).copied(),
                vlans: vlans_by_if
                    .get(&i)
                    .map(|s| s.iter().copied().collect())
                    .unwrap_or_default(),
                mac_count,
                physical: cols.if_type.get(&i).is_some_and(|t| is_physical(*t)),
                uplink: mac_count >= UPLINK_MAC_THRESHOLD,
            }
        })
        .collect();

    let port_by_if: HashMap<u32, &PortRow> = ports.iter().map(|p| (p.if_index, p)).collect();

    let mut macs: Vec<MacRow> = fdb
        .iter()
        .map(|e| {
            let port = e.if_index.and_then(|i| port_by_if.get(&i));
            MacRow {
                mac: format_mac(&e.mac),
                vendor: vendor(&e.mac),
                vlan: e.vlan,
                if_index: e.if_index,
                port: match (port, e.if_index) {
                    (Some(p), _) => p.name.clone(),
                    (None, Some(i)) => format!("ifIndex {i}"),
                    (None, None) => "unknown".to_string(),
                },
                ips: input
                    .arp
                    .get(&e.mac)
                    .map(|s| s.iter().map(|ip| ip.to_string()).collect())
                    .unwrap_or_default(),
                on_uplink: port.is_some_and(|p| p.uplink),
            }
        })
        .collect();
    macs.sort_by(|a, b| {
        (a.if_index.is_none(), a.if_index, a.vlan, &a.mac).cmp(&(
            b.if_index.is_none(),
            b.if_index,
            b.vlan,
            &b.mac,
        ))
    });

    PortMap {
        sys_name: input.sys_name,
        sys_descr: input.sys_descr,
        source: input.source,
        ports,
        macs,
        warnings: input.warnings,
        truncated,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn int(idx: &[u32], n: i64) -> (Vec<u32>, RawValue) {
        (idx.to_vec(), RawValue::Int(n))
    }

    fn text(idx: &[u32], s: &str) -> (Vec<u32>, RawValue) {
        (idx.to_vec(), RawValue::Bytes(s.as_bytes().to_vec()))
    }

    const MAC_A: Mac = [0x00, 0x1b, 0x44, 0x11, 0x3a, 0xb7];
    const MAC_A_ARCS: [u32; 6] = [0, 27, 68, 17, 58, 183];

    #[test]
    fn mac_from_index_tail() {
        let mut idx = vec![10];
        idx.extend(MAC_A_ARCS);
        assert_eq!(mac_from_arcs(&idx), Some(MAC_A));
        assert_eq!(mac_from_arcs(&MAC_A_ARCS), Some(MAC_A));
    }

    #[test]
    fn mac_rejects_short_or_out_of_range() {
        assert_eq!(mac_from_arcs(&[1, 2, 3]), None);
        assert_eq!(mac_from_arcs(&[0, 1, 2, 3, 4, 256]), None);
    }

    #[test]
    fn mac_formats_uppercase_colons() {
        assert_eq!(format_mac(&MAC_A), "00:1B:44:11:3A:B7");
    }

    #[test]
    fn system_identity_picks_scalars() {
        let rows = vec![
            text(&[1, 0], "Cisco IOS"),
            text(&[5, 0], "core-sw1"),
            text(&[6, 0], "IDF 2"),
        ];
        assert_eq!(
            system_identity(&rows),
            ("core-sw1".to_string(), "Cisco IOS".to_string())
        );
    }

    #[test]
    fn index_helpers_skip_multi_arc_rows() {
        let rows = vec![int(&[1], 5), int(&[2, 3], 9)];
        let m = index_ints(&rows);
        assert_eq!(m.len(), 1);
        assert_eq!(m[&1], 5);
        let t = index_text(&vec![text(&[4], " Gi1/0/4 ")]);
        assert_eq!(t[&4], "Gi1/0/4");
    }

    #[test]
    fn qbridge_fdb_with_vlan_translation() {
        let mut idx = vec![7];
        idx.extend(MAC_A_ARCS);
        let ports = vec![(idx.clone(), RawValue::Int(3))];
        let status = vec![(idx, RawValue::Int(3))];
        let map = HashMap::from([(7, 20)]);
        let fdb = parse_qbridge_fdb(&ports, &status, &map);
        assert_eq!(
            fdb,
            vec![RawFdb {
                mac: MAC_A,
                vlan: Some(20),
                bridge_port: 3,
                status: Some(3),
            }]
        );
        // Without a translation the FDB id is used as the VLAN.
        let fdb = parse_qbridge_fdb(&ports, &[].to_vec(), &HashMap::new());
        assert_eq!(fdb[0].vlan, Some(7));
        assert_eq!(fdb[0].status, None);
    }

    #[test]
    fn qbridge_fdb_rejects_bad_index() {
        let ports = vec![int(&[1, 2, 3], 3)];
        assert!(parse_qbridge_fdb(&ports, &vec![], &HashMap::new()).is_empty());
    }

    #[test]
    fn bridge_fdb_parses_mac_index() {
        let ports = vec![(MAC_A_ARCS.to_vec(), RawValue::Int(12))];
        let fdb = parse_bridge_fdb(&ports, &vec![], Some(30));
        assert_eq!(fdb[0].mac, MAC_A);
        assert_eq!(fdb[0].vlan, Some(30));
        assert_eq!(fdb[0].bridge_port, 12);
    }

    #[test]
    fn vlan_fdb_map_prefers_lowest_vlan() {
        let rows = vec![int(&[0, 30], 1), int(&[0, 10], 1), int(&[0, 20], 2)];
        let m = parse_vlan_fdb_map(&rows);
        assert_eq!(m[&1], 10);
        assert_eq!(m[&2], 20);
    }

    #[test]
    fn vtp_vlans_skip_reserved_and_inactive() {
        let rows = vec![
            int(&[1, 1], 1),
            int(&[1, 10], 1),
            int(&[1, 20], 2),
            int(&[1, 1002], 1),
            int(&[1, 1005], 1),
        ];
        assert_eq!(parse_vtp_vlans(&rows), vec![1, 10]);
    }

    #[test]
    fn arp_maps_mac_to_ips() {
        let rows = vec![
            (vec![5, 10, 0, 0, 5], RawValue::Bytes(MAC_A.to_vec())),
            (vec![6, 10, 0, 1, 5], RawValue::Bytes(MAC_A.to_vec())),
            (vec![6, 10, 0, 1, 6], RawValue::Bytes(vec![0; 6])),
            (vec![6, 10, 0, 1, 7], RawValue::Bytes(vec![1, 2, 3])),
        ];
        let m = parse_arp(&rows);
        assert_eq!(m.len(), 1);
        let ips: Vec<String> = m[&MAC_A].iter().map(|i| i.to_string()).collect();
        assert_eq!(ips, vec!["10.0.0.5", "10.0.1.5"]);
    }

    #[test]
    fn resolve_drops_self_invalid_and_port_zero() {
        let mk = |port, status| RawFdb {
            mac: MAC_A,
            vlan: None,
            bridge_port: port,
            status,
        };
        let base = HashMap::from([(1, 10101), (2, 10102)]);
        let out = resolve_fdb(
            vec![
                mk(1, Some(3)),
                mk(2, Some(4)),
                mk(1, Some(2)),
                mk(0, Some(3)),
                mk(9, None),
            ],
            &base,
        );
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].if_index, Some(10101));
        assert_eq!(out[1].if_index, None);
    }

    #[test]
    fn resolve_without_base_ports_uses_bridge_port() {
        let out = resolve_fdb(
            vec![RawFdb {
                mac: MAC_A,
                vlan: None,
                bridge_port: 5,
                status: None,
            }],
            &HashMap::new(),
        );
        assert_eq!(out[0].if_index, Some(5));
    }

    #[test]
    fn speed_formatting() {
        assert_eq!(format_speed(Some(100_000_000), None), "100M");
        assert_eq!(format_speed(Some(4_294_967_295), Some(10_000)), "10G");
        assert_eq!(format_speed(None, Some(2500)), "2.5G");
        assert_eq!(format_speed(Some(0), Some(0)), "");
        assert_eq!(format_speed(None, None), "");
    }

    #[test]
    fn status_names() {
        assert_eq!(status_name(Some(1)), "up");
        assert_eq!(status_name(Some(7)), "lowerLayerDown");
        assert_eq!(status_name(None), "");
    }

    fn sample_input() -> MapInput {
        let mut cols = InterfaceColumns::default();
        for (i, name, oper) in [(1, "Gi1/0/1", 1), (2, "Gi1/0/2", 2), (3, "Gi1/0/48", 1)] {
            cols.name.insert(i, name.to_string());
            cols.descr
                .insert(i, format!("GigabitEthernet{}", &name[2..]));
            cols.if_type.insert(i, 6);
            cols.oper.insert(i, oper);
            cols.admin.insert(i, 1);
            cols.speed.insert(i, 1_000_000_000);
        }
        cols.name.insert(100, "Vlan10".to_string());
        cols.if_type.insert(100, 53);
        cols.alias.insert(1, "printer".to_string());

        let mut fdb = vec![FdbEntry {
            mac: MAC_A,
            vlan: Some(10),
            if_index: Some(1),
        }];
        // Duplicate row must collapse.
        fdb.push(fdb[0].clone());
        for n in 0..UPLINK_MAC_THRESHOLD as u8 {
            fdb.push(FdbEntry {
                mac: [2, 0, 0, 0, 0, n],
                vlan: Some(10 + (n % 2) as u32),
                if_index: Some(3),
            });
        }
        fdb.push(FdbEntry {
            mac: [2, 0, 0, 0, 1, 0],
            vlan: None,
            if_index: None,
        });

        MapInput {
            sys_name: "sw1".into(),
            sys_descr: "test".into(),
            interfaces: cols,
            base_ports: HashMap::from([(1, 1), (2, 2), (48, 3)]),
            pvid: HashMap::from([(1, 10), (48, 1)]),
            fdb,
            arp: HashMap::from([(MAC_A, BTreeSet::from([Ipv4Addr::new(10, 0, 0, 5)]))]),
            source: "Q-BRIDGE-MIB".into(),
            warnings: vec![],
        }
    }

    #[test]
    fn build_map_joins_everything() {
        let map = build_map(sample_input(), |m| {
            (m[0] == 0x00).then(|| "Acme".to_string())
        });
        assert_eq!(map.ports.len(), 4);

        let p1 = &map.ports[0];
        assert_eq!(p1.name, "Gi1/0/1");
        assert_eq!(p1.alias, "printer");
        assert_eq!(p1.oper_status, "up");
        assert_eq!(p1.speed, "1G");
        assert_eq!(p1.pvid, Some(10));
        assert_eq!(p1.mac_count, 1);
        assert!(p1.physical);
        assert!(!p1.uplink);

        let p3 = map.ports.iter().find(|p| p.if_index == 3).unwrap();
        assert_eq!(p3.pvid, Some(1));
        assert_eq!(p3.vlans, vec![10, 11]);
        assert!(p3.uplink);

        let svi = map.ports.iter().find(|p| p.if_index == 100).unwrap();
        assert!(!svi.physical);
        assert_eq!(svi.name, "Vlan10");

        // 1 (deduped) + threshold + 1 unknown.
        assert_eq!(map.macs.len(), UPLINK_MAC_THRESHOLD + 2);
        let a = &map.macs[0];
        assert_eq!(a.mac, "00:1B:44:11:3A:B7");
        assert_eq!(a.vendor.as_deref(), Some("Acme"));
        assert_eq!(a.port, "Gi1/0/1");
        assert_eq!(a.ips, vec!["10.0.0.5"]);
        assert!(!a.on_uplink);
        assert!(map.macs[1].on_uplink);
        let last = map.macs.last().unwrap();
        assert_eq!(last.port, "unknown");
        assert!(!map.truncated);
    }

    #[test]
    fn build_map_name_falls_back_to_descr() {
        let mut input = MapInput::default();
        input.interfaces.descr.insert(7, "eth7".into());
        input.interfaces.name.insert(7, String::new());
        input.fdb.push(FdbEntry {
            mac: MAC_A,
            vlan: None,
            if_index: Some(99),
        });
        let map = build_map(input, |_| None);
        assert_eq!(map.ports[0].name, "eth7");
        assert_eq!(map.macs[0].port, "ifIndex 99");
    }
}
