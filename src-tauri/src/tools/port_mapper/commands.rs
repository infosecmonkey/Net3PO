//! Tauri command for the switch port mapper. Walks the interface, bridge, and
//! ARP tables of one switch over SNMP v1/v2c/v3 (reusing the SNMP walk's
//! session setup), then hands the rows to `core` to build the map. Cisco
//! per-VLAN forwarding tables are read with community indexing
//! (`community@vlan`) or v3 contexts (`vlan-N`). Runs on a blocking task,
//! streams stage progress, and is cancellable.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use snmp2::{Oid, SyncSession, Value};
use tauri::State;
use tauri::ipc::Channel;

use super::core::{self, MapInput, PortMap, RawValue, Rows, oids};
use crate::tools::mac_vendor;
use crate::tools::snmp_walk::commands::{WalkConfig, build_session_in_context, humanize};

#[derive(Default)]
pub struct PortMapRegistry {
    inner: Arc<Mutex<HashMap<u32, Arc<AtomicBool>>>>,
}

/// Rows kept per walked column; a guard against runaway agents.
const MAX_ROWS_PER_TABLE: usize = 100_000;
/// Cisco VLANs queried for per-VLAN forwarding tables.
const MAX_VLANS: usize = 1024;
const GETBULK_REPETITIONS: u32 = 25;
/// Stack for the mapper thread; see `port_map`.
const MAPPER_STACK_BYTES: usize = 8 * 1024 * 1024;

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct PortMapConfig {
    /// Target switch and credentials. `start_oid` is ignored.
    pub snmp: WalkConfig,
    /// Optional router or L3 switch to read ARP from, with the same credentials.
    pub arp_host: String,
}

#[derive(Clone, Serialize)]
#[serde(
    tag = "type",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum MapEvent {
    Stage { message: String },
    Done { map: PortMap },
    Error { message: String },
    Cancelled,
}

/// Write exported CSV to a path chosen via the save dialog.
#[tauri::command]
pub fn port_map_save(path: String, contents: String) -> Result<(), String> {
    std::fs::write(&path, contents).map_err(|e| format!("could not write {path}: {e}"))
}

/// Cancel a running map by id.
#[tauri::command]
pub fn port_map_cancel(registry: State<'_, PortMapRegistry>, map_id: u32) {
    if let Some(flag) = registry.inner.lock().unwrap().get(&map_id) {
        flag.store(true, Ordering::Relaxed);
    }
}

/// Map a switch's MACs to ports, streaming stage progress and a final result.
#[tauri::command]
pub async fn port_map(
    registry: State<'_, PortMapRegistry>,
    map_id: u32,
    config: PortMapConfig,
    on_event: Channel<MapEvent>,
) -> Result<(), String> {
    if config.snmp.host.trim().is_empty() {
        return Err("enter the switch host or IP".to_string());
    }
    let cancel = Arc::new(AtomicBool::new(false));
    let reg = registry.inner.clone();
    reg.lock().unwrap().insert(map_id, cancel.clone());

    // A dedicated thread with an explicit stack rather than spawn_blocking:
    // snmp2 builds its ~128 KB session buffers on the stack, which leaves little
    // headroom on the default 2 MB in debug builds.
    let flag = cancel.clone();
    let events = on_event.clone();
    let (tx, rx) = tokio::sync::oneshot::channel();
    let spawned = std::thread::Builder::new()
        .name("port-mapper".to_string())
        .stack_size(MAPPER_STACK_BYTES)
        .spawn(move || {
            let _ = tx.send(run_map(&config, &events, &flag));
        });
    let outcome = match spawned {
        Ok(_) => rx.await.unwrap_or_else(|_| {
            Err(Stop::Failed(
                "mapper thread exited unexpectedly".to_string(),
            ))
        }),
        Err(e) => Err(Stop::Failed(format!("could not start mapper thread: {e}"))),
    };

    reg.lock().unwrap().remove(&map_id);
    let _ = on_event.send(match outcome {
        Ok(map) => MapEvent::Done { map },
        Err(Stop::Cancelled) => MapEvent::Cancelled,
        Err(Stop::Failed(message)) => MapEvent::Error { message },
    });
    Ok(())
}

/// Why a mapping run ended early.
enum Stop {
    Cancelled,
    Failed(String),
}

fn run_map(
    config: &PortMapConfig,
    events: &Channel<MapEvent>,
    cancel: &AtomicBool,
) -> Result<PortMap, Stop> {
    let stage = |m: &str| {
        let _ = events.send(MapEvent::Stage {
            message: m.to_string(),
        });
    };
    let snmp = &config.snmp;
    let mut input = MapInput::default();

    stage("Connecting");
    let mut w = Walker::open(snmp, None, cancel)?;
    let system = w.walk(oids::SYSTEM)?;
    if system.is_empty() {
        return Err(Stop::Failed(
            "the agent answered but returned no system group; check the view/ACL for this community or user".to_string(),
        ));
    }
    (input.sys_name, input.sys_descr) = core::system_identity(&system);

    stage("Reading interfaces");
    let cols = &mut input.interfaces;
    cols.descr = core::index_text(&w.walk(oids::IF_DESCR)?);
    cols.if_type = core::index_ints(&w.walk(oids::IF_TYPE)?);
    cols.speed = core::index_ints(&w.walk(oids::IF_SPEED)?);
    cols.admin = core::index_ints(&w.walk(oids::IF_ADMIN_STATUS)?);
    cols.oper = core::index_ints(&w.walk(oids::IF_OPER_STATUS)?);
    cols.name = core::index_text(&w.walk(oids::IF_NAME)?);
    cols.alias = core::index_text(&w.walk(oids::IF_ALIAS)?);
    cols.high_speed = core::index_ints(&w.walk(oids::IF_HIGH_SPEED)?);

    stage("Reading bridge ports");
    input.base_ports = core::index_ints(&w.walk(oids::BASE_PORT_IF_INDEX)?);
    input.pvid = core::index_ints(&w.walk(oids::Q_PVID)?);

    stage("Reading forwarding table (Q-BRIDGE-MIB)");
    let q_ports = w.walk(oids::Q_FDB_PORT)?;
    if !q_ports.is_empty() {
        let q_status = w.walk(oids::Q_FDB_STATUS)?;
        let fdb_map = core::parse_vlan_fdb_map(&w.walk(oids::Q_VLAN_FDB_ID)?);
        let raw = core::parse_qbridge_fdb(&q_ports, &q_status, &fdb_map);
        input.fdb = core::resolve_fdb(raw, &input.base_ports);
        input.source = "Q-BRIDGE-MIB".to_string();
    } else {
        let vlans = core::parse_vtp_vlans(&w.walk(oids::CISCO_VTP_VLAN_STATE)?);
        if vlans.is_empty() {
            stage("Reading forwarding table (BRIDGE-MIB)");
            let ports = w.walk(oids::TP_FDB_PORT)?;
            let status = w.walk(oids::TP_FDB_STATUS)?;
            let raw = core::parse_bridge_fdb(&ports, &status, None);
            input.fdb = core::resolve_fdb(raw, &input.base_ports);
            input.source = "BRIDGE-MIB".to_string();
        } else {
            read_cisco_vlans(snmp, &vlans, &mut input, &stage, cancel)?;
        }
    }
    if input.base_ports.is_empty() && !input.fdb.is_empty() {
        input.warnings.push(
            "dot1dBasePortIfIndex is empty; assuming bridge port numbers equal ifIndex".to_string(),
        );
    }

    stage("Reading ARP table");
    let arp_rows = w.walk(oids::ARP_PHYS)?;
    input.arp = core::parse_arp(&arp_rows);
    let arp_host = config.arp_host.trim();
    if !arp_host.is_empty() {
        stage(&format!("Reading ARP table from {arp_host}"));
        let mut gw_cfg = snmp.clone();
        gw_cfg.host = arp_host.to_string();
        match Walker::open(&gw_cfg, None, cancel).and_then(|mut g| g.walk(oids::ARP_PHYS)) {
            Ok(rows) => merge_arp(&mut input.arp, core::parse_arp(&rows)),
            Err(Stop::Cancelled) => return Err(Stop::Cancelled),
            Err(Stop::Failed(e)) => input
                .warnings
                .push(format!("ARP from {arp_host} failed: {e}")),
        }
    }
    if input.fdb.is_empty() {
        input.warnings.push(
            "no learned MACs found; the device may not expose its forwarding table over SNMP, or the view excludes BRIDGE-MIB".to_string(),
        );
    }

    let db = mac_vendor::database();
    Ok(core::build_map(input, |mac| {
        db.lookup(mac).map(|(org, _)| org)
    }))
}

/// Cisco keeps one forwarding table per VLAN, reachable with community
/// indexing (v1/v2c) or a `vlan-N` context (v3). A VLAN that fails becomes a
/// warning rather than aborting the map.
fn read_cisco_vlans(
    snmp: &WalkConfig,
    vlans: &[u32],
    input: &mut MapInput,
    stage: &dyn Fn(&str),
    cancel: &AtomicBool,
) -> Result<(), Stop> {
    let vlans = &vlans[..vlans.len().min(MAX_VLANS)];
    let mut failed = Vec::new();
    for (n, vlan) in vlans.iter().enumerate() {
        stage(&format!(
            "Reading forwarding table for VLAN {vlan} ({}/{})",
            n + 1,
            vlans.len()
        ));
        match read_vlan_fdb(snmp, *vlan, cancel) {
            Ok(mut entries) => input.fdb.append(&mut entries),
            Err(Stop::Cancelled) => return Err(Stop::Cancelled),
            Err(Stop::Failed(_)) => failed.push(vlan.to_string()),
        }
    }
    input.source = "BRIDGE-MIB per VLAN (Cisco)".to_string();
    if !failed.is_empty() {
        input.warnings.push(format!(
            "could not read the forwarding table for VLAN {}",
            failed.join(", ")
        ));
    }
    Ok(())
}

fn read_vlan_fdb(
    snmp: &WalkConfig,
    vlan: u32,
    cancel: &AtomicBool,
) -> Result<Vec<core::FdbEntry>, Stop> {
    let mut cfg = snmp.clone();
    let ctx = format!("vlan-{vlan}");
    let mut w = if snmp.version == "v3" {
        Walker::open(&cfg, Some(&ctx), cancel)?
    } else {
        cfg.community = format!("{}@{vlan}", snmp.community);
        Walker::open(&cfg, None, cancel)?
    };
    // Bridge port numbering can differ per VLAN instance, so resolve against
    // this context's own base port table.
    let base = core::index_ints(&w.walk(oids::BASE_PORT_IF_INDEX)?);
    let ports = w.walk(oids::TP_FDB_PORT)?;
    let status = w.walk(oids::TP_FDB_STATUS)?;
    let raw = core::parse_bridge_fdb(&ports, &status, Some(vlan));
    Ok(core::resolve_fdb(raw, &base))
}

fn merge_arp(
    into: &mut HashMap<core::Mac, std::collections::BTreeSet<Ipv4Addr>>,
    from: HashMap<core::Mac, std::collections::BTreeSet<Ipv4Addr>>,
) {
    for (mac, ips) in from {
        into.entry(mac).or_default().extend(ips);
    }
}

/// A session plus the bits needed to walk a table with it. The session is
/// boxed: SyncSession carries ~128 KB of inline buffers, and holding several by
/// value overflows a 2 MB thread stack in debug builds.
struct Walker<'a> {
    session: Box<SyncSession>,
    bulk: bool,
    cancel: &'a AtomicBool,
}

impl<'a> Walker<'a> {
    /// Open a session; for v3, run engine discovery first.
    fn open(
        cfg: &WalkConfig,
        v3_context: Option<&str>,
        cancel: &'a AtomicBool,
    ) -> Result<Self, Stop> {
        let timeout = Some(Duration::from_millis(cfg.timeout_ms.clamp(200, 30_000)));
        let dest = (cfg.host.trim(), cfg.port);
        let mut session = Box::new(
            build_session_in_context(cfg, dest, timeout, v3_context).map_err(Stop::Failed)?,
        );
        if cfg.version == "v3"
            && let Err(e) = session.init()
        {
            return Err(Stop::Failed(format!(
                "v3 engine discovery failed: {}",
                humanize(&e)
            )));
        }
        Ok(Walker {
            session,
            bulk: cfg.version != "v1",
            cancel,
        })
    }

    /// Walk one column, returning rows keyed by the index suffix after `root`.
    fn walk(&mut self, root: &[u32]) -> Result<Rows, Stop> {
        let mut rows = Rows::new();
        let mut last = root.to_vec();
        loop {
            if self.cancel.load(Ordering::Relaxed) {
                return Err(Stop::Cancelled);
            }
            let batch = self.fetch(&last)?;
            let mut advanced = false;
            for (oid, value) in batch {
                // Left the column, or stopped advancing: end of table.
                if !oid.starts_with(root) || oid <= last {
                    return Ok(rows);
                }
                if let Some(v) = value {
                    rows.push((oid[root.len()..].to_vec(), v));
                }
                last = oid;
                advanced = true;
                if rows.len() >= MAX_ROWS_PER_TABLE {
                    return Ok(rows);
                }
            }
            if !advanced {
                return Ok(rows);
            }
        }
    }

    /// One GETNEXT/GETBULK round, with values copied out of the PDU buffer.
    /// An error-status PDU (v1 noSuchName past the end) yields no rows.
    #[allow(clippy::type_complexity)]
    fn fetch(&mut self, from: &[u32]) -> Result<Vec<(Vec<u32>, Option<RawValue>)>, Stop> {
        let arcs: Vec<u64> = from.iter().map(|n| u64::from(*n)).collect();
        let cur = Oid::from(&arcs[..]).map_err(|_| Stop::Failed("bad OID".to_string()))?;
        let mut attempts = 0u32;
        loop {
            let result = if self.bulk {
                self.session.getbulk(&[&cur], 0, GETBULK_REPETITIONS)
            } else {
                self.session.getnext(&cur)
            };
            match result {
                Ok(pdu) if pdu.error_status != 0 => return Ok(Vec::new()),
                Ok(pdu) => {
                    return Ok(pdu
                        .varbinds
                        .map(|(oid, val)| (oid_to_vec(&oid), to_raw(&val)))
                        .collect());
                }
                Err(snmp2::Error::AuthUpdated) if attempts < 3 => attempts += 1,
                Err(snmp2::Error::AuthUpdated) => {
                    return Err(Stop::Failed(
                        "SNMPv3 auth parameters kept changing".to_string(),
                    ));
                }
                Err(e) => return Err(Stop::Failed(humanize(&e))),
            }
        }
    }
}

/// Copy a varbind value into an owned form. Exception values map to None.
fn to_raw(val: &Value) -> Option<RawValue> {
    Some(match val {
        Value::Integer(n) => RawValue::Int(*n),
        Value::Counter32(n) | Value::Unsigned32(n) | Value::Timeticks(n) => {
            RawValue::Int(i64::from(*n))
        }
        Value::Counter64(n) => RawValue::Int(i64::try_from(*n).unwrap_or(i64::MAX)),
        Value::OctetString(b) | Value::Opaque(b) => RawValue::Bytes(b.to_vec()),
        Value::IpAddress(a) => RawValue::Text(Ipv4Addr::from(*a).to_string()),
        Value::ObjectIdentifier(o) => RawValue::Text(o.to_string()),
        Value::EndOfMibView | Value::NoSuchObject | Value::NoSuchInstance | Value::Null => {
            return None;
        }
        other => RawValue::Text(format!("{other:?}")),
    })
}

fn oid_to_vec(oid: &Oid) -> Vec<u32> {
    oid.to_string()
        .trim_start_matches('.')
        .split('.')
        .filter_map(|p| p.parse::<u32>().ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression: snmp2's SyncSession holds ~128 KB of inline buffers, and
    /// keeping sessions by value overflowed a 2 MB tokio thread stack in debug
    /// builds. Run a full map attempt against a closed port on a thread with
    /// half the stack `port_map` uses; it must fail cleanly, not abort.
    #[test]
    fn run_map_fits_mapper_stack() {
        let handle = std::thread::Builder::new()
            .stack_size(MAPPER_STACK_BYTES / 2)
            .spawn(|| {
                let mut config = PortMapConfig::default();
                config.snmp.host = "127.0.0.1".to_string();
                config.snmp.port = 9;
                config.snmp.timeout_ms = 200;
                config.arp_host = "127.0.0.1".to_string();
                let channel = Channel::new(|_| Ok(()));
                let cancel = AtomicBool::new(false);
                matches!(run_map(&config, &channel, &cancel), Err(Stop::Failed(_)))
            })
            .unwrap();
        assert!(handle.join().unwrap());
    }
}
