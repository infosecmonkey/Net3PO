//! Tauri command for the SNMP sweep. Enumerates a subnet (reusing the port
//! scanner's target parsing), probes each host for sysDescr/sysName/sysObjectID
//! over SNMP v1/v2c with bounded concurrency, and streams responders. The sync
//! SNMP probe runs on blocking tasks so a slow host never stalls the runtime.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use snmp2::{Oid, SyncSession, Value};
use tauri::State;
use tauri::ipc::Channel;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use super::core::{self, SYS_DESCR, SYS_NAME, SYS_OBJECT_ID};
use crate::tools::port_scanner::core as targets;
use crate::tools::snmp_walk::commands::MibState;

#[derive(Default)]
pub struct SweepRegistry {
    inner: Arc<Mutex<HashMap<u32, Arc<AtomicBool>>>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SweepConfig {
    pub targets: String,
    pub port: u16,
    pub version: String,
    pub community: String,
    pub timeout_ms: u64,
    pub concurrency: usize,
}

impl Default for SweepConfig {
    fn default() -> Self {
        SweepConfig {
            targets: String::new(),
            port: 161,
            version: "v2c".to_string(),
            community: "public".to_string(),
            timeout_ms: 1000,
            concurrency: 64,
        }
    }
}

#[derive(Clone, Serialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum SweepEvent {
    Responder {
        ip: String,
        sys_descr: String,
        sys_name: String,
        sys_object_id: String,
    },
    Progress {
        done: usize,
        total: usize,
        found: usize,
    },
    Done {
        total: usize,
        found: usize,
        cancelled: bool,
    },
}

const PROGRESS_EVERY: usize = 16;

/// Cancel a running sweep by id.
#[tauri::command]
pub fn snmp_sweep_cancel(registry: State<'_, SweepRegistry>, sweep_id: u32) {
    if let Some(flag) = registry.inner.lock().unwrap().get(&sweep_id) {
        flag.store(true, Ordering::Relaxed);
    }
}

/// Sweep a subnet for SNMP responders, streaming each as it answers.
#[tauri::command]
pub async fn snmp_sweep(
    registry: State<'_, SweepRegistry>,
    mib_state: State<'_, MibState>,
    sweep_id: u32,
    config: SweepConfig,
    on_event: Channel<SweepEvent>,
) -> Result<(), String> {
    let hosts = resolve_hosts(&config.targets).await?;
    let mib = mib_state.0.lock().unwrap().clone();

    let cancel = Arc::new(AtomicBool::new(false));
    let reg = registry.inner.clone();
    reg.lock().unwrap().insert(sweep_id, cancel.clone());

    let total = hosts.len();
    let semaphore = Arc::new(Semaphore::new(config.concurrency.max(1)));
    let mut set: JoinSet<Option<(IpAddr, Probe)>> = JoinSet::new();
    let mut done = 0usize;
    let mut found = 0usize;

    let emit_responder = |ip: IpAddr, p: Probe, on_event: &Channel<SweepEvent>| {
        let sys_object_id = translate_oid(&p.objid, &mib);
        let _ = on_event.send(SweepEvent::Responder {
            ip: ip.to_string(),
            sys_descr: p.descr,
            sys_name: p.name,
            sys_object_id,
        });
    };

    for ip in hosts {
        if cancel.load(Ordering::Relaxed) {
            break;
        }
        let permit = semaphore.clone().acquire_owned().await.unwrap();
        let cfg = ProbeCfg {
            port: config.port,
            version: config.version.clone(),
            community: config.community.clone().into_bytes(),
            timeout_ms: config.timeout_ms,
        };
        set.spawn(async move {
            let _permit = permit;
            tokio::task::spawn_blocking(move || probe(ip, cfg))
                .await
                .ok()
                .flatten()
        });

        while let Some(joined) = set.try_join_next() {
            done += 1;
            if let Ok(Some((ip, p))) = joined {
                found += 1;
                emit_responder(ip, p, &on_event);
            }
            if done.is_multiple_of(PROGRESS_EVERY) {
                let _ = on_event.send(SweepEvent::Progress { done, total, found });
            }
        }
    }

    while let Some(joined) = set.join_next().await {
        if let Ok(Some((ip, p))) = joined {
            found += 1;
            emit_responder(ip, p, &on_event);
        }
    }

    let cancelled = cancel.load(Ordering::Relaxed);
    reg.lock().unwrap().remove(&sweep_id);
    let _ = on_event.send(SweepEvent::Done {
        total,
        found,
        cancelled,
    });
    Ok(())
}

async fn resolve_hosts(spec: &str) -> Result<Vec<IpAddr>, String> {
    let parsed = targets::parse_targets(spec).map_err(|e| e.to_string())?;
    let mut hosts = Vec::new();
    for t in parsed {
        match t {
            targets::Target::Ip(ip) => hosts.push(ip),
            targets::Target::Host(h) => match tokio::net::lookup_host((h.as_str(), 0u16)).await {
                Ok(addrs) => {
                    if let Some(ip) = addrs.map(|s| s.ip()).next() {
                        hosts.push(ip);
                    }
                }
                Err(e) => return Err(format!("could not resolve '{h}': {e}")),
            },
        }
    }
    Ok(hosts)
}

struct ProbeCfg {
    port: u16,
    version: String,
    community: Vec<u8>,
    timeout_ms: u64,
}

struct Probe {
    descr: String,
    name: String,
    objid: String,
}

/// Probe one host. Returns Some if it answered SNMP. Runs blocking SNMP I/O.
fn probe(ip: IpAddr, cfg: ProbeCfg) -> Option<(IpAddr, Probe)> {
    let addr = SocketAddr::new(ip, cfg.port);
    let timeout = Some(Duration::from_millis(cfg.timeout_ms));
    let mut descr = String::new();
    let mut name = String::new();
    let mut objid = String::new();

    if cfg.version == "v1" {
        let mut sess = SyncSession::new_v1(addr, &cfg.community, timeout, 0).ok()?;
        // The first GET gates liveness: no response -> Err -> None.
        let d0 = u64_instance(SYS_DESCR);
        let pdu = sess.get(&Oid::from(&d0[..]).ok()?).ok()?;
        descr = first_value(pdu);
        let n0 = u64_instance(SYS_NAME);
        if let Ok(p) = sess.get(&Oid::from(&n0[..]).ok()?) {
            name = first_value(p);
        }
        let o0 = u64_instance(SYS_OBJECT_ID);
        if let Ok(p) = sess.get(&Oid::from(&o0[..]).ok()?) {
            objid = first_value(p);
        }
    } else {
        let mut sess = SyncSession::new_v2c(addr, &cfg.community, timeout, 0).ok()?;
        let (dv, nv, ov) = (u64v(SYS_DESCR), u64v(SYS_NAME), u64v(SYS_OBJECT_ID));
        let d = Oid::from(&dv[..]).ok()?;
        let n = Oid::from(&nv[..]).ok()?;
        let o = Oid::from(&ov[..]).ok()?;
        // One GETBULK with 3 non-repeaters returns the three scalar .0 values.
        let pdu = sess.getbulk(&[&d, &n, &o], 3, 0).ok()?;
        for (oid, val) in pdu.varbinds {
            let ovec = oid_to_vec(&oid);
            let s = value_string(&val);
            if ovec.starts_with(SYS_DESCR) {
                descr = s;
            } else if ovec.starts_with(SYS_NAME) {
                name = s;
            } else if ovec.starts_with(SYS_OBJECT_ID) {
                objid = s;
            }
        }
    }

    Some((ip, Probe { descr, name, objid }))
}

fn u64v(arcs: &[u32]) -> Vec<u64> {
    arcs.iter().map(|n| *n as u64).collect()
}

fn u64_instance(arcs: &[u32]) -> Vec<u64> {
    let mut v = u64v(arcs);
    v.push(0);
    v
}

fn first_value(pdu: snmp2::pdu::Pdu<'_>) -> String {
    let mut vb = pdu.varbinds;
    vb.next()
        .map(|(_, val)| value_string(&val))
        .unwrap_or_default()
}

fn value_string(val: &Value) -> String {
    if let Value::OctetString(bytes) = val {
        return core::render_octets(bytes);
    }
    let dbg = format!("{val:?}");
    match (dbg.find('('), dbg.rfind(')')) {
        (Some(a), Some(b)) if b > a => dbg[a + 1..b].to_string(),
        _ => dbg,
    }
}

fn oid_to_vec(oid: &Oid) -> Vec<u32> {
    oid.to_string()
        .trim_start_matches('.')
        .split('.')
        .filter_map(|p| p.parse::<u32>().ok())
        .collect()
}

/// Translate a dotted sysObjectID into a MIB name when possible.
fn translate_oid(dotted: &str, mib: &crate::tools::snmp_walk::core::Mib) -> String {
    let trimmed = dotted.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    if let Some(oid) = mib.resolve(trimmed) {
        let name = mib.translate(&oid);
        if name != trimmed {
            return format!("{name} ({trimmed})");
        }
    }
    trimmed.to_string()
}
