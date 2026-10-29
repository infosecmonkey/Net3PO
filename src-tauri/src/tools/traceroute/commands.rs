//! Tauri commands for the visual traceroute. Each cycle probes every TTL in
//! parallel on blocking threads, folds the results into the path tracker,
//! resolves new routers' names, and streams the hop table and summary. Path
//! MTU is measured once the destination answers. Cancellable throughout.

use std::collections::HashMap;
use std::hash::{BuildHasher, Hasher};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hickory_resolver::TokioAsyncResolver;
use serde::{Deserialize, Serialize};
use tauri::State;
use tauri::ipc::Channel;
use tokio::task::JoinSet;

use super::core::{HopView, MtuProbe, MtuResult, MtuSearch, Outcome, PathSummary, PathTracker};
use super::probe::{self, ProbeError, ProbeSpec};

#[derive(Default)]
pub struct TraceRegistry {
    inner: Arc<Mutex<HashMap<u32, Arc<AtomicBool>>>>,
}

/// TTL used for Path MTU probes: high enough to reach any destination.
const MTU_PROBE_TTL: u8 = 64;
/// Largest Path MTU searched (standard Ethernet).
const MTU_MAX: u16 = 1500;
/// Reverse-DNS budget per cycle; slow resolvers never stall the trace.
const RDNS_TIMEOUT: Duration = Duration::from_millis(1500);
/// Longest hostname kept (DNS limit); PTR data is untrusted.
const MAX_HOSTNAME: usize = 253;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct TraceConfig {
    pub target: String,
    pub max_hops: u8,
    /// Cycles to run; 0 runs until stopped.
    pub cycles: u32,
    pub interval_ms: u64,
    pub timeout_ms: u64,
    /// Total IP packet size of trace probes.
    pub packet_size: u16,
    pub measure_mtu: bool,
    pub resolve_names: bool,
}

impl Default for TraceConfig {
    fn default() -> Self {
        TraceConfig {
            target: String::new(),
            max_hops: 30,
            cycles: 5,
            interval_ms: 1000,
            timeout_ms: 2000,
            packet_size: 60,
            measure_mtu: true,
            resolve_names: true,
        }
    }
}

#[derive(Clone, Serialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum TraceEvent {
    Started {
        target: String,
        ip: String,
        method: String,
    },
    Cycle {
        n: u32,
        hops: Vec<HopView>,
        summary: PathSummary,
    },
    MtuStarted,
    Mtu {
        result: MtuResult,
    },
    Error {
        message: String,
    },
    Done {
        cycles: u32,
        cancelled: bool,
    },
}

/// Probe method used on this OS, shown in the panel before a run.
#[tauri::command]
pub fn trace_method() -> String {
    probe::method()
}

/// Stop a running trace by id.
#[tauri::command]
pub fn trace_stop(registry: State<'_, TraceRegistry>, trace_id: u32) {
    if let Some(flag) = registry.inner.lock().unwrap().get(&trace_id) {
        flag.store(true, Ordering::Relaxed);
    }
}

/// Run a traceroute, streaming per-cycle hop tables and the Path MTU.
#[tauri::command]
pub async fn trace_run(
    registry: State<'_, TraceRegistry>,
    trace_id: u32,
    config: TraceConfig,
    on_event: Channel<TraceEvent>,
) -> Result<(), String> {
    let dst = resolve_target(&config.target).await?;
    let cancel = Arc::new(AtomicBool::new(false));
    let reg = registry.inner.clone();
    reg.lock().unwrap().insert(trace_id, cancel.clone());

    let _ = on_event.send(TraceEvent::Started {
        target: config.target.trim().to_string(),
        ip: dst.to_string(),
        method: probe::method(),
    });
    let outcome = run_trace(dst, &config, &on_event, &cancel).await;
    reg.lock().unwrap().remove(&trace_id);

    let cycles = match outcome {
        Ok(n) => n,
        Err((n, message)) => {
            let _ = on_event.send(TraceEvent::Error { message });
            n
        }
    };
    let _ = on_event.send(TraceEvent::Done {
        cycles,
        cancelled: cancel.load(Ordering::Relaxed),
    });
    Ok(())
}

/// Resolve the target to an IPv4 address.
async fn resolve_target(target: &str) -> Result<Ipv4Addr, String> {
    let t = target.trim();
    if t.is_empty() {
        return Err("enter a host or IPv4 address".to_string());
    }
    if let Ok(ip) = t.parse::<IpAddr>() {
        return match ip {
            IpAddr::V4(v4) => Ok(v4),
            IpAddr::V6(_) => Err("IPv6 traceroute is not supported yet".to_string()),
        };
    }
    let addrs = tokio::net::lookup_host((t, 0u16))
        .await
        .map_err(|e| format!("could not resolve '{t}': {e}"))?;
    let mut saw_v6 = false;
    for a in addrs {
        match a.ip() {
            IpAddr::V4(v4) => return Ok(v4),
            IpAddr::V6(_) => saw_v6 = true,
        }
    }
    Err(if saw_v6 {
        format!("'{t}' has only IPv6 addresses; IPv6 traceroute is not supported yet")
    } else {
        format!("'{t}' did not resolve to an address")
    })
}

/// Returns cycles completed, or (cycles, error) when probing fails outright.
async fn run_trace(
    dst: Ipv4Addr,
    config: &TraceConfig,
    events: &Channel<TraceEvent>,
    cancel: &AtomicBool,
) -> Result<u32, (u32, String)> {
    let mut tracker = PathTracker::new(config.max_hops);
    let ident = (random_u64() & 0xffff) as u16;
    let seq = Arc::new(AtomicU16::new(1));
    let timeout = Duration::from_millis(config.timeout_ms.clamp(200, 10_000));
    let interval = Duration::from_millis(config.interval_ms.clamp(200, 60_000));
    let size = config.packet_size.clamp(28, MTU_MAX);
    let resolver = config
        .resolve_names
        .then(|| TokioAsyncResolver::tokio_from_system_conf().ok())
        .flatten();
    let mut names: HashMap<Ipv4Addr, Option<String>> = HashMap::new();
    let mut mtu_done = !config.measure_mtu;
    let mut n = 0u32;

    loop {
        if cancel.load(Ordering::Relaxed) {
            return Ok(n);
        }

        // One probe per TTL, all in flight at once.
        let mut set = JoinSet::new();
        for ttl in tracker.ttls() {
            let spec = ProbeSpec {
                dst,
                ttl,
                ident,
                seq: seq.fetch_add(1, Ordering::Relaxed),
                size,
                df: false,
                timeout,
            };
            set.spawn_blocking(move || probe::probe(&spec));
        }
        let mut results = Vec::new();
        let mut setup_error = None;
        while let Some(joined) = set.join_next().await {
            match joined {
                Ok(Ok(r)) => results.push(r),
                Ok(Err(ProbeError::Setup(e))) => setup_error = Some(e),
                Err(e) => setup_error = Some(format!("probe task failed: {e}")),
            }
        }
        if results.is_empty() {
            return Err((
                n,
                setup_error.unwrap_or_else(|| "no probes could be sent".to_string()),
            ));
        }
        results.sort_by_key(|r| r.ttl);
        tracker.record_cycle(&results);
        n += 1;

        if let Some(res) = &resolver {
            resolve_names(res, &mut tracker, &mut names).await;
        }
        let _ = events.send(TraceEvent::Cycle {
            n,
            hops: tracker.views(),
            summary: tracker.summary(),
        });

        if !mtu_done && tracker.summary().reached {
            mtu_done = true;
            let _ = events.send(TraceEvent::MtuStarted);
            if let Some(result) = measure_mtu(dst, ident, &seq, timeout, cancel).await {
                let _ = events.send(TraceEvent::Mtu { result });
            }
        }

        if config.cycles != 0 && n >= config.cycles {
            return Ok(n);
        }
        // Sleep in small steps so Stop is prompt.
        let mut slept = Duration::ZERO;
        while slept < interval {
            if cancel.load(Ordering::Relaxed) {
                return Ok(n);
            }
            let step = (interval - slept).min(Duration::from_millis(100));
            tokio::time::sleep(step).await;
            slept += step;
        }
    }
}

/// Look up PTR names for routers not seen before, within a fixed budget, and
/// attach every known name to the hops.
async fn resolve_names(
    resolver: &TokioAsyncResolver,
    tracker: &mut PathTracker,
    names: &mut HashMap<Ipv4Addr, Option<String>>,
) {
    let new_ips: Vec<Ipv4Addr> = tracker
        .active()
        .iter()
        .flat_map(|h| h.responder_ips().collect::<Vec<_>>())
        .filter(|ip| !names.contains_key(ip))
        .collect();

    let mut set = JoinSet::new();
    for ip in new_ips {
        names.insert(ip, None);
        let r = resolver.clone();
        set.spawn(async move {
            let name = tokio::time::timeout(RDNS_TIMEOUT, r.reverse_lookup(IpAddr::V4(ip)))
                .await
                .ok()
                .and_then(|res| res.ok())
                .and_then(|lookup| lookup.iter().next().map(|ptr| ptr.to_utf8()))
                .map(|s| s.trim_end_matches('.').chars().take(MAX_HOSTNAME).collect());
            (ip, name)
        });
    }
    while let Some(Ok((ip, name))) = set.join_next().await {
        names.insert(ip, name);
    }

    for ttl in tracker.ttls() {
        let Some(hop) = tracker.hop_mut(ttl) else {
            continue;
        };
        let known: Vec<(Ipv4Addr, String)> = hop
            .responder_ips()
            .filter_map(|ip| names.get(&ip).cloned().flatten().map(|n| (ip, n)))
            .collect();
        for (ip, name) in known {
            hop.set_hostname(ip, name);
        }
    }
}

/// Binary-search the largest don't-fragment packet that reaches `dst`.
/// Lost probes get one retry so a single drop is not mistaken for a limit.
async fn measure_mtu(
    dst: Ipv4Addr,
    ident: u16,
    seq: &AtomicU16,
    timeout: Duration,
    cancel: &AtomicBool,
) -> Option<MtuResult> {
    let mut search = MtuSearch::new(MTU_MAX);
    while let Some(size) = search.next_size() {
        if cancel.load(Ordering::Relaxed) {
            return None;
        }
        let mut result = MtuProbe::Lost;
        for _ in 0..2 {
            let spec = ProbeSpec {
                dst,
                ttl: MTU_PROBE_TTL,
                ident,
                seq: seq.fetch_add(1, Ordering::Relaxed),
                size,
                df: true,
                timeout,
            };
            let r = tokio::task::spawn_blocking(move || probe::probe(&spec))
                .await
                .ok()
                .and_then(Result::ok);
            result = match r.map(|r| (r.outcome, r.responder)) {
                Some((Outcome::Reached, _)) => MtuProbe::Fits,
                Some((Outcome::TooBig(mtu), from)) => MtuProbe::TooBig { mtu, from },
                _ => MtuProbe::Lost,
            };
            if result != MtuProbe::Lost {
                break;
            }
        }
        search.feed(size, result);
    }
    search.result().cloned()
}

/// Random bits from the std hasher's per-process keys plus the clock.
fn random_u64() -> u64 {
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write_u128(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
    );
    h.finish()
}
