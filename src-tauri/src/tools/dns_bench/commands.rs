//! Tauri commands for the DNS benchmark. Each resolver is tested on its own
//! thread; within a resolver, transports take turns each round so network
//! changes during a run affect them alike. Results stream over a channel and
//! a run can be cancelled.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use hickory_proto::op::ResponseCode;
use hickory_proto::rr::RecordType;
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use tauri::State;
use tauri::ipc::Channel;

use super::core::{self, Dnssec, Provider, Resolver, ResolverSpec, Stats, Transport};
use super::net::{self, Conn};

/// A transport is given up after this many failures in a row.
const MAX_CONSECUTIVE_FAILURES: u32 = 3;

/// Cancellation flags of running benchmarks, by run id.
#[derive(Default)]
pub struct BenchRegistry {
    inner: Arc<Mutex<HashMap<u32, Arc<AtomicBool>>>>,
}

/// Built-in resolvers and this computer's configured resolvers.
#[derive(Serialize)]
pub struct Defaults {
    pub providers: Vec<Provider>,
    pub system: Vec<String>,
}

/// What to run.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BenchConfig {
    pub resolvers: Vec<ResolverSpec>,
    pub transports: Vec<Transport>,
    /// Measured queries of each kind per resolver and transport.
    pub rounds: u32,
    /// Run the DNSSEC and NXDOMAIN checks.
    pub checks: bool,
}

/// Streamed events.
#[derive(Clone, Serialize)]
#[serde(
    tag = "type",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum BenchEvent {
    Started {
        total: u32,
    },
    Result {
        resolver_id: String,
        transport: Transport,
        connect_ms: Option<f64>,
        cached: Stats,
        uncached: Stats,
        error: Option<String>,
    },
    Check {
        resolver_id: String,
        dnssec: Dnssec,
        hijack: Option<bool>,
    },
    Progress {
        done: u32,
        total: u32,
    },
    Done {
        elapsed_ms: u64,
        cancelled: bool,
    },
    Error {
        message: String,
    },
}

/// Built-in resolvers plus the system resolvers.
#[tauri::command]
pub async fn dns_bench_defaults() -> Defaults {
    let system = tokio::task::spawn_blocking(|| {
        let mut out: Vec<String> = Vec::new();
        if let Ok((cfg, _)) = hickory_resolver::system_conf::read_system_conf() {
            for ns in cfg.name_servers() {
                let ip = ns.ip.to_string();
                if !out.contains(&ip) {
                    out.push(ip);
                }
            }
        }
        out
    })
    .await
    .unwrap_or_default();
    Defaults {
        providers: core::providers(),
        system,
    }
}

/// Cancel a running benchmark.
#[tauri::command]
pub fn dns_bench_cancel(registry: State<'_, BenchRegistry>, run_id: u32) {
    if let Some(flag) = registry.inner.lock().unwrap().get(&run_id) {
        flag.store(true, Ordering::Relaxed);
    }
}

/// Run a benchmark, streaming results to `on_event`.
#[tauri::command]
pub async fn dns_bench_run(
    registry: State<'_, BenchRegistry>,
    run_id: u32,
    config: BenchConfig,
    on_event: Channel<BenchEvent>,
) -> Result<(), String> {
    let (resolvers, transports) =
        core::validate_run(&config.resolvers, &config.transports).map_err(|e| e.to_string())?;
    let rounds = config.rounds.clamp(1, core::MAX_ROUNDS);
    let reg = registry.inner.clone();
    let cancel = Arc::new(AtomicBool::new(false));
    reg.lock().unwrap().insert(run_id, cancel.clone());

    let events = on_event.clone();
    let flag = cancel.clone();
    let checks = config.checks;
    let res = tokio::task::spawn_blocking(move || {
        run(
            &resolvers,
            &transports,
            rounds,
            checks,
            &|e| {
                let _ = events.send(e);
            },
            &flag,
        )
    })
    .await;
    reg.lock().unwrap().remove(&run_id);
    if let Err(e) = res {
        let message = format!("benchmark stopped: {e}");
        let _ = on_event.send(BenchEvent::Error {
            message: message.clone(),
        });
        return Err(message);
    }
    Ok(())
}

fn run(
    resolvers: &[Resolver],
    transports: &[Transport],
    rounds: u32,
    checks: bool,
    events: &(dyn Fn(BenchEvent) + Sync),
    cancel: &AtomicBool,
) {
    let start = Instant::now();
    let per_resolver = |r: &Resolver| {
        let live = transports.iter().filter(|t| r.supports(**t)).count() as u32;
        live * rounds * 2 + if checks { 3 } else { 0 }
    };
    let total: u32 = resolvers.iter().map(per_resolver).sum();
    events(BenchEvent::Started { total });
    let done = AtomicU32::new(0);
    std::thread::scope(|s| {
        for r in resolvers {
            let done = &done;
            s.spawn(move || {
                bench_resolver(r, transports, rounds, checks, events, cancel, done, total)
            });
        }
    });
    events(BenchEvent::Done {
        elapsed_ms: start.elapsed().as_millis() as u64,
        cancelled: cancel.load(Ordering::Relaxed),
    });
}

/// One transport's state during a run.
struct Lane {
    transport: Transport,
    conn: Option<Conn>,
    connect_ms: Option<f64>,
    error: Option<String>,
    failures: u32,
    dead: bool,
    cached: Vec<f64>,
    uncached: Vec<f64>,
    cached_sent: u32,
    uncached_sent: u32,
}

struct Rng(SystemRandom);

impl Rng {
    fn bytes<const N: usize>(&self) -> [u8; N] {
        let mut b = [0u8; N];
        // SystemRandom only fails if the OS has no randomness source; fall
        // back to the clock so a benchmark still runs.
        if self.0.fill(&mut b).is_err() {
            let t = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0)
                .to_le_bytes();
            for (i, x) in b.iter_mut().enumerate() {
                *x = t[i % 4].wrapping_add(i as u8);
            }
        }
        b
    }
    fn id(&self) -> u16 {
        u16::from_le_bytes(self.bytes::<2>())
    }
    fn label(&self) -> String {
        core::random_label(&self.bytes::<16>())
    }
}

/// Send one query on `lane`, reconnecting once if the connection dropped.
/// Returns the latency in ms and the parsed answer.
fn query(
    r: &Resolver,
    lane: &mut Lane,
    rng: &Rng,
    name: &str,
    rtype: RecordType,
    dnssec: bool,
) -> Result<(f64, core::Answer), String> {
    if lane.conn.is_none() {
        let (c, ms) = net::connect(lane.transport, r.ip, r.doh.as_deref(), r.dot.as_deref())?;
        lane.conn = Some(c);
        if lane.connect_ms.is_none() {
            lane.connect_ms = ms;
        }
    }
    // DoH uses ID 0 (RFC 8484) and has no ID check.
    let doh = lane.transport == Transport::Doh;
    let id = if doh { 0 } else { rng.id() };
    let q = core::build_query(id, name, rtype, dnssec).map_err(|e| e.to_string())?;
    let conn = lane.conn.as_mut().expect("connected above");
    let start = Instant::now();
    let res = net::exchange(conn, &q, id);
    let ms = start.elapsed().as_secs_f64() * 1000.0;
    match res {
        Ok(bytes) => {
            // DoH connects inside the first request; report that request
            // as its connect time.
            if doh && lane.connect_ms.is_none() {
                lane.connect_ms = Some(ms);
            }
            let a = core::parse_answer(&bytes, (!doh).then_some(id)).map_err(|e| e.to_string())?;
            Ok((ms, a))
        }
        Err(e) => {
            // Drop stream connections so the next query reconnects.
            if !matches!(lane.transport, Transport::Udp) {
                lane.conn = None;
            }
            Err(e)
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn bench_resolver(
    r: &Resolver,
    transports: &[Transport],
    rounds: u32,
    checks: bool,
    events: &(dyn Fn(BenchEvent) + Sync),
    cancel: &AtomicBool,
    done: &AtomicU32,
    total: u32,
) {
    let rng = Rng(SystemRandom::new());
    let mut lanes: Vec<Lane> = transports
        .iter()
        .filter(|t| r.supports(**t))
        .map(|&transport| Lane {
            transport,
            conn: None,
            connect_ms: None,
            error: None,
            failures: 0,
            dead: false,
            cached: Vec::new(),
            uncached: Vec::new(),
            cached_sent: 0,
            uncached_sent: 0,
        })
        .collect();
    let tick = |n: u32| {
        let d = done.fetch_add(n, Ordering::Relaxed) + n;
        events(BenchEvent::Progress { done: d, total });
    };
    let stopped = || cancel.load(Ordering::Relaxed);

    // Connect each lane, then warm the cache through it (not measured).
    for lane in &mut lanes {
        if stopped() {
            break;
        }
        for name in core::CACHED_NAMES {
            if let Err(e) = query(r, lane, &rng, name, RecordType::A, false) {
                lane.error = Some(e);
                lane.failures += 1;
                if lane.failures >= MAX_CONSECUTIVE_FAILURES {
                    lane.dead = true;
                    break;
                }
            } else {
                lane.failures = 0;
            }
        }
    }

    let mut hijack_seen = false;
    for round in 0..rounds {
        if stopped() {
            break;
        }
        let cached_name = core::CACHED_NAMES[round as usize % core::CACHED_NAMES.len()];
        let zone = core::UNCACHED_ZONES[round as usize % core::UNCACHED_ZONES.len()];
        for lane in &mut lanes {
            lane.cached_sent += 1;
            lane.uncached_sent += 1;
            if lane.dead {
                continue;
            }
            match query(r, lane, &rng, cached_name, RecordType::A, false) {
                Ok((ms, a)) if a.rcode == ResponseCode::NoError => {
                    lane.cached.push(ms);
                    lane.failures = 0;
                }
                Ok((_, a)) => lane.error = Some(format!("{cached_name}: {}", a.rcode)),
                Err(e) => fail(lane, e),
            }
            let uncached = format!("{}.{zone}", rng.label());
            match query(r, lane, &rng, &uncached, RecordType::A, false) {
                Ok((ms, a))
                    if matches!(a.rcode, ResponseCode::NXDomain | ResponseCode::NoError) =>
                {
                    hijack_seen |= core::is_hijack(&a);
                    lane.uncached.push(ms);
                    lane.failures = 0;
                }
                Ok((_, a)) => lane.error = Some(format!("random name: {}", a.rcode)),
                Err(e) => fail(lane, e),
            }
        }
        tick(lanes.len() as u32 * 2);
    }

    for lane in &lanes {
        events(BenchEvent::Result {
            resolver_id: r.id.clone(),
            transport: lane.transport,
            connect_ms: lane.connect_ms.map(|v| (v * 10.0).round() / 10.0),
            cached: core::stats(&lane.cached, lane.cached_sent),
            uncached: core::stats(&lane.uncached, lane.uncached_sent),
            error: if lane.cached.is_empty() && lane.uncached.is_empty() {
                lane.error.clone().or_else(|| Some("no answers".into()))
            } else {
                None
            },
        });
    }

    if checks && !stopped() {
        // Use the first transport that answered.
        let lane = lanes
            .iter_mut()
            .find(|l| !l.dead && !(l.cached.is_empty() && l.uncached.is_empty()));
        let (dnssec, hijack) = match lane {
            Some(lane) => {
                let signed = query(r, lane, &rng, core::SIGNED_NAME, RecordType::A, true).ok();
                let broken =
                    query(r, lane, &rng, core::BROKEN_DNSSEC_NAME, RecordType::A, true).ok();
                let nx = query(
                    r,
                    lane,
                    &rng,
                    &format!("{}.com", rng.label()),
                    RecordType::A,
                    false,
                )
                .ok();
                let verdict = core::dnssec_verdict(
                    signed.as_ref().map(|x| &x.1),
                    broken.as_ref().map(|x| &x.1),
                );
                let hijack = match nx {
                    Some((_, a)) => Some(hijack_seen || core::is_hijack(&a)),
                    None if hijack_seen => Some(true),
                    None => None,
                };
                (verdict, hijack)
            }
            None => (Dnssec::Unknown, None),
        };
        events(BenchEvent::Check {
            resolver_id: r.id.clone(),
            dnssec,
            hijack,
        });
        tick(3);
    }
}

fn fail(lane: &mut Lane, e: String) {
    lane.error = Some(e);
    lane.failures += 1;
    if lane.failures >= MAX_CONSECUTIVE_FAILURES {
        lane.dead = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Full run against two public resolvers; run with `--ignored`.
    #[test]
    #[ignore]
    fn live_run() {
        let specs: Vec<ResolverSpec> = core::providers()
            .into_iter()
            .filter(|p| p.id == "cloudflare" || p.id == "quad9")
            .map(|p| ResolverSpec {
                id: p.id.into(),
                name: p.name.into(),
                ip: p.ipv4[0].into(),
                doh: p.doh.into(),
                dot: p.dot.into(),
            })
            .collect();
        let (rs, ts) = core::validate_run(
            &specs,
            &[
                Transport::Udp,
                Transport::Tcp,
                Transport::Dot,
                Transport::Doh,
            ],
        )
        .unwrap();
        let cancel = AtomicBool::new(false);
        let out = Mutex::new(Vec::new());
        run(&rs, &ts, 5, true, &|e| out.lock().unwrap().push(e), &cancel);
        for e in out.lock().unwrap().iter() {
            if !matches!(e, BenchEvent::Progress { .. }) {
                println!("{}", serde_json::to_string(e).unwrap());
            }
        }
    }
}
