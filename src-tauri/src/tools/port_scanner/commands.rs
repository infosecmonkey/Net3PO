//! Tauri commands for the port scanner. Runs a TCP connect scan with bounded
//! concurrency, streams open ports and progress to the UI over a channel, and
//! can be cancelled mid-run.

use std::collections::HashMap;
use std::io::ErrorKind;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::Serialize;
use tauri::State;
use tauri::ipc::Channel;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use super::core::{self, ScanParams};

/// Tracks in-flight scans so they can be cancelled by id.
#[derive(Default)]
pub struct ScanRegistry {
    inner: Arc<Mutex<HashMap<u32, Arc<AtomicBool>>>>,
}

/// Streamed scan events.
#[derive(Clone, Serialize)]
#[serde(
    tag = "type",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum ScanEvent {
    Open {
        host: String,
        port: u16,
        service: Option<String>,
    },
    Progress {
        done: usize,
        total: usize,
        open: usize,
    },
    Done {
        total: usize,
        hosts: usize,
        hosts_with_open: usize,
        open: usize,
        closed: usize,
        filtered: usize,
        elapsed_ms: u64,
        cancelled: bool,
    },
    Error {
        message: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum PortState {
    Open,
    Closed,
    Filtered,
}

/// Progress events are emitted at most this many times over a scan (plus the
/// floor below), so a large host*port scan does not flood the UI.
const MAX_PROGRESS_EVENTS: usize = 200;
/// Never emit progress more often than every this many connections.
const PROGRESS_FLOOR: usize = 64;

/// Cancel a running scan by id.
#[tauri::command]
pub fn port_scan_cancel(registry: State<'_, ScanRegistry>, scan_id: u32) {
    if let Some(flag) = registry.inner.lock().unwrap().get(&scan_id) {
        flag.store(true, Ordering::Relaxed);
    }
}

/// Run a TCP connect scan against one host, streaming results to `on_event`.
#[tauri::command]
pub async fn port_scan(
    registry: State<'_, ScanRegistry>,
    scan_id: u32,
    target: String,
    ports: String,
    preset: String,
    on_event: Channel<ScanEvent>,
) -> Result<(), String> {
    // Register a cancellation flag and keep an owned handle for cleanup, so we
    // do not hold the State guard across awaits.
    let reg = registry.inner.clone();
    let cancel = Arc::new(AtomicBool::new(false));
    reg.lock().unwrap().insert(scan_id, cancel.clone());

    let result = run_scan(&target, &ports, &preset, &on_event, &cancel).await;

    reg.lock().unwrap().remove(&scan_id);

    if let Err(message) = &result {
        let _ = on_event.send(ScanEvent::Error {
            message: message.clone(),
        });
    }
    result
}

async fn run_scan(
    target: &str,
    ports: &str,
    preset: &str,
    on_event: &Channel<ScanEvent>,
    cancel: &Arc<AtomicBool>,
) -> Result<(), String> {
    let port_list = core::resolve_ports(ports).map_err(|e| e.to_string())?;
    let hosts = resolve_targets(target).await?;
    let ScanParams {
        concurrency,
        timeout_ms,
    } = core::preset_params(preset);
    let timeout = Duration::from_millis(timeout_ms);

    let total = hosts.len() * port_list.len();
    let progress_every = (total / MAX_PROGRESS_EVENTS).max(PROGRESS_FLOOR);
    let start = Instant::now();
    let semaphore = Arc::new(Semaphore::new(concurrency));
    let mut set: JoinSet<(IpAddr, u16, PortState)> = JoinSet::new();

    let mut done = 0usize;
    let mut open = 0usize;
    let mut closed = 0usize;
    let mut filtered = 0usize;
    let mut hosts_with_open: std::collections::HashSet<IpAddr> = std::collections::HashSet::new();

    'outer: for &ip in &hosts {
        for &port in &port_list {
            if cancel.load(Ordering::Relaxed) {
                break 'outer;
            }
            // acquire_owned pauses the loop when all permits are in use, which
            // bounds concurrency across the whole host*port set.
            let permit = semaphore.clone().acquire_owned().await.unwrap();
            set.spawn(async move {
                let _permit = permit;
                (ip, port, scan_one(ip, port, timeout).await)
            });

            while let Some(joined) = set.try_join_next() {
                let (host, port, state) = joined.map_err(|e| e.to_string())?;
                tally(
                    state,
                    host,
                    port,
                    on_event,
                    &mut open,
                    &mut closed,
                    &mut filtered,
                    &mut hosts_with_open,
                );
                done += 1;
                if done.is_multiple_of(progress_every) {
                    let _ = on_event.send(ScanEvent::Progress { done, total, open });
                }
            }
        }
    }

    // Drain the remaining in-flight connections.
    while let Some(joined) = set.join_next().await {
        let (host, port, state) = joined.map_err(|e| e.to_string())?;
        tally(
            state,
            host,
            port,
            on_event,
            &mut open,
            &mut closed,
            &mut filtered,
            &mut hosts_with_open,
        );
    }

    let cancelled = cancel.load(Ordering::Relaxed);
    let _ = on_event.send(ScanEvent::Done {
        total,
        hosts: hosts.len(),
        hosts_with_open: hosts_with_open.len(),
        open,
        closed,
        filtered,
        elapsed_ms: start.elapsed().as_millis() as u64,
        cancelled,
    });
    Ok(())
}

/// Record one result and stream an Open event for it.
#[allow(clippy::too_many_arguments)]
fn tally(
    state: PortState,
    host: IpAddr,
    port: u16,
    on_event: &Channel<ScanEvent>,
    open: &mut usize,
    closed: &mut usize,
    filtered: &mut usize,
    hosts_with_open: &mut std::collections::HashSet<IpAddr>,
) {
    match state {
        PortState::Open => {
            *open += 1;
            hosts_with_open.insert(host);
            let _ = on_event.send(ScanEvent::Open {
                host: host.to_string(),
                port,
                service: core::service_name(port).map(String::from),
            });
        }
        PortState::Closed => *closed += 1,
        PortState::Filtered => *filtered += 1,
    }
}

/// Expand the target spec and resolve any hostnames to addresses.
async fn resolve_targets(target: &str) -> Result<Vec<IpAddr>, String> {
    let targets = core::parse_targets(target).map_err(|e| e.to_string())?;
    let mut ips: Vec<IpAddr> = Vec::new();
    for t in targets {
        match t {
            core::Target::Ip(ip) => ips.push(ip),
            core::Target::Host(host) => {
                match tokio::net::lookup_host((host.as_str(), 0u16)).await {
                    Ok(addrs) => {
                        // Take the first resolved address for the host.
                        if let Some(first) = addrs.map(|s| s.ip()).next() {
                            ips.push(first);
                        } else {
                            return Err(format!("could not resolve '{host}'"));
                        }
                    }
                    Err(e) => return Err(format!("could not resolve '{host}': {e}")),
                }
            }
        }
    }
    if ips.len() > core::MAX_TARGETS {
        return Err(format!(
            "target set too large ({} addresses, max {})",
            ips.len(),
            core::MAX_TARGETS
        ));
    }
    Ok(ips)
}

/// A single TCP connect attempt, classified as open/closed/filtered.
async fn scan_one(ip: IpAddr, port: u16, timeout: Duration) -> PortState {
    let addr = SocketAddr::new(ip, port);
    match tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
        Ok(Ok(_stream)) => PortState::Open,
        Ok(Err(e)) => match e.kind() {
            ErrorKind::TimedOut => PortState::Filtered,
            // Refused and unreachable both mean "nothing listening here".
            _ => PortState::Closed,
        },
        // Our own timeout elapsed: no response, so treat as filtered.
        Err(_) => PortState::Filtered,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use tokio::net::TcpListener;

    #[test]
    fn done_event_fields_are_camel_case() {
        let ev = ScanEvent::Done {
            total: 1,
            hosts: 1,
            hosts_with_open: 1,
            open: 1,
            closed: 0,
            filtered: 0,
            elapsed_ms: 5,
            cancelled: false,
        };
        let v = serde_json::to_value(&ev).unwrap();
        assert_eq!(v["type"], "done");
        assert_eq!(v["hostsWithOpen"], 1);
        assert_eq!(v["elapsedMs"], 5);
    }

    #[tokio::test]
    async fn open_port_detected() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let state = scan_one(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            port,
            Duration::from_secs(1),
        )
        .await;
        assert_eq!(state, PortState::Open);
    }

    #[tokio::test]
    async fn closed_port_detected() {
        // Bind to get a free port, then drop the listener so nothing is there.
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let state = scan_one(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            port,
            Duration::from_secs(1),
        )
        .await;
        assert_eq!(state, PortState::Closed);
    }
}
