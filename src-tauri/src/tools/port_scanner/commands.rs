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
#[serde(tag = "type", rename_all = "camelCase")]
pub enum ScanEvent {
    Open {
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

/// How often to emit a progress event, in ports scanned.
const PROGRESS_EVERY: usize = 64;

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
    let ScanParams {
        concurrency,
        timeout_ms,
    } = core::preset_params(preset);
    let timeout = Duration::from_millis(timeout_ms);
    let ip = resolve_target(target).await?;

    let total = port_list.len();
    let start = Instant::now();
    let semaphore = Arc::new(Semaphore::new(concurrency));
    let mut set: JoinSet<(u16, PortState)> = JoinSet::new();

    let mut done = 0usize;
    let mut open = 0usize;
    let mut closed = 0usize;
    let mut filtered = 0usize;

    for port in port_list {
        if cancel.load(Ordering::Relaxed) {
            break;
        }
        // acquire_owned pauses the loop when all permits are in use, which
        // bounds concurrency.
        let permit = semaphore.clone().acquire_owned().await.unwrap();
        set.spawn(async move {
            let _permit = permit;
            (port, scan_one(ip, port, timeout).await)
        });

        while let Some(joined) = set.try_join_next() {
            let (port, state) = joined.map_err(|e| e.to_string())?;
            match state {
                PortState::Open => open += 1,
                PortState::Closed => closed += 1,
                PortState::Filtered => filtered += 1,
            }
            done += 1;
            if state == PortState::Open {
                let _ = on_event.send(ScanEvent::Open {
                    port,
                    service: core::service_name(port).map(String::from),
                });
            }
            if done.is_multiple_of(PROGRESS_EVERY) {
                let _ = on_event.send(ScanEvent::Progress { done, total, open });
            }
        }
    }

    // Drain the remaining in-flight connections.
    while let Some(joined) = set.join_next().await {
        let (port, state) = joined.map_err(|e| e.to_string())?;
        match state {
            PortState::Open => open += 1,
            PortState::Closed => closed += 1,
            PortState::Filtered => filtered += 1,
        }
        if state == PortState::Open {
            let _ = on_event.send(ScanEvent::Open {
                port,
                service: core::service_name(port).map(String::from),
            });
        }
    }

    let cancelled = cancel.load(Ordering::Relaxed);
    let _ = on_event.send(ScanEvent::Done {
        total,
        open,
        closed,
        filtered,
        elapsed_ms: start.elapsed().as_millis() as u64,
        cancelled,
    });
    Ok(())
}

/// Resolve a hostname or IP to a single address.
async fn resolve_target(target: &str) -> Result<IpAddr, String> {
    let t = target.trim();
    if t.is_empty() {
        return Err("enter a host or IP to scan".to_string());
    }
    if let Ok(ip) = t.parse::<IpAddr>() {
        return Ok(ip);
    }
    match tokio::net::lookup_host((t, 0u16)).await {
        Ok(mut addrs) => addrs
            .next()
            .map(|s| s.ip())
            .ok_or_else(|| format!("could not resolve '{t}'")),
        Err(e) => Err(format!("could not resolve '{t}': {e}")),
    }
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
