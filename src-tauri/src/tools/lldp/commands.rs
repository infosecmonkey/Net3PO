//! Tauri commands for LLDP/CDP neighbors: listen on an interface through a
//! user-installed libpcap/Npcap, or read a capture file (no library needed).

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use tauri::State;
use tauri::ipc::Channel;

use super::capture::{self, Device, Next, Pcap};
use super::core::{self, FileResult, Seen, Tracker};

#[derive(Default)]
pub struct LldpRegistry {
    inner: Arc<Mutex<HashMap<u32, Arc<AtomicBool>>>>,
}

/// Longest listen, even when "until stopped" is chosen.
const MAX_LISTEN: Duration = Duration::from_secs(3600);
/// Neighbor updates streamed per second at most; floods are counted.
const MAX_EVENTS_PER_SEC: u32 = 20;
/// Largest capture file read.
const MAX_FILE_BYTES: u64 = 2 * 1024 * 1024 * 1024;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    pub available: bool,
    pub version: String,
    /// Why capture is unavailable, with what to install.
    pub error: String,
    pub devices: Vec<Device>,
}

#[derive(Clone, Serialize)]
#[serde(
    tag = "type",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum LldpEvent {
    Started { device: String, link: i32 },
    Neighbor { seen: Box<Seen> },
    Warning { message: String },
    Done { frames: u64, cancelled: bool },
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Whether live capture is available, and the interfaces it can open.
#[tauri::command]
pub async fn lldp_status() -> Status {
    tokio::task::spawn_blocking(|| match Pcap::load() {
        Ok(p) => {
            let version = p.version();
            match p.devices() {
                Ok(mut devices) => {
                    devices.retain(|d| !d.loopback);
                    Status {
                        available: true,
                        version,
                        error: String::new(),
                        devices,
                    }
                }
                Err(e) => Status {
                    available: false,
                    version,
                    error: capture::open_error(&format!("could not list interfaces: {e}")),
                    devices: Vec::new(),
                },
            }
        }
        Err(e) => Status {
            available: false,
            version: String::new(),
            error: e,
            devices: Vec::new(),
        },
    })
    .await
    .unwrap_or_else(|e| Status {
        available: false,
        version: String::new(),
        error: e.to_string(),
        devices: Vec::new(),
    })
}

/// Stop a listen by id.
#[tauri::command]
pub fn lldp_stop(registry: State<'_, LldpRegistry>, run_id: u32) {
    if let Some(flag) = registry.inner.lock().unwrap().get(&run_id) {
        flag.store(true, Ordering::Relaxed);
    }
}

/// Listen on `device` for `seconds` (0: until stopped, at most an hour),
/// streaming each neighbor as it announces itself.
#[tauri::command]
pub async fn lldp_listen(
    registry: State<'_, LldpRegistry>,
    run_id: u32,
    device: String,
    seconds: u64,
    on_event: Channel<LldpEvent>,
) -> Result<(), String> {
    if device.trim().is_empty() {
        return Err("choose an interface".into());
    }
    let cancel = Arc::new(AtomicBool::new(false));
    let reg = registry.inner.clone();
    reg.lock().unwrap().insert(run_id, cancel.clone());
    let limit = if seconds == 0 {
        MAX_LISTEN
    } else {
        Duration::from_secs(seconds).min(MAX_LISTEN)
    };
    let result = tokio::task::spawn_blocking(move || listen(&device, limit, &cancel, &on_event))
        .await
        .map_err(|e| e.to_string())
        .and_then(|r| r);
    reg.lock().unwrap().remove(&run_id);
    result
}

fn listen(
    device: &str,
    limit: Duration,
    cancel: &AtomicBool,
    events: &Channel<LldpEvent>,
) -> Result<(), String> {
    let pcap = Pcap::load()?;
    let mut h = pcap.open(device)?;
    let link = h.link();
    if !matches!(link, core::LINK_ETHERNET | core::LINK_SLL | core::LINK_SLL2) {
        return Err(format!(
            "{device} is not an Ethernet interface (link type {link}); LLDP and CDP run on Ethernet"
        ));
    }
    let _ = events.send(LldpEvent::Started {
        device: device.to_string(),
        link,
    });

    let start = Instant::now();
    let mut tracker = Tracker::default();
    let mut frames = 0u64;
    let mut window = (Instant::now(), 0u32, 0u64);
    let mut cap_warned = false;
    let mut errors = 0u32;
    while !cancel.load(Ordering::Relaxed) && start.elapsed() < limit {
        let frame = match h.next() {
            Ok(Next::Frame(f)) => f.to_vec(),
            Ok(Next::Timeout) => continue,
            Err(e) => {
                errors += 1;
                if errors >= 20 {
                    return Err(format!("capture stopped: {e}"));
                }
                continue;
            }
        };
        let Some(found) = core::find(link, &frame) else {
            continue;
        };
        frames += 1;
        let n = core::decode(&found);
        let Some(seen) = tracker.record(n, now_ms()).cloned() else {
            if !cap_warned {
                cap_warned = true;
                let _ = events.send(LldpEvent::Warning {
                    message: format!(
                        "more than {} neighbors; ignoring new ones (possible flood)",
                        core::MAX_NEIGHBORS
                    ),
                });
            }
            continue;
        };
        if window.0.elapsed() >= Duration::from_secs(1) {
            if window.2 > 0 {
                let _ = events.send(LldpEvent::Warning {
                    message: format!("{} updates not shown (rate limit)", window.2),
                });
            }
            window = (Instant::now(), 0, 0);
        }
        if window.1 >= MAX_EVENTS_PER_SEC {
            window.2 += 1;
            continue;
        }
        window.1 += 1;
        let _ = events.send(LldpEvent::Neighbor {
            seen: Box::new(seen),
        });
    }
    let _ = events.send(LldpEvent::Done {
        frames,
        cancelled: cancel.load(Ordering::Relaxed),
    });
    Ok(())
}

/// Read LLDP and CDP neighbors from a PCAP or PCAPNG file.
#[tauri::command]
pub async fn lldp_read_file(path: String) -> Result<FileResult, String> {
    tokio::task::spawn_blocking(move || {
        let file = std::fs::File::open(&path).map_err(|e| format!("could not open {path}: {e}"))?;
        let size = file.metadata().map(|m| m.len()).unwrap_or(0);
        if size > MAX_FILE_BYTES {
            return Err("capture file larger than 2 GB".into());
        }
        core::read_capture(std::io::BufReader::new(file))
    })
    .await
    .map_err(|e| e.to_string())?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn reads_a_file_from_disk() {
        let path =
            std::env::temp_dir().join(format!("omnipacket_lldp_{}.pcap", std::process::id()));
        let bytes =
            core::tests::pcap_file(&[core::tests::lldp_frame(false), core::tests::cdp_frame()]);
        std::fs::write(&path, bytes).unwrap();
        let r = lldp_read_file(path.display().to_string()).await.unwrap();
        assert_eq!(r.neighbors.len(), 2);
        let _ = std::fs::remove_file(&path);
        assert!(lldp_read_file("/nonexistent/x.pcap".into()).await.is_err());
    }

    #[tokio::test]
    async fn status_never_fails() {
        let s = lldp_status().await;
        if !s.available {
            assert!(!s.error.is_empty());
        }
    }
}
