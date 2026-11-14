//! Tauri commands for the connectivity monitor. Each target runs in its own
//! task that waits for its probe before the next tick, so probes for one
//! target never overlap; a slow probe delays the next one instead.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tauri::State;
use tauri::ipc::Channel;
use tokio::sync::watch;
use tokio::time::MissedTickBehavior;

use super::probes::{self, Sample, Target};

/// Most targets in one monitor.
const MAX_TARGETS: usize = 20;
/// Largest CSV export written.
const MAX_CSV: usize = 50 * 1024 * 1024;

#[derive(Default)]
pub struct MonitorRegistry {
    inner: Arc<Mutex<HashMap<u32, watch::Sender<bool>>>>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MonitorRequest {
    pub targets: Vec<Target>,
    pub interval_ms: u64,
    pub timeout_ms: u64,
}

#[derive(Clone, Serialize)]
#[serde(
    tag = "type",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum MonitorEvent {
    Started {
        icmp_method: String,
    },
    Sample {
        sample: Sample,
    },
    /// A probe took longer than the interval; the next one was delayed.
    Overrun {
        target: u32,
        ms: u64,
    },
    Stopped,
}

#[tauri::command]
pub fn mon_stop(registry: State<'_, MonitorRegistry>, id: u32) {
    if let Some(tx) = registry
        .inner
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .get(&id)
    {
        let _ = tx.send(true);
    }
}

/// Write exported samples (CSV built by the UI) to a chosen path.
#[tauri::command]
pub fn mon_save(path: String, contents: String) -> Result<(), String> {
    if contents.len() > MAX_CSV {
        return Err("export larger than 50 MB".into());
    }
    std::fs::write(&path, contents).map_err(|e| format!("could not write {path}: {e}"))
}

/// Monitor until stopped.
#[tauri::command]
pub async fn mon_start(
    registry: State<'_, MonitorRegistry>,
    id: u32,
    req: MonitorRequest,
    on_event: Channel<MonitorEvent>,
) -> Result<(), String> {
    if req.targets.is_empty() {
        return Err("add at least one target".into());
    }
    if req.targets.len() > MAX_TARGETS {
        return Err(format!("at most {MAX_TARGETS} targets"));
    }
    for t in &req.targets {
        probes::validate(t)?;
    }
    let interval = Duration::from_millis(req.interval_ms.clamp(1000, 3_600_000));
    // A probe never runs longer than the interval allows.
    let timeout = Duration::from_millis(req.timeout_ms.clamp(200, 30_000)).min(interval);

    let (tx, rx) = watch::channel(false);
    registry
        .inner
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .insert(id, tx);
    let _ = on_event.send(MonitorEvent::Started {
        icmp_method: crate::tools::traceroute::probe::method(),
    });

    let ident = (id & 0xffff) as u16;
    let mut tasks = tokio::task::JoinSet::new();
    for t in req.targets {
        let mut stop = rx.clone();
        let ev = on_event.clone();
        tasks.spawn(async move {
            let mut tick = tokio::time::interval(interval);
            tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
            let mut seq: u64 = 0;
            loop {
                tokio::select! {
                    _ = stop.changed() => break,
                    _ = tick.tick() => {}
                }
                seq += 1;
                let target = t.clone();
                let started = std::time::Instant::now();
                let probe =
                    tokio::task::spawn_blocking(move || probes::run(&target, seq, timeout, ident));
                let sample = tokio::select! {
                    _ = stop.changed() => break,
                    r = probe => match r { Ok(s) => s, Err(_) => continue },
                };
                let _ = ev.send(MonitorEvent::Sample { sample });
                let took = started.elapsed();
                if took > interval {
                    let _ = ev.send(MonitorEvent::Overrun {
                        target: t.id,
                        ms: took.as_millis() as u64,
                    });
                }
            }
        });
    }
    let mut stop = rx.clone();
    let _ = stop.wait_for(|s| *s).await;
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    registry
        .inner
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .remove(&id);
    let _ = on_event.send(MonitorEvent::Stopped);
    Ok(())
}
