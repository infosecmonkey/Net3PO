//! Tauri commands for the hash calculator. Files are streamed on a blocking
//! thread with progress events and can be stopped.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::Serialize;
use tauri::State;
use tauri::ipc::Channel;

use super::core::{self, Comparison, Digests};

#[derive(Default)]
pub struct HashRegistry {
    inner: Arc<Mutex<HashMap<u32, Arc<AtomicBool>>>>,
}

#[derive(Clone, Serialize)]
#[serde(
    tag = "type",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum HashEvent {
    Started { size: u64 },
    Progress { bytes: u64 },
}

/// Hash text as its UTF-8 bytes, exactly as typed.
#[tauri::command]
pub fn hash_text(text: String) -> Digests {
    core::hash_bytes(text.as_bytes())
}

/// Compare an expected digest with computed ones.
#[tauri::command]
pub fn hash_compare(expected: String, digests: Digests) -> Comparison {
    core::compare(&expected, &digests)
}

#[tauri::command]
pub fn hash_stop(registry: State<'_, HashRegistry>, id: u32) {
    if let Some(flag) = registry
        .inner
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .get(&id)
    {
        flag.store(true, Ordering::Relaxed);
    }
}

/// Hash a file. Returns None when stopped.
#[tauri::command]
pub async fn hash_file(
    registry: State<'_, HashRegistry>,
    id: u32,
    path: String,
    on_event: Channel<HashEvent>,
) -> Result<Option<Digests>, String> {
    let stop = Arc::new(AtomicBool::new(false));
    registry
        .inner
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .insert(id, stop.clone());
    let reg = registry.inner.clone();
    let res = tokio::task::spawn_blocking(move || {
        let f = std::fs::File::open(&path).map_err(|e| format!("could not open {path}: {e}"))?;
        let size = f.metadata().map(|m| m.len()).unwrap_or(0);
        let _ = on_event.send(HashEvent::Started { size });
        let mut last = Instant::now();
        core::hash_reader(f, |bytes| {
            if last.elapsed() > Duration::from_millis(150) {
                last = Instant::now();
                let _ = on_event.send(HashEvent::Progress { bytes });
            }
            !stop.load(Ordering::Relaxed)
        })
        .map_err(|e| format!("reading {path}: {e}"))
    })
    .await
    .map_err(|e| e.to_string())?;
    reg.lock().unwrap_or_else(|p| p.into_inner()).remove(&id);
    res
}
