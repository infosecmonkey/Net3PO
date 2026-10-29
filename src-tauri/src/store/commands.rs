//! Tauri commands for the local store. The directory is always the OS app
//! data dir; the UI only names a collection. A lock serializes access so two
//! panels saving at once cannot interleave.

use std::path::PathBuf;
use std::sync::Mutex;

use serde_json::Value;
use tauri::{AppHandle, Manager, State};

use super::core::{self, Loaded};

/// Serializes store reads and writes.
#[derive(Default)]
pub struct StoreLock(Mutex<()>);

impl StoreLock {
    /// Hold the store lock, for other modules that read or write collections.
    pub fn guard(&self) -> std::sync::MutexGuard<'_, ()> {
        self.0.lock().unwrap_or_else(|p| p.into_inner())
    }
}

/// The OS app data dir where collections live.
pub fn app_data_dir(app: &AppHandle) -> Result<PathBuf, String> {
    data_dir(app)
}

fn data_dir(app: &AppHandle) -> Result<PathBuf, String> {
    app.path()
        .app_data_dir()
        .map_err(|e| format!("could not locate the app data folder: {e}"))
}

/// Load a collection's items.
#[tauri::command]
pub fn store_load(
    app: AppHandle,
    lock: State<'_, StoreLock>,
    collection: String,
) -> Result<Loaded, String> {
    let _guard = lock.0.lock().unwrap_or_else(|p| p.into_inner());
    core::load(&data_dir(&app)?, &collection).map_err(|e| e.to_string())
}

/// Replace a collection's items.
#[tauri::command]
pub fn store_save(
    app: AppHandle,
    lock: State<'_, StoreLock>,
    collection: String,
    items: Vec<Value>,
) -> Result<(), String> {
    let _guard = lock.0.lock().unwrap_or_else(|p| p.into_inner());
    core::save(&data_dir(&app)?, &collection, items).map_err(|e| e.to_string())
}
