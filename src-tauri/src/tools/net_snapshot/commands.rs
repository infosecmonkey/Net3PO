//! Tauri commands for network snapshots.

use std::path::PathBuf;

use tauri::AppHandle;

use super::model::{self, SectionDiff, Snapshot};
use super::store::{self, Store, Summary};
use crate::store::commands::app_data_dir;

fn store(app: &AppHandle) -> Result<Store, String> {
    Ok(Store::new(app_data_dir(app)?.join("snapshots")))
}

/// A new id and RFC 3339 time for "now".
fn stamp() -> (String, String) {
    let now = jiff::Zoned::now();
    let id = format!("{}-{:03}", now.strftime("%Y%m%d-%H%M%S"), now.millisecond());
    let taken = now.strftime("%Y-%m-%dT%H:%M:%S%:z").to_string();
    (id, taken)
}

/// Take a snapshot of this computer and save it.
#[tauri::command]
pub async fn snap_take(app: AppHandle) -> Result<Snapshot, String> {
    let mut s = super::collect::take().await;
    let (id, taken) = stamp();
    s.id = id;
    s.taken = taken;
    let st = store(&app)?;
    let saved = s.clone();
    tauri::async_runtime::spawn_blocking(move || st.save(&saved))
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())?;
    Ok(s)
}

/// Saved snapshots, newest first.
#[tauri::command]
pub fn snap_list(app: AppHandle) -> Result<Vec<Summary>, String> {
    store(&app)?.list().map_err(|e| e.to_string())
}

#[tauri::command]
pub fn snap_get(app: AppHandle, id: String) -> Result<Snapshot, String> {
    store(&app)?.get(&id).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn snap_label(app: AppHandle, id: String, label: String) -> Result<(), String> {
    store(&app)?
        .set_label(&id, &label)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn snap_delete(app: AppHandle, id: String) -> Result<(), String> {
    store(&app)?.delete(&id).map_err(|e| e.to_string())
}

/// Compare saved snapshot `a` (before) with `b` (after).
#[tauri::command]
pub fn snap_compare(app: AppHandle, a: String, b: String) -> Result<Vec<SectionDiff>, String> {
    let st = store(&app)?;
    let sa = st.get(&a).map_err(|e| format!("snapshot A: {e}"))?;
    let sb = st.get(&b).map_err(|e| format!("snapshot B: {e}"))?;
    Ok(model::compare(&sa, &sb))
}

/// Write a saved snapshot to a file the user chose.
#[tauri::command]
pub fn snap_export_file(app: AppHandle, id: String, path: String) -> Result<(), String> {
    let s = store(&app)?.get(&id).map_err(|e| e.to_string())?;
    let json = serde_json::to_vec_pretty(&s).map_err(|e| e.to_string())?;
    std::fs::write(PathBuf::from(path), json).map_err(|e| format!("could not write the file: {e}"))
}

/// Add a snapshot file (for example from another computer) to the saved list.
#[tauri::command]
pub fn snap_import_file(app: AppHandle, path: String) -> Result<Summary, String> {
    let (id, _) = stamp();
    store(&app)?
        .import(&PathBuf::from(path), id)
        .map_err(|e| match e {
            store::StoreError::Io(io) => format!("could not read the file: {io}"),
            other => other.to_string(),
        })
}
