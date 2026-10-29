//! Tauri commands for projects. The directory is always
//! `<app data>/projects`; the UI only passes ids the backend generated. A lock
//! serializes access so two panels cannot interleave writes.

use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use tauri::{AppHandle, Manager, State};

use super::core::{self, ItemEdit, ProjectStore, ProjectSummary, ProjectView};
use crate::report::core::{self as report, Format, Report};

/// Serializes project reads and writes.
#[derive(Default)]
pub struct ProjectsLock(Mutex<()>);

fn open_store(app: &AppHandle) -> Result<ProjectStore, String> {
    let data = app
        .path()
        .app_data_dir()
        .map_err(|e| format!("could not locate the app data folder: {e}"))?;
    Ok(ProjectStore::new(core::projects_dir(&data)))
}

fn now() -> (u64, u128) {
    let d = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    (d.as_secs(), d.as_nanos())
}

/// Every project, most recently updated first.
#[tauri::command]
pub fn project_list(
    app: AppHandle,
    lock: State<'_, ProjectsLock>,
) -> Result<Vec<ProjectSummary>, String> {
    let _g = lock.0.lock().unwrap_or_else(|p| p.into_inner());
    open_store(&app)?.list().map_err(|e| e.to_string())
}

/// Create an empty project.
#[tauri::command]
pub fn project_create(
    app: AppHandle,
    lock: State<'_, ProjectsLock>,
    name: String,
) -> Result<ProjectSummary, String> {
    let _g = lock.0.lock().unwrap_or_else(|p| p.into_inner());
    let (secs, nanos) = now();
    open_store(&app)?
        .create(&name, core::new_id(nanos), secs)
        .map_err(|e| e.to_string())
}

/// One project with its item list (without item contents).
#[tauri::command]
pub fn project_get(
    app: AppHandle,
    lock: State<'_, ProjectsLock>,
    id: String,
) -> Result<ProjectView, String> {
    let _g = lock.0.lock().unwrap_or_else(|p| p.into_inner());
    open_store(&app)?.get(&id).map_err(|e| e.to_string())
}

/// Save the name, notes, and item order, titles and notes.
#[tauri::command]
pub fn project_update(
    app: AppHandle,
    lock: State<'_, ProjectsLock>,
    id: String,
    name: String,
    notes: String,
    items: Vec<ItemEdit>,
) -> Result<ProjectView, String> {
    let _g = lock.0.lock().unwrap_or_else(|p| p.into_inner());
    open_store(&app)?
        .update(&id, &name, &notes, &items, now().0)
        .map_err(|e| e.to_string())
}

/// Delete a project file.
#[tauri::command]
pub fn project_delete(
    app: AppHandle,
    lock: State<'_, ProjectsLock>,
    id: String,
) -> Result<(), String> {
    let _g = lock.0.lock().unwrap_or_else(|p| p.into_inner());
    open_store(&app)?.delete(&id).map_err(|e| e.to_string())
}

/// Add a tool's report to a project.
#[tauri::command]
pub fn project_add(
    app: AppHandle,
    lock: State<'_, ProjectsLock>,
    id: String,
    tool: String,
    added_label: String,
    report: Report,
) -> Result<ProjectSummary, String> {
    let _g = lock.0.lock().unwrap_or_else(|p| p.into_inner());
    let (secs, nanos) = now();
    open_store(&app)?
        .add(&id, core::new_id(nanos), &tool, &added_label, report, secs)
        .map_err(|e| e.to_string())
}

/// Render the whole project as one report and write it to `path` (chosen by
/// the UI via a native save dialog). Returns the number of bytes written.
#[tauri::command]
pub fn project_export(
    app: AppHandle,
    lock: State<'_, ProjectsLock>,
    id: String,
    format: Format,
    path: String,
    generated: String,
) -> Result<usize, String> {
    let combined = {
        let _g = lock.0.lock().unwrap_or_else(|p| p.into_inner());
        open_store(&app)?
            .report(&id, &generated)
            .map_err(|e| e.to_string())?
    };
    let bytes = report::render(&combined, format).map_err(|e| e.to_string())?;
    std::fs::write(&path, &bytes).map_err(|e| format!("could not write {path}: {e}"))?;
    Ok(bytes.len())
}
