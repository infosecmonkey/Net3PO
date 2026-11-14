//! Tauri commands for projects. The directory is always
//! `<app data>/projects`; the UI only passes ids the backend generated. A lock
//! serializes access so two panels cannot interleave writes.

use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use tauri::{AppHandle, Manager, State};

use super::core::{self, ItemEdit, NoteInput, ProjectStore, ProjectSummary, ProjectView, ToolNote};
use crate::report::commands::{self as report_cmd, RedactPreview};
use crate::report::core::{Format, Report};
use crate::report::redact::RedactOptions;

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

fn combined(
    app: &AppHandle,
    lock: &State<'_, ProjectsLock>,
    id: &str,
    generated: &str,
) -> Result<Report, String> {
    let _g = lock.0.lock().unwrap_or_else(|p| p.into_inner());
    open_store(app)?
        .report(id, generated)
        .map_err(|e| e.to_string())
}

/// Save a timestamped tool note (add, or update the note with the same id).
#[tauri::command]
pub fn project_note_save(
    app: AppHandle,
    lock: State<'_, ProjectsLock>,
    id: String,
    note: NoteInput,
    edited_label: String,
) -> Result<ToolNote, String> {
    let _g = lock.0.lock().unwrap_or_else(|p| p.into_inner());
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    open_store(&app)?
        .save_note(&id, note, &edited_label, ms)
        .map_err(|e| e.to_string())
}

/// Delete a tool note.
#[tauri::command]
pub fn project_note_delete(
    app: AppHandle,
    lock: State<'_, ProjectsLock>,
    id: String,
    note_id: String,
) -> Result<(), String> {
    let _g = lock.0.lock().unwrap_or_else(|p| p.into_inner());
    open_store(&app)?
        .delete_note(&id, &note_id, now().0)
        .map_err(|e| e.to_string())
}

/// Render the whole project as one report and write it to `path` (chosen by
/// the UI via a native save dialog), redacted first when `redact` is set.
/// Returns the number of bytes written. Stored project data is not changed.
#[tauri::command]
pub fn project_export(
    app: AppHandle,
    lock: State<'_, ProjectsLock>,
    id: String,
    format: Format,
    path: String,
    generated: String,
    redact: Option<RedactOptions>,
) -> Result<usize, String> {
    let report = combined(&app, &lock, &id, &generated)?;
    report_cmd::write_report(&report, format, &path, redact.as_ref())
}

/// Preview the redaction of a whole-project export.
#[tauri::command]
pub fn project_redact_preview(
    app: AppHandle,
    lock: State<'_, ProjectsLock>,
    id: String,
    generated: String,
    opts: RedactOptions,
) -> Result<RedactPreview, String> {
    let report = combined(&app, &lock, &id, &generated)?;
    report_cmd::preview(&report, &opts)
}
