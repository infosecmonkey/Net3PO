//! Tauri command for report export. Thin wrapper over the pure core.

use super::core::{self, Format, Report};

/// Render `report` in `format` and write it to `path` (chosen by the UI via a
/// native save dialog). Returns the number of bytes written.
#[tauri::command]
pub fn report_export(report: Report, format: Format, path: String) -> Result<usize, String> {
    let bytes = core::render(&report, format).map_err(|e| e.to_string())?;
    std::fs::write(&path, &bytes).map_err(|e| format!("could not write {path}: {e}"))?;
    Ok(bytes.len())
}
