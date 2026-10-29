//! Tauri commands for the config diff. Thin wrappers over the pure core.

use super::core::{self, DiffOptions, DiffResult, MAX_INPUT_BYTES};

/// Compare two texts.
#[tauri::command]
pub fn diff_compare(
    left: String,
    right: String,
    options: DiffOptions,
) -> Result<DiffResult, String> {
    core::diff(&left, &right, &options).map_err(|e| e.to_string())
}

/// Read a file chosen by the UI via a native open dialog, refusing files over
/// the diff input limit before reading them.
#[tauri::command]
pub fn diff_read_file(path: String) -> Result<String, String> {
    let meta = std::fs::metadata(&path).map_err(|e| format!("could not read {path}: {e}"))?;
    if meta.len() > MAX_INPUT_BYTES as u64 {
        return Err(format!(
            "{path} is too large ({} bytes, limit {MAX_INPUT_BYTES})",
            meta.len()
        ));
    }
    let bytes = std::fs::read(&path).map_err(|e| format!("could not read {path}: {e}"))?;
    // Config backups are sometimes Latin-1; replace invalid UTF-8 rather than fail.
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// Write the unified diff to `path` (chosen by the UI via a native save dialog).
#[tauri::command]
pub fn diff_save(path: String, text: String) -> Result<(), String> {
    std::fs::write(&path, text).map_err(|e| format!("could not write {path}: {e}"))
}
