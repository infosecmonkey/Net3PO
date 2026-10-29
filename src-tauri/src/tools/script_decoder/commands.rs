//! Tauri commands for the script decoder. Thin wrappers over the pure core.

use super::core::{self, DecodeResult, MAX_INPUT};

/// Decode a pasted script. Runs on a blocking thread: decoding is CPU bound.
#[tauri::command]
pub async fn script_decode(text: String) -> Result<DecodeResult, String> {
    tauri::async_runtime::spawn_blocking(move || core::decode(&text))
        .await
        .map_err(|e| format!("decoder failed: {e}"))?
        .map_err(|e| e.to_string())
}

/// Read a script chosen by the UI via a native open dialog, as text. The size
/// is checked before reading and the file is never executed.
#[tauri::command]
pub fn script_read_file(path: String) -> Result<String, String> {
    let meta = std::fs::metadata(&path).map_err(|e| format!("could not read {path}: {e}"))?;
    if meta.len() > MAX_INPUT as u64 {
        return Err(format!(
            "{path} is too large ({} bytes, limit {MAX_INPUT})",
            meta.len()
        ));
    }
    let bytes = std::fs::read(&path).map_err(|e| format!("could not read {path}: {e}"))?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}
