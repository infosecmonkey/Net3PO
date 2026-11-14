//! Tauri commands for the debug flow parser.

use super::core::{self, MAX_INPUT, Parsed};

/// Parse pasted debug flow output.
#[tauri::command]
pub async fn flow_parse(text: String) -> Parsed {
    tokio::task::spawn_blocking(move || core::parse(&text))
        .await
        .unwrap_or_default()
}

/// Read a saved debug flow log chosen in the open dialog.
#[tauri::command]
pub async fn flow_read_file(path: String) -> Result<String, String> {
    tokio::task::spawn_blocking(move || {
        let meta = std::fs::metadata(&path).map_err(|e| format!("could not read {path}: {e}"))?;
        if meta.len() > MAX_INPUT as u64 {
            return Err("file larger than 20 MB".into());
        }
        let bytes = std::fs::read(&path).map_err(|e| format!("could not read {path}: {e}"))?;
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    })
    .await
    .map_err(|e| e.to_string())?
}
