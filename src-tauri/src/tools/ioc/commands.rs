//! Tauri commands for the IOC extractor.

use super::core::{self, Extraction};

/// Extract indicators from pasted text.
#[tauri::command]
pub async fn ioc_extract(text: String) -> Extraction {
    tokio::task::spawn_blocking(move || core::extract(&text))
        .await
        .unwrap_or_default()
}

/// Defang (`defang = true`) or refang free text in place.
#[tauri::command]
pub fn ioc_transform(text: String, defang: bool) -> Result<String, String> {
    core::transform(&text, defang)
}
