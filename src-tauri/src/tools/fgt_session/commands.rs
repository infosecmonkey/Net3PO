//! Tauri commands for the session list parser. Files are read with the
//! debug flow parser's `flow_read_file` (same 20 MB limit).

use super::core::{self, Parsed};

/// Parse pasted session list output.
#[tauri::command]
pub async fn session_parse(text: String) -> Parsed {
    tokio::task::spawn_blocking(move || core::parse(&text))
        .await
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    /// Write the parse of SESSION_TEXT (a file) to SESSION_JSON, for UI checks.
    #[test]
    #[ignore = "writes a file; run by hand"]
    fn dump() {
        let (Ok(src), Ok(dst)) = (std::env::var("SESSION_TEXT"), std::env::var("SESSION_JSON"))
        else {
            return;
        };
        let text = std::fs::read_to_string(src).unwrap();
        std::fs::write(
            dst,
            serde_json::to_string(&super::core::parse(&text)).unwrap(),
        )
        .unwrap();
    }
}
