//! Tauri commands for the Obfuscator.

use serde::Serialize;

use super::core::{self, Piece, Restored};
use crate::report::redact::{self, MAX_TEXT, MappingEntry, RedactOptions, RedactedText};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Obfuscated {
    #[serde(flatten)]
    pub result: RedactedText,
    /// None when the output is too large to highlight.
    pub pieces: Option<Vec<Piece>>,
}

/// Obfuscate pasted text, continuing the session given by `key` and `mapping`.
#[tauri::command]
pub async fn obfuscate_text(
    text: String,
    opts: RedactOptions,
    key: String,
    mapping: Vec<MappingEntry>,
) -> Result<Obfuscated, String> {
    tokio::task::spawn_blocking(move || {
        let result =
            redact::redact_text(&text, &opts, &key, &mapping).map_err(|e| e.to_string())?;
        let pieces = core::highlight(&result.text, &result.mapping);
        Ok(Obfuscated { result, pieces })
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Map a reply back to the original values of this session.
#[tauri::command]
pub async fn obfuscate_restore(
    text: String,
    mapping: Vec<MappingEntry>,
    secrets: bool,
) -> Result<Restored, String> {
    if text.len() > MAX_TEXT {
        return Err(format!(
            "the text is larger than {} MB",
            MAX_TEXT / (1024 * 1024)
        ));
    }
    tokio::task::spawn_blocking(move || core::restore(&text, &mapping, secrets))
        .await
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    /// Write the result for OBFUSCATE_TEXT (a file) to OBFUSCATE_JSON, for UI checks.
    #[test]
    #[ignore = "writes a file; run by hand"]
    fn dump() {
        let (Ok(src), Ok(dst)) = (
            std::env::var("OBFUSCATE_TEXT"),
            std::env::var("OBFUSCATE_JSON"),
        ) else {
            return;
        };
        let text = std::fs::read_to_string(src).unwrap();
        let opts = crate::report::redact::RedactOptions {
            macs: true,
            serials: true,
            certificates: true,
            fake_addresses: true,
            ..Default::default()
        };
        let result = crate::report::redact::redact_text(&text, &opts, "", &[]).unwrap();
        let pieces = super::core::highlight(&result.text, &result.mapping);
        let out = super::Obfuscated { result, pieces };
        std::fs::write(dst, serde_json::to_string(&out).unwrap()).unwrap();
    }
}
