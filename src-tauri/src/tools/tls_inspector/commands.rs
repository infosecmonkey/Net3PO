//! Tauri commands for the TLS inspector. Decoding is offline; live checks
//! connect only when the user clicks, with timeouts on every socket.

use super::cert::{self, DecodeResult, MAX_INPUT};
use super::live::{self, LiveRequest, LiveResult, SuiteResult};

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or_default()
}

/// Decode pasted PEM text.
#[tauri::command]
pub fn tls_decode(text: String) -> DecodeResult {
    cert::decode(text.as_bytes(), now_ms())
}

/// Decode a PEM or DER file chosen in the native open dialog.
#[tauri::command]
pub async fn tls_decode_file(path: String) -> Result<DecodeResult, String> {
    tokio::task::spawn_blocking(move || {
        let meta = std::fs::metadata(&path).map_err(|e| format!("could not read {path}: {e}"))?;
        if meta.len() > MAX_INPUT as u64 {
            return Err("file larger than 1 MB; certificates and CSRs are much smaller".into());
        }
        let bytes = std::fs::read(&path).map_err(|e| format!("could not read {path}: {e}"))?;
        Ok(cert::decode(&bytes, now_ms()))
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Connect, optionally STARTTLS, and inspect the handshake.
#[tauri::command]
pub async fn tls_inspect(req: LiveRequest) -> Result<LiveResult, String> {
    tokio::task::spawn_blocking(move || live::inspect(&req))
        .await
        .map_err(|e| e.to_string())?
}

/// Separate active test: which of the testable versions and suites the
/// server accepts.
#[tauri::command]
pub async fn tls_test_suites(req: LiveRequest) -> Result<Vec<SuiteResult>, String> {
    tokio::task::spawn_blocking(move || live::test_suites(&req))
        .await
        .map_err(|e| e.to_string())?
}
