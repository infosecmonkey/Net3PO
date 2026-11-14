//! Tauri command for the HTTP troubleshooter. One request per click, with
//! timeouts on every socket operation.

use super::client::{self, HttpRequest, HttpResult};

/// Send the request (and follow redirects when asked).
#[tauri::command]
pub async fn http_send(req: HttpRequest) -> Result<HttpResult, String> {
    tokio::task::spawn_blocking(move || client::run(&req))
        .await
        .map_err(|e| e.to_string())?
}
