//! Tauri command for the encoder workbench.

use super::core::{self, Op, Run};

/// Run a chain of steps over the input.
#[tauri::command]
pub async fn codec_run(input: String, input_is_hex: bool, ops: Vec<Op>) -> Run {
    tokio::task::spawn_blocking(move || core::run(&input, input_is_hex, &ops))
        .await
        .unwrap_or_else(|_| core::run("", false, &[]))
}
