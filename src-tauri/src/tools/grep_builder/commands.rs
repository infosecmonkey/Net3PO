//! Tauri commands for the grep builder. Thin wrappers over the pure core.

use super::core::{self, BuiltCommand, GrepOptions, GrepPreview};

/// Build the grep command (or pipeline) and its warnings from the options.
#[tauri::command]
pub fn grep_build(options: GrepOptions) -> BuiltCommand {
    core::build_command(&options)
}

/// Simulate the command over sample text, reusing the regex builder core.
#[tauri::command]
pub fn grep_preview(options: GrepOptions, text: String) -> Result<GrepPreview, String> {
    core::preview(&options, &text).map_err(|e| e.to_string())
}
