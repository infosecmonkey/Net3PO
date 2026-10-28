//! Tauri commands for the grep builder. Thin wrappers over the pure core.

use super::core::{self, GrepOptions};
use crate::tools::regex_builder::core::RegexResult;

/// Build the grep command line from the current options.
#[tauri::command]
pub fn grep_build(options: GrepOptions) -> String {
    core::build_command(&options)
}

/// Preview the pattern against sample text, reusing the regex builder core.
#[tauri::command]
pub fn grep_preview(options: GrepOptions, text: String) -> Result<RegexResult, String> {
    core::preview(&options, &text).map_err(|e| e.to_string())
}
