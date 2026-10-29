//! Tauri commands for the regex builder. Thin wrappers over the pure core.

use super::core::{self, Engine, RegexFlags, RegexResult};
use super::recipes::{self, Recipe};

/// Test a pattern against sample text, returning matches and capture groups.
#[tauri::command]
pub fn regex_test(
    pattern: String,
    text: String,
    flags: RegexFlags,
    engine: Engine,
) -> Result<RegexResult, String> {
    core::test(&pattern, &text, &flags, engine).map_err(|e| e.to_string())
}

/// Replace every match with `replacement` (supports `$1` and `${name}`).
#[tauri::command]
pub fn regex_replace(
    pattern: String,
    text: String,
    flags: RegexFlags,
    replacement: String,
    engine: Engine,
) -> Result<String, String> {
    core::replace_all(&pattern, &text, &flags, &replacement, engine).map_err(|e| e.to_string())
}

/// The built-in recipe library for the picker.
#[tauri::command]
pub fn regex_recipes() -> &'static [Recipe] {
    recipes::recipes()
}
