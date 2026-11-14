//! Tauri command for the filter builder.

use super::core::{self, Filters, Group};

/// Render the filter in every supported language.
#[tauri::command]
pub fn filter_build(groups: Vec<Group>, interface: String) -> Filters {
    core::build(&groups, &interface)
}
