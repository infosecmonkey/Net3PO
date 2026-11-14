//! Tauri commands for the timestamp converter.

use jiff::Timestamp;

use super::core::{self, Conversion};

/// Convert a timestamp; show results in the IANA zone `zone`.
#[tauri::command]
pub fn ts_convert(input: String, zone: String) -> Conversion {
    core::convert(&input, &zone, Timestamp::now())
}

/// The current time in every format.
#[tauri::command]
pub fn ts_now(zone: String) -> Conversion {
    core::now(&zone, Timestamp::now())
}
