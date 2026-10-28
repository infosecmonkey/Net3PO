//! Tauri commands for the MAC vendor lookup.

use serde::Serialize;

use super::core::{self, MacInfo};
use super::{OUI_SOURCE, database};

/// Look up the vendor for a MAC address.
#[tauri::command]
pub fn mac_lookup(mac: String) -> Result<MacInfo, String> {
    let bytes = core::parse_mac(&mac).map_err(|e| e.to_string())?;
    Ok(core::describe(&bytes, database()))
}

/// Dataset coverage and provenance, for display in the UI.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DbInfo {
    pub source: String,
    pub total: usize,
    pub ma_l: usize,
    pub ma_m: usize,
    pub ma_s: usize,
}

/// Report how many assignments are loaded and where they came from.
#[tauri::command]
pub fn mac_db_info() -> DbInfo {
    let s = database().stats();
    DbInfo {
        source: OUI_SOURCE.to_string(),
        total: s.total,
        ma_l: s.ma_l,
        ma_m: s.ma_m,
        ma_s: s.ma_s,
    }
}
