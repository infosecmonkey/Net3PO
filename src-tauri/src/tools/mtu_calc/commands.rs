//! Tauri command for the MTU calculator.

use super::core::{self, Layer, Result};

/// Apply `layers` (outside in) to the link MTU.
#[tauri::command]
pub fn mtu_calculate(link_mtu: u32, layers: Vec<Layer>) -> Result {
    core::calculate(link_mtu, &layers)
}
