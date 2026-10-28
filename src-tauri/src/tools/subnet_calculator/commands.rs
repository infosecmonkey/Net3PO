//! Tauri commands for the subnet calculator. These are thin wrappers that call
//! the pure core and map errors to plain strings for the UI.

use super::core::{self, SplitResult, SubnetReport};

/// Analyze an address/prefix such as `10.1.1.0/24` or `2001:db8::/48`.
#[tauri::command]
pub fn subnet_calculate(input: String) -> Result<SubnetReport, String> {
    let net = core::parse_network(&input).map_err(|e| e.to_string())?;
    Ok(core::analyze(&net))
}

/// Split an address/prefix into subnets of `new_prefix`.
#[tauri::command]
pub fn subnet_split(input: String, new_prefix: u32) -> Result<SplitResult, String> {
    let net = core::parse_network(&input).map_err(|e| e.to_string())?;
    core::split(&net, new_prefix).map_err(|e| e.to_string())
}
