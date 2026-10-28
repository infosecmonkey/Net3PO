//! Tauri commands for the FortiGate sniffer to PCAP tool.

use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

use super::core::{self, Options};

const PREVIEW_LIMIT: usize = 500;

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PacketMeta {
    pub index: usize,
    pub time: String,
    pub interface: Option<String>,
    pub direction: Option<String>,
    pub length: usize,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ParseSummary {
    pub total: usize,
    pub skipped_eth0: usize,
    pub total_bytes: usize,
    pub shown: usize,
    pub truncated: bool,
    pub packets: Vec<PacketMeta>,
}

/// Parse sniffer text and return a summary plus a bounded packet list for
/// preview.
#[tauri::command]
pub fn fgt_parse(input: String, options: Options) -> ParseSummary {
    let out = core::parse(&input, &options);
    let times = core::resolve_times(&out.packets, now_secs());
    let total_bytes = out.packets.iter().map(|p| p.bytes.len()).sum();

    let packets = out
        .packets
        .iter()
        .take(PREVIEW_LIMIT)
        .enumerate()
        .map(|(i, p)| {
            let (s, u) = times[i];
            PacketMeta {
                index: i + 1,
                time: core::format_epoch(s, u),
                interface: p.interface.clone(),
                direction: p.direction.clone(),
                length: p.bytes.len(),
            }
        })
        .collect();

    ParseSummary {
        total: out.packets.len(),
        skipped_eth0: out.skipped_eth0,
        total_bytes,
        shown: out.packets.len().min(PREVIEW_LIMIT),
        truncated: out.packets.len() > PREVIEW_LIMIT,
        packets,
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SaveSummary {
    pub packets: usize,
    pub bytes_written: usize,
    pub skipped_eth0: usize,
}

/// Read a sniffer capture file chosen by the UI via a native open dialog.
#[tauri::command]
pub fn fgt_read_file(path: String) -> Result<String, String> {
    std::fs::read_to_string(&path).map_err(|e| format!("could not read {path}: {e}"))
}

/// Convert sniffer text to pcap and write it to `path` (chosen by the UI via a
/// native save dialog).
#[tauri::command]
pub fn fgt_save(input: String, options: Options, path: String) -> Result<SaveSummary, String> {
    let out = core::parse(&input, &options);
    if out.packets.is_empty() {
        return Err("no packets found in the input".to_string());
    }
    let pcap = core::to_pcap(&out.packets, now_secs());
    std::fs::write(&path, &pcap).map_err(|e| format!("could not write {path}: {e}"))?;
    Ok(SaveSummary {
        packets: out.packets.len(),
        bytes_written: pcap.len(),
        skipped_eth0: out.skipped_eth0,
    })
}
