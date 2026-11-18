//! Tauri commands for the PCAP inspector. Captures are scanned on a blocking
//! thread with progress and cancel; loaded captures stay in a small
//! registry so the packet list can be paged and filtered, and single
//! packets read back for detail.

use std::collections::HashMap;
use std::io::{Cursor, Read};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use serde::Serialize;
use tauri::ipc::Channel;
use tauri::{AppHandle, Manager, State};
use tauri_plugin_opener::OpenerExt;

use super::core::{self, Filter, Stats, Summary};
use super::decode::{self, Field};
use super::sanitize;
use crate::tools::fgt_sniffer::core as fgt;

/// Captures kept loaded at once.
const MAX_SETS: usize = 3;
/// Largest FortiGate sniffer text accepted for conversion.
const MAX_TEXT: u64 = 64 * 1024 * 1024;
/// Most rows returned per page.
const MAX_PAGE: usize = 2000;

enum Source {
    File(String),
    /// Converted from FortiGate sniffer text.
    Bytes(Vec<u8>),
}

struct Dataset {
    name: String,
    source: Source,
    summaries: Vec<Summary>,
}

#[derive(Default)]
pub struct PcapRegistry {
    sets: Mutex<HashMap<u32, Dataset>>,
    order: Mutex<Vec<u32>>,
    cancel: Mutex<HashMap<u32, Arc<AtomicBool>>>,
}

#[derive(Clone, Serialize)]
#[serde(
    tag = "type",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum OpenEvent {
    Progress { bytes: u64, total: u64 },
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenResult {
    pub name: String,
    pub format: String,
    pub stats: Stats,
    pub listed: usize,
    pub warnings: Vec<String>,
    pub cancelled: bool,
}

fn is_capture_magic(b: &[u8]) -> bool {
    matches!(
        b.get(..4),
        Some([0xd4, 0xc3, 0xb2, 0xa1])
            | Some([0xa1, 0xb2, 0xc3, 0xd4])
            | Some([0x4d, 0x3c, 0xb2, 0xa1])
            | Some([0xa1, 0xb2, 0x3c, 0x4d])
            | Some([0x0a, 0x0d, 0x0d, 0x0a])
    )
}

/// Open and scan a capture file (or FortiGate sniffer text).
#[tauri::command]
pub async fn pcap_open(
    registry: State<'_, PcapRegistry>,
    id: u32,
    path: String,
    on_event: Channel<OpenEvent>,
) -> Result<OpenResult, String> {
    let cancel = Arc::new(AtomicBool::new(false));
    registry
        .cancel
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .insert(id, cancel.clone());
    let p = path.clone();
    let res = tokio::task::spawn_blocking(move || -> Result<(core::Scan, Source, String), String> {
        let name = std::path::Path::new(&p).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| p.clone());
        let mut f = std::fs::File::open(&p).map_err(|e| format!("could not open {p}: {e}"))?;
        let total = f.metadata().map(|m| m.len()).unwrap_or(0);
        let mut head = [0u8; 4];
        let n = f.read(&mut head).map_err(|e| e.to_string())?;
        drop(f);
        let progress = |bytes: u64| {
            let _ = on_event.send(OpenEvent::Progress { bytes, total });
            !cancel.load(Ordering::Relaxed)
        };
        if n == 4 && is_capture_magic(&head) {
            let file = std::fs::File::open(&p).map_err(|e| e.to_string())?;
            let scan = core::scan(file, progress)?;
            return Ok((scan, Source::File(p), name));
        }
        // Not a capture: try FortiGate `diagnose sniffer packet` text.
        if total > MAX_TEXT {
            return Err("not a PCAP/PCAPNG file, and too large to be FortiGate sniffer text".into());
        }
        let text = std::fs::read(&p).map_err(|e| e.to_string())?;
        let text = String::from_utf8_lossy(&text);
        let parsed = fgt::parse(&text, &fgt::Options::default());
        if parsed.packets.is_empty() {
            return Err("not a PCAP/PCAPNG file or FortiGate sniffer output (verbose 3, 4 or 6 with hex)".into());
        }
        let today = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() / 86_400 * 86_400).unwrap_or(0);
        let bytes = fgt::to_pcap(&parsed.packets, today);
        let mut scan = core::scan(Cursor::new(bytes.clone()), progress)?;
        scan.format = "FortiGate sniffer text, converted".into();
        scan.warnings.insert(0, "Converted from FortiGate sniffer output with the Sniffer to PCAP converter. Relative timestamps are placed on today's date.".into());
        Ok((scan, Source::Bytes(bytes), name))
    })
    .await
    .map_err(|e| e.to_string())?;
    registry
        .cancel
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .remove(&id);
    let (scan, source, name) = res?;
    let result = OpenResult {
        name: name.clone(),
        format: scan.format.clone(),
        listed: scan.summaries.len(),
        stats: scan.stats,
        warnings: scan.warnings,
        cancelled: scan.cancelled,
    };
    let mut sets = registry.sets.lock().unwrap_or_else(|p| p.into_inner());
    let mut order = registry.order.lock().unwrap_or_else(|p| p.into_inner());
    sets.insert(
        id,
        Dataset {
            name,
            source,
            summaries: scan.summaries,
        },
    );
    order.retain(|x| *x != id);
    order.push(id);
    while order.len() > MAX_SETS {
        let old = order.remove(0);
        sets.remove(&old);
    }
    Ok(result)
}

#[tauri::command]
pub fn pcap_cancel(registry: State<'_, PcapRegistry>, id: u32) {
    if let Some(c) = registry
        .cancel
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .get(&id)
    {
        c.store(true, Ordering::Relaxed);
    }
}

#[tauri::command]
pub fn pcap_close(registry: State<'_, PcapRegistry>, id: u32) {
    registry
        .sets
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .remove(&id);
    registry
        .order
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .retain(|x| *x != id);
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Page {
    pub rows: Vec<Summary>,
    pub total: usize,
}

/// A page of packets matching `filter`.
#[tauri::command]
pub fn pcap_query(
    registry: State<'_, PcapRegistry>,
    id: u32,
    filter: Filter,
    offset: usize,
    limit: usize,
) -> Result<Page, String> {
    let sets = registry.sets.lock().unwrap_or_else(|p| p.into_inner());
    let ds = sets
        .get(&id)
        .ok_or("this capture is no longer loaded; open it again")?;
    let limit = limit.clamp(1, MAX_PAGE);
    let mut total = 0;
    let mut rows = Vec::new();
    for s in ds.summaries.iter().filter(|s| core::matches(s, &filter)) {
        if total >= offset && rows.len() < limit {
            rows.push(s.clone());
        }
        total += 1;
    }
    Ok(Page { rows, total })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PacketDetail {
    pub summary: Summary,
    pub fields: Vec<Field>,
    pub hex: String,
    pub malformed: Option<String>,
    pub link: String,
}

/// Full detail for one packet, read back from the capture.
#[tauri::command]
pub fn pcap_packet(
    registry: State<'_, PcapRegistry>,
    id: u32,
    index: u32,
) -> Result<PacketDetail, String> {
    let sets = registry.sets.lock().unwrap_or_else(|p| p.into_inner());
    let ds = sets
        .get(&id)
        .ok_or("this capture is no longer loaded; open it again")?;
    let s = ds
        .summaries
        .iter()
        .find(|s| s.index == index)
        .ok_or("packet not in the listed range")?;
    let bytes = match &ds.source {
        Source::File(p) => {
            let mut f = std::fs::File::open(p).map_err(|e| format!("could not reopen {p}: {e}"))?;
            core::read_packet(&mut f, s)?
        }
        Source::Bytes(b) => core::read_packet(&mut Cursor::new(b.as_slice()), s)?,
    };
    let d = decode::decode(s.link, &bytes, true);
    let mut fields = vec![
        Field {
            layer: "Frame".into(),
            name: "Number".into(),
            value: (s.index + 1).to_string(),
        },
        Field {
            layer: "Frame".into(),
            name: "Length on the wire".into(),
            value: s.orig_len.to_string(),
        },
        Field {
            layer: "Frame".into(),
            name: "Captured length".into(),
            value: s.cap_len.to_string(),
        },
    ];
    fields.extend(d.fields);
    Ok(PacketDetail {
        summary: s.clone(),
        fields,
        hex: decode::hexdump(&bytes[..bytes.len().min(16 * 1024)]),
        malformed: d.malformed,
        link: decode::link_name(s.link)
            .map(str::to_string)
            .unwrap_or_else(|| format!("linktype {}", s.link)),
    })
}

/// Open the capture in the system's default app for it (usually Wireshark).
#[tauri::command]
pub fn pcap_open_external(
    app: AppHandle,
    registry: State<'_, PcapRegistry>,
    id: u32,
) -> Result<(), String> {
    let sets = registry.sets.lock().unwrap_or_else(|p| p.into_inner());
    let ds = sets.get(&id).ok_or("this capture is no longer loaded")?;
    let path = match &ds.source {
        Source::File(p) => p.clone(),
        Source::Bytes(b) => {
            let dir = app.path().app_cache_dir().map_err(|e| e.to_string())?;
            std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
            let stem = ds.name.rsplit_once('.').map(|x| x.0).unwrap_or(&ds.name);
            let safe: String = stem
                .chars()
                .map(|c| {
                    if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                        c
                    } else {
                        '_'
                    }
                })
                .collect();
            let p = dir.join(format!("{safe}.pcap"));
            std::fs::write(&p, b).map_err(|e| e.to_string())?;
            p.to_string_lossy().into_owned()
        }
    };
    app.opener().open_path(&path, None::<&str>).map_err(|e| {
        format!(
            "could not open the capture: {e}. Is Wireshark installed and set to open .pcap files?"
        )
    })
}

/// Write a cleaned copy of a loaded capture to `out` (PCAPNG): payloads cut,
/// addresses and MACs replaced, as `opts` says. Cancel with `pcap_cancel`.
#[tauri::command]
pub async fn pcap_sanitize(
    registry: State<'_, PcapRegistry>,
    id: u32,
    out: String,
    opts: sanitize::Options,
    on_event: Channel<OpenEvent>,
) -> Result<sanitize::Report, String> {
    let source = {
        let sets = registry.sets.lock().unwrap_or_else(|p| p.into_inner());
        let ds = sets
            .get(&id)
            .ok_or("this capture is no longer loaded; open it again")?;
        match &ds.source {
            Source::File(p) => Source::File(p.clone()),
            Source::Bytes(b) => Source::Bytes(b.clone()),
        }
    };
    if let Source::File(p) = &source
        && std::fs::canonicalize(p)
            .ok()
            .is_some_and(|a| std::fs::canonicalize(&out).ok().is_some_and(|b| a == b))
    {
        return Err(
            "choose a different file name: the cleaned copy cannot replace the original".into(),
        );
    }
    let cancel = Arc::new(AtomicBool::new(false));
    registry
        .cancel
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .insert(id, cancel.clone());
    let path = out.clone();
    let res = tokio::task::spawn_blocking(move || -> Result<sanitize::Report, String> {
        let file =
            std::fs::File::create(&path).map_err(|e| format!("could not create {path}: {e}"))?;
        let writer = std::io::BufWriter::new(file);
        let result = match &source {
            Source::File(p) => {
                let f = std::fs::File::open(p).map_err(|e| format!("could not reopen {p}: {e}"))?;
                let total = f.metadata().map(|m| m.len()).unwrap_or(0);
                let progress = |bytes: u64| {
                    let _ = on_event.send(OpenEvent::Progress { bytes, total });
                    !cancel.load(Ordering::Relaxed)
                };
                sanitize::sanitize(f, writer, &opts, progress)
            }
            Source::Bytes(b) => {
                let total = b.len() as u64;
                let progress = |bytes: u64| {
                    let _ = on_event.send(OpenEvent::Progress { bytes, total });
                    !cancel.load(Ordering::Relaxed)
                };
                sanitize::sanitize(Cursor::new(b.as_slice()), writer, &opts, progress)
            }
        };
        match result {
            Ok(r) if !r.cancelled => Ok(r),
            Ok(r) => {
                let _ = std::fs::remove_file(&path);
                Ok(r)
            }
            Err(e) => {
                let _ = std::fs::remove_file(&path);
                Err(e)
            }
        }
    })
    .await
    .map_err(|e| e.to_string())?;
    registry
        .cancel
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .remove(&id);
    res
}
