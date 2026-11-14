//! Tauri commands for the Windows Event Log Reader. Files are parsed locally
//! in a background task with progress and Cancel; the records stay here and
//! the UI asks for filtered pages, facets and single records.

use std::collections::HashMap;
use std::io::Read;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use evtx::{EvtxParser, ParserSettings};
use serde::Serialize;
use tauri::State;
use tauri::ipc::Channel;

use super::explain::{self, Explanation};
use super::model::{self, EventRecord};
use super::query::{self, Filter, QueryResult};
use super::{csv, xml};

/// Most records loaded from one file.
pub const MAX_RECORDS: usize = 500_000;
/// Largest EVTX file accepted (read in a streaming way).
const MAX_EVTX_BYTES: u64 = 2 * 1024 * 1024 * 1024;
/// Largest XML or CSV file accepted (read into memory).
const MAX_TEXT_BYTES: u64 = 512 * 1024 * 1024;
/// Raw record text kept in total; beyond this only parsed fields are kept.
const MAX_RAW_TOTAL: usize = 256 * 1024 * 1024;
/// Loaded sets kept at once; the oldest is dropped first.
const MAX_SETS: usize = 3;
/// Parse error messages kept for display.
const MAX_ERRORS_SHOWN: usize = 20;

pub struct Dataset {
    pub records: Vec<EventRecord>,
}

#[derive(Default)]
pub struct EventLogRegistry {
    sets: Mutex<Vec<(u32, Arc<Dataset>)>>,
    runs: Mutex<HashMap<u32, Arc<AtomicBool>>>,
    next: AtomicU32,
}

impl EventLogRegistry {
    fn get(&self, id: u32) -> Result<Arc<Dataset>, String> {
        self.sets
            .lock()
            .unwrap()
            .iter()
            .find(|(i, _)| *i == id)
            .map(|(_, d)| d.clone())
            .ok_or_else(|| "that log is no longer loaded; open the file again".to_string())
    }
}

#[derive(Clone, Serialize)]
#[serde(
    tag = "type",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum LoadEvent {
    Progress { records: usize, errors: usize },
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LoadSummary {
    pub dataset_id: u32,
    pub name: String,
    pub format: String,
    pub records: usize,
    pub error_count: usize,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
    pub truncated: bool,
    pub cancelled: bool,
    /// Earliest and latest sort times, and whether they are UTC.
    pub first_ms: Option<i64>,
    pub last_ms: Option<i64>,
    pub zone_unknown: bool,
}

/// What kind of file this is, from its first bytes and extension.
fn sniff(path: &str, head: &[u8]) -> Result<&'static str, String> {
    if head.starts_with(b"ElfFile\0") {
        return Ok("evtx");
    }
    let text = String::from_utf8_lossy(head);
    let trimmed = text.trim_start_matches('\u{feff}').trim_start();
    if trimmed.starts_with('<') {
        return Ok("xml");
    }
    let lower = path.to_ascii_lowercase();
    if lower.ends_with(".csv") || trimmed.contains(',') {
        return Ok("csv");
    }
    if lower.ends_with(".evtx") {
        return Err("this .evtx file does not start with the EVTX signature; it may be damaged or not an event log".into());
    }
    Err("unsupported format: open an .evtx file, an XML export or a CSV export".into())
}

/// Load an event log file.
#[tauri::command]
pub async fn evtlog_load(
    registry: State<'_, EventLogRegistry>,
    run_id: u32,
    path: String,
    on_event: Channel<LoadEvent>,
) -> Result<LoadSummary, String> {
    let cancel = Arc::new(AtomicBool::new(false));
    registry.runs.lock().unwrap().insert(run_id, cancel.clone());
    let p = path.clone();
    let flag = cancel.clone();
    let result = tokio::task::spawn_blocking(move || load_file(&p, &flag, &on_event))
        .await
        .map_err(|e| format!("loading failed: {e}"));
    registry.runs.lock().unwrap().remove(&run_id);
    let (dataset, mut summary) = result??;

    let id = registry.next.fetch_add(1, Ordering::Relaxed) + 1;
    summary.dataset_id = id;
    let mut sets = registry.sets.lock().unwrap();
    sets.push((id, Arc::new(dataset)));
    while sets.len() > MAX_SETS {
        sets.remove(0);
    }
    Ok(summary)
}

fn load_file(
    path: &str,
    cancel: &AtomicBool,
    on_event: &Channel<LoadEvent>,
) -> Result<(Dataset, LoadSummary), String> {
    let meta = std::fs::metadata(path).map_err(|e| format!("could not read {path}: {e}"))?;
    let mut head = [0u8; 4096];
    let n = std::fs::File::open(path)
        .and_then(|mut f| f.read(&mut head))
        .map_err(|e| format!("could not read {path}: {e}"))?;
    let format = sniff(path, &head[..n])?;
    let name = std::path::Path::new(path)
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.to_string());

    let mut errors: Vec<String> = Vec::new();
    let mut error_count = 0usize;
    let mut warnings = Vec::new();
    let mut truncated = false;
    let records = match format {
        "evtx" => {
            if meta.len() > MAX_EVTX_BYTES {
                return Err(format!(
                    "file is too large ({} bytes; limit {MAX_EVTX_BYTES})",
                    meta.len()
                ));
            }
            let mut parser = EvtxParser::from_path(path)
                .map_err(|e| format!("not a readable EVTX file: {e}"))?
                .with_configuration(ParserSettings::new().num_threads(1));
            let mut out = Vec::new();
            let mut raw_total = 0usize;
            for item in parser.records_json_value() {
                if cancel.load(Ordering::Relaxed) {
                    break;
                }
                match item {
                    Ok(rec) => {
                        if out.len() >= MAX_RECORDS {
                            truncated = true;
                            break;
                        }
                        let mut r = model::from_event_json(
                            out.len() as u32,
                            &rec.data,
                            Some(rec.event_record_id),
                            &rec.timestamp.to_string(),
                        );
                        raw_total += r.raw.len();
                        if raw_total > MAX_RAW_TOTAL {
                            r.raw = String::new();
                        }
                        out.push(r);
                    }
                    Err(e) => {
                        error_count += 1;
                        if errors.len() < MAX_ERRORS_SHOWN {
                            errors.push(e.to_string());
                        }
                    }
                }
                if (out.len() + error_count).is_multiple_of(2000) {
                    let _ = on_event.send(LoadEvent::Progress {
                        records: out.len(),
                        errors: error_count,
                    });
                }
            }
            if raw_total > MAX_RAW_TOTAL {
                warnings.push("Very large log: the raw view is kept only for the first records; parsed fields are kept for all.".into());
            }
            out
        }
        _ => {
            if meta.len() > MAX_TEXT_BYTES {
                return Err(format!(
                    "file is too large ({} bytes; limit {MAX_TEXT_BYTES})",
                    meta.len()
                ));
            }
            let bytes = std::fs::read(path).map_err(|e| format!("could not read {path}: {e}"))?;
            let text = decode_text(&bytes);
            if format == "xml" {
                let imp = xml::parse(&text, MAX_RECORDS);
                error_count = imp.errors.len();
                errors = imp.errors.into_iter().take(MAX_ERRORS_SHOWN).collect();
                truncated = imp.truncated;
                imp.records
            } else {
                let imp = csv::import(&text, MAX_RECORDS)?;
                warnings.extend(imp.warnings);
                truncated = imp.truncated;
                imp.records
            }
        }
    };
    let cancelled = cancel.load(Ordering::Relaxed);
    if records.is_empty() && !cancelled {
        let why = errors
            .first()
            .cloned()
            .unwrap_or_else(|| "no events found".into());
        return Err(format!("no events could be read: {why}"));
    }
    let timed: Vec<i64> = records
        .iter()
        .map(|r| r.sort_ms)
        .filter(|t| *t != 0)
        .collect();
    let summary = LoadSummary {
        dataset_id: 0,
        name: name.clone(),
        format: format.to_string(),
        records: records.len(),
        error_count,
        errors,
        warnings,
        truncated,
        cancelled,
        first_ms: timed.iter().min().copied(),
        last_ms: timed.iter().max().copied(),
        zone_unknown: records.iter().any(|r| r.zone_unknown),
    };
    Ok((Dataset { records }, summary))
}

/// UTF-8, or UTF-16 with a byte order mark (PowerShell's default for some exports).
fn decode_text(bytes: &[u8]) -> String {
    let utf16 = |le: bool| {
        let units: Vec<u16> = bytes[2..]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| {
                if le {
                    u16::from_le_bytes(*c)
                } else {
                    u16::from_be_bytes(*c)
                }
            })
            .collect();
        String::from_utf16_lossy(&units)
    };
    match bytes {
        [0xff, 0xfe, ..] => utf16(true),
        [0xfe, 0xff, ..] => utf16(false),
        _ => String::from_utf8_lossy(bytes).into_owned(),
    }
}

/// Stop a load in progress; records read so far are kept.
#[tauri::command]
pub fn evtlog_cancel(registry: State<'_, EventLogRegistry>, run_id: u32) {
    if let Some(flag) = registry.runs.lock().unwrap().get(&run_id) {
        flag.store(true, Ordering::Relaxed);
    }
}

/// Filtered page, facets and timeline.
#[tauri::command]
pub async fn evtlog_query(
    registry: State<'_, EventLogRegistry>,
    dataset_id: u32,
    filter: Filter,
    offset: usize,
    limit: usize,
) -> Result<QueryResult, String> {
    let set = registry.get(dataset_id)?;
    tokio::task::spawn_blocking(move || query::run(&set.records, &filter, offset, limit))
        .await
        .map_err(|e| format!("query failed: {e}"))?
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordDetail {
    pub record: EventRecord,
    pub level_name: String,
    pub explanation: Option<Explanation>,
    pub decoded: Vec<(String, String)>,
}

/// One full record with its explanation.
#[tauri::command]
pub fn evtlog_record(
    registry: State<'_, EventLogRegistry>,
    dataset_id: u32,
    index: u32,
) -> Result<RecordDetail, String> {
    let set = registry.get(dataset_id)?;
    let r = set
        .records
        .get(index as usize)
        .ok_or_else(|| "record not found".to_string())?
        .clone();
    Ok(RecordDetail {
        level_name: r.level_name().to_string(),
        explanation: explain::explain(&r),
        decoded: explain::decode(&r),
        record: r,
    })
}

/// Rows for export: the first `limit` matches of a filter.
#[tauri::command]
pub async fn evtlog_export_rows(
    registry: State<'_, EventLogRegistry>,
    dataset_id: u32,
    filter: Filter,
    limit: usize,
) -> Result<Vec<query::Row>, String> {
    let set = registry.get(dataset_id)?;
    tokio::task::spawn_blocking(move || {
        query::run(&set.records, &filter, 0, limit.min(query::MAX_PAGE)).map(|q| q.rows)
    })
    .await
    .map_err(|e| format!("export failed: {e}"))?
}

/// Free a loaded log.
#[tauri::command]
pub fn evtlog_close(registry: State<'_, EventLogRegistry>, dataset_id: u32) {
    registry
        .sets
        .lock()
        .unwrap()
        .retain(|(i, _)| *i != dataset_id);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sniffing() {
        assert_eq!(sniff("a.evtx", b"ElfFile\0rest").unwrap(), "evtx");
        assert_eq!(sniff("a.xml", b"\xef\xbb\xbf  <Events>").unwrap(), "xml");
        assert_eq!(sniff("a.csv", b"Level,Date and Time").unwrap(), "csv");
        assert!(sniff("a.evtx", b"MZ\x90\0").is_err());
        assert!(sniff("a.bin", b"\0\0\0\0").is_err());
    }

    #[test]
    fn text_decoding() {
        assert_eq!(decode_text(b"abc"), "abc");
        let le: Vec<u8> = [0xff, 0xfe]
            .into_iter()
            .chain("Id,X".encode_utf16().flat_map(|u| u.to_le_bytes()))
            .collect();
        assert_eq!(decode_text(&le), "Id,X");
    }
}
