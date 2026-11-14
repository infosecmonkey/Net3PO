//! Tauri commands for report export. Thin wrappers over the pure core.

use serde::Serialize;

use super::core::{self, Format, Report};
use super::redact::{self, MappingEntry, RedactOptions};

/// Render `report` in `format` and write it to `path` (chosen by the UI via a
/// native save dialog), redacting it first when `redact` is set. Returns the
/// number of bytes written.
#[tauri::command]
pub fn report_export(
    report: Report,
    format: Format,
    path: String,
    redact: Option<RedactOptions>,
) -> Result<usize, String> {
    write_report(&report, format, &path, redact.as_ref())
}

/// Shared by single-tool and project export.
pub fn write_report(
    report: &Report,
    format: Format,
    path: &str,
    redact: Option<&RedactOptions>,
) -> Result<usize, String> {
    let redacted;
    let report = match redact {
        Some(opts) => {
            redacted = redact::redact(report, opts).map_err(|e| e.to_string())?;
            &redacted.report
        }
        None => report,
    };
    let bytes = core::render(report, format).map_err(|e| e.to_string())?;
    std::fs::write(path, &bytes).map_err(|e| format!("could not write {path}: {e}"))?;
    Ok(bytes.len())
}

/// What a redaction would change, for the preview. Never written to disk.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RedactPreview {
    pub title: String,
    pub mapping: Vec<MappingEntry>,
    pub mapping_truncated: bool,
    pub replacements: usize,
    pub emails: usize,
    pub private_keys: usize,
}

pub fn preview(report: &Report, opts: &RedactOptions) -> Result<RedactPreview, String> {
    let r = redact::redact(report, opts).map_err(|e| e.to_string())?;
    Ok(RedactPreview {
        title: r.report.title,
        mapping: r.mapping,
        mapping_truncated: r.mapping_truncated,
        replacements: r.replacements,
        emails: r.emails,
        private_keys: r.private_keys,
    })
}

/// Preview the redaction of a single-tool report.
#[tauri::command]
pub fn report_redact_preview(report: Report, opts: RedactOptions) -> Result<RedactPreview, String> {
    preview(&report, &opts)
}
