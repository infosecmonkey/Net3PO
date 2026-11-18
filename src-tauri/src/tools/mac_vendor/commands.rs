//! Tauri commands for the MAC vendor lookup and its database updates.

use serde::Serialize;

use super::core::{self, MacInfo};
use super::{Loaded, OUI_DATE, database, update};

/// Look up the vendor for a MAC address.
#[tauri::command]
pub fn mac_lookup(mac: String) -> Result<MacInfo, String> {
    let bytes = core::parse_mac(&mac).map_err(|e| e.to_string())?;
    Ok(core::describe(&bytes, &database()))
}

/// Dataset coverage and provenance, for display in the UI.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DbInfo {
    /// "downloaded", "live" (built in from IEEE), "file" or "seed".
    pub source: String,
    pub total: usize,
    pub ma_l: usize,
    pub ma_m: usize,
    pub ma_s: usize,
    /// IEEE date of the data in use (YYYY-MM-DD), when known.
    pub ieee_date: Option<String>,
    /// When the downloaded copy was fetched (RFC 3339).
    pub downloaded: Option<String>,
    /// IEEE date of the built-in data, when known.
    pub builtin_date: Option<String>,
}

fn info(l: &Loaded) -> DbInfo {
    let s = l.stats();
    let builtin = (!OUI_DATE.is_empty()).then(|| OUI_DATE.to_string());
    DbInfo {
        source: l.source.to_string(),
        total: s.total,
        ma_l: s.ma_l,
        ma_m: s.ma_m,
        ma_s: s.ma_s,
        ieee_date: match &l.meta {
            Some(m) => m.ieee_date.clone(),
            None => builtin.clone(),
        },
        downloaded: l.meta.as_ref().map(|m| m.downloaded.clone()),
        builtin_date: builtin,
    }
}

/// Report how many assignments are loaded and where they came from.
#[tauri::command]
pub fn mac_db_info() -> DbInfo {
    info(&database())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckResult {
    /// IEEE date of the files online (YYYY-MM-DD).
    pub remote_date: Option<String>,
    /// True when the online files are newer than the data in use; None when
    /// either date is unknown.
    pub newer: Option<bool>,
}

/// Ask the IEEE whether its registry is newer than the data in use. Reads
/// only the files' dates.
#[tauri::command]
pub async fn mac_db_check() -> Result<CheckResult, String> {
    let remote = tokio::task::spawn_blocking(update::remote_date)
        .await
        .map_err(|e| e.to_string())??;
    let local = info(&database()).ieee_date;
    let newer = match (&remote, &local) {
        (Some(r), Some(l)) => Some(r > l),
        _ => None,
    };
    Ok(CheckResult {
        remote_date: remote,
        newer,
    })
}

/// Download the IEEE registry, validate it, keep it in the app data folder
/// and start using it.
#[tauri::command]
pub async fn mac_db_download() -> Result<DbInfo, String> {
    let dir = super::data_dir()
        .cloned()
        .ok_or("the app data folder is not available")?;
    let loaded = tokio::task::spawn_blocking(move || -> Result<Loaded, String> {
        let (csv, ieee_date) = update::download()?;
        let db = core::Database::parse(&csv);
        let stats = db.stats();
        update::validate(&stats)?;
        let meta = update::Meta {
            downloaded: jiff::Timestamp::now()
                .strftime("%Y-%m-%dT%H:%M:%SZ")
                .to_string(),
            ieee_date,
            stats,
        };
        update::save(&dir, &csv, &meta)?;
        Ok(Loaded {
            db,
            source: "downloaded",
            meta: Some(meta),
        })
    })
    .await
    .map_err(|e| e.to_string())??;
    Ok(info(&super::replace(loaded)))
}

/// Remove the downloaded copy and go back to the built-in data.
#[tauri::command]
pub fn mac_db_reset() -> Result<DbInfo, String> {
    if let Some(dir) = super::data_dir() {
        update::remove(dir)?;
    }
    Ok(info(&super::reset_to_embedded()))
}
