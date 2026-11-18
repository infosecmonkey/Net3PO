//! Refresh the MAC vendor database from the IEEE registry on request.
//! Nothing here runs unless the user clicks Check or Download in Settings.
//! Downloads are size-capped and time-limited, validated before use, and
//! written to a temporary file that replaces the stored copy only when
//! complete, so a failed or partial download never replaces working data.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::core::{Database, DbStats};

/// IEEE registry CSVs: MA-L (/24), MA-M (/28), MA-S (/36).
pub const URLS: [&str; 3] = [
    "https://standards-oui.ieee.org/oui/oui.csv",
    "https://standards-oui.ieee.org/oui28/mam.csv",
    "https://standards-oui.ieee.org/oui36/oui36.csv",
];

/// Largest file accepted (MA-L is about 4 MB).
const MAX_FILE: u64 = 64 * 1024 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const READ_TIMEOUT: Duration = Duration::from_secs(120);

const CSV_NAME: &str = "oui-registry.csv";
const META_NAME: &str = "oui-registry.json";

/// What is known about a downloaded copy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Meta {
    /// When it was downloaded, RFC 3339 UTC.
    pub downloaded: String,
    /// IEEE's Last-Modified date of the newest of the three files, YYYY-MM-DD.
    pub ieee_date: Option<String>,
    pub stats: DbStats,
}

fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout_connect(CONNECT_TIMEOUT)
        .timeout_read(READ_TIMEOUT)
        // A plain product name; nothing about the user or computer.
        .user_agent(concat!("Net3PO/", env!("CARGO_PKG_VERSION")))
        .build()
}

/// An HTTP date (`Tue, 17 Nov 2026 21:01:40 GMT`) as YYYY-MM-DD.
pub fn http_date(v: &str) -> Option<String> {
    let ts = jiff::fmt::rfc2822::parse(v.trim()).ok()?;
    Some(ts.timestamp().strftime("%Y-%m-%d").to_string())
}

/// The newest of several YYYY-MM-DD dates.
fn newest(dates: impl IntoIterator<Item = Option<String>>) -> Option<String> {
    dates.into_iter().flatten().max()
}

/// The IEEE date of the files online, without downloading them.
pub fn remote_date() -> Result<Option<String>, String> {
    let a = agent();
    let mut dates = Vec::new();
    for url in URLS {
        let r = a.head(url).call().map_err(|e| format!("{url}: {e}"))?;
        dates.push(r.header("Last-Modified").and_then(http_date));
    }
    Ok(newest(dates))
}

/// Refuse data that does not look like the full registry.
pub fn validate(s: &DbStats) -> Result<(), String> {
    if s.ma_l < 20_000 || s.ma_m < 1_000 || s.ma_s < 1_000 {
        return Err(format!(
            "the download does not look like the full IEEE registry (MA-L {}, MA-M {}, MA-S {}); kept the current data",
            s.ma_l, s.ma_m, s.ma_s
        ));
    }
    Ok(())
}

/// Download all three files. Returns the combined CSV and IEEE's date.
pub fn download() -> Result<(String, Option<String>), String> {
    let a = agent();
    let mut out = String::new();
    let mut dates = Vec::new();
    for url in URLS {
        let r = a.get(url).call().map_err(|e| format!("{url}: {e}"))?;
        dates.push(r.header("Last-Modified").and_then(http_date));
        let mut buf = Vec::new();
        r.into_reader()
            .take(MAX_FILE + 1)
            .read_to_end(&mut buf)
            .map_err(|e| format!("{url}: {e}"))?;
        if buf.len() as u64 > MAX_FILE {
            return Err(format!("{url}: larger than 64 MB; not used"));
        }
        out.push_str(&String::from_utf8_lossy(&buf));
        if !out.ends_with('\n') {
            out.push('\n');
        }
    }
    Ok((out, newest(dates)))
}

fn paths(dir: &Path) -> (PathBuf, PathBuf) {
    (dir.join(CSV_NAME), dir.join(META_NAME))
}

/// Write a validated copy: temporary files first, then rename into place.
pub fn save(dir: &Path, csv: &str, meta: &Meta) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("could not create {}: {e}", dir.display()))?;
    let (csv_path, meta_path) = paths(dir);
    let tmp_csv = csv_path.with_extension("csv.tmp");
    let tmp_meta = meta_path.with_extension("json.tmp");
    let json = serde_json::to_string_pretty(meta).map_err(|e| e.to_string())?;
    let write = || -> std::io::Result<()> {
        std::fs::write(&tmp_csv, csv)?;
        std::fs::write(&tmp_meta, json)?;
        std::fs::rename(&tmp_csv, &csv_path)?;
        std::fs::rename(&tmp_meta, &meta_path)
    };
    write().map_err(|e| {
        let _ = std::fs::remove_file(&tmp_csv);
        let _ = std::fs::remove_file(&tmp_meta);
        format!("could not save the database: {e}")
    })
}

/// The stored copy, if present and still valid.
pub fn load(dir: &Path) -> Option<(Database, Meta)> {
    let (csv_path, meta_path) = paths(dir);
    let meta: Meta = serde_json::from_str(&std::fs::read_to_string(meta_path).ok()?).ok()?;
    if std::fs::metadata(&csv_path).ok()?.len() > 3 * MAX_FILE {
        return None;
    }
    let db = Database::parse(&std::fs::read_to_string(csv_path).ok()?);
    validate(&db.stats()).ok()?;
    Some((db, meta))
}

/// Remove the stored copy (back to the built-in data).
pub fn remove(dir: &Path) -> Result<(), String> {
    let (csv_path, meta_path) = paths(dir);
    for p in [csv_path, meta_path] {
        match std::fs::remove_file(&p) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(format!("could not remove {}: {e}", p.display())),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registry(ma_l: usize, ma_m: usize, ma_s: usize) -> String {
        let mut s = String::from("Registry,Assignment,Organization Name,Organization Address\n");
        for i in 0..ma_l {
            s.push_str(&format!("MA-L,{i:06X},Vendor {i},Somewhere\n"));
        }
        for i in 0..ma_m {
            s.push_str(&format!("MA-M,{i:07X},\"Maker, Inc.\",Elsewhere\n"));
        }
        for i in 0..ma_s {
            s.push_str(&format!("MA-S,{i:09X},Small {i},There\n"));
        }
        s
    }

    #[test]
    fn dates() {
        assert_eq!(
            http_date("Tue, 17 Nov 2026 21:01:40 GMT").as_deref(),
            Some("2026-11-17")
        );
        assert_eq!(http_date("garbage"), None);
        assert_eq!(
            newest([Some("2026-11-01".into()), None, Some("2026-11-17".into())]).as_deref(),
            Some("2026-11-17")
        );
    }

    #[test]
    fn validation_rejects_partial_data() {
        let small = Database::parse(&registry(100, 10, 10));
        assert!(validate(&small.stats()).is_err());
        let full = Database::parse(&registry(20_000, 1_000, 1_000));
        assert!(validate(&full.stats()).is_ok());
    }

    #[test]
    fn save_load_remove_round_trip() {
        let dir = std::env::temp_dir().join(format!("omnipacket-oui-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        assert!(load(&dir).is_none());
        let csv = registry(20_000, 1_000, 1_000);
        let db = Database::parse(&csv);
        let meta = Meta {
            downloaded: "2026-11-18T00:00:00Z".into(),
            ieee_date: Some("2026-11-17".into()),
            stats: db.stats(),
        };
        save(&dir, &csv, &meta).unwrap();
        let (loaded, m) = load(&dir).unwrap();
        assert_eq!(m, meta);
        assert_eq!(loaded.stats(), db.stats());
        assert_eq!(
            loaded.lookup(&[0, 0, 5]).map(|x| x.0).as_deref(),
            Some("Vendor 5")
        );
        // A damaged copy is ignored, not used.
        std::fs::write(dir.join(CSV_NAME), "MA-L,000001,Only one\n").unwrap();
        assert!(load(&dir).is_none());
        remove(&dir).unwrap();
        remove(&dir).unwrap();
        assert!(load(&dir).is_none());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    #[ignore = "contacts the IEEE; run by hand"]
    fn live_registry() {
        let d = remote_date().unwrap();
        assert!(d.is_some(), "no Last-Modified");
        let (csv, date) = download().unwrap();
        let db = Database::parse(&csv);
        validate(&db.stats()).unwrap();
        eprintln!("{date:?} {:?}", db.stats());
    }
}
