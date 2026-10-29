//! Local JSON collections (saved commands, saved queries) in a directory the
//! caller chooses, normally the OS app data dir. Writes are atomic (temp file
//! then rename), sizes are capped, and only known collection names are
//! accepted, so the UI cannot write arbitrary files. A file that fails to
//! parse is moved aside, never deleted, and loading starts empty.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

/// Collections the app may read and write.
pub const COLLECTIONS: &[&str] = &[
    "fortinet_saved_commands",
    "fortinet_interfaces",
    "grep_saved_queries",
];

/// Largest collection file accepted, on load and on save.
pub const MAX_BYTES: usize = 5 * 1024 * 1024;
/// Most items in one collection.
pub const MAX_ITEMS: usize = 10_000;
/// On-disk format version.
const VERSION: u32 = 1;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum StoreError {
    #[error("unknown collection '{0}'")]
    UnknownCollection(String),
    #[error("collection is too large ({0} bytes; limit {MAX_BYTES})")]
    TooLarge(usize),
    #[error("too many items ({0}; limit {MAX_ITEMS})")]
    TooManyItems(usize),
    #[error("{0}")]
    Io(String),
}

#[derive(Serialize, Deserialize)]
struct Document {
    version: u32,
    items: Vec<Value>,
}

/// Result of loading a collection.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Loaded {
    pub items: Vec<Value>,
    /// The file was unreadable and was moved aside to this name.
    pub recovered_to: Option<String>,
}

/// Reject anything not on the collection list.
pub fn validate(name: &str) -> Result<(), StoreError> {
    if COLLECTIONS.contains(&name) {
        Ok(())
    } else {
        Err(StoreError::UnknownCollection(name.to_string()))
    }
}

fn file_path(dir: &Path, name: &str) -> PathBuf {
    dir.join(format!("{name}.json"))
}

/// Load a collection. A missing file is an empty collection. An oversized or
/// corrupt file is renamed to `<name>.corrupt-<n>.json` and an empty
/// collection is returned, so a bad file never blocks the app.
pub fn load(dir: &Path, name: &str) -> Result<Loaded, StoreError> {
    validate(name)?;
    let path = file_path(dir, name);
    let bytes = match fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Loaded {
                items: Vec::new(),
                recovered_to: None,
            });
        }
        Err(e) => {
            return Err(StoreError::Io(format!(
                "could not read {}: {e}",
                path.display()
            )));
        }
    };

    let parsed = (bytes.len() <= MAX_BYTES)
        .then(|| serde_json::from_slice::<Document>(&bytes).ok())
        .flatten()
        .filter(|d| d.items.len() <= MAX_ITEMS);
    match parsed {
        Some(doc) => Ok(Loaded {
            items: doc.items,
            recovered_to: None,
        }),
        None => {
            let aside = move_aside(dir, name, &path)?;
            Ok(Loaded {
                items: Vec::new(),
                recovered_to: Some(aside),
            })
        }
    }
}

/// Rename a bad file to the first free `<name>.corrupt-<n>.json`.
fn move_aside(dir: &Path, name: &str, path: &Path) -> Result<String, StoreError> {
    for n in 1..1000 {
        let target = dir.join(format!("{name}.corrupt-{n}.json"));
        if !target.exists() {
            fs::rename(path, &target).map_err(|e| {
                StoreError::Io(format!("could not move aside {}: {e}", path.display()))
            })?;
            return Ok(target
                .file_name()
                .map(|f| f.to_string_lossy().into_owned())
                .unwrap_or_default());
        }
    }
    Err(StoreError::Io(format!(
        "too many corrupt copies of {name}; clean up {}",
        dir.display()
    )))
}

/// Save a collection atomically: write a temp file, flush it to disk, then
/// rename it over the old file.
pub fn save(dir: &Path, name: &str, items: Vec<Value>) -> Result<(), StoreError> {
    validate(name)?;
    if items.len() > MAX_ITEMS {
        return Err(StoreError::TooManyItems(items.len()));
    }
    let doc = Document {
        version: VERSION,
        items,
    };
    let bytes = serde_json::to_vec_pretty(&doc).map_err(|e| StoreError::Io(e.to_string()))?;
    if bytes.len() > MAX_BYTES {
        return Err(StoreError::TooLarge(bytes.len()));
    }

    fs::create_dir_all(dir)
        .map_err(|e| StoreError::Io(format!("could not create {}: {e}", dir.display())))?;
    let path = file_path(dir, name);
    let tmp = dir.join(format!("{name}.json.tmp"));
    let io =
        |what: &str, e: std::io::Error| StoreError::Io(format!("{what} {}: {e}", tmp.display()));
    let mut f = fs::File::create(&tmp).map_err(|e| io("could not create", e))?;
    f.write_all(&bytes).map_err(|e| io("could not write", e))?;
    f.sync_all().map_err(|e| io("could not flush", e))?;
    drop(f);
    fs::rename(&tmp, &path)
        .map_err(|e| StoreError::Io(format!("could not replace {}: {e}", path.display())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A fresh, empty directory under the OS temp dir.
    fn temp_dir(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let d = std::env::temp_dir().join(format!(
            "omnipacket-store-{tag}-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&d).unwrap();
        d
    }

    const C: &str = "fortinet_saved_commands";

    #[test]
    fn missing_file_is_empty() {
        let d = temp_dir("missing");
        assert_eq!(
            load(&d, C).unwrap(),
            Loaded {
                items: vec![],
                recovered_to: None
            }
        );
    }

    #[test]
    fn round_trip() {
        let d = temp_dir("roundtrip");
        let items = vec![
            json!({"title": "a", "command": "diagnose sys session list"}),
            json!(2),
        ];
        save(&d, C, items.clone()).unwrap();
        assert_eq!(load(&d, C).unwrap().items, items);
        // Overwrite replaces, and no temp file is left behind.
        save(&d, C, vec![json!("only")]).unwrap();
        assert_eq!(load(&d, C).unwrap().items, vec![json!("only")]);
        assert!(!d.join(format!("{C}.json.tmp")).exists());
    }

    #[test]
    fn rejects_unknown_and_path_like_names() {
        let d = temp_dir("names");
        for bad in [
            "settings",
            "../etc/passwd",
            "fortinet_saved_commands/..",
            "",
        ] {
            assert_eq!(
                load(&d, bad),
                Err(StoreError::UnknownCollection(bad.to_string()))
            );
            assert!(save(&d, bad, vec![]).is_err());
        }
    }

    #[test]
    fn corrupt_file_moved_aside() {
        let d = temp_dir("corrupt");
        fs::write(d.join(format!("{C}.json")), b"{not json").unwrap();
        let first = load(&d, C).unwrap();
        assert!(first.items.is_empty());
        assert_eq!(
            first.recovered_to.as_deref(),
            Some("fortinet_saved_commands.corrupt-1.json")
        );
        assert!(d.join("fortinet_saved_commands.corrupt-1.json").exists());
        // A second bad file gets the next free name.
        fs::write(d.join(format!("{C}.json")), b"[]").unwrap();
        assert_eq!(
            load(&d, C).unwrap().recovered_to.as_deref(),
            Some("fortinet_saved_commands.corrupt-2.json")
        );
    }

    #[test]
    fn caps_items_and_size() {
        let d = temp_dir("caps");
        assert_eq!(
            save(&d, C, vec![json!(0); MAX_ITEMS + 1]),
            Err(StoreError::TooManyItems(MAX_ITEMS + 1))
        );
        let big = "x".repeat(MAX_BYTES);
        assert!(matches!(
            save(&d, C, vec![json!(big)]),
            Err(StoreError::TooLarge(_))
        ));
        // Nothing was written by the failed saves.
        assert!(!d.join(format!("{C}.json")).exists());
    }

    #[test]
    fn oversized_file_on_disk_is_moved_aside() {
        let d = temp_dir("bigdisk");
        let big = format!(
            "{{\"version\":1,\"items\":[\"{}\"]}}",
            "x".repeat(MAX_BYTES)
        );
        fs::write(d.join(format!("{C}.json")), big).unwrap();
        assert!(load(&d, C).unwrap().recovered_to.is_some());
    }
}
