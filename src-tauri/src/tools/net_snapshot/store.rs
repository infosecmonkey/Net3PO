//! Saved snapshots: one JSON file each in a folder under the app data dir.

use std::fs;
use std::path::{Path, PathBuf};

use serde::Serialize;
use thiserror::Error;

use super::model::Snapshot;

/// Largest snapshot file read (store or import).
pub const MAX_FILE: u64 = 16 * 1024 * 1024;
/// Most snapshots listed.
const MAX_LISTED: usize = 500;
/// Longest label kept.
const MAX_LABEL: usize = 200;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("snapshot not found")]
    NotFound,
    #[error("invalid snapshot id")]
    BadId,
    #[error("file is larger than 16 MB")]
    TooLarge,
    #[error("not a Net3PO snapshot file: {0}")]
    BadFile(String),
    #[error("{0}")]
    Io(#[from] std::io::Error),
}

/// What the saved list shows for each snapshot.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Summary {
    pub id: String,
    pub label: String,
    pub taken: String,
    pub host: String,
    pub os: String,
    pub interfaces: usize,
    pub routes: usize,
    pub listeners: usize,
    /// Sections whose command failed.
    pub failed: usize,
}

impl From<&Snapshot> for Summary {
    fn from(s: &Snapshot) -> Self {
        Summary {
            id: s.id.clone(),
            label: s.label.clone(),
            taken: s.taken.clone(),
            host: s.host.clone(),
            os: s.os.clone(),
            interfaces: s.interfaces.len(),
            routes: s.routes.len(),
            listeners: s.listeners.len(),
            failed: s.sources.iter().filter(|x| !x.ok).count(),
        }
    }
}

/// Ids are generated here; anything else is refused so a crafted id cannot
/// reach outside the folder.
pub fn valid_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 64 && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

/// The snapshot store in `dir`.
pub struct Store {
    dir: PathBuf,
}

impl Store {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Store { dir: dir.into() }
    }

    fn path(&self, id: &str) -> Result<PathBuf, StoreError> {
        if !valid_id(id) {
            return Err(StoreError::BadId);
        }
        Ok(self.dir.join(format!("{id}.json")))
    }

    /// Save (create or replace) a snapshot under its id.
    pub fn save(&self, s: &Snapshot) -> Result<(), StoreError> {
        let path = self.path(&s.id)?;
        fs::create_dir_all(&self.dir)?;
        let json = serde_json::to_vec_pretty(s).map_err(|e| StoreError::BadFile(e.to_string()))?;
        // Write then rename, so a crash never leaves a half-written file.
        let tmp = path.with_extension("json.tmp");
        fs::write(&tmp, json)?;
        fs::rename(&tmp, &path)?;
        Ok(())
    }

    pub fn get(&self, id: &str) -> Result<Snapshot, StoreError> {
        let path = self.path(id)?;
        if !path.exists() {
            return Err(StoreError::NotFound);
        }
        read_file(&path)
    }

    /// Saved snapshots, newest first. Unreadable files are skipped.
    pub fn list(&self) -> Result<Vec<Summary>, StoreError> {
        let entries = match fs::read_dir(&self.dir) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e.into()),
        };
        let mut out: Vec<Summary> = entries
            .filter_map(Result::ok)
            .filter(|e| e.path().extension().is_some_and(|x| x == "json"))
            .filter_map(|e| read_file(&e.path()).ok())
            .filter(|s| valid_id(&s.id))
            .map(|s| Summary::from(&s))
            .collect();
        out.sort_by(|a, b| b.taken.cmp(&a.taken).then(b.id.cmp(&a.id)));
        out.truncate(MAX_LISTED);
        Ok(out)
    }

    pub fn set_label(&self, id: &str, label: &str) -> Result<(), StoreError> {
        let mut s = self.get(id)?;
        s.label = label.trim().chars().take(MAX_LABEL).collect();
        self.save(&s)
    }

    pub fn delete(&self, id: &str) -> Result<(), StoreError> {
        let path = self.path(id)?;
        match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(StoreError::NotFound),
            Err(e) => Err(e.into()),
        }
    }

    /// Bring in a snapshot file from elsewhere. It gets a fresh id if one
    /// with the same id is already saved.
    pub fn import(&self, path: &Path, fresh_id: String) -> Result<Summary, StoreError> {
        let mut s = read_file(path)?;
        if !valid_id(&s.id) || self.path(&s.id)?.exists() {
            s.id = fresh_id;
        }
        s.label = s.label.chars().take(MAX_LABEL).collect();
        self.save(&s)?;
        Ok(Summary::from(&s))
    }
}

/// Read and parse one snapshot file, with a size cap.
pub fn read_file(path: &Path) -> Result<Snapshot, StoreError> {
    let len = fs::metadata(path)?.len();
    if len > MAX_FILE {
        return Err(StoreError::TooLarge);
    }
    let bytes = fs::read(path)?;
    let s: Snapshot =
        serde_json::from_slice(&bytes).map_err(|e| StoreError::BadFile(e.to_string()))?;
    if s.taken.is_empty() && s.os.is_empty() {
        return Err(StoreError::BadFile("missing snapshot fields".into()));
    }
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::net_snapshot::model::Interface;

    fn dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("net3po_snap_{name}_{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        d
    }

    fn snap(id: &str, taken: &str) -> Snapshot {
        Snapshot {
            id: id.into(),
            taken: taken.into(),
            os: "Linux".into(),
            interfaces: vec![Interface {
                name: "eth0".into(),
                ..Default::default()
            }],
            ..Default::default()
        }
    }

    #[test]
    fn save_list_label_delete() {
        let d = dir("crud");
        let st = Store::new(&d);
        assert!(st.list().unwrap().is_empty());
        st.save(&snap("a1", "2026-11-14T10:00:00-05:00")).unwrap();
        st.save(&snap("b2", "2026-11-14T11:00:00-05:00")).unwrap();
        let l = st.list().unwrap();
        assert_eq!(
            l.iter().map(|s| s.id.as_str()).collect::<Vec<_>>(),
            vec!["b2", "a1"]
        );
        assert_eq!(l[0].interfaces, 1);
        st.set_label("a1", "  before change  ").unwrap();
        assert_eq!(st.get("a1").unwrap().label, "before change");
        st.delete("a1").unwrap();
        assert!(matches!(st.get("a1"), Err(StoreError::NotFound)));
        assert!(matches!(st.delete("a1"), Err(StoreError::NotFound)));
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn ids_cannot_escape() {
        let st = Store::new(dir("ids"));
        for bad in ["../x", "a/b", "", "a.b", "C:\\x"] {
            assert!(matches!(st.get(bad), Err(StoreError::BadId)), "{bad}");
        }
        let mut s = snap("../../evil", "t");
        assert!(matches!(st.save(&s), Err(StoreError::BadId)));
        s.id = "ok-1".into();
        assert!(st.save(&s).is_ok());
    }

    #[test]
    fn import_assigns_fresh_id_on_clash_and_rejects_junk() {
        let d = dir("import");
        let st = Store::new(d.join("store"));
        fs::create_dir_all(&d).unwrap();
        st.save(&snap("same", "2026-11-14T10:00:00Z")).unwrap();
        let file = d.join("other.json");
        fs::write(
            &file,
            serde_json::to_vec(&snap("same", "2026-11-13T10:00:00Z")).unwrap(),
        )
        .unwrap();
        let s = st.import(&file, "fresh-1".into()).unwrap();
        assert_eq!(s.id, "fresh-1");
        assert_eq!(st.list().unwrap().len(), 2);

        let junk = d.join("junk.json");
        fs::write(&junk, b"{\"hello\": 1}").unwrap();
        assert!(matches!(
            st.import(&junk, "x".into()),
            Err(StoreError::BadFile(_))
        ));
        fs::write(&junk, b"not json").unwrap();
        assert!(matches!(
            st.import(&junk, "x".into()),
            Err(StoreError::BadFile(_))
        ));
        let _ = fs::remove_dir_all(&d);
    }
}
