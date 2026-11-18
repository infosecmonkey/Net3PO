//! MAC vendor lookup. The IEEE registry CSV is fetched and embedded at build
//! time (see build.rs). A newer copy downloaded from Settings, kept in the
//! app data folder, is used instead when present and valid.

pub mod commands;
pub mod core;
pub mod update;

use std::ops::Deref;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock, RwLock};

use core::Database;

/// The registry CSV embedded by build.rs. May be the live IEEE data, a file
/// provided via OUI_DATA_FILE, or a small seed set when fetching was skipped.
const OUI_DATA: &str = include_str!(concat!(env!("OUT_DIR"), "/oui_data.csv"));

/// Where the embedded data came from: "live", "file", or "seed".
pub const OUI_SOURCE: &str = env!("OUI_SOURCE");

/// IEEE date of the embedded data (YYYY-MM-DD), empty when unknown.
pub const OUI_DATE: &str = env!("OUI_DATE");

/// The database in use and where it came from.
pub struct Loaded {
    pub db: Database,
    /// "downloaded", or the embedded data's source.
    pub source: &'static str,
    pub meta: Option<update::Meta>,
}

impl Deref for Loaded {
    type Target = Database;
    fn deref(&self) -> &Database {
        &self.db
    }
}

static DATA_DIR: OnceLock<PathBuf> = OnceLock::new();
static CURRENT: RwLock<Option<Arc<Loaded>>> = RwLock::new(None);

/// Set once at startup: where downloaded copies are kept.
pub fn set_data_dir(dir: PathBuf) {
    let _ = DATA_DIR.set(dir.join("mac-vendor"));
}

pub(crate) fn data_dir() -> Option<&'static PathBuf> {
    DATA_DIR.get()
}

fn embedded() -> Loaded {
    Loaded {
        db: Database::parse(OUI_DATA),
        source: OUI_SOURCE,
        meta: None,
    }
}

fn load() -> Loaded {
    match data_dir().and_then(|d| update::load(d)) {
        Some((db, meta)) => Loaded {
            db,
            source: "downloaded",
            meta: Some(meta),
        },
        None => embedded(),
    }
}

/// The lookup database, loaded on first use.
pub fn database() -> Arc<Loaded> {
    if let Some(l) = CURRENT.read().unwrap_or_else(|p| p.into_inner()).as_ref() {
        return l.clone();
    }
    let mut w = CURRENT.write().unwrap_or_else(|p| p.into_inner());
    w.get_or_insert_with(|| Arc::new(load())).clone()
}

/// Swap in a new database (after a download or a reset).
pub(crate) fn replace(l: Loaded) -> Arc<Loaded> {
    let l = Arc::new(l);
    *CURRENT.write().unwrap_or_else(|p| p.into_inner()) = Some(l.clone());
    l
}

pub(crate) fn reset_to_embedded() -> Arc<Loaded> {
    replace(embedded())
}
