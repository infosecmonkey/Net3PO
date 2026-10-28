//! MAC vendor lookup. The IEEE registry CSV is fetched and embedded at build
//! time (see build.rs); here it is parsed once, lazily, into the lookup table.

pub mod commands;
pub mod core;

use std::sync::OnceLock;

use core::Database;

/// The registry CSV embedded by build.rs. May be the live IEEE data, a file
/// provided via OUI_DATA_FILE, or a small seed set when fetching was skipped.
const OUI_DATA: &str = include_str!(concat!(env!("OUT_DIR"), "/oui_data.csv"));

/// Where the embedded data came from: "live", "file", or "seed".
pub const OUI_SOURCE: &str = env!("OUI_SOURCE");

static DB: OnceLock<Database> = OnceLock::new();

/// The lookup database, parsed on first use.
pub fn database() -> &'static Database {
    DB.get_or_init(|| Database::parse(OUI_DATA))
}
