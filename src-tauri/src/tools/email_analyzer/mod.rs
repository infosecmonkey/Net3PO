//! Email Header Analyzer: parses pasted headers or .eml files offline, and
//! offers explicit, user-triggered lookups (origin IP owner, registration and blocklists).

pub mod commands;
pub mod core;
pub mod domains;
pub mod lookalike;
pub mod lookup;
pub mod rdap;
