//! Shared local storage for settings and history (saved commands, saved
//! queries), kept in the OS app data dir. No telemetry: nothing leaves the
//! machine.

pub mod commands;
pub mod core;
