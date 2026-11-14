//! NTP checker: query servers repeatedly and report offset, delay, stratum
//! and reference. Read-only: the system clock is never changed.

pub mod commands;
pub mod core;
