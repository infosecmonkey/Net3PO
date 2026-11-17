//! FortiGate session list parser: `diagnose sys session list` and
//! `diagnose sys session6 list` output as a filterable table with decoded
//! state flags, NAT, counters and offload status. Offline.

pub mod commands;
pub mod core;
