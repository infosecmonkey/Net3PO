//! Throughput tester: drives a user-installed iperf3 (never bundled) in
//! client or server mode and reads its JSON output.

pub mod commands;
pub mod core;
