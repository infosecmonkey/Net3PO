//! FortiGate sniffer to PCAP. Converts `diagnose sniffer packet` verbose output
//! into a .pcap, written directly without any external tools.

pub mod commands;
pub mod core;
