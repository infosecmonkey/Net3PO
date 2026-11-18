//! PCAP/PCAPNG inspector: packet summaries, L2-L4 fields, conversations,
//! top talkers, protocols and DNS queries from a capture file (or
//! FortiGate sniffer text). Reports what the capture shows; it does not
//! replace Wireshark for deep protocol analysis.

pub mod commands;
pub mod core;
pub mod decode;
pub mod packets;
pub mod sanitize;
