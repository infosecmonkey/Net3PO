//! TCP/UDP sender, listener and connection timing. Connection timing is
//! measured around the OS connect call; it is not packet-level SYN/SYN-ACK
//! timing, and a UDP non-answer proves nothing on its own.

pub mod commands;
pub mod core;
