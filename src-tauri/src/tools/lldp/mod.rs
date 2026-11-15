//! LLDP and CDP neighbor discovery: see which switch and port this computer
//! is plugged into, from live capture (user-installed libpcap/Npcap) or a
//! capture file.

pub mod capture;
pub mod commands;
pub mod core;
