//! DNS benchmark: compare resolvers over UDP, TCP, DoT and DoH, with DNSSEC
//! validation and NXDOMAIN hijack checks. No admin rights needed.

pub mod commands;
pub mod core;
pub mod net;
