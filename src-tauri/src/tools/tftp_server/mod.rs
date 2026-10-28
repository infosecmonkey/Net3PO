//! TFTP server: a UDP listener that serves files from a chosen folder (and
//! optionally accepts uploads), confined to that folder, with live transfer
//! reporting and clean stop.

pub mod commands;
pub mod core;
