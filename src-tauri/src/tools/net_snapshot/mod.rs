//! Local network snapshot and compare: interfaces, routes, DNS, neighbors
//! and listening ports, read with the OS's own commands (no admin rights),
//! saved locally, and compared section by section.

pub mod collect;
pub mod commands;
pub mod model;
pub mod parse;
pub mod store;
