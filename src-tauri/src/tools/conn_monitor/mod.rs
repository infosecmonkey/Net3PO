//! Continuous connectivity monitor: TCP, HTTP and ICMP probes against
//! several targets on an interval, streamed to the UI. History, graphs and
//! outage windows live in the UI, which bounds them.

pub mod commands;
pub mod probes;
