//! Tool modules. Each tool keeps pure logic in `core.rs` and Tauri commands in
//! `commands.rs`, registered in `lib.rs`.

pub mod config_diff;
pub mod dhcp_monitor;
pub mod dig;
pub mod dns_analyzer;
pub mod email_analyzer;
pub mod event_log;
pub mod fgt_sniffer;
pub mod fortinet_builder;
pub mod grep_builder;
pub mod mac_vendor;
pub mod port_mapper;
pub mod port_scanner;
pub mod regex_builder;
pub mod script_decoder;
pub mod snmp_sweep;
pub mod snmp_walk;
pub mod socket_tools;
pub mod ssh;
pub mod subnet_calculator;
pub mod syslog_server;
pub mod tftp_server;
pub mod tls_inspector;
pub mod traceroute;
pub mod wake_on_lan;
