mod tools;

use tools::dhcp_monitor::commands::{DhcpRegistry, dhcp_interfaces, dhcp_monitor, dhcp_stop};
use tools::dig::commands::dig_query;
use tools::dns_analyzer::commands::dns_analyze;
use tools::fgt_sniffer::commands::{fgt_parse, fgt_read_file, fgt_save};
use tools::grep_builder::commands::{grep_build, grep_preview};
use tools::mac_vendor::commands::{mac_db_info, mac_lookup};
use tools::port_mapper::commands::{PortMapRegistry, port_map, port_map_cancel, port_map_save};
use tools::port_scanner::commands::{ScanRegistry, port_scan, port_scan_cancel};
use tools::regex_builder::commands::{regex_replace, regex_test};
use tools::snmp_sweep::commands::{SweepRegistry, snmp_sweep, snmp_sweep_cancel};
use tools::snmp_walk::commands::{
    MibState, SnmpRegistry, snmp_load_mib, snmp_mib_info, snmp_walk, snmp_walk_cancel,
};
use tools::subnet_calculator::commands::{subnet_calculate, subnet_split};
use tools::syslog_server::commands::{
    SyslogRegistry, syslog_save, syslog_send, syslog_start, syslog_stop,
};
use tools::tftp_server::commands::{TftpRegistry, tftp_start, tftp_stop};

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .manage(ScanRegistry::default())
        .manage(SyslogRegistry::default())
        .manage(TftpRegistry::default())
        .manage(SnmpRegistry::default())
        .manage(MibState::default())
        .manage(SweepRegistry::default())
        .manage(PortMapRegistry::default())
        .manage(DhcpRegistry::default())
        .invoke_handler(tauri::generate_handler![
            subnet_calculate,
            subnet_split,
            regex_test,
            regex_replace,
            grep_build,
            grep_preview,
            mac_lookup,
            mac_db_info,
            fgt_parse,
            fgt_save,
            fgt_read_file,
            dig_query,
            dns_analyze,
            port_scan,
            port_scan_cancel,
            syslog_start,
            syslog_stop,
            syslog_save,
            syslog_send,
            tftp_start,
            tftp_stop,
            snmp_walk,
            snmp_walk_cancel,
            snmp_load_mib,
            snmp_mib_info,
            snmp_sweep,
            snmp_sweep_cancel,
            port_map,
            port_map_cancel,
            port_map_save,
            dhcp_interfaces,
            dhcp_monitor,
            dhcp_stop
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
