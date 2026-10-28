mod tools;

use tools::dig::commands::dig_query;
use tools::dns_analyzer::commands::dns_analyze;
use tools::fgt_sniffer::commands::{fgt_parse, fgt_read_file, fgt_save};
use tools::grep_builder::commands::{grep_build, grep_preview};
use tools::mac_vendor::commands::{mac_db_info, mac_lookup};
use tools::port_scanner::commands::{ScanRegistry, port_scan, port_scan_cancel};
use tools::regex_builder::commands::{regex_replace, regex_test};
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
            tftp_stop
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
