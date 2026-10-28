mod tools;

use tools::dig::commands::dig_query;
use tools::fgt_sniffer::commands::{fgt_parse, fgt_read_file, fgt_save};
use tools::grep_builder::commands::{grep_build, grep_preview};
use tools::mac_vendor::commands::{mac_db_info, mac_lookup};
use tools::regex_builder::commands::{regex_replace, regex_test};
use tools::subnet_calculator::commands::{subnet_calculate, subnet_split};

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
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
            dig_query
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
