mod tools;

use tools::subnet_calculator::commands::{subnet_calculate, subnet_split};

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![subnet_calculate, subnet_split])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
