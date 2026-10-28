use std::{env, fs, path::PathBuf, time::Duration};

fn main() {
    tauri_build::build();
    generate_oui_data();
}

/// IEEE registry CSV endpoints: MA-L (/24), MA-M (/28), MA-S (/36).
const URLS: [&str; 3] = [
    "https://standards-oui.ieee.org/oui/oui.csv",
    "https://standards-oui.ieee.org/oui28/mam.csv",
    "https://standards-oui.ieee.org/oui36/oui36.csv",
];

/// Produce `$OUT_DIR/oui_data.csv` for the crate to embed. Fetches the IEEE
/// registry by default; falls back to a committed seed set so the build never
/// fails without network. Overrides:
/// - `OUI_DATA_FILE=/path/to.csv` uses a pre-downloaded file (e.g. CI cache).
/// - `OUI_OFFLINE=1` skips fetching and uses the seed set.
fn generate_oui_data() {
    println!("cargo:rerun-if-env-changed=OUI_DATA_FILE");
    println!("cargo:rerun-if-env-changed=OUI_OFFLINE");
    println!("cargo:rerun-if-env-changed=OUI_REFRESH");
    println!("cargo:rerun-if-changed=seed_oui.csv");

    let out_file = PathBuf::from(env::var("OUT_DIR").unwrap()).join("oui_data.csv");
    let seed = include_str!("seed_oui.csv").to_string();

    let (data, source) = if let Ok(path) = env::var("OUI_DATA_FILE") {
        match fs::read_to_string(&path) {
            Ok(s) => (s, "file"),
            Err(e) => {
                warn(&format!(
                    "OUI_DATA_FILE '{path}' unreadable: {e}; using seed set"
                ));
                (seed, "seed")
            }
        }
    } else if env::var_os("OUI_OFFLINE").is_some() {
        (seed, "seed")
    } else {
        match fetch_all() {
            Ok(s) => (s, "live"),
            Err(e) => {
                warn(&format!(
                    "OUI fetch failed ({e}); using seed set. \
                     Set OUI_DATA_FILE to a downloaded CSV or OUI_OFFLINE=1 to silence this."
                ));
                (seed, "seed")
            }
        }
    };

    fs::write(&out_file, data).expect("write oui_data.csv");
    println!("cargo:rustc-env=OUI_SOURCE={source}");
}

fn warn(msg: &str) {
    println!("cargo:warning={msg}");
}

fn fetch_all() -> Result<String, String> {
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(20))
        .timeout_read(Duration::from_secs(90))
        .build();

    let mut out = String::new();
    for url in URLS {
        let body = agent
            .get(url)
            .call()
            .map_err(|e| format!("{url}: {e}"))?
            .into_string()
            .map_err(|e| format!("{url}: {e}"))?;
        out.push_str(&body);
        if !out.ends_with('\n') {
            out.push('\n');
        }
    }
    Ok(out)
}
