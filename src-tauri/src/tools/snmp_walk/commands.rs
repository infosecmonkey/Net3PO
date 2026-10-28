//! Tauri commands for the SNMP walk. The live SNMP I/O uses `snmp2`'s blocking
//! `SyncSession` (which covers v1/v2c/v3 uniformly) on a blocking task, so a
//! slow agent never stalls the async runtime. Varbinds stream to the UI and the
//! walk is cancellable. OID display names come from the shared MIB registry.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use snmp2::v3::{Auth, AuthProtocol, Cipher, Security};
use snmp2::{Oid, SyncSession, Value};
use tauri::State;
use tauri::ipc::Channel;

use super::core::Mib;

/// Shared MIB registry (built-ins plus any loaded MIB files).
pub struct MibState(pub Mutex<Mib>);

impl Default for MibState {
    fn default() -> Self {
        MibState(Mutex::new(Mib::with_builtins()))
    }
}

/// Tracks running walks so they can be cancelled by id.
#[derive(Default)]
pub struct SnmpRegistry {
    inner: Arc<Mutex<HashMap<u32, Arc<AtomicBool>>>>,
}

const MAX_VARBINDS: usize = 100_000;
const GETBULK_REPETITIONS: u32 = 20;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct WalkConfig {
    pub host: String,
    pub port: u16,
    pub version: String,
    pub community: String,
    pub username: String,
    pub auth_protocol: String,
    pub auth_password: String,
    pub priv_cipher: String,
    pub priv_password: String,
    pub start_oid: String,
    pub timeout_ms: u64,
}

impl Default for WalkConfig {
    fn default() -> Self {
        WalkConfig {
            host: String::new(),
            port: 161,
            version: "v2c".to_string(),
            community: "public".to_string(),
            username: String::new(),
            auth_protocol: "sha1".to_string(),
            auth_password: String::new(),
            priv_cipher: "aes128".to_string(),
            priv_password: String::new(),
            start_oid: "1.3.6.1.2.1".to_string(),
            timeout_ms: 3000,
        }
    }
}

#[derive(Clone, Serialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum WalkEvent {
    Varbind {
        oid: String,
        name: String,
        value: String,
        value_type: String,
    },
    Done {
        count: usize,
        cancelled: bool,
        error: Option<String>,
    },
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MibInfo {
    pub total: usize,
}

/// Load a MIB file into the shared registry; returns names added and the total.
#[tauri::command]
pub fn snmp_load_mib(state: State<'_, MibState>, path: String) -> Result<MibInfo, String> {
    let text = std::fs::read_to_string(&path).map_err(|e| format!("could not read {path}: {e}"))?;
    let mut mib = state.0.lock().unwrap();
    mib.load_mib(&text);
    Ok(MibInfo { total: mib.len() })
}

/// Current size of the MIB registry.
#[tauri::command]
pub fn snmp_mib_info(state: State<'_, MibState>) -> MibInfo {
    MibInfo {
        total: state.0.lock().unwrap().len(),
    }
}

/// Cancel a running walk by id.
#[tauri::command]
pub fn snmp_walk_cancel(registry: State<'_, SnmpRegistry>, walk_id: u32) {
    if let Some(flag) = registry.inner.lock().unwrap().get(&walk_id) {
        flag.store(true, Ordering::Relaxed);
    }
}

/// Walk `start_oid` on the target, streaming each varbind. Runs on a blocking
/// task; cancellable via `snmp_walk_cancel`.
#[tauri::command]
pub async fn snmp_walk(
    registry: State<'_, SnmpRegistry>,
    mib_state: State<'_, MibState>,
    walk_id: u32,
    config: WalkConfig,
    on_event: Channel<WalkEvent>,
) -> Result<(), String> {
    let cancel = Arc::new(AtomicBool::new(false));
    registry
        .inner
        .lock()
        .unwrap()
        .insert(walk_id, cancel.clone());

    // Snapshot the MIB so translation does not hold the lock during the walk.
    let mib = mib_state.0.lock().unwrap().clone();
    let reg = registry.inner.clone();

    // run_walk emits Varbind events and the final Done event itself.
    let _ = tokio::task::spawn_blocking(move || run_walk(config, mib, &on_event, &cancel)).await;

    reg.lock().unwrap().remove(&walk_id);
    Ok(())
}

/// Returns (count, cancelled, error). Emits Varbind and the final Done event.
fn run_walk(
    config: WalkConfig,
    mib: Mib,
    on_event: &Channel<WalkEvent>,
    cancel: &AtomicBool,
) -> (usize, bool, Option<String>) {
    let root = match mib.resolve(&config.start_oid) {
        Some(o) => o,
        None => {
            let err = Some(format!("invalid start OID '{}'", config.start_oid));
            let _ = on_event.send(WalkEvent::Done {
                count: 0,
                cancelled: false,
                error: err.clone(),
            });
            return (0, false, err);
        }
    };

    let timeout = Some(Duration::from_millis(config.timeout_ms));
    let dest = (config.host.as_str(), config.port);
    let use_bulk = config.version != "v1";

    let mut session = match build_session(&config, dest, timeout) {
        Ok(s) => s,
        Err(e) => {
            let _ = on_event.send(WalkEvent::Done {
                count: 0,
                cancelled: false,
                error: Some(e.clone()),
            });
            return (0, false, Some(e));
        }
    };

    let mut last = root.clone();
    let mut count = 0usize;
    let mut cancelled = false;
    let mut error = None;

    'walk: loop {
        if cancel.load(Ordering::Relaxed) {
            cancelled = true;
            break;
        }

        // Convert this round's varbinds to owned data before touching `last`
        // (the varbind values borrow the PDU buffer).
        let fetched: Result<Vec<(Vec<u32>, String, String)>, String> = (|| {
            let arcs: Vec<u64> = last.iter().map(|n| *n as u64).collect();
            let cur = Oid::from(&arcs[..]).map_err(|_| "bad OID".to_string())?;
            let pdu = if use_bulk {
                session.getbulk(&[&cur], 0, GETBULK_REPETITIONS)
            } else {
                session.getnext(&cur)
            }
            .map_err(|e| format!("{e:?}"))?;
            let mut out = Vec::new();
            for (oid, val) in pdu.varbinds {
                let (vt, v) = format_value(&val);
                out.push((oid_to_vec(&oid), vt, v));
            }
            Ok(out)
        })();

        let rows = match fetched {
            Ok(r) => r,
            Err(e) => {
                error = Some(e);
                break;
            }
        };

        if rows.is_empty() {
            break; // agent returned nothing more
        }

        let mut advanced = false;
        for (oid_vec, value_type, value) in rows {
            // Stop emitting the current batch the moment a cancel arrives.
            if cancel.load(Ordering::Relaxed) {
                cancelled = true;
                break 'walk;
            }
            // End of walk: left the requested subtree or stopped advancing
            // (covers endOfMibView and lexicographic end).
            if !oid_vec.starts_with(&root) || oid_vec <= last {
                break 'walk;
            }
            let _ = on_event.send(WalkEvent::Varbind {
                oid: dotted(&oid_vec),
                name: mib.translate(&oid_vec),
                value,
                value_type,
            });
            last = oid_vec;
            count += 1;
            advanced = true;
            if count >= MAX_VARBINDS {
                break 'walk;
            }
        }
        if !advanced {
            break;
        }
    }

    let _ = on_event.send(WalkEvent::Done {
        count,
        cancelled,
        error: error.clone(),
    });
    (count, cancelled, error)
}

fn build_session(
    config: &WalkConfig,
    dest: (&str, u16),
    timeout: Option<Duration>,
) -> Result<SyncSession, String> {
    match config.version.as_str() {
        "v1" => SyncSession::new_v1(dest, config.community.as_bytes(), timeout, 0)
            .map_err(|e| format!("connect failed: {e}")),
        "v3" => {
            let security = build_v3_security(config);
            SyncSession::new_v3(dest, timeout, 0, security)
                .map_err(|e| format!("connect failed: {e}"))
        }
        _ => SyncSession::new_v2c(dest, config.community.as_bytes(), timeout, 0)
            .map_err(|e| format!("connect failed: {e}")),
    }
}

fn build_v3_security(config: &WalkConfig) -> Security {
    let mut sec = Security::new(config.username.as_bytes(), config.auth_password.as_bytes());
    sec = sec.with_auth_protocol(match config.auth_protocol.to_ascii_lowercase().as_str() {
        "md5" => AuthProtocol::Md5,
        "sha224" => AuthProtocol::Sha224,
        "sha256" => AuthProtocol::Sha256,
        "sha384" => AuthProtocol::Sha384,
        "sha512" => AuthProtocol::Sha512,
        _ => AuthProtocol::Sha1,
    });

    let auth_none =
        config.auth_protocol.eq_ignore_ascii_case("none") || config.auth_password.is_empty();
    let priv_none =
        config.priv_cipher.eq_ignore_ascii_case("none") || config.priv_password.is_empty();

    let auth = if auth_none {
        Auth::NoAuthNoPriv
    } else if priv_none {
        Auth::AuthNoPriv
    } else {
        let cipher = match config.priv_cipher.to_ascii_lowercase().as_str() {
            "des" => Cipher::Des,
            "aes192" => Cipher::Aes192,
            "aes256" => Cipher::Aes256,
            _ => Cipher::Aes128,
        };
        Auth::AuthPriv {
            cipher,
            privacy_password: config.priv_password.as_bytes().to_vec(),
        }
    };
    sec.with_auth(auth)
}

fn oid_to_vec(oid: &Oid) -> Vec<u32> {
    oid.to_string()
        .trim_start_matches('.')
        .split('.')
        .filter_map(|p| p.parse::<u32>().ok())
        .collect()
}

fn dotted(oid: &[u32]) -> String {
    oid.iter()
        .map(|n| n.to_string())
        .collect::<Vec<_>>()
        .join(".")
}

/// Return (type label, display value) for a varbind value.
fn format_value(val: &Value) -> (String, String) {
    if let Value::OctetString(bytes) = val {
        return ("OctetString".to_string(), render_octets(bytes));
    }
    let dbg = format!("{val:?}");
    let ty = dbg
        .split(['(', ' '])
        .next()
        .unwrap_or(&dbg)
        .trim()
        .to_string();
    let value = match (dbg.find('('), dbg.rfind(')')) {
        (Some(a), Some(b)) if b > a => dbg[a + 1..b].to_string(),
        _ => dbg.clone(),
    };
    (ty, value)
}

/// Printable octet strings render as text; anything else as hex bytes.
fn render_octets(bytes: &[u8]) -> String {
    let printable = !bytes.is_empty()
        && bytes
            .iter()
            .all(|b| *b == b'\t' || *b == b'\n' || *b == b'\r' || (0x20..=0x7e).contains(b));
    if printable {
        String::from_utf8_lossy(bytes).into_owned()
    } else {
        bytes
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(" ")
    }
}
