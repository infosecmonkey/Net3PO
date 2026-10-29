//! Tauri commands for SSH sessions and keychain secrets.
//!
//! Each session is one tokio task that owns the russh handle and channel,
//! fed by an mpsc queue (write, resize, close) and streaming output to the UI
//! over a Tauri channel. Host keys are pinned in the `ssh_known_hosts`
//! collection on first use; a changed key stops the connection until the user
//! explicitly accepts the new fingerprint. Secrets live only in the OS
//! keychain and never travel back to the UI.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use russh::keys::{HashAlg, PrivateKeyWithHashAlg, load_secret_key};
use russh::{ChannelMsg, client};
use serde::Serialize;
use tauri::ipc::Channel;
use tauri::{AppHandle, Manager, State};
use tokio::sync::mpsc;

use super::core::{self, AuthKind, ConnectParams, HostKeyStatus, KnownHost};
use crate::store::commands::{StoreLock, app_data_dir};
use crate::store::core as store;

/// Keychain service name for SSH secrets.
// Kept from the original product name so existing saved secrets still resolve.
const KEYCHAIN_SERVICE: &str = "OmniPacket SSH";
/// Most sessions open at once.
const MAX_SESSIONS: usize = 16;
/// TCP connect plus SSH handshake budget.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// Largest single write from the terminal.
const MAX_WRITE: usize = 64 * 1024;
const KNOWN_HOSTS: &str = "ssh_known_hosts";

enum Cmd {
    Write(Vec<u8>),
    Resize(u32, u32),
    Close,
}

/// Open sessions by id.
#[derive(Default)]
pub struct SshRegistry {
    sessions: Mutex<HashMap<u32, mpsc::Sender<Cmd>>>,
    next: AtomicU32,
}

impl SshRegistry {
    fn sender(&self, id: u32) -> Result<mpsc::Sender<Cmd>, String> {
        self.sessions
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&id)
            .cloned()
            .ok_or_else(|| "session is closed".to_string())
    }
}

/// Output streamed to the terminal.
#[derive(Clone, Serialize)]
#[serde(
    tag = "type",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum SshEvent {
    /// Base64 of raw terminal bytes (they may split UTF-8 sequences).
    Data {
        b64: String,
    },
    Closed {
        reason: String,
    },
}

/// Result of a connect attempt.
#[derive(Serialize)]
#[serde(
    tag = "type",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum ConnectOutcome {
    Connected {
        session: u32,
        fingerprint: String,
    },
    /// The user must confirm this key before connecting.
    HostKey {
        status: String,
        algorithm: String,
        fingerprint: String,
        previous: Option<String>,
    },
}

/// Records the presented host key and accepts it only when trusted.
struct Client {
    known: Vec<KnownHost>,
    host: String,
    port: u16,
    confirmed: Option<String>,
    seen: Arc<Mutex<Option<(String, String)>>>,
}

impl client::Handler for Client {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        key: &russh::keys::PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        let (algorithm, fingerprint) = match key {
            russh::keys::PublicKeyOrCertificate::PublicKey { key, .. } => (
                key.algorithm().to_string(),
                key.fingerprint(HashAlg::Sha256).to_string(),
            ),
            russh::keys::PublicKeyOrCertificate::Certificate(cert) => (
                cert.algorithm().to_string(),
                cert.public_key().fingerprint(HashAlg::Sha256).to_string(),
            ),
        };
        let status = core::host_key_status(
            &self.known,
            &self.host,
            self.port,
            &fingerprint,
            self.confirmed.as_deref(),
        );
        *self.seen.lock().unwrap_or_else(|p| p.into_inner()) = Some((algorithm, fingerprint));
        Ok(status == HostKeyStatus::Trusted)
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn load_known(app: &AppHandle, lock: &StoreLock) -> Vec<KnownHost> {
    let _g = lock.guard();
    let Ok(dir) = app_data_dir(app) else {
        return Vec::new();
    };
    store::load(&dir, KNOWN_HOSTS)
        .map(|l| {
            l.items
                .into_iter()
                .filter_map(|v| serde_json::from_value(v).ok())
                .collect()
        })
        .unwrap_or_default()
}

fn save_known(app: &AppHandle, lock: &StoreLock, entry: KnownHost) -> Result<(), String> {
    let _g = lock.guard();
    let dir = app_data_dir(app)?;
    let mut known: Vec<KnownHost> = store::load(&dir, KNOWN_HOSTS)
        .map(|l| {
            l.items
                .into_iter()
                .filter_map(|v| serde_json::from_value(v).ok())
                .collect()
        })
        .unwrap_or_default();
    core::pin(&mut known, entry);
    let items = known
        .iter()
        .filter_map(|k| serde_json::to_value(k).ok())
        .collect();
    store::save(&dir, KNOWN_HOSTS, items).map_err(|e| e.to_string())
}

fn keychain(id: &str) -> Result<keyring::Entry, String> {
    core::validate_id(id).map_err(|e| e.to_string())?;
    keyring::Entry::new(KEYCHAIN_SERVICE, id).map_err(|e| format!("keychain unavailable: {e}"))
}

fn keychain_get(id: &str) -> Option<String> {
    keychain(id).ok()?.get_password().ok()
}

/// Save a password or key passphrase for a saved connection.
#[tauri::command]
pub fn ssh_secret_set(id: String, secret: String) -> Result<(), String> {
    keychain(&id)?
        .set_password(&secret)
        .map_err(|e| format!("could not save to the keychain: {e}"))
}

/// Whether a secret is saved, without revealing it.
#[tauri::command]
pub fn ssh_secret_has(id: String) -> Result<bool, String> {
    Ok(keychain_get(&id).is_some())
}

/// Remove a saved secret. Missing secrets are fine.
#[tauri::command]
pub fn ssh_secret_delete(id: String) -> Result<(), String> {
    match keychain(&id)?.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(format!("could not remove from the keychain: {e}")),
    }
}

/// A connect attempt's result before a session task exists.
enum Established {
    Ready {
        handle: client::Handle<Client>,
        channel: russh::Channel<client::Msg>,
        algorithm: String,
        fingerprint: String,
    },
    /// The host key needs the user's confirmation.
    Prompt(ConnectOutcome),
}

/// Connect, check the host key, authenticate, and start a PTY shell.
/// `stored_secret` is the keychain secret, if any; a typed one wins.
async fn establish(
    params: &ConnectParams,
    host: &str,
    known: &[KnownHost],
    stored_secret: Option<String>,
    cols: u32,
    rows: u32,
) -> Result<Established, String> {
    let seen = Arc::new(Mutex::new(None));
    let handler = Client {
        known: known.to_vec(),
        host: host.to_string(),
        port: params.port,
        confirmed: params.trust_fingerprint.clone(),
        seen: seen.clone(),
    };
    let config = Arc::new(client::Config {
        inactivity_timeout: None,
        keepalive_interval: Some(Duration::from_secs(30)),
        keepalive_max: 3,
        ..Default::default()
    });

    let connect = client::connect(config, (host, params.port), handler);
    let result = tokio::time::timeout(CONNECT_TIMEOUT, connect).await;
    let presented = seen.lock().unwrap_or_else(|p| p.into_inner()).clone();
    let mut handle = match result {
        Err(_) => return Err(format!("timed out connecting to {host}:{}", params.port)),
        Ok(Ok(h)) => h,
        Ok(Err(e)) => {
            // Rejected only because the key is not trusted yet: ask the user.
            if let Some((algorithm, fingerprint)) = presented {
                match core::host_key_status(
                    known,
                    host,
                    params.port,
                    &fingerprint,
                    params.trust_fingerprint.as_deref(),
                ) {
                    HostKeyStatus::Trusted => {}
                    HostKeyStatus::New => {
                        return Ok(Established::Prompt(ConnectOutcome::HostKey {
                            status: "new".into(),
                            algorithm,
                            fingerprint,
                            previous: None,
                        }));
                    }
                    HostKeyStatus::Changed { previous } => {
                        return Ok(Established::Prompt(ConnectOutcome::HostKey {
                            status: "changed".into(),
                            algorithm,
                            fingerprint,
                            previous: Some(previous),
                        }));
                    }
                }
            }
            return Err(format!("could not connect to {host}:{}: {e}", params.port));
        }
    };
    let (algorithm, fingerprint) = presented.unwrap_or_default();

    let secret = params
        .secret
        .clone()
        .filter(|s| !s.is_empty())
        .or(stored_secret);
    let auth = match params.auth {
        AuthKind::Password => {
            let pw = secret.clone().ok_or("enter the password")?;
            handle
                .authenticate_password(params.user.clone(), pw)
                .await
                .map_err(|e| format!("authentication error: {e}"))?
        }
        AuthKind::Key => {
            let key = load_secret_key(params.key_path.trim(), secret.as_deref()).map_err(|e| {
                if secret.is_none() {
                    format!("could not load the key (if it has a passphrase, enter it): {e}")
                } else {
                    format!("could not load the key: {e}")
                }
            })?;
            let hash = handle
                .best_supported_rsa_hash()
                .await
                .ok()
                .flatten()
                .flatten();
            handle
                .authenticate_publickey(
                    params.user.clone(),
                    PrivateKeyWithHashAlg::new(Arc::new(key), hash),
                )
                .await
                .map_err(|e| format!("authentication error: {e}"))?
        }
    };
    if !auth.success() {
        return Err("authentication failed: check the user name and credentials".to_string());
    }

    let channel = handle
        .channel_open_session()
        .await
        .map_err(|e| format!("could not open a session channel: {e}"))?;
    let (cols, rows) = core::clamp_size(cols, rows);
    channel
        .request_pty(false, "xterm-256color", cols, rows, 0, 0, &[])
        .await
        .map_err(|e| format!("could not start a terminal: {e}"))?;
    channel
        .request_shell(true)
        .await
        .map_err(|e| format!("could not start a shell: {e}"))?;
    Ok(Established::Ready {
        handle,
        channel,
        algorithm,
        fingerprint,
    })
}

/// Connect, authenticate and start an interactive shell.
#[tauri::command]
pub async fn ssh_connect(
    app: AppHandle,
    registry: State<'_, SshRegistry>,
    lock: State<'_, StoreLock>,
    params: ConnectParams,
    cols: u32,
    rows: u32,
    on_event: Channel<SshEvent>,
) -> Result<ConnectOutcome, String> {
    let host = core::validate(&params).map_err(|e| e.to_string())?;
    if registry
        .sessions
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .len()
        >= MAX_SESSIONS
    {
        return Err(format!(
            "too many open sessions (limit {MAX_SESSIONS}); close one first"
        ));
    }
    let known = load_known(&app, &lock);
    let stored = params.connection_id.as_deref().and_then(keychain_get);
    let (handle, channel, algorithm, fingerprint) =
        match establish(&params, &host, &known, stored, cols, rows).await? {
            Established::Prompt(outcome) => return Ok(outcome),
            Established::Ready {
                handle,
                channel,
                algorithm,
                fingerprint,
            } => (handle, channel, algorithm, fingerprint),
        };

    // Pin a newly confirmed key, and save a typed secret if asked, only
    // after a successful login.
    if params.trust_fingerprint.is_some() {
        save_known(
            &app,
            &lock,
            KnownHost {
                host: host.clone(),
                port: params.port,
                algorithm,
                fingerprint: fingerprint.clone(),
                added: now_secs(),
            },
        )?;
    }
    let typed = params.secret.clone().filter(|s| !s.is_empty());
    if params.save_secret
        && let (Some(id), Some(s)) = (&params.connection_id, &typed)
        && let Err(e) = ssh_secret_set(id.clone(), s.clone())
    {
        let _ = on_event.send(SshEvent::Data {
            b64: base64::engine::general_purpose::STANDARD.encode(format!("\r\n[Net3PO] {e}\r\n")),
        });
    }

    let id = registry.next.fetch_add(1, Ordering::Relaxed) + 1;
    let (tx, rx) = mpsc::channel::<Cmd>(256);
    registry
        .sessions
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .insert(id, tx);

    let app2 = app.clone();
    tokio::spawn(async move {
        let reason = pump(handle, channel, rx, |ev| on_event.send(ev).is_ok()).await;
        if let Some(reg) = app2.try_state::<SshRegistry>() {
            reg.sessions
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .remove(&id);
        }
        let _ = on_event.send(SshEvent::Closed { reason });
    });

    Ok(ConnectOutcome::Connected {
        session: id,
        fingerprint,
    })
}

/// Move data between the channel and the UI until either side closes.
/// Returns why the session ended.
async fn pump(
    handle: client::Handle<Client>,
    mut channel: russh::Channel<client::Msg>,
    mut rx: mpsc::Receiver<Cmd>,
    mut emit: impl FnMut(SshEvent) -> bool,
) -> String {
    let b64 = base64::engine::general_purpose::STANDARD;
    let reason = loop {
        tokio::select! {
            msg = channel.wait() => match msg {
                Some(ChannelMsg::Data { data }) | Some(ChannelMsg::ExtendedData { data, .. }) => {
                    if !emit(SshEvent::Data { b64: b64.encode(&data[..]) }) {
                        break "window closed".to_string();
                    }
                }
                Some(ChannelMsg::ExitStatus { exit_status }) => {
                    break format!("remote shell exited with status {exit_status}");
                }
                Some(ChannelMsg::Eof) | Some(ChannelMsg::Close) | None => break "connection closed".to_string(),
                Some(_) => {}
            },
            cmd = rx.recv() => match cmd {
                Some(Cmd::Write(bytes)) => {
                    if let Err(e) = channel.data_bytes(bytes).await {
                        break format!("write failed: {e}");
                    }
                }
                Some(Cmd::Resize(c, r)) => {
                    let _ = channel.window_change(c, r, 0, 0).await;
                }
                Some(Cmd::Close) | None => {
                    let _ = channel.close().await;
                    break "closed".to_string();
                }
            },
        }
    };
    let _ = handle
        .disconnect(russh::Disconnect::ByApplication, "", "en")
        .await;
    reason
}

/// Send keystrokes or pasted text to a session.
#[tauri::command]
pub async fn ssh_write(
    registry: State<'_, SshRegistry>,
    session: u32,
    data: String,
) -> Result<(), String> {
    if data.len() > MAX_WRITE {
        return Err(format!(
            "input is too large ({} bytes, limit {MAX_WRITE})",
            data.len()
        ));
    }
    registry
        .sender(session)?
        .send(Cmd::Write(data.into_bytes()))
        .await
        .map_err(|_| "session is closed".to_string())
}

/// Tell the server the terminal size changed.
#[tauri::command]
pub async fn ssh_resize(
    registry: State<'_, SshRegistry>,
    session: u32,
    cols: u32,
    rows: u32,
) -> Result<(), String> {
    let (c, r) = core::clamp_size(cols, rows);
    let _ = registry.sender(session)?.send(Cmd::Resize(c, r)).await;
    Ok(())
}

/// Close a session.
#[tauri::command]
pub async fn ssh_close(registry: State<'_, SshRegistry>, session: u32) -> Result<(), String> {
    if let Ok(tx) = registry.sender(session) {
        let _ = tx.send(Cmd::Close).await;
    }
    Ok(())
}

/// Forget a pinned host key, so the next connect asks again.
#[tauri::command]
pub fn ssh_forget_host(
    app: AppHandle,
    lock: State<'_, StoreLock>,
    host: String,
    port: u16,
) -> Result<(), String> {
    let host = core::validate_host(&host).map_err(|e| e.to_string())?;
    let _g = lock.guard();
    let dir = app_data_dir(&app)?;
    let mut known: Vec<KnownHost> = store::load(&dir, KNOWN_HOSTS)
        .map(|l| {
            l.items
                .into_iter()
                .filter_map(|v| serde_json::from_value(v).ok())
                .collect()
        })
        .unwrap_or_default();
    known.retain(|k| !(k.host.eq_ignore_ascii_case(&host) && k.port == port));
    let items = known
        .iter()
        .filter_map(|k| serde_json::to_value(k).ok())
        .collect();
    store::save(&dir, KNOWN_HOSTS, items).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use russh::server::{self, Msg, Server as _, Session};
    use russh::{Channel as SshChannel, ChannelId};

    #[test]
    fn events_are_camel_case() {
        let v = serde_json::to_value(SshEvent::Closed { reason: "x".into() }).unwrap();
        assert_eq!(v["type"], "closed");
        let v = serde_json::to_value(ConnectOutcome::HostKey {
            status: "new".into(),
            algorithm: "ssh-ed25519".into(),
            fingerprint: "SHA256:x".into(),
            previous: None,
        })
        .unwrap();
        assert_eq!(v["type"], "hostKey");
        assert_eq!(v["fingerprint"], "SHA256:x");
    }

    /// A tiny in-process SSH server: password "secret", a shell that greets
    /// and then echoes.
    #[derive(Clone)]
    struct TestServer;

    impl server::Server for TestServer {
        type Handler = Self;
        fn new_client(&mut self, _: Option<std::net::SocketAddr>) -> Self {
            self.clone()
        }
    }

    impl server::Handler for TestServer {
        type Error = russh::Error;

        async fn auth_password(
            &mut self,
            user: &str,
            password: &str,
        ) -> Result<server::Auth, Self::Error> {
            Ok(if user == "admin" && password == "secret" {
                server::Auth::Accept
            } else {
                server::Auth::reject()
            })
        }

        async fn channel_open_session(
            &mut self,
            _channel: SshChannel<Msg>,
            reply: server::ChannelOpenHandle,
            _session: &mut Session,
        ) -> Result<(), Self::Error> {
            reply.accept().await;
            Ok(())
        }

        #[allow(clippy::too_many_arguments)]
        async fn pty_request(
            &mut self,
            channel: ChannelId,
            _term: &str,
            _c: u32,
            _r: u32,
            _pw: u32,
            _ph: u32,
            _modes: &[(russh::Pty, u32)],
            session: &mut Session,
        ) -> Result<(), Self::Error> {
            session.channel_success(channel)?;
            Ok(())
        }

        async fn shell_request(
            &mut self,
            channel: ChannelId,
            session: &mut Session,
        ) -> Result<(), Self::Error> {
            session.channel_success(channel)?;
            session.data(channel, b"welcome\r\n".to_vec())?;
            Ok(())
        }

        async fn data(
            &mut self,
            channel: ChannelId,
            data: &[u8],
            session: &mut Session,
        ) -> Result<(), Self::Error> {
            session.data(channel, data.to_vec())?;
            Ok(())
        }
    }

    async fn start_server() -> u16 {
        let config = Arc::new(server::Config {
            keys: vec![
                russh::keys::PrivateKey::random(&mut rand::rng(), russh::keys::Algorithm::Ed25519)
                    .unwrap(),
            ],
            auth_rejection_time: Duration::from_millis(10),
            auth_rejection_time_initial: Some(Duration::from_millis(0)),
            ..Default::default()
        });
        let socket: &'static tokio::net::TcpListener = Box::leak(Box::new(
            tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap(),
        ));
        let port = socket.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut s = TestServer;
            let _ = s.run_on_socket(config, socket).await;
        });
        port
    }

    fn params(port: u16, secret: &str, trust: Option<String>) -> ConnectParams {
        ConnectParams {
            connection_id: None,
            host: "127.0.0.1".into(),
            port,
            user: "admin".into(),
            auth: AuthKind::Password,
            key_path: String::new(),
            secret: Some(secret.into()),
            save_secret: false,
            trust_fingerprint: trust,
        }
    }

    #[tokio::test]
    async fn host_key_prompt_then_session_then_changed_key() {
        let port = start_server().await;

        // Unknown host: asks for confirmation.
        let fp = match establish(
            &params(port, "secret", None),
            "127.0.0.1",
            &[],
            None,
            80,
            24,
        )
        .await
        .unwrap()
        {
            Established::Prompt(ConnectOutcome::HostKey {
                status,
                fingerprint,
                ..
            }) => {
                assert_eq!(status, "new");
                assert!(fingerprint.starts_with("SHA256:"));
                fingerprint
            }
            _ => panic!("expected a host key prompt"),
        };

        // Confirmed: logs in, starts a shell, greets and echoes.
        let Established::Ready {
            handle,
            channel,
            fingerprint,
            ..
        } = establish(
            &params(port, "secret", Some(fp.clone())),
            "127.0.0.1",
            &[],
            None,
            80,
            24,
        )
        .await
        .unwrap()
        else {
            panic!("expected a session");
        };
        assert_eq!(fingerprint, fp);
        let (tx, rx) = mpsc::channel(8);
        let out = Arc::new(Mutex::new(Vec::<u8>::new()));
        let out2 = out.clone();
        let task = tokio::spawn(pump(handle, channel, rx, move |ev| {
            if let SshEvent::Data { b64 } = ev {
                out2.lock().unwrap().extend(
                    base64::engine::general_purpose::STANDARD
                        .decode(b64)
                        .unwrap(),
                );
            }
            true
        }));
        tx.send(Cmd::Write(b"ping".to_vec())).await.unwrap();
        for _ in 0..100 {
            if String::from_utf8_lossy(&out.lock().unwrap()).contains("ping") {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        tx.send(Cmd::Close).await.unwrap();
        assert_eq!(task.await.unwrap(), "closed");
        let got = String::from_utf8_lossy(&out.lock().unwrap()).into_owned();
        assert!(got.contains("welcome") && got.contains("ping"), "{got:?}");

        // A different key pinned for this host: hard stop with both prints.
        let pinned = vec![KnownHost {
            host: "127.0.0.1".into(),
            port,
            algorithm: "ssh-ed25519".into(),
            fingerprint: "SHA256:something-else".into(),
            added: 0,
        }];
        match establish(
            &params(port, "secret", None),
            "127.0.0.1",
            &pinned,
            None,
            80,
            24,
        )
        .await
        .unwrap()
        {
            Established::Prompt(ConnectOutcome::HostKey {
                status,
                previous,
                fingerprint,
                ..
            }) => {
                assert_eq!(status, "changed");
                assert_eq!(previous.as_deref(), Some("SHA256:something-else"));
                assert_eq!(fingerprint, fp);
            }
            _ => panic!("expected a changed key prompt"),
        }

        // The right key but the wrong password.
        let good = vec![KnownHost {
            fingerprint: fp.clone(),
            ..pinned[0].clone()
        }];
        let err = establish(
            &params(port, "wrong", None),
            "127.0.0.1",
            &good,
            None,
            80,
            24,
        )
        .await
        .err()
        .unwrap();
        assert!(err.contains("authentication failed"), "{err}");

        // A keychain secret is used when none is typed.
        let mut p = params(port, "", None);
        p.secret = None;
        assert!(matches!(
            establish(&p, "127.0.0.1", &good, Some("secret".into()), 80, 24).await,
            Ok(Established::Ready { .. })
        ));
    }

    #[tokio::test]
    async fn connection_refused_is_a_clear_error() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        drop(l);
        let err = establish(&params(port, "x", None), "127.0.0.1", &[], None, 80, 24)
            .await
            .err()
            .unwrap();
        assert!(err.starts_with("could not connect to 127.0.0.1"), "{err}");
    }
}
