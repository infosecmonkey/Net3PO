//! Tauri commands for SFTP: connect with a saved SSH connection (same host
//! key pinning and keychain secrets as the SSH tool), browse, and move files
//! with progress and cancel.
//!
//! Everything the server sends is untrusted: listings are capped, file names
//! are made safe before they touch the local disk, and reads larger than
//! requested are rejected. Transfers go to a temporary name first, so a
//! failed or cancelled transfer never leaves a truncated file in place.

use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use russh::client;
use russh_sftp::client::RawSftpSession;
use russh_sftp::client::error::Error as SftpErr;
use russh_sftp::protocol::{FileAttributes, OpenFlags, StatusCode};
use serde::Serialize;
use tauri::ipc::Channel;
use tauri::{AppHandle, State};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::task::JoinHandle;

use super::core::{self, Entry, Kind, Listing};
use crate::store::commands::StoreLock;
use crate::tools::ssh::commands::{
    Authed, Client, ConnectOutcome, after_login, authenticate, keychain_get, load_known,
};
use crate::tools::ssh::core::{self as ssh_core, ConnectParams};

/// Most SFTP sessions open at once.
const MAX_SESSIONS: usize = 8;
/// Most entries shown for one directory.
const MAX_ENTRIES: usize = 10_000;
/// Symlinks resolved per listing to find out whether they point at folders.
const MAX_LINK_STATS: usize = 256;
/// Bytes per read or write request.
const CHUNK: u32 = 32 * 1024;
/// Requests in flight per transfer.
const WINDOW: usize = 16;
/// Seconds to wait for any one SFTP reply.
const REQUEST_TIMEOUT: u64 = 20;
/// Progress events per second at most.
const PROGRESS_EVERY: Duration = Duration::from_millis(200);

struct Conn {
    sftp: Arc<RawSftpSession>,
    handle: client::Handle<Client>,
}

/// Open SFTP sessions and running transfers.
#[derive(Default)]
pub struct SftpRegistry {
    sessions: Mutex<HashMap<u32, Arc<Conn>>>,
    transfers: Mutex<HashMap<u32, Arc<AtomicBool>>>,
    next: AtomicU32,
}

impl SftpRegistry {
    fn get(&self, id: u32) -> Result<Arc<Conn>, String> {
        self.sessions
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&id)
            .cloned()
            .ok_or_else(|| "SFTP session is closed; connect again".to_string())
    }
}

/// Transfer progress.
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Progress {
    pub done: u64,
    pub total: Option<u64>,
}

/// How a transfer ended.
#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(
    tag = "type",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum TransferOutcome {
    Done {
        bytes: u64,
        path: String,
    },
    /// The target exists; ask, then retry with `overwrite`.
    Exists {
        path: String,
    },
    Cancelled,
}

fn err(e: SftpErr) -> String {
    match e {
        SftpErr::Status(s) => {
            let what = match s.status_code {
                StatusCode::NoSuchFile => "no such file or folder",
                StatusCode::PermissionDenied => "permission denied",
                StatusCode::Failure => "the server refused",
                StatusCode::OpUnsupported => "the server does not support this",
                StatusCode::ConnectionLost | StatusCode::NoConnection => "connection lost",
                _ => "error",
            };
            let msg = s.error_message.trim();
            if msg.is_empty()
                || msg.eq_ignore_ascii_case(what)
                || msg.eq_ignore_ascii_case(&s.status_code.to_string())
            {
                what.to_string()
            } else {
                format!("{what}: {msg}")
            }
        }
        SftpErr::Timeout => "the server did not answer in time".to_string(),
        other => other.to_string(),
    }
}

fn is_eof(e: &SftpErr) -> bool {
    matches!(e, SftpErr::Status(s) if s.status_code == StatusCode::Eof)
}

fn is_missing(e: &SftpErr) -> bool {
    matches!(e, SftpErr::Status(s) if s.status_code == StatusCode::NoSuchFile)
}

/// Start the SFTP subsystem on an authenticated connection.
async fn open_sftp(handle: &client::Handle<Client>) -> Result<Arc<RawSftpSession>, String> {
    let channel = handle
        .channel_open_session()
        .await
        .map_err(|e| format!("could not open a session channel: {e}"))?;
    channel
        .request_subsystem(true, "sftp")
        .await
        .map_err(|e| format!("could not start SFTP: {e}"))?;
    let sftp = RawSftpSession::new(channel.into_stream());
    sftp.set_timeout(REQUEST_TIMEOUT);
    tokio::time::timeout(Duration::from_secs(REQUEST_TIMEOUT), sftp.init())
        .await
        .map_err(|_| "the server did not start SFTP (is the SFTP subsystem enabled?)".to_string())?
        .map_err(|e| format!("could not start SFTP: {}", err(e)))?;
    Ok(Arc::new(sftp))
}

/// Connect with SSH credentials and start SFTP. A host key prompt comes back
/// for the user to confirm, exactly as in the SSH tool.
#[tauri::command]
pub async fn sftp_connect(
    app: AppHandle,
    registry: State<'_, SftpRegistry>,
    lock: State<'_, StoreLock>,
    params: ConnectParams,
) -> Result<ConnectOutcome, String> {
    let host = ssh_core::validate(&params).map_err(|e| e.to_string())?;
    if registry
        .sessions
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .len()
        >= MAX_SESSIONS
    {
        return Err(format!(
            "too many SFTP sessions (limit {MAX_SESSIONS}); disconnect one first"
        ));
    }
    let known = load_known(&app, &lock);
    let stored = params.connection_id.as_deref().and_then(keychain_get);
    let (handle, algorithm, fingerprint) =
        match authenticate(&params, &host, &known, stored).await? {
            Authed::Prompt(p) => return Ok(p),
            Authed::Ready {
                handle,
                algorithm,
                fingerprint,
            } => (handle, algorithm, fingerprint),
        };
    let sftp = open_sftp(&handle).await?;
    // A keychain warning should not fail an otherwise good login.
    let _ = after_login(&app, &lock, &params, &host, algorithm, &fingerprint)?;
    let id = registry.next.fetch_add(1, Ordering::Relaxed) + 1;
    registry
        .sessions
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .insert(id, Arc::new(Conn { sftp, handle }));
    Ok(ConnectOutcome::Connected {
        session: id,
        fingerprint,
    })
}

/// Close an SFTP session.
#[tauri::command]
pub async fn sftp_close(registry: State<'_, SftpRegistry>, session: u32) -> Result<(), String> {
    let conn = registry
        .sessions
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .remove(&session);
    if let Some(c) = conn {
        let _ = c.sftp.close_session();
        let _ = c
            .handle
            .disconnect(russh::Disconnect::ByApplication, "", "en")
            .await;
    }
    Ok(())
}

/// List a remote directory. An empty path or `.` is the login folder.
#[tauri::command]
pub async fn sftp_list(
    registry: State<'_, SftpRegistry>,
    session: u32,
    path: String,
) -> Result<Listing, String> {
    let conn = registry.get(session)?;
    let path = if path.trim().is_empty() {
        ".".to_string()
    } else {
        path
    };
    list(&conn.sftp, &path).await
}

async fn list(sftp: &RawSftpSession, path: &str) -> Result<Listing, String> {
    core::validate_path(path).map_err(|e| e.to_string())?;
    let canonical = sftp
        .realpath(path)
        .await
        .map_err(|e| format!("{path}: {}", err(e)))?
        .files
        .into_iter()
        .next()
        .map(|f| f.filename)
        .ok_or_else(|| format!("{path}: the server returned no path"))?;
    let handle = sftp
        .opendir(canonical.as_str())
        .await
        .map_err(|e| format!("{canonical}: {}", err(e)))?
        .handle;

    let mut entries = Vec::new();
    let mut truncated = false;
    let result = loop {
        match sftp.readdir(handle.as_str()).await {
            Ok(name) => {
                for f in name.files {
                    if f.filename == "." || f.filename == ".." {
                        continue;
                    }
                    if entries.len() >= MAX_ENTRIES {
                        truncated = true;
                        break;
                    }
                    let mode = f.attrs.permissions;
                    entries.push(Entry {
                        kind: core::kind(mode),
                        link_dir: false,
                        size: f.attrs.size,
                        mtime: f.attrs.mtime,
                        perms: core::perm_string(mode),
                        name: f.filename,
                    });
                }
                if truncated {
                    break Ok(());
                }
            }
            Err(e) if is_eof(&e) => break Ok(()),
            Err(e) => break Err(format!("{canonical}: {}", err(e))),
        }
    };
    let _ = sftp.close(handle.as_str()).await;
    result?;

    for e in entries
        .iter_mut()
        .filter(|e| e.kind == Kind::Link)
        .take(MAX_LINK_STATS)
    {
        if let Ok(a) = sftp.stat(core::join(&canonical, &e.name)).await {
            e.link_dir = core::kind(a.attrs.permissions) == Kind::Dir;
        }
    }
    core::sort_entries(&mut entries);
    Ok(Listing {
        path: canonical,
        entries,
        truncated,
    })
}

/// Create a folder in `dir`.
#[tauri::command]
pub async fn sftp_mkdir(
    registry: State<'_, SftpRegistry>,
    session: u32,
    dir: String,
    name: String,
) -> Result<(), String> {
    core::validate_path(&dir).map_err(|e| e.to_string())?;
    core::validate_name(&name).map_err(|e| e.to_string())?;
    let conn = registry.get(session)?;
    conn.sftp
        .mkdir(core::join(&dir, &name), FileAttributes::empty())
        .await
        .map(|_| ())
        .map_err(|e| format!("could not create {name}: {}", err(e)))
}

/// Rename an entry in `dir`.
#[tauri::command]
pub async fn sftp_rename(
    registry: State<'_, SftpRegistry>,
    session: u32,
    dir: String,
    from: String,
    to: String,
) -> Result<(), String> {
    core::validate_path(&dir).map_err(|e| e.to_string())?;
    core::validate_name(&from).map_err(|e| e.to_string())?;
    core::validate_name(&to).map_err(|e| e.to_string())?;
    let conn = registry.get(session)?;
    conn.sftp
        .rename(core::join(&dir, &from), core::join(&dir, &to))
        .await
        .map(|_| ())
        .map_err(|e| format!("could not rename {from}: {}", err(e)))
}

/// Delete a file, or an empty folder.
#[tauri::command]
pub async fn sftp_remove(
    registry: State<'_, SftpRegistry>,
    session: u32,
    dir: String,
    name: String,
    folder: bool,
) -> Result<(), String> {
    core::validate_path(&dir).map_err(|e| e.to_string())?;
    core::validate_name(&name).map_err(|e| e.to_string())?;
    let conn = registry.get(session)?;
    let path = core::join(&dir, &name);
    let r = if folder {
        conn.sftp.rmdir(path).await
    } else {
        conn.sftp.remove(path).await
    };
    r.map(|_| ()).map_err(|e| {
        if folder {
            format!(
                "could not delete {name} (folders must be empty): {}",
                err(e)
            )
        } else {
            format!("could not delete {name}: {}", err(e))
        }
    })
}

/// Cancel a running transfer.
#[tauri::command]
pub fn sftp_cancel(registry: State<'_, SftpRegistry>, transfer: u32) {
    if let Some(f) = registry
        .transfers
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .get(&transfer)
    {
        f.store(true, Ordering::Relaxed);
    }
}

impl SftpRegistry {
    /// Register a cancel flag for a transfer.
    fn begin(&self, transfer: u32) -> Arc<AtomicBool> {
        let cancel = Arc::new(AtomicBool::new(false));
        self.transfers
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(transfer, cancel.clone());
        cancel
    }

    fn end(&self, transfer: u32) {
        self.transfers
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&transfer);
    }
}

/// Throttled progress reporting.
struct Reporter<'a> {
    on: &'a (dyn Fn(Progress) + Sync),
    total: Option<u64>,
    last: Instant,
}

impl<'a> Reporter<'a> {
    fn new(on: &'a (dyn Fn(Progress) + Sync), total: Option<u64>) -> Self {
        on(Progress { done: 0, total });
        Self {
            on,
            total,
            last: Instant::now(),
        }
    }

    fn tick(&mut self, done: u64) {
        if self.last.elapsed() >= PROGRESS_EVERY {
            self.last = Instant::now();
            (self.on)(Progress {
                done,
                total: self.total,
            });
        }
    }
}

/// Download `remote` into the local folder `dir`, named after the remote file.
#[tauri::command]
pub async fn sftp_download(
    registry: State<'_, SftpRegistry>,
    session: u32,
    transfer: u32,
    remote: String,
    dir: String,
    overwrite: bool,
    on_progress: Channel<Progress>,
) -> Result<TransferOutcome, String> {
    core::validate_path(&remote).map_err(|e| e.to_string())?;
    let conn = registry.get(session)?;
    let name = core::safe_local_name(core::base_name(&remote)).map_err(|e| e.to_string())?;
    let target = PathBuf::from(&dir).join(name);
    let report = move |p: Progress| {
        let _ = on_progress.send(p);
    };
    let cancel = registry.begin(transfer);
    let out = download(&conn.sftp, &remote, &target, overwrite, &cancel, &report).await;
    registry.end(transfer);
    out
}

/// The `.part` file used while downloading `target`.
fn part_path(target: &Path) -> PathBuf {
    let mut name = target.file_name().unwrap_or_default().to_os_string();
    name.push(".part");
    target.with_file_name(name)
}

async fn download(
    sftp: &Arc<RawSftpSession>,
    remote: &str,
    target: &Path,
    overwrite: bool,
    cancel: &AtomicBool,
    on: &(dyn Fn(Progress) + Sync),
) -> Result<TransferOutcome, String> {
    if !overwrite && tokio::fs::try_exists(target).await.unwrap_or(false) {
        return Ok(TransferOutcome::Exists {
            path: target.display().to_string(),
        });
    }
    let attrs = sftp
        .stat(remote)
        .await
        .map_err(|e| format!("{remote}: {}", err(e)))?
        .attrs;
    if core::kind(attrs.permissions) == Kind::Dir {
        return Err(format!(
            "{remote} is a folder; downloading folders is not supported yet"
        ));
    }
    let handle = sftp
        .open(remote, OpenFlags::READ, FileAttributes::empty())
        .await
        .map_err(|e| format!("could not open {remote}: {}", err(e)))?
        .handle;
    let part = part_path(target);
    let result = match tokio::fs::File::create(&part).await {
        Ok(mut out) => {
            let r = read_all(sftp, &handle, &mut out, attrs.size, cancel, on).await;
            let r = match r {
                Ok(n) => out.flush().await.map(|_| n).map_err(|e| e.to_string()),
                e => e,
            };
            drop(out);
            r
        }
        Err(e) => Err(format!("could not create {}: {e}", part.display())),
    };
    let _ = sftp.close(handle.as_str()).await;
    match result {
        Ok(Some(bytes)) => {
            if overwrite {
                // Windows will not rename over an existing file.
                let _ = tokio::fs::remove_file(target).await;
            }
            tokio::fs::rename(&part, target)
                .await
                .map_err(|e| format!("could not save {}: {e}", target.display()))?;
            Ok(TransferOutcome::Done {
                bytes,
                path: target.display().to_string(),
            })
        }
        Ok(None) => {
            let _ = tokio::fs::remove_file(&part).await;
            Ok(TransferOutcome::Cancelled)
        }
        Err(e) => {
            let _ = tokio::fs::remove_file(&part).await;
            Err(e)
        }
    }
}

type ReadTask = JoinHandle<Result<Vec<u8>, SftpErr>>;

fn spawn_read(sftp: &Arc<RawSftpSession>, handle: &str, offset: u64, len: u32) -> ReadTask {
    let sftp = sftp.clone();
    let handle = handle.to_string();
    tokio::spawn(async move { sftp.read(handle, offset, len).await.map(|d| d.data) })
}

/// Read a whole remote file with up to WINDOW requests in flight, writing in
/// order. Returns the byte count, or None when cancelled.
async fn read_all(
    sftp: &Arc<RawSftpSession>,
    handle: &str,
    out: &mut (impl AsyncWriteExt + Unpin),
    total: Option<u64>,
    cancel: &AtomicBool,
    on: &(dyn Fn(Progress) + Sync),
) -> Result<Option<u64>, String> {
    let mut report = Reporter::new(on, total);
    let mut pending: VecDeque<(u64, ReadTask)> = VecDeque::new();
    let mut next = 0u64;
    let mut written = 0u64;
    let mut eof = false;
    let abort = |pending: &mut VecDeque<(u64, ReadTask)>| {
        for (_, t) in pending.drain(..) {
            t.abort();
        }
    };
    loop {
        if cancel.load(Ordering::Relaxed) {
            abort(&mut pending);
            return Ok(None);
        }
        while !eof && pending.len() < WINDOW {
            pending.push_back((next, spawn_read(sftp, handle, next, CHUNK)));
            next += u64::from(CHUNK);
        }
        let Some((offset, task)) = pending.pop_front() else {
            break;
        };
        let reply = task.await.map_err(|e| e.to_string())?;
        let data = match reply {
            Ok(d) => d,
            Err(e) if is_eof(&e) => {
                eof = true;
                abort(&mut pending);
                continue;
            }
            Err(e) => {
                abort(&mut pending);
                return Err(format!("read failed: {}", err(e)));
            }
        };
        if offset != written || data.len() > CHUNK as usize {
            abort(&mut pending);
            return Err("the server sent a malformed reply".to_string());
        }
        out.write_all(&data).await.map_err(|e| e.to_string())?;
        written += data.len() as u64;
        // A short read is legal: fetch the rest of this chunk before moving on,
        // so the file is written strictly in order.
        let end = offset + u64::from(CHUNK);
        while written < end && !eof {
            let want = (end - written) as u32;
            match sftp.read(handle, written, want).await {
                Ok(d) if d.data.is_empty() => {
                    abort(&mut pending);
                    return Err("the server sent an empty read".to_string());
                }
                Ok(d) if d.data.len() > want as usize => {
                    abort(&mut pending);
                    return Err("the server sent a malformed reply".to_string());
                }
                Ok(d) => {
                    out.write_all(&d.data).await.map_err(|e| e.to_string())?;
                    written += d.data.len() as u64;
                }
                Err(e) if is_eof(&e) => {
                    eof = true;
                    abort(&mut pending);
                }
                Err(e) => {
                    abort(&mut pending);
                    return Err(format!("read failed: {}", err(e)));
                }
            }
        }
        report.tick(written);
    }
    on(Progress {
        done: written,
        total,
    });
    Ok(Some(written))
}

/// Upload the local file `local` into the remote folder `dir`.
#[tauri::command]
#[allow(clippy::too_many_arguments)]
pub async fn sftp_upload(
    registry: State<'_, SftpRegistry>,
    session: u32,
    transfer: u32,
    local: String,
    dir: String,
    overwrite: bool,
    on_progress: Channel<Progress>,
) -> Result<TransferOutcome, String> {
    core::validate_path(&dir).map_err(|e| e.to_string())?;
    let conn = registry.get(session)?;
    let local = PathBuf::from(local);
    let name = local
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or("the file name is not valid UTF-8")?
        .to_string();
    core::validate_name(&name).map_err(|e| e.to_string())?;
    let report = move |p: Progress| {
        let _ = on_progress.send(p);
    };
    let cancel = registry.begin(transfer);
    let out = upload(&conn.sftp, &local, &dir, &name, overwrite, &cancel, &report).await;
    registry.end(transfer);
    out
}

async fn upload(
    sftp: &Arc<RawSftpSession>,
    local: &Path,
    dir: &str,
    name: &str,
    overwrite: bool,
    cancel: &AtomicBool,
    on: &(dyn Fn(Progress) + Sync),
) -> Result<TransferOutcome, String> {
    let meta = tokio::fs::metadata(local)
        .await
        .map_err(|e| format!("could not read {}: {e}", local.display()))?;
    if !meta.is_file() {
        return Err(format!(
            "{} is not a file; uploading folders is not supported yet",
            local.display()
        ));
    }
    let target = core::join(dir, name);
    let exists = match sftp.stat(target.as_str()).await {
        Ok(_) => true,
        Err(e) if is_missing(&e) => false,
        Err(e) => return Err(format!("{target}: {}", err(e))),
    };
    if exists && !overwrite {
        return Ok(TransferOutcome::Exists { path: target });
    }
    let part = core::join(dir, &core::upload_temp_name(name));
    let mut file = tokio::fs::File::open(local)
        .await
        .map_err(|e| format!("could not open {}: {e}", local.display()))?;
    let handle = sftp
        .open(
            part.as_str(),
            OpenFlags::CREATE | OpenFlags::TRUNCATE | OpenFlags::WRITE,
            FileAttributes::empty(),
        )
        .await
        .map_err(|e| format!("could not create a file in {dir}: {}", err(e)))?
        .handle;
    let result = write_all(sftp, &handle, &mut file, meta.len(), cancel, on).await;
    let closed = sftp.close(handle.as_str()).await;
    let finish = match (result, closed) {
        (Ok(Some(bytes)), Ok(_)) => {
            // SFTP v3 servers will not rename over a file, so the old one is
            // removed only once the new one is complete.
            let mut moved = sftp.rename(part.as_str(), target.as_str()).await;
            if moved.is_err() && exists {
                let _ = sftp.remove(target.as_str()).await;
                moved = sftp.rename(part.as_str(), target.as_str()).await;
            }
            match moved {
                Ok(_) => {
                    return Ok(TransferOutcome::Done {
                        bytes,
                        path: target,
                    });
                }
                Err(e) => Err(format!("could not move the upload into place: {}", err(e))),
            }
        }
        (Ok(Some(_)), Err(e)) => Err(format!("could not finish the upload: {}", err(e))),
        (Ok(None), _) => Ok(TransferOutcome::Cancelled),
        (Err(e), _) => Err(e),
    };
    let _ = sftp.remove(part.as_str()).await;
    finish
}

type WriteTask = JoinHandle<Result<(), SftpErr>>;

/// Write a local file with up to WINDOW requests in flight. Returns the byte
/// count, or None when cancelled.
async fn write_all(
    sftp: &Arc<RawSftpSession>,
    handle: &str,
    file: &mut (impl AsyncReadExt + Unpin),
    total: u64,
    cancel: &AtomicBool,
    on: &(dyn Fn(Progress) + Sync),
) -> Result<Option<u64>, String> {
    let mut report = Reporter::new(on, Some(total));
    let mut pending: VecDeque<WriteTask> = VecDeque::new();
    let mut offset = 0u64;
    let mut acked = 0u64;
    let mut buf = vec![0u8; CHUNK as usize];
    let abort = |pending: &mut VecDeque<WriteTask>| {
        for t in pending.drain(..) {
            t.abort();
        }
    };
    loop {
        if cancel.load(Ordering::Relaxed) {
            abort(&mut pending);
            return Ok(None);
        }
        let n = read_full(file, &mut buf).await.map_err(|e| e.to_string())?;
        if n > 0 {
            let sftp = sftp.clone();
            let handle = handle.to_string();
            let data = buf[..n].to_vec();
            let at = offset;
            pending.push_back(tokio::spawn(async move {
                sftp.write(handle, at, data).await.map(|_| ())
            }));
            offset += n as u64;
        }
        while pending.len() >= WINDOW || (n == 0 && !pending.is_empty()) {
            let Some(t) = pending.pop_front() else { break };
            match t.await.map_err(|e| e.to_string())? {
                Ok(()) => {
                    acked = (acked + u64::from(CHUNK)).min(offset);
                    report.tick(acked);
                }
                Err(e) => {
                    abort(&mut pending);
                    return Err(format!("write failed: {}", err(e)));
                }
            }
        }
        if n == 0 {
            break;
        }
    }
    on(Progress {
        done: offset,
        total: Some(total),
    });
    Ok(Some(offset))
}

/// Fill `buf` unless the file ends first.
async fn read_full(
    file: &mut (impl AsyncReadExt + Unpin),
    buf: &mut [u8],
) -> std::io::Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        let r = file.read(&mut buf[n..]).await?;
        if r == 0 {
            break;
        }
        n += r;
    }
    Ok(n)
}

#[cfg(test)]
mod tests;
