//! Tauri commands for the TFTP server. Binds the main UDP socket, then runs
//! each transfer on its own ephemeral socket per the TFTP spec. Streams
//! transfer events to the UI and stops cleanly. All filename resolution goes
//! through the path-safe helpers in `core`.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::Serialize;
use tauri::State;
use tauri::ipc::Channel;
use tokio::io::AsyncWriteExt;
use tokio::net::UdpSocket;
use tokio::sync::watch;

use super::core::{self, ReqKind, Request, TftpError};

const TRANSFER_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_RETRIES: u32 = 5;
/// Emit a progress event every this many blocks.
const PROGRESS_EVERY: u16 = 64;

#[derive(Default)]
pub struct TftpRegistry {
    inner: Arc<Mutex<HashMap<u32, watch::Sender<bool>>>>,
}

#[derive(Clone, Serialize)]
#[serde(
    tag = "type",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum TftpEvent {
    Started {
        port: u16,
        root: String,
        writable: bool,
    },
    TransferStart {
        id: u32,
        file: String,
        client: String,
        direction: String,
    },
    TransferProgress {
        id: u32,
        bytes: u64,
    },
    TransferEnd {
        id: u32,
        bytes: u64,
        ok: bool,
        message: String,
    },
    /// A request refused before any transfer started (not found, uploads
    /// off, outside the folder, malformed).
    Rejected {
        id: u32,
        file: String,
        client: String,
        direction: String,
        message: String,
    },
    Stopped,
}

/// Stop a running server by id.
#[tauri::command]
pub fn tftp_stop(registry: State<'_, TftpRegistry>, server_id: u32) {
    if let Some(tx) = registry.inner.lock().unwrap().get(&server_id) {
        let _ = tx.send(true);
    }
}

/// Start the TFTP server on `port`, serving `root`. Runs until stopped.
#[tauri::command]
pub async fn tftp_start(
    registry: State<'_, TftpRegistry>,
    server_id: u32,
    port: u16,
    root: String,
    writable: bool,
    on_event: Channel<TftpEvent>,
) -> Result<(), String> {
    let root_path = PathBuf::from(&root);
    if !root_path.is_dir() {
        return Err("choose a folder to serve".to_string());
    }

    let sock = UdpSocket::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)))
        .await
        .map_err(|e| bind_error(port, e))?;

    let (tx, rx) = watch::channel(false);
    let reg = registry.inner.clone();
    reg.lock().unwrap().insert(server_id, tx);

    let _ = on_event.send(TftpEvent::Started {
        port,
        root,
        writable,
    });

    let events = on_event.clone();
    let emit = move |ev: TftpEvent| {
        let _ = events.send(ev);
    };
    serve(sock, root_path, writable, rx, emit).await;

    reg.lock().unwrap().remove(&server_id);
    let _ = on_event.send(TftpEvent::Stopped);
    Ok(())
}

fn bind_error(port: u16, e: std::io::Error) -> String {
    use std::io::ErrorKind::*;
    match e.kind() {
        PermissionDenied => format!(
            "cannot bind UDP port {port}: permission denied. Ports below 1024 need admin/root; try a port such as 6969."
        ),
        AddrInUse => format!("cannot bind UDP port {port}: already in use."),
        _ => format!("cannot bind UDP port {port}: {e}"),
    }
}

/// Accept loop on the main socket. Each request is handed to its own task and
/// ephemeral socket.
async fn serve<F>(
    sock: UdpSocket,
    root: PathBuf,
    writable: bool,
    mut rx: watch::Receiver<bool>,
    emit: F,
) where
    F: Fn(TftpEvent) + Clone + Send + Sync + 'static,
{
    let mut buf = vec![0u8; 2048];
    let ids = Arc::new(AtomicU32::new(1));
    loop {
        tokio::select! {
            r = sock.recv_from(&mut buf) => {
                if let Ok((n, client)) = r {
                    let packet = buf[..n].to_vec();
                    let id = ids.fetch_add(1, Ordering::Relaxed);
                    let root = root.clone();
                    let emit = emit.clone();
                    let shutdown = rx.clone();
                    tokio::spawn(async move {
                        handle(id, packet, client, root, writable, emit, shutdown).await;
                    });
                }
            }
            _ = rx.changed() => break,
        }
    }
}

/// Handle one request on a fresh ephemeral socket connected to the client.
async fn handle<F>(
    id: u32,
    packet: Vec<u8>,
    client: SocketAddr,
    root: PathBuf,
    writable: bool,
    emit: F,
    shutdown: watch::Receiver<bool>,
) where
    F: Fn(TftpEvent) + Clone + Send + Sync + 'static,
{
    let sock = match UdpSocket::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))).await {
        Ok(s) => s,
        Err(_) => return,
    };
    if sock.connect(client).await.is_err() {
        return;
    }

    let req = match core::parse_request(&packet) {
        Ok(r) => r,
        Err(e) => {
            let _ = sock
                .send(&core::build_error(e.code(), &e.to_string()))
                .await;
            emit(TftpEvent::Rejected {
                id,
                file: String::new(),
                client: client.to_string(),
                direction: String::new(),
                message: e.to_string(),
            });
            return;
        }
    };

    // Note whether the transfer got as far as starting, so a refusal before
    // that is reported as its own row rather than an end with no start.
    let started = AtomicBool::new(false);
    let tracked = |ev: TftpEvent| {
        if matches!(ev, TftpEvent::TransferStart { .. }) {
            started.store(true, Ordering::Relaxed);
        }
        emit(ev);
    };
    let result = match req.kind {
        ReqKind::Read => handle_read(id, &sock, &req, &root, &tracked, shutdown).await,
        ReqKind::Write => {
            if writable {
                handle_write(id, &sock, &req, &root, &tracked, shutdown).await
            } else {
                Err(TftpError::AccessViolation)
            }
        }
    };

    if let Err(e) = result {
        let _ = sock
            .send(&core::build_error(e.code(), &e.to_string()))
            .await;
        if started.load(Ordering::Relaxed) {
            emit(TftpEvent::TransferEnd {
                id,
                bytes: 0,
                ok: false,
                message: e.to_string(),
            });
        } else {
            let message = match (&req.kind, &e) {
                (ReqKind::Write, TftpError::AccessViolation) if !writable => {
                    "upload refused: uploads are off".to_string()
                }
                _ => e.to_string(),
            };
            emit(TftpEvent::Rejected {
                id,
                file: req.filename.clone(),
                client: client.to_string(),
                direction: match req.kind {
                    ReqKind::Read => "read",
                    ReqKind::Write => "write",
                }
                .to_string(),
                message,
            });
        }
    }
}

async fn handle_read<F>(
    id: u32,
    sock: &UdpSocket,
    req: &Request,
    root: &std::path::Path,
    emit: &F,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), TftpError>
where
    F: Fn(TftpEvent),
{
    let path = core::resolve_read(root, &req.filename)?;
    let data = tokio::fs::read(&path)
        .await
        .map_err(|_| TftpError::NotFound)?;

    let accepted = core::negotiate(&req.options, Some(data.len() as u64));
    let blksize = core::blksize_of(&accepted);

    emit(TftpEvent::TransferStart {
        id,
        file: req.filename.clone(),
        client: sock.peer_addr().map(|a| a.to_string()).unwrap_or_default(),
        direction: "read".to_string(),
    });

    let mut buf = [0u8; 2048];

    // If options were accepted, send OACK and wait for the client's ACK(0).
    if !accepted.is_empty() {
        send_and_wait_ack(
            sock,
            &core::build_oack(&accepted),
            0,
            &mut buf,
            &mut shutdown,
        )
        .await?;
    }

    // Send DATA blocks 1.. lockstep.
    let mut block: u16 = 1;
    let mut sent: u64 = 0;
    let mut chunks = data.chunks(blksize);
    loop {
        let chunk = chunks.next().unwrap_or(&[]);
        send_and_wait_ack(
            sock,
            &core::build_data(block, chunk),
            block,
            &mut buf,
            &mut shutdown,
        )
        .await?;
        sent += chunk.len() as u64;
        if block.is_multiple_of(PROGRESS_EVERY) {
            emit(TftpEvent::TransferProgress { id, bytes: sent });
        }
        // The transfer ends on the first block shorter than a full block.
        if chunk.len() < blksize {
            break;
        }
        block = block.wrapping_add(1);
    }

    emit(TftpEvent::TransferEnd {
        id,
        bytes: sent,
        ok: true,
        message: "sent".to_string(),
    });
    Ok(())
}

async fn handle_write<F>(
    id: u32,
    sock: &UdpSocket,
    req: &Request,
    root: &std::path::Path,
    emit: &F,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), TftpError>
where
    F: Fn(TftpEvent),
{
    let path = core::resolve_write(root, &req.filename)?;
    let accepted = core::negotiate(&req.options, None);
    let blksize = core::blksize_of(&accepted);

    emit(TftpEvent::TransferStart {
        id,
        file: req.filename.clone(),
        client: sock.peer_addr().map(|a| a.to_string()).unwrap_or_default(),
        direction: "write".to_string(),
    });

    // Receive into a new temporary file beside the target, then rename it into
    // place. `create_new` never follows a link, and the rename replaces the
    // directory entry itself, so a symlink or hard link planted in the root
    // cannot redirect the write outside it. A failed upload leaves any
    // existing file untouched.
    let tmp = core::upload_temp_path(&path, id);
    let mut file = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)
        .await
        .map_err(|_| TftpError::AccessViolation)?;

    let result = receive_blocks(sock, &mut file, accepted, blksize, id, emit, &mut shutdown).await;
    drop(file);
    let received = match result {
        Ok(n) => n,
        Err(e) => {
            let _ = tokio::fs::remove_file(&tmp).await;
            return Err(e);
        }
    };
    if tokio::fs::rename(&tmp, &path).await.is_err() {
        let _ = tokio::fs::remove_file(&tmp).await;
        return Err(TftpError::AccessViolation);
    }

    emit(TftpEvent::TransferEnd {
        id,
        bytes: received,
        ok: true,
        message: "received".to_string(),
    });
    Ok(())
}

/// Receive DATA blocks into `file` until the final short block. Returns the
/// byte count.
async fn receive_blocks<F>(
    sock: &UdpSocket,
    file: &mut tokio::fs::File,
    accepted: Vec<(String, String)>,
    blksize: usize,
    id: u32,
    emit: &F,
    shutdown: &mut watch::Receiver<bool>,
) -> Result<u64, TftpError>
where
    F: Fn(TftpEvent),
{
    // Acknowledge the request: OACK if options were accepted, else ACK(0).
    let opening = if accepted.is_empty() {
        core::build_ack(0)
    } else {
        core::build_oack(&accepted)
    };

    let mut buf = [0u8; 65_600];
    let mut expected: u16 = 1;
    let mut received: u64 = 0;
    let mut last_reply = opening;

    loop {
        let payload = send_and_wait_data(sock, &last_reply, expected, &mut buf, shutdown).await?;
        file.write_all(&payload)
            .await
            .map_err(|_| TftpError::AccessViolation)?;
        received += payload.len() as u64;

        last_reply = core::build_ack(expected);
        if expected.is_multiple_of(PROGRESS_EVERY) {
            emit(TftpEvent::TransferProgress {
                id,
                bytes: received,
            });
        }
        if payload.len() < blksize {
            // Final block: send the last ACK and finish.
            let _ = sock.send(&last_reply).await;
            break;
        }
        expected = expected.wrapping_add(1);
    }
    file.flush().await.map_err(|_| TftpError::AccessViolation)?;
    Ok(received)
}

/// Send `packet` and wait for ACK(expect), retransmitting on timeout.
async fn send_and_wait_ack(
    sock: &UdpSocket,
    packet: &[u8],
    expect: u16,
    buf: &mut [u8],
    shutdown: &mut watch::Receiver<bool>,
) -> Result<(), TftpError> {
    for _ in 0..=MAX_RETRIES {
        if *shutdown.borrow() {
            return Err(TftpError::IllegalOperation);
        }
        sock.send(packet)
            .await
            .map_err(|_| TftpError::IllegalOperation)?;
        tokio::select! {
            _ = shutdown.changed() => return Err(TftpError::IllegalOperation),
            res = tokio::time::timeout(TRANSFER_TIMEOUT, sock.recv(buf)) => {
                if let Ok(Ok(n)) = res {
                    if core::parse_ack(&buf[..n]) == Some(expect) {
                        return Ok(());
                    }
                    // An ERROR from the client (or a stale ACK) aborts/ignores.
                    if n >= 2 && u16::from_be_bytes([buf[0], buf[1]]) == core::OP_ERROR {
                        return Err(TftpError::IllegalOperation);
                    }
                }
                // Timeout or unexpected packet: retransmit.
            }
        }
    }
    Err(TftpError::IllegalOperation)
}

/// Send `reply` and wait for DATA(expect), retransmitting on timeout. Returns
/// the payload.
async fn send_and_wait_data(
    sock: &UdpSocket,
    reply: &[u8],
    expect: u16,
    buf: &mut [u8],
    shutdown: &mut watch::Receiver<bool>,
) -> Result<Vec<u8>, TftpError> {
    for _ in 0..=MAX_RETRIES {
        if *shutdown.borrow() {
            return Err(TftpError::IllegalOperation);
        }
        sock.send(reply)
            .await
            .map_err(|_| TftpError::IllegalOperation)?;
        tokio::select! {
            _ = shutdown.changed() => return Err(TftpError::IllegalOperation),
            res = tokio::time::timeout(TRANSFER_TIMEOUT, sock.recv(buf)) => {
                if let Ok(Ok(n)) = res {
                    if let Some((block, payload)) = core::parse_data(&buf[..n]) {
                        if block == expect {
                            return Ok(payload.to_vec());
                        }
                    } else if n >= 2 && u16::from_be_bytes([buf[0], buf[1]]) == core::OP_ERROR {
                        return Err(TftpError::IllegalOperation);
                    }
                }
            }
        }
    }
    Err(TftpError::IllegalOperation)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal classic-TFTP client that reads a file, for end-to-end testing.
    async fn tftp_get(server: SocketAddr, filename: &str) -> Vec<u8> {
        let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let mut rrq = core::OP_RRQ.to_be_bytes().to_vec();
        rrq.extend_from_slice(filename.as_bytes());
        rrq.push(0);
        rrq.extend_from_slice(b"octet");
        rrq.push(0);
        client.send_to(&rrq, server).await.unwrap();

        let mut out = Vec::new();
        let mut buf = [0u8; 2048];
        let mut expect: u16 = 1;
        loop {
            let (n, from) = client.recv_from(&mut buf).await.unwrap();
            let (block, payload) = core::parse_data(&buf[..n]).expect("DATA");
            assert_eq!(block, expect);
            out.extend_from_slice(payload);
            client.send_to(&core::build_ack(block), from).await.unwrap();
            if payload.len() < core::DEFAULT_BLKSIZE {
                break;
            }
            expect = expect.wrapping_add(1);
        }
        out
    }

    #[tokio::test]
    async fn rrq_download_roundtrips() {
        // A payload spanning several blocks, not a multiple of 512.
        let root = std::env::temp_dir().join(format!("omnipacket_tftp_srv_{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let content: Vec<u8> = (0..1300u32).map(|i| (i % 251) as u8).collect();
        std::fs::write(root.join("img.bin"), &content).unwrap();

        let sock = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = sock.local_addr().unwrap();
        let (_tx, rx) = watch::channel(false);
        tokio::spawn(serve(sock, root.clone(), false, rx, |_| {}));

        let got = tftp_get(addr, "img.bin").await;
        assert_eq!(got, content);

        let _ = std::fs::remove_file(root.join("img.bin"));
    }
    /// A minimal classic-TFTP client that uploads `data`.
    async fn tftp_put(server: SocketAddr, filename: &str, data: &[u8]) {
        let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let mut wrq = core::OP_WRQ.to_be_bytes().to_vec();
        wrq.extend_from_slice(filename.as_bytes());
        wrq.push(0);
        wrq.extend_from_slice(b"octet");
        wrq.push(0);
        client.send_to(&wrq, server).await.unwrap();

        let mut buf = [0u8; 2048];
        let (n, from) = client.recv_from(&mut buf).await.unwrap();
        assert_eq!(core::parse_ack(&buf[..n]), Some(0), "expected ACK(0)");
        let mut chunks: Vec<&[u8]> = data.chunks(core::DEFAULT_BLKSIZE).collect();
        if data.len().is_multiple_of(core::DEFAULT_BLKSIZE) {
            chunks.push(&[]);
        }
        for (i, chunk) in chunks.iter().enumerate() {
            let block = (i + 1) as u16;
            let mut pkt = core::OP_DATA.to_be_bytes().to_vec();
            pkt.extend_from_slice(&block.to_be_bytes());
            pkt.extend_from_slice(chunk);
            client.send_to(&pkt, from).await.unwrap();
            let (n, _) = client.recv_from(&mut buf).await.unwrap();
            assert_eq!(core::parse_ack(&buf[..n]), Some(block));
        }
    }

    #[tokio::test]
    async fn refused_requests_are_reported() {
        let root = std::env::temp_dir().join(format!("omnipacket_tftp_rej_{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let sock = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = sock.local_addr().unwrap();
        let (_tx, rx) = watch::channel(false);
        let (etx, mut erx) = tokio::sync::mpsc::unbounded_channel::<TftpEvent>();
        tokio::spawn(serve(sock, root.clone(), false, rx, move |e| {
            let _ = etx.send(e);
        }));

        let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let req = |op: u16, name: &str| {
            let mut p = op.to_be_bytes().to_vec();
            p.extend_from_slice(name.as_bytes());
            p.extend_from_slice(b"\0octet\0");
            p
        };
        let mut seen = Vec::new();
        for pkt in [
            req(core::OP_RRQ, "missing.bin"),
            req(core::OP_WRQ, "up.cfg"),
            vec![0, 9],
        ] {
            client.send_to(&pkt, addr).await.unwrap();
            let ev = tokio::time::timeout(Duration::from_secs(2), erx.recv())
                .await
                .unwrap()
                .unwrap();
            match ev {
                TftpEvent::Rejected {
                    file,
                    direction,
                    message,
                    ..
                } => seen.push((file, direction, message)),
                _ => panic!("expected a Rejected event"),
            }
        }
        assert_eq!(seen[0].0, "missing.bin");
        assert_eq!(seen[0].1, "read");
        assert_eq!(seen[1].1, "write");
        assert!(seen[1].2.contains("uploads are off"), "{}", seen[1].2);
        assert_eq!(seen[2].0, "");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn wrq_replaces_an_existing_file_and_cleans_up() {
        let root = std::env::temp_dir().join(format!("omnipacket_tftp_put_{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("backup.cfg"), b"old contents").unwrap();

        let sock = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = sock.local_addr().unwrap();
        let (_tx, rx) = watch::channel(false);
        tokio::spawn(serve(sock, root.clone(), true, rx, |_| {}));

        // Exactly two blocks, so the upload ends with an empty DATA block.
        let content = vec![7u8; 1024];
        tftp_put(addr, "backup.cfg", &content).await;
        let mut done = false;
        for _ in 0..50 {
            if std::fs::read(root.join("backup.cfg")).unwrap() == content {
                done = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(done, "file not replaced");
        let names: Vec<_> = std::fs::read_dir(&root)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names.len(), 1, "temporary file left behind: {names:?}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn wrq_replaces_a_symlink_instead_of_following_it() {
        let base =
            std::env::temp_dir().join(format!("omnipacket_tftp_link_{}", std::process::id()));
        let root = base.join("root");
        std::fs::create_dir_all(&root).unwrap();
        let outside = base.join("outside.txt");
        std::fs::write(&outside, b"untouched").unwrap();
        std::os::unix::fs::symlink(&outside, root.join("sw1.cfg")).unwrap();

        let sock = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = sock.local_addr().unwrap();
        let (_tx, rx) = watch::channel(false);
        tokio::spawn(serve(sock, root.clone(), true, rx, |_| {}));

        let content: Vec<u8> = (0..1100u32).map(|i| (i % 97) as u8).collect();
        tftp_put(addr, "sw1.cfg", &content).await;
        // The server renames after its final ACK; give it a moment.
        for _ in 0..50 {
            if !std::fs::symlink_metadata(root.join("sw1.cfg"))
                .unwrap()
                .file_type()
                .is_symlink()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        assert_eq!(std::fs::read(&outside).unwrap(), b"untouched");
        let meta = std::fs::symlink_metadata(root.join("sw1.cfg")).unwrap();
        assert!(meta.file_type().is_file());
        assert_eq!(std::fs::read(root.join("sw1.cfg")).unwrap(), content);
        let leftovers = std::fs::read_dir(&root).unwrap().count();
        assert_eq!(leftovers, 1, "temporary file left behind");
        let _ = std::fs::remove_dir_all(&base);
    }
}
