//! End-to-end tests against an in-process SSH server with an in-memory SFTP
//! file system that can misbehave (short reads, endless listings).

use super::*;
use crate::tools::ssh::core::{AuthKind, KnownHost};
use russh::server::{self, Msg, Server as _, Session};
use russh::{Channel as SshChannel, ChannelId};
use russh_sftp::protocol::{Attrs, Data, File, Handle, Name, Status, Version};
use std::collections::HashSet;
use tokio::sync::Mutex as AsyncMutex;

#[derive(Default)]
struct Fs {
    files: HashMap<String, Vec<u8>>,
    dirs: HashSet<String>,
    handles: HashMap<String, String>,
    listed: HashSet<String>,
    next: u32,
}

#[derive(Clone, Copy, Default)]
struct Quirks {
    /// Answer reads with at most this many bytes.
    short_reads: Option<usize>,
    /// Never end a directory listing.
    endless_dir: bool,
}

#[derive(Clone)]
struct TestServer {
    fs: Arc<Mutex<Fs>>,
    quirks: Quirks,
}

struct SshHandler {
    server: TestServer,
    channels: Arc<AsyncMutex<HashMap<ChannelId, SshChannel<Msg>>>>,
}

impl server::Server for TestServer {
    type Handler = SshHandler;
    fn new_client(&mut self, _: Option<std::net::SocketAddr>) -> SshHandler {
        SshHandler {
            server: self.clone(),
            channels: Arc::default(),
        }
    }
}

impl server::Handler for SshHandler {
    type Error = russh::Error;

    async fn auth_password(&mut self, user: &str, pw: &str) -> Result<server::Auth, Self::Error> {
        Ok(if user == "admin" && pw == "secret" {
            server::Auth::Accept
        } else {
            server::Auth::reject()
        })
    }

    async fn channel_open_session(
        &mut self,
        channel: SshChannel<Msg>,
        reply: server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.channels.lock().await.insert(channel.id(), channel);
        reply.accept().await;
        Ok(())
    }

    async fn subsystem_request(
        &mut self,
        id: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let channel = self.channels.lock().await.remove(&id);
        match (name, channel) {
            ("sftp", Some(ch)) => {
                session.channel_success(id)?;
                russh_sftp::server::run(ch.into_stream(), self.server.clone()).await;
            }
            _ => session.channel_failure(id)?,
        }
        Ok(())
    }
}

fn ok(id: u32) -> Status {
    Status {
        id,
        status_code: StatusCode::Ok,
        error_message: "Ok".into(),
        language_tag: "en-US".into(),
    }
}

fn attrs_for(fs: &Fs, path: &str) -> Option<FileAttributes> {
    let mut a = FileAttributes::empty();
    if fs.dirs.contains(path) {
        a.permissions = Some(0o040755);
    } else {
        let f = fs.files.get(path)?;
        a.permissions = Some(0o100644);
        a.size = Some(f.len() as u64);
    }
    Some(a)
}

fn normalize(p: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    let start = if p.starts_with('/') {
        ""
    } else {
        "/home/admin/"
    };
    let full = format!("{start}{p}");
    for c in full.split('/') {
        match c {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            c => parts.push(c),
        }
    }
    format!("/{}", parts.join("/"))
}

impl russh_sftp::server::Handler for TestServer {
    type Error = StatusCode;

    fn unimplemented(&self) -> StatusCode {
        StatusCode::OpUnsupported
    }

    async fn init(&mut self, _v: u32, _e: HashMap<String, String>) -> Result<Version, StatusCode> {
        Ok(Version::new())
    }

    async fn realpath(&mut self, id: u32, path: String) -> Result<Name, StatusCode> {
        Ok(Name {
            id,
            files: vec![File::dummy(normalize(&path))],
        })
    }

    async fn stat(&mut self, id: u32, path: String) -> Result<Attrs, StatusCode> {
        let fs = self.fs.lock().unwrap();
        attrs_for(&fs, &normalize(&path))
            .map(|attrs| Attrs { id, attrs })
            .ok_or(StatusCode::NoSuchFile)
    }

    async fn opendir(&mut self, id: u32, path: String) -> Result<Handle, StatusCode> {
        let mut fs = self.fs.lock().unwrap();
        if !fs.dirs.contains(&path) {
            return Err(StatusCode::NoSuchFile);
        }
        fs.next += 1;
        let h = format!("d{}", fs.next);
        fs.handles.insert(h.clone(), path);
        Ok(Handle { id, handle: h })
    }

    async fn readdir(&mut self, id: u32, handle: String) -> Result<Name, StatusCode> {
        let mut fs = self.fs.lock().unwrap();
        if self.quirks.endless_dir {
            fs.next += 1;
            let n = fs.next;
            let files = (0..100)
                .map(|i| File::new(format!("f{n}-{i}"), FileAttributes::empty()))
                .collect();
            return Ok(Name { id, files });
        }
        let dir = fs
            .handles
            .get(&handle)
            .cloned()
            .ok_or(StatusCode::Failure)?;
        if !fs.listed.insert(handle) {
            return Err(StatusCode::Eof);
        }
        let prefix = if dir == "/" {
            "/".to_string()
        } else {
            format!("{dir}/")
        };
        let mut files = vec![File::new(".", FileAttributes::empty())];
        let children: Vec<String> = fs
            .files
            .keys()
            .chain(fs.dirs.iter())
            .filter_map(|p| p.strip_prefix(&prefix))
            .filter(|rest| !rest.is_empty() && !rest.contains('/'))
            .map(str::to_string)
            .collect();
        for c in children {
            let a = attrs_for(&fs, &format!("{prefix}{c}")).unwrap_or_else(FileAttributes::empty);
            files.push(File::new(c, a));
        }
        Ok(Name { id, files })
    }

    async fn close(&mut self, id: u32, handle: String) -> Result<Status, StatusCode> {
        let mut fs = self.fs.lock().unwrap();
        fs.handles.remove(&handle);
        fs.listed.remove(&handle);
        Ok(ok(id))
    }

    async fn open(
        &mut self,
        id: u32,
        filename: String,
        flags: OpenFlags,
        _attrs: FileAttributes,
    ) -> Result<Handle, StatusCode> {
        let mut fs = self.fs.lock().unwrap();
        let path = normalize(&filename);
        if flags.contains(OpenFlags::CREATE) {
            if flags.contains(OpenFlags::TRUNCATE) || !fs.files.contains_key(&path) {
                fs.files.insert(path.clone(), Vec::new());
            }
        } else if !fs.files.contains_key(&path) {
            return Err(StatusCode::NoSuchFile);
        }
        fs.next += 1;
        let h = format!("f{}", fs.next);
        fs.handles.insert(h.clone(), path);
        Ok(Handle { id, handle: h })
    }

    async fn read(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        len: u32,
    ) -> Result<Data, StatusCode> {
        let fs = self.fs.lock().unwrap();
        let path = fs.handles.get(&handle).ok_or(StatusCode::Failure)?;
        let data = fs.files.get(path).ok_or(StatusCode::NoSuchFile)?;
        let start = offset as usize;
        if start >= data.len() {
            return Err(StatusCode::Eof);
        }
        let mut end = (start + len as usize).min(data.len());
        if let Some(max) = self.quirks.short_reads {
            end = end.min(start + max);
        }
        Ok(Data {
            id,
            data: data[start..end].to_vec(),
        })
    }

    async fn write(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        data: Vec<u8>,
    ) -> Result<Status, StatusCode> {
        let mut fs = self.fs.lock().unwrap();
        let path = fs
            .handles
            .get(&handle)
            .cloned()
            .ok_or(StatusCode::Failure)?;
        let f = fs.files.get_mut(&path).ok_or(StatusCode::NoSuchFile)?;
        let end = offset as usize + data.len();
        if f.len() < end {
            f.resize(end, 0);
        }
        f[offset as usize..end].copy_from_slice(&data);
        Ok(ok(id))
    }

    async fn mkdir(
        &mut self,
        id: u32,
        path: String,
        _a: FileAttributes,
    ) -> Result<Status, StatusCode> {
        let mut fs = self.fs.lock().unwrap();
        let p = normalize(&path);
        if fs.dirs.contains(&p) || fs.files.contains_key(&p) {
            return Err(StatusCode::Failure);
        }
        fs.dirs.insert(p);
        Ok(ok(id))
    }

    async fn rmdir(&mut self, id: u32, path: String) -> Result<Status, StatusCode> {
        let mut fs = self.fs.lock().unwrap();
        let p = normalize(&path);
        let prefix = format!("{p}/");
        if fs
            .files
            .keys()
            .chain(fs.dirs.iter())
            .any(|k| k.starts_with(&prefix))
        {
            return Err(StatusCode::Failure);
        }
        fs.dirs
            .remove(&p)
            .then(|| ok(id))
            .ok_or(StatusCode::NoSuchFile)
    }

    async fn remove(&mut self, id: u32, filename: String) -> Result<Status, StatusCode> {
        let mut fs = self.fs.lock().unwrap();
        fs.files
            .remove(&normalize(&filename))
            .map(|_| ok(id))
            .ok_or(StatusCode::NoSuchFile)
    }

    async fn rename(&mut self, id: u32, from: String, to: String) -> Result<Status, StatusCode> {
        let mut fs = self.fs.lock().unwrap();
        let (from, to) = (normalize(&from), normalize(&to));
        // SFTP v3 servers refuse to rename over an existing file.
        if fs.files.contains_key(&to) || fs.dirs.contains(&to) {
            return Err(StatusCode::Failure);
        }
        if let Some(d) = fs.files.remove(&from) {
            fs.files.insert(to, d);
        } else if fs.dirs.remove(&from) {
            fs.dirs.insert(to);
        } else {
            return Err(StatusCode::NoSuchFile);
        }
        Ok(ok(id))
    }
}

async fn start(quirks: Quirks) -> (u16, Arc<Mutex<Fs>>) {
    let mut fs = Fs::default();
    for d in ["/", "/home", "/home/admin", "/home/admin/configs"] {
        fs.dirs.insert(d.to_string());
    }
    fs.files
        .insert("/home/admin/notes.txt".into(), b"hello".to_vec());
    let fs = Arc::new(Mutex::new(fs));
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
    let mut server = TestServer {
        fs: fs.clone(),
        quirks,
    };
    tokio::spawn(async move {
        let _ = server.run_on_socket(config, socket).await;
    });
    (port, fs)
}

/// Log in (confirming the host key) and start SFTP.
async fn session(port: u16) -> Arc<RawSftpSession> {
    let mut params = ConnectParams {
        connection_id: None,
        host: "127.0.0.1".into(),
        port,
        user: "admin".into(),
        auth: AuthKind::Password,
        key_path: String::new(),
        secret: Some("secret".into()),
        save_secret: false,
        trust_fingerprint: None,
    };
    let fp = match authenticate(&params, "127.0.0.1", &[], None).await.unwrap() {
        Authed::Prompt(ConnectOutcome::HostKey { fingerprint, .. }) => fingerprint,
        _ => panic!("expected a host key prompt"),
    };
    params.trust_fingerprint = Some(fp.clone());
    let known = [KnownHost {
        host: "127.0.0.1".into(),
        port,
        algorithm: String::new(),
        fingerprint: fp,
        added: 0,
    }];
    let Authed::Ready { handle, .. } = authenticate(&params, "127.0.0.1", &known, None)
        .await
        .unwrap()
    else {
        panic!("expected a login");
    };
    let sftp = open_sftp(&handle).await.unwrap();
    // Keep the connection alive for the test's duration.
    Box::leak(Box::new(handle));
    sftp
}

fn temp_dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("omnipacket_sftp_{tag}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn pattern(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i * 31 % 251) as u8).collect()
}

#[tokio::test]
async fn browse_upload_download_round_trip() {
    let (port, fs) = start(Quirks::default()).await;
    let sftp = session(port).await;

    let l = list(&sftp, ".").await.unwrap();
    assert_eq!(l.path, "/home/admin");
    assert!(!l.truncated);
    let names: Vec<_> = l.entries.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(names, ["configs", "notes.txt"]);
    assert_eq!(l.entries[0].kind, Kind::Dir);
    assert_eq!(l.entries[1].size, Some(5));
    assert_eq!(l.entries[1].perms, "-rw-r--r--");

    // Upload a multi-chunk file with an odd tail.
    let dir = temp_dir("rt");
    let src = dir.join("fw.out");
    let body = pattern(CHUNK as usize * 20 + 123);
    std::fs::write(&src, &body).unwrap();
    let cancel = AtomicBool::new(false);
    let seen = Mutex::new(Vec::<Progress>::new());
    let on = |p: Progress| seen.lock().unwrap().push(p);
    let out = upload(&sftp, &src, "/home/admin", "fw.out", false, &cancel, &on)
        .await
        .unwrap();
    assert_eq!(
        out,
        TransferOutcome::Done {
            bytes: body.len() as u64,
            path: "/home/admin/fw.out".into()
        }
    );
    assert_eq!(fs.lock().unwrap().files["/home/admin/fw.out"], body);
    assert!(
        !fs.lock()
            .unwrap()
            .files
            .keys()
            .any(|k| k.contains("net3po-part"))
    );
    let last = seen.lock().unwrap().last().cloned().unwrap();
    assert_eq!(last.done, body.len() as u64);

    // Uploading again asks first; overwrite replaces.
    let out = upload(&sftp, &src, "/home/admin", "fw.out", false, &cancel, &on)
        .await
        .unwrap();
    assert!(matches!(out, TransferOutcome::Exists { .. }));
    let smaller = pattern(1000);
    std::fs::write(&src, &smaller).unwrap();
    upload(&sftp, &src, "/home/admin", "fw.out", true, &cancel, &on)
        .await
        .unwrap();
    assert_eq!(fs.lock().unwrap().files["/home/admin/fw.out"], smaller);

    // Download back.
    fs.lock()
        .unwrap()
        .files
        .insert("/home/admin/big.bin".into(), body.clone());
    let target = dir.join("big.bin");
    let out = download(&sftp, "/home/admin/big.bin", &target, false, &cancel, &on)
        .await
        .unwrap();
    assert!(matches!(out, TransferOutcome::Done { bytes, .. } if bytes == body.len() as u64));
    assert_eq!(std::fs::read(&target).unwrap(), body);
    assert!(!part_path(&target).exists());
    let out = download(&sftp, "/home/admin/big.bin", &target, false, &cancel, &on)
        .await
        .unwrap();
    assert!(matches!(out, TransferOutcome::Exists { .. }));

    // Empty file, and a folder is refused.
    fs.lock()
        .unwrap()
        .files
        .insert("/home/admin/empty".into(), Vec::new());
    let t = dir.join("empty");
    download(&sftp, "/home/admin/empty", &t, false, &cancel, &on)
        .await
        .unwrap();
    assert_eq!(std::fs::read(&t).unwrap(), b"");
    let e = download(
        &sftp,
        "/home/admin/configs",
        &dir.join("c"),
        false,
        &cancel,
        &on,
    )
    .await
    .unwrap_err();
    assert!(e.contains("is a folder"), "{e}");

    // A cancelled download leaves nothing behind.
    let cancelled = AtomicBool::new(true);
    let t = dir.join("never.bin");
    let out = download(&sftp, "/home/admin/big.bin", &t, false, &cancelled, &on)
        .await
        .unwrap();
    assert_eq!(out, TransferOutcome::Cancelled);
    assert!(!t.exists() && !part_path(&t).exists());

    // A cancelled upload removes its temporary file.
    let out = upload(&sftp, &src, "/home/admin", "x.bin", false, &cancelled, &on)
        .await
        .unwrap();
    assert_eq!(out, TransferOutcome::Cancelled);
    assert!(!fs.lock().unwrap().files.keys().any(|k| k.contains("x.bin")));

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn short_reads_are_filled_in_order() {
    let (port, fs) = start(Quirks {
        short_reads: Some(1000),
        ..Default::default()
    })
    .await;
    let sftp = session(port).await;
    let body = pattern(CHUNK as usize * 5 + 7);
    fs.lock()
        .unwrap()
        .files
        .insert("/home/admin/s.bin".into(), body.clone());
    let dir = temp_dir("short");
    let t = dir.join("s.bin");
    let cancel = AtomicBool::new(false);
    download(&sftp, "/home/admin/s.bin", &t, false, &cancel, &|_| {})
        .await
        .unwrap();
    assert_eq!(std::fs::read(&t).unwrap(), body);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn endless_listing_is_capped() {
    let (port, _fs) = start(Quirks {
        endless_dir: true,
        ..Default::default()
    })
    .await;
    let sftp = session(port).await;
    let l = list(&sftp, "/home/admin").await.unwrap();
    assert!(l.truncated);
    assert_eq!(l.entries.len(), MAX_ENTRIES);
}

#[tokio::test]
async fn folders_rename_and_delete() {
    let (port, fs) = start(Quirks::default()).await;
    let sftp = session(port).await;
    sftp.mkdir("/home/admin/new", FileAttributes::empty())
        .await
        .unwrap();
    assert!(fs.lock().unwrap().dirs.contains("/home/admin/new"));
    let e = sftp
        .rmdir("/home/admin/nope")
        .await
        .map_err(err)
        .unwrap_err();
    assert_eq!(e, "no such file or folder");
}

#[test]
fn outcomes_are_camel_case() {
    let v = serde_json::to_value(TransferOutcome::Done {
        bytes: 3,
        path: "/x".into(),
    })
    .unwrap();
    assert_eq!(v["type"], "done");
    let v = serde_json::to_value(TransferOutcome::Exists { path: "/x".into() }).unwrap();
    assert_eq!(v["type"], "exists");
}
