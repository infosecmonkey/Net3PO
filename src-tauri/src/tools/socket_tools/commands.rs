//! Tauri commands for the socket tools: a TCP/UDP sender, a TCP/UDP
//! listener and repeated TCP connection timing. Each streams events over a
//! channel and stops on `sock_stop` with its id. All waits are bounded.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tauri::State;
use tauri::ipc::Channel;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket, lookup_host};
use tokio::sync::watch;

use super::core::{self, Chunk, Outcome, PayloadKind, Stats};

/// Longest wait for replies after sending.
const MAX_WAIT_MS: u64 = 120_000;
/// Most reply bytes collected by the sender.
const MAX_REPLY: usize = 1024 * 1024;
/// Most simultaneous TCP connections on a listener.
const MAX_CONNS: usize = 64;
/// Most attempts in one timing run.
const MAX_ATTEMPTS: u32 = 10_000;

/// Running tasks by id; sending `true` stops one.
#[derive(Default)]
pub struct SocketRegistry {
    inner: Arc<Mutex<HashMap<u32, watch::Sender<bool>>>>,
}

impl SocketRegistry {
    fn register(&self, id: u32) -> watch::Receiver<bool> {
        let (tx, rx) = watch::channel(false);
        self.inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(id, tx);
        rx
    }

    fn remove(&self, id: u32) {
        self.inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&id);
    }
}

/// Stop a running send, listener or timing run.
#[tauri::command]
pub fn sock_stop(registry: State<'_, SocketRegistry>, id: u32) {
    if let Some(tx) = registry
        .inner
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .get(&id)
    {
        let _ = tx.send(true);
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Proto {
    Tcp,
    Udp,
}

fn ms_since(t: Instant) -> f64 {
    (t.elapsed().as_secs_f64() * 1000.0 * 100.0).round() / 100.0
}

async fn resolve(host: &str, port: u16) -> Result<SocketAddr, String> {
    let host = host.trim().trim_matches(|c| c == '[' || c == ']');
    if host.is_empty() {
        return Err("enter a host".into());
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    let mut addrs = tokio::time::timeout(Duration::from_secs(10), lookup_host((host, port)))
        .await
        .map_err(|_| format!("resolving {host} timed out"))?
        .map_err(|e| format!("could not resolve {host}: {e}"))?;
    // Prefer IPv4 when both exist; it is what most people expect to test.
    let all: Vec<SocketAddr> = addrs.by_ref().take(16).collect();
    all.iter()
        .find(|a| a.is_ipv4())
        .or(all.first())
        .copied()
        .ok_or_else(|| format!("{host} has no addresses"))
}

fn bind_error(proto: &str, addr: &SocketAddr, e: std::io::Error) -> String {
    use std::io::ErrorKind::*;
    match e.kind() {
        PermissionDenied => format!(
            "cannot bind {proto} {addr}: permission denied. Ports below 1024 need admin/root on Linux and Windows; try a higher port."
        ),
        AddrInUse => format!("cannot bind {proto} {addr}: already in use."),
        AddrNotAvailable => {
            format!("cannot bind {proto} {addr}: that address is not on this computer.")
        }
        _ => format!("cannot bind {proto} {addr}: {e}"),
    }
}

// ------------------------------------------------------------------ sender

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SendRequest {
    pub host: String,
    pub port: u16,
    pub proto: Proto,
    pub payload: String,
    pub kind: PayloadKind,
    /// How long to wait for replies after sending.
    pub wait_ms: u64,
    pub connect_timeout_ms: u64,
}

#[derive(Clone, Serialize)]
#[serde(
    tag = "type",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum SendEvent {
    Resolved {
        addr: String,
    },
    Connected {
        ms: f64,
        local: String,
    },
    Sent {
        bytes: usize,
        ms: f64,
    },
    Received {
        at_ms: f64,
        from: String,
        chunk: Chunk,
    },
    Done {
        received: usize,
        reason: String,
        note: String,
    },
}

/// Send one payload over TCP or UDP and collect replies for `wait_ms`.
#[tauri::command]
pub async fn sock_send(
    registry: State<'_, SocketRegistry>,
    id: u32,
    req: SendRequest,
    on_event: Channel<SendEvent>,
) -> Result<(), String> {
    let payload = core::parse_payload(&req.payload, req.kind)?;
    let addr = resolve(&req.host, req.port).await?;
    let _ = on_event.send(SendEvent::Resolved {
        addr: addr.to_string(),
    });
    let mut stop = registry.register(id);
    let res = match req.proto {
        Proto::Tcp => send_tcp(&req, addr, &payload, &mut stop, &on_event).await,
        Proto::Udp => send_udp(&req, addr, &payload, &mut stop, &on_event).await,
    };
    registry.remove(id);
    res
}

async fn send_tcp(
    req: &SendRequest,
    addr: SocketAddr,
    payload: &[u8],
    stop: &mut watch::Receiver<bool>,
    ev: &Channel<SendEvent>,
) -> Result<(), String> {
    let timeout = Duration::from_millis(req.connect_timeout_ms.clamp(100, 60_000));
    let t0 = Instant::now();
    let mut s = match tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return Err(format!("connect to {addr}: {}", core::classify(&e).1)),
        Err(_) => {
            return Err(format!(
                "connect to {addr}: no answer within {} ms",
                timeout.as_millis()
            ));
        }
    };
    let _ = ev.send(SendEvent::Connected {
        ms: ms_since(t0),
        local: s.local_addr().map(|a| a.to_string()).unwrap_or_default(),
    });
    let start = Instant::now();
    if !payload.is_empty() {
        s.write_all(payload)
            .await
            .map_err(|e| format!("send: {e}"))?;
    }
    let _ = ev.send(SendEvent::Sent {
        bytes: payload.len(),
        ms: ms_since(start),
    });

    let deadline =
        tokio::time::Instant::now() + Duration::from_millis(req.wait_ms.min(MAX_WAIT_MS));
    let mut buf = vec![0u8; 16 * 1024];
    let mut total = 0usize;
    let reason = loop {
        tokio::select! {
            _ = stop.changed() => break "stopped".to_string(),
            _ = tokio::time::sleep_until(deadline) => break "wait time over".to_string(),
            r = s.read(&mut buf) => match r {
                Ok(0) => break "the server closed the connection".to_string(),
                Ok(n) => {
                    total += n;
                    let _ = ev.send(SendEvent::Received { at_ms: ms_since(start), from: addr.to_string(), chunk: core::chunk(&buf[..n]) });
                    if total >= MAX_REPLY {
                        break "1 MB received; stopped reading".to_string();
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => break "the server reset the connection".to_string(),
                Err(e) => break format!("read error: {e}"),
            }
        }
    };
    let note = if total == 0 && reason == "wait time over" {
        "Connected and sent, but no reply. Many services wait for a specific request before answering.".into()
    } else {
        String::new()
    };
    let _ = ev.send(SendEvent::Done {
        received: total,
        reason,
        note,
    });
    Ok(())
}

async fn send_udp(
    req: &SendRequest,
    addr: SocketAddr,
    payload: &[u8],
    stop: &mut watch::Receiver<bool>,
    ev: &Channel<SendEvent>,
) -> Result<(), String> {
    let local: SocketAddr = if addr.is_ipv4() {
        "0.0.0.0:0".parse().unwrap_or(addr)
    } else {
        "[::]:0".parse().unwrap_or(addr)
    };
    let s = UdpSocket::bind(local)
        .await
        .map_err(|e| format!("open UDP socket: {e}"))?;
    // Connecting a UDP socket filters replies to the target and lets the OS
    // report ICMP port unreachable as a refused error.
    s.connect(addr)
        .await
        .map_err(|e| format!("UDP to {addr}: {e}"))?;
    let start = Instant::now();
    s.send(payload).await.map_err(|e| format!("send: {e}"))?;
    let _ = ev.send(SendEvent::Sent {
        bytes: payload.len(),
        ms: ms_since(start),
    });

    let deadline =
        tokio::time::Instant::now() + Duration::from_millis(req.wait_ms.min(MAX_WAIT_MS));
    let mut buf = vec![0u8; 65_535];
    let mut total = 0usize;
    let mut refused = false;
    let reason = loop {
        tokio::select! {
            _ = stop.changed() => break "stopped".to_string(),
            _ = tokio::time::sleep_until(deadline) => break "wait time over".to_string(),
            r = s.recv(&mut buf) => match r {
                Ok(n) => {
                    total += n;
                    let _ = ev.send(SendEvent::Received { at_ms: ms_since(start), from: addr.to_string(), chunk: core::chunk(&buf[..n]) });
                    if total >= MAX_REPLY {
                        break "1 MB received; stopped reading".to_string();
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused || e.kind() == std::io::ErrorKind::ConnectionReset => {
                    refused = true;
                    break "ICMP port unreachable received".to_string();
                }
                Err(e) => break format!("receive error: {e}"),
            }
        }
    };
    let note = if refused {
        "The target (or a device on the path) reported the port as unreachable: most likely nothing listens there.".to_string()
    } else if total == 0 {
        "No reply. UDP silence is inconclusive: the port may be open and ignoring this payload, filtered, or closed with ICMP blocked.".to_string()
    } else {
        String::new()
    };
    let _ = ev.send(SendEvent::Done {
        received: total,
        reason,
        note,
    });
    Ok(())
}

// ---------------------------------------------------------------- listener

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListenRequest {
    pub proto: Proto,
    /// Empty means all IPv4 addresses.
    pub bind: String,
    pub port: u16,
    /// Send each received chunk back to the sender.
    pub echo: bool,
    /// Optional reply sent once to each new TCP connection or UDP peer.
    #[serde(default)]
    pub banner: String,
    pub banner_kind: PayloadKind,
}

#[derive(Clone, Serialize)]
#[serde(
    tag = "type",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum ListenEvent {
    Started {
        addr: String,
    },
    Accepted {
        conn: u32,
        peer: String,
    },
    Data {
        conn: Option<u32>,
        peer: String,
        chunk: Chunk,
    },
    Closed {
        conn: u32,
        peer: String,
        bytes: usize,
        reason: String,
    },
    Rejected {
        peer: String,
        reason: String,
    },
    Stopped,
}

/// Listen until stopped. Binding happens first so errors return at once.
#[tauri::command]
pub async fn sock_listen(
    registry: State<'_, SocketRegistry>,
    id: u32,
    req: ListenRequest,
    on_event: Channel<ListenEvent>,
) -> Result<(), String> {
    let ip: IpAddr = match req.bind.trim() {
        "" => IpAddr::from([0, 0, 0, 0]),
        s => s.parse().map_err(|_| format!("not an IP address: {s}"))?,
    };
    if req.port == 0 {
        return Err("choose a port from 1 to 65535".into());
    }
    let banner = if req.banner.is_empty() {
        Vec::new()
    } else {
        core::parse_payload(&req.banner, req.banner_kind)?
    };
    let addr = SocketAddr::new(ip, req.port);
    let mut stop = registry.register(id);
    let res = match req.proto {
        Proto::Tcp => match TcpListener::bind(addr).await {
            Ok(l) => {
                let _ = on_event.send(ListenEvent::Started {
                    addr: addr.to_string(),
                });
                listen_tcp(l, req.echo, banner, &mut stop, &on_event).await;
                Ok(())
            }
            Err(e) => Err(bind_error("TCP", &addr, e)),
        },
        Proto::Udp => match UdpSocket::bind(addr).await {
            Ok(s) => {
                let _ = on_event.send(ListenEvent::Started {
                    addr: addr.to_string(),
                });
                listen_udp(s, req.echo, banner, &mut stop, &on_event).await;
                Ok(())
            }
            Err(e) => Err(bind_error("UDP", &addr, e)),
        },
    };
    registry.remove(id);
    let _ = on_event.send(ListenEvent::Stopped);
    res
}

async fn listen_tcp(
    l: TcpListener,
    echo: bool,
    banner: Vec<u8>,
    stop: &mut watch::Receiver<bool>,
    ev: &Channel<ListenEvent>,
) {
    let active = Arc::new(AtomicUsize::new(0));
    let banner = Arc::new(banner);
    let mut next_conn = 0u32;
    let mut tasks = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            _ = stop.changed() => break,
            r = l.accept() => {
                let Ok((mut s, peer)) = r else { continue };
                if active.load(Ordering::Relaxed) >= MAX_CONNS {
                    let _ = ev.send(ListenEvent::Rejected { peer: peer.to_string(), reason: format!("more than {MAX_CONNS} connections open") });
                    continue;
                }
                next_conn += 1;
                let conn = next_conn;
                let _ = ev.send(ListenEvent::Accepted { conn, peer: peer.to_string() });
                let ev = ev.clone();
                let active = active.clone();
                let banner = banner.clone();
                let mut stop = stop.clone();
                active.fetch_add(1, Ordering::Relaxed);
                tasks.spawn(async move {
                    let mut total = 0usize;
                    let mut buf = vec![0u8; 16 * 1024];
                    let reason = 'conn: {
                        if !banner.is_empty() && s.write_all(&banner).await.is_err() {
                            break 'conn "could not send the reply".to_string();
                        }
                        loop {
                            tokio::select! {
                                _ = stop.changed() => break 'conn "listener stopped".to_string(),
                                r = s.read(&mut buf) => match r {
                                    Ok(0) => break 'conn "closed by peer".to_string(),
                                    Ok(n) => {
                                        total += n;
                                        let _ = ev.send(ListenEvent::Data { conn: Some(conn), peer: peer.to_string(), chunk: core::chunk(&buf[..n]) });
                                        if echo && s.write_all(&buf[..n]).await.is_err() {
                                            break 'conn "echo failed".to_string();
                                        }
                                    }
                                    Err(e) => break 'conn format!("error: {e}"),
                                }
                            }
                        }
                    };
                    active.fetch_sub(1, Ordering::Relaxed);
                    let _ = ev.send(ListenEvent::Closed { conn, peer: peer.to_string(), bytes: total, reason });
                });
            }
        }
    }
    // Give connection tasks a moment to report their close, then stop them.
    let _ = tokio::time::timeout(Duration::from_millis(500), async {
        while tasks.join_next().await.is_some() {}
    })
    .await;
    tasks.abort_all();
}

async fn listen_udp(
    s: UdpSocket,
    echo: bool,
    banner: Vec<u8>,
    stop: &mut watch::Receiver<bool>,
    ev: &Channel<ListenEvent>,
) {
    let mut buf = vec![0u8; 65_535];
    let mut greeted: std::collections::HashSet<SocketAddr> = std::collections::HashSet::new();
    loop {
        tokio::select! {
            _ = stop.changed() => break,
            r = s.recv_from(&mut buf) => {
                let Ok((n, peer)) = r else { continue };
                let _ = ev.send(ListenEvent::Data { conn: None, peer: peer.to_string(), chunk: core::chunk(&buf[..n]) });
                if echo {
                    let _ = s.send_to(&buf[..n], peer).await;
                }
                // Reply once per peer; the set is bounded so a flood cannot grow it.
                if !banner.is_empty() && greeted.len() < 10_000 && greeted.insert(peer) {
                    let _ = s.send_to(&banner, peer).await;
                }
            }
        }
    }
}

// ------------------------------------------------------------------ timing

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TimingRequest {
    pub host: String,
    pub port: u16,
    pub count: u32,
    pub interval_ms: u64,
    pub timeout_ms: u64,
}

#[derive(Clone, Serialize)]
#[serde(
    tag = "type",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum TimingEvent {
    Resolved {
        addr: String,
    },
    Attempt {
        seq: u32,
        outcome: Outcome,
        ms: f64,
        detail: String,
    },
    Done {
        stats: Stats,
        stopped: bool,
    },
}

/// Connect repeatedly and time each TCP connect. This is socket connect
/// time measured by the OS call, not packet-level SYN/SYN-ACK timing.
#[tauri::command]
pub async fn sock_timing(
    registry: State<'_, SocketRegistry>,
    id: u32,
    req: TimingRequest,
    on_event: Channel<TimingEvent>,
) -> Result<(), String> {
    let addr = resolve(&req.host, req.port).await?;
    let _ = on_event.send(TimingEvent::Resolved {
        addr: addr.to_string(),
    });
    let count = req.count.clamp(1, MAX_ATTEMPTS);
    let interval = Duration::from_millis(req.interval_ms.clamp(100, 3_600_000));
    let timeout = Duration::from_millis(req.timeout_ms.clamp(100, 60_000));
    let mut stop = registry.register(id);
    let mut results: Vec<(Outcome, f64)> = Vec::new();
    let mut stopped = false;
    for seq in 1..=count {
        let started = tokio::time::Instant::now();
        let t = Instant::now();
        let (outcome, detail) = tokio::select! {
            _ = stop.changed() => { stopped = true; break; }
            r = tokio::time::timeout(timeout, TcpStream::connect(addr)) => match r {
                Ok(Ok(s)) => {
                    drop(s);
                    (Outcome::Connected, String::new())
                }
                Ok(Err(e)) => core::classify(&e),
                Err(_) => (Outcome::TimedOut, format!("no answer within {} ms", timeout.as_millis())),
            }
        };
        let ms = ms_since(t);
        results.push((outcome, ms));
        let _ = on_event.send(TimingEvent::Attempt {
            seq,
            outcome,
            ms,
            detail,
        });
        if seq < count {
            tokio::select! {
                _ = stop.changed() => { stopped = true; break; }
                _ = tokio::time::sleep_until(started + interval) => {}
            }
        }
    }
    registry.remove(id);
    let _ = on_event.send(TimingEvent::Done {
        stats: core::stats(&results),
        stopped,
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tauri::ipc::InvokeResponseBody;

    /// A channel that records every event as JSON.
    fn capture<T: serde::Serialize + Clone>() -> (Channel<T>, Arc<Mutex<Vec<String>>>) {
        let log = Arc::new(Mutex::new(Vec::new()));
        let l = log.clone();
        let ch = Channel::new(move |body| {
            if let InvokeResponseBody::Json(s) = body {
                l.lock().unwrap().push(s);
            }
            Ok(())
        });
        (ch, log)
    }

    fn joined(log: &Arc<Mutex<Vec<String>>>) -> String {
        log.lock().unwrap().join("\n")
    }

    fn req(port: u16, proto: Proto, payload: &str, wait_ms: u64) -> SendRequest {
        SendRequest {
            host: "127.0.0.1".into(),
            port,
            proto,
            payload: payload.into(),
            kind: PayloadKind::Text,
            wait_ms,
            connect_timeout_ms: 2000,
        }
    }

    #[tokio::test]
    async fn tcp_send_gets_reply_and_close() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let mut b = [0u8; 64];
            let n = s.read(&mut b).await.unwrap();
            s.write_all(&b[..n]).await.unwrap();
            s.write_all(b"\r\nbye").await.unwrap();
        });
        let (ch, log) = capture();
        let (_tx, mut rx) = watch::channel(false);
        let r = req(port, Proto::Tcp, "PING\\r\\n", 3000);
        send_tcp(
            &r,
            format!("127.0.0.1:{port}").parse().unwrap(),
            b"PING\r\n",
            &mut rx,
            &ch,
        )
        .await
        .unwrap();
        let out = joined(&log);
        assert!(out.contains("\"type\":\"connected\""), "{out}");
        assert!(out.contains("PING\\\\r\\\\n"), "{out}");
        assert!(out.contains("closed the connection"), "{out}");
    }

    #[tokio::test]
    async fn tcp_refused_and_udp_silence() {
        // Grab a free port, then close it so nothing listens.
        let port = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let (ch, _) = capture();
        let (_tx, mut rx) = watch::channel(false);
        let r = req(port, Proto::Tcp, "", 100);
        let e = send_tcp(
            &r,
            format!("127.0.0.1:{port}").parse().unwrap(),
            b"",
            &mut rx,
            &ch,
        )
        .await
        .unwrap_err();
        assert!(e.contains("refused"), "{e}");

        // UDP to a port with nothing behind it: either ICMP unreachable is
        // reported, or silence is called inconclusive. Both are honest.
        let (ch, log) = capture();
        let r = req(port, Proto::Udp, "hi", 300);
        send_udp(
            &r,
            format!("127.0.0.1:{port}").parse().unwrap(),
            b"hi",
            &mut rx,
            &ch,
        )
        .await
        .unwrap();
        let out = joined(&log);
        assert!(
            out.contains("unreachable") || out.contains("inconclusive"),
            "{out}"
        );
    }

    #[tokio::test]
    async fn udp_listener_echo_and_banner() {
        let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = s.local_addr().unwrap();
        let (ch, log) = capture::<ListenEvent>();
        let (tx, mut rx) = watch::channel(false);
        let task =
            tokio::spawn(async move { listen_udp(s, true, b"HELLO".to_vec(), &mut rx, &ch).await });
        let c = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        c.send_to(b"abc", addr).await.unwrap();
        let mut got = Vec::new();
        let mut b = [0u8; 64];
        for _ in 0..2 {
            let (n, _) = tokio::time::timeout(Duration::from_secs(2), c.recv_from(&mut b))
                .await
                .unwrap()
                .unwrap();
            got.push(b[..n].to_vec());
        }
        assert!(got.contains(&b"abc".to_vec()) && got.contains(&b"HELLO".to_vec()));
        tx.send(true).unwrap();
        task.await.unwrap();
        assert!(joined(&log).contains("\"type\":\"data\""));
    }

    #[tokio::test]
    async fn tcp_listener_reports_lifecycle() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let (ch, log) = capture::<ListenEvent>();
        let (tx, mut rx) = watch::channel(false);
        let task =
            tokio::spawn(async move { listen_tcp(l, false, Vec::new(), &mut rx, &ch).await });
        let mut c = TcpStream::connect(addr).await.unwrap();
        c.write_all(b"hello").await.unwrap();
        drop(c);
        tokio::time::sleep(Duration::from_millis(200)).await;
        tx.send(true).unwrap();
        task.await.unwrap();
        let out = joined(&log);
        assert!(
            out.contains("\"type\":\"accepted\"")
                && out.contains("hello")
                && out.contains("closed by peer"),
            "{out}"
        );
    }

    #[tokio::test]
    async fn payload_errors_surface() {
        assert!(core::parse_payload("\\q", PayloadKind::Text).is_err());
        assert!(resolve("", 80).await.is_err());
        assert_eq!(resolve("[::1]", 80).await.unwrap().to_string(), "[::1]:80");
    }
}
