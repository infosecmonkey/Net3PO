//! Tauri commands for the syslog server. Binds a UDP and/or TCP listener on a
//! port, streams parsed messages to the UI, and tears down cleanly on stop.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};

use serde::Serialize;
use tauri::State;
use tauri::ipc::Channel;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::watch;

use super::core::{self, SyslogMessage};

/// Tracks running listeners so they can be stopped by id. The value signals
/// shutdown when set to true.
#[derive(Default)]
pub struct SyslogRegistry {
    inner: Arc<Mutex<HashMap<u32, watch::Sender<bool>>>>,
}

#[derive(Clone, Serialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum SyslogEvent {
    Started {
        port: u16,
        udp: bool,
        tcp: bool,
    },
    Message {
        source: String,
        transport: String,
        data: Box<SyslogMessage>,
    },
    Stopped,
}

/// Stop a running listener by id.
#[tauri::command]
pub fn syslog_stop(registry: State<'_, SyslogRegistry>, listener_id: u32) {
    if let Some(tx) = registry.inner.lock().unwrap().get(&listener_id) {
        let _ = tx.send(true);
    }
}

/// Write collected syslog text to a path chosen via the save dialog.
#[tauri::command]
pub fn syslog_save(path: String, contents: String) -> Result<(), String> {
    std::fs::write(&path, contents).map_err(|e| format!("could not write {path}: {e}"))
}

/// Start a listener on `port`. Runs until `syslog_stop` is called with the same
/// id. Binding happens up front so permission or in-use errors surface
/// immediately.
#[tauri::command]
pub async fn syslog_start(
    registry: State<'_, SyslogRegistry>,
    listener_id: u32,
    port: u16,
    udp: bool,
    tcp: bool,
    on_event: Channel<SyslogEvent>,
) -> Result<(), String> {
    if !udp && !tcp {
        return Err("enable at least one of UDP or TCP".to_string());
    }

    let bind = SocketAddr::from((Ipv4Addr::UNSPECIFIED, port));

    // Bind both sockets before spawning so errors are returned to the caller.
    let udp_sock = if udp {
        Some(
            UdpSocket::bind(bind)
                .await
                .map_err(|e| bind_error("UDP", port, e))?,
        )
    } else {
        None
    };
    let tcp_listener = if tcp {
        Some(
            TcpListener::bind(bind)
                .await
                .map_err(|e| bind_error("TCP", port, e))?,
        )
    } else {
        None
    };

    let (tx, rx) = watch::channel(false);
    let reg = registry.inner.clone();
    reg.lock().unwrap().insert(listener_id, tx);

    let _ = on_event.send(SyslogEvent::Started { port, udp, tcp });

    let mut handles = Vec::new();
    if let Some(sock) = udp_sock {
        handles.push(tokio::spawn(udp_loop(sock, rx.clone(), on_event.clone())));
    }
    if let Some(listener) = tcp_listener {
        handles.push(tokio::spawn(tcp_loop(
            listener,
            rx.clone(),
            on_event.clone(),
        )));
    }

    // Wait for the stop signal.
    let mut stop_rx = rx.clone();
    let _ = stop_rx.wait_for(|stopped| *stopped).await;

    for h in handles {
        h.abort();
    }
    reg.lock().unwrap().remove(&listener_id);
    let _ = on_event.send(SyslogEvent::Stopped);
    Ok(())
}

fn bind_error(proto: &str, port: u16, e: std::io::Error) -> String {
    use std::io::ErrorKind::*;
    match e.kind() {
        PermissionDenied => format!(
            "cannot bind {proto} port {port}: permission denied. Ports below 1024 need admin/root; try a port such as 5140."
        ),
        AddrInUse => format!("cannot bind {proto} port {port}: already in use."),
        _ => format!("cannot bind {proto} port {port}: {e}"),
    }
}

async fn udp_loop(sock: UdpSocket, mut rx: watch::Receiver<bool>, on_event: Channel<SyslogEvent>) {
    let mut buf = vec![0u8; 65535];
    loop {
        tokio::select! {
            r = sock.recv_from(&mut buf) => {
                if let Ok((n, src)) = r {
                    let text = String::from_utf8_lossy(&buf[..n]);
                    emit_message(&on_event, &src.to_string(), "UDP", &text);
                }
            }
            _ = rx.changed() => break,
        }
    }
}

async fn tcp_loop(
    listener: TcpListener,
    mut rx: watch::Receiver<bool>,
    on_event: Channel<SyslogEvent>,
) {
    loop {
        tokio::select! {
            a = listener.accept() => {
                if let Ok((stream, src)) = a {
                    tokio::spawn(tcp_conn(stream, src, rx.clone(), on_event.clone()));
                }
            }
            _ = rx.changed() => break,
        }
    }
}

/// Read newline-delimited messages from one TCP connection.
async fn tcp_conn(
    stream: tokio::net::TcpStream,
    src: SocketAddr,
    mut rx: watch::Receiver<bool>,
    on_event: Channel<SyslogEvent>,
) {
    let mut lines = BufReader::new(stream).lines();
    loop {
        tokio::select! {
            line = lines.next_line() => {
                match line {
                    Ok(Some(text)) => emit_message(&on_event, &src.to_string(), "TCP", &text),
                    // EOF or read error: the connection is done.
                    _ => break,
                }
            }
            _ = rx.changed() => break,
        }
    }
}

fn emit_message(on_event: &Channel<SyslogEvent>, source: &str, transport: &str, text: &str) {
    // A single UDP datagram may carry multiple newline-separated messages.
    for line in text.split('\n') {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            continue;
        }
        let _ = on_event.send(SyslogEvent::Message {
            source: source.to_string(),
            transport: transport.to_string(),
            data: Box::new(core::parse(line)),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn udp_receive_and_parse() {
        // Bind a listener on an ephemeral port and send one datagram to it.
        let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = server.local_addr().unwrap();
        let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        client
            .send_to(b"<13>Jan  1 00:00:00 host app: hi there", addr)
            .await
            .unwrap();

        let mut buf = vec![0u8; 1024];
        let (n, _src) = server.recv_from(&mut buf).await.unwrap();
        let msg = core::parse(&String::from_utf8_lossy(&buf[..n]));
        assert_eq!(msg.facility_name.as_deref(), Some("user"));
        assert_eq!(msg.severity_name.as_deref(), Some("notice"));
        assert_eq!(msg.tag.as_deref(), Some("app"));
        assert_eq!(msg.message, "hi there");
    }
}
