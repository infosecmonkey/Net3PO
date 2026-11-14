//! Tauri commands for Wake-on-LAN: list interfaces, send magic packets over
//! UDP from a chosen interface, and an optional, cancellable TCP check that
//! reports when the target starts answering. No privileges are needed: the
//! packet is a normal UDP datagram, sent with SO_BROADCAST.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use socket2::{Domain, Protocol, Socket, Type};
use tauri::State;
use tauri::ipc::Channel;
use tokio::net::{TcpSocket, UdpSocket};

use super::core::{self, DeliveryKind, Destination};

/// Host name resolution budget.
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(5);
/// Gap between repeated magic packets.
const REPEAT_GAP: Duration = Duration::from_millis(100);
/// Longest reachability wait the UI may ask for.
const MAX_CHECK_SECS: u64 = 600;
/// Time between reachability rounds, and the per-port connect timeout.
const CHECK_INTERVAL: Duration = Duration::from_secs(2);
const CONNECT_TIMEOUT: Duration = Duration::from_millis(1500);

/// Running reachability checks, by id, so they can be cancelled.
#[derive(Default)]
pub struct WolRegistry {
    inner: Mutex<HashMap<u32, Arc<AtomicBool>>>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WolInterface {
    pub name: String,
    pub ip: String,
    pub prefix: u8,
    /// Subnet-directed broadcast address for this interface.
    pub broadcast: String,
}

fn ipv4_interfaces() -> Vec<if_addrs::Interface> {
    if_addrs::get_if_addrs()
        .unwrap_or_default()
        .into_iter()
        .filter(|i| !i.is_loopback() && matches!(i.addr, if_addrs::IfAddr::V4(_)))
        .collect()
}

/// IPv4, non-loopback interfaces with their broadcast addresses.
#[tauri::command]
pub fn wol_interfaces() -> Vec<WolInterface> {
    let mut list: Vec<WolInterface> = ipv4_interfaces()
        .into_iter()
        .filter_map(|i| match i.addr {
            if_addrs::IfAddr::V4(v4) => Some(WolInterface {
                name: i.name,
                ip: v4.ip.to_string(),
                prefix: v4.prefixlen,
                broadcast: core::directed_broadcast(v4.ip, v4.prefixlen).to_string(),
            }),
            if_addrs::IfAddr::V6(_) => None,
        })
        .collect();
    list.sort_by(|a, b| a.name.cmp(&b.name));
    list
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WolRequest {
    pub mac: String,
    pub destination: String,
    pub port: u32,
    /// Interface name; empty lets the OS route it.
    #[serde(default)]
    pub interface: String,
    pub repeats: u32,
    /// Optional SecureOn password.
    #[serde(default)]
    pub password: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WolSendResult {
    pub mac: String,
    /// Address the packets were sent to (resolved if a name was given).
    pub destination: String,
    pub port: u16,
    pub delivery: DeliveryKind,
    pub packets: u8,
    pub bytes: usize,
    /// Local address the OS used, when known.
    pub source: Option<String>,
    pub interface: String,
    pub sent_at_ms: u64,
    pub warnings: Vec<String>,
}

/// Send magic packets. Success means the OS accepted them for sending; it
/// says nothing about whether the target woke up.
#[tauri::command]
pub async fn wol_send(request: WolRequest) -> Result<WolSendResult, String> {
    let mac = core::parse_mac(&request.mac).map_err(|e| e.to_string())?;
    let password = core::parse_password(&request.password).map_err(|e| e.to_string())?;
    let port = core::validate_port(request.port).map_err(|e| e.to_string())?;
    let repeats = core::validate_repeats(request.repeats).map_err(|e| e.to_string())?;
    let dest = match core::parse_destination(&request.destination).map_err(|e| e.to_string())? {
        Destination::Ip(ip) => ip,
        Destination::Host(name) => resolve_v4(&name).await?,
    };

    let ifs = ipv4_interfaces();
    let local: Vec<(Ipv4Addr, u8)> = ifs
        .iter()
        .filter_map(|i| match &i.addr {
            if_addrs::IfAddr::V4(v4) => Some((v4.ip, v4.prefixlen)),
            _ => None,
        })
        .collect();
    let delivery = core::classify(dest, &local);

    let mut warnings = Vec::new();
    let chosen = request.interface.trim();
    let socket = open_socket(chosen, &ifs, &mut warnings)?;
    let packet = core::magic_packet(&mac, &password);
    let target = SocketAddr::new(IpAddr::V4(dest), port);
    for n in 0..repeats {
        if n > 0 {
            tokio::time::sleep(REPEAT_GAP).await;
        }
        socket
            .send_to(&packet, target)
            .await
            .map_err(|e| send_error(&e, dest, delivery))?;
    }
    let source = socket.local_addr().ok().map(|a| a.ip().to_string());

    Ok(WolSendResult {
        mac: core::format_mac(&mac),
        destination: dest.to_string(),
        port,
        delivery,
        packets: repeats,
        bytes: packet.len(),
        source: source.filter(|s| s != "0.0.0.0"),
        interface: if chosen.is_empty() {
            "OS default".into()
        } else {
            chosen.to_string()
        },
        sent_at_ms: unix_ms(),
        warnings,
    })
}

async fn resolve_v4(name: &str) -> Result<Ipv4Addr, String> {
    let lookup = tokio::time::timeout(RESOLVE_TIMEOUT, tokio::net::lookup_host((name, 0u16)))
        .await
        .map_err(|_| format!("resolving {name} timed out"))?
        .map_err(|e| format!("could not resolve {name}: {e}"))?;
    lookup
        .filter_map(|a| match a.ip() {
            IpAddr::V4(v4) => Some(v4),
            IpAddr::V6(_) => None,
        })
        .next()
        .ok_or_else(|| format!("{name} has no IPv4 address"))
}

/// A broadcast-capable UDP socket, bound to the chosen interface's address
/// (which sets the source IP on every OS without privileges).
fn open_socket(
    name: &str,
    ifs: &[if_addrs::Interface],
    warnings: &mut Vec<String>,
) -> Result<UdpSocket, String> {
    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
        .map_err(|e| format!("could not open a UDP socket: {e}"))?;
    sock.set_broadcast(true)
        .map_err(|e| format!("could not enable broadcast: {e}"))?;
    let mut bind_ip = Ipv4Addr::UNSPECIFIED;
    if !name.is_empty() {
        match ifs.iter().find(|i| i.name == name) {
            Some(iface) => {
                if let if_addrs::IfAddr::V4(v4) = &iface.addr {
                    bind_ip = v4.ip;
                }
                pin_interface(&sock, iface, warnings);
            }
            None => warnings.push(format!(
                "interface {name} not found; the OS chose the route"
            )),
        }
    }
    sock.bind(&SocketAddr::new(IpAddr::V4(bind_ip), 0).into())
        .map_err(|e| format!("could not bind the UDP socket to {bind_ip}: {e}"))?;
    sock.set_nonblocking(true)
        .map_err(|e| format!("socket setup failed: {e}"))?;
    UdpSocket::from_std(sock.into()).map_err(|e| format!("socket setup failed: {e}"))
}

/// Binding to an address picks the source IP, but 255.255.255.255 may still
/// leave by the default interface. Also pin the socket to the device where
/// the OS allows it without privileges.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn pin_interface(sock: &Socket, iface: &if_addrs::Interface, warnings: &mut Vec<String>) {
    let Some(index) = iface.index.and_then(std::num::NonZeroU32::new) else {
        return;
    };
    if let Err(e) = sock.bind_device_by_index_v4(Some(index)) {
        let hint = if cfg!(target_os = "linux") {
            " (pinning to a device needs CAP_NET_RAW on Linux)"
        } else {
            ""
        };
        warnings.push(format!(
            "could not pin to {}: {e}{hint}. The source address is still {}, but \
             255.255.255.255 may leave by the default interface; use the subnet \
             broadcast address instead.",
            iface.name,
            iface.ip()
        ));
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn pin_interface(_sock: &Socket, _iface: &if_addrs::Interface, _warnings: &mut Vec<String>) {}

fn send_error(e: &io::Error, dest: Ipv4Addr, delivery: DeliveryKind) -> String {
    let hint = match (e.kind(), delivery) {
        (io::ErrorKind::PermissionDenied, _) => {
            " The OS or a host firewall refused to send this broadcast."
        }
        (_, DeliveryKind::LimitedBroadcast) => {
            " Pick an interface, or use its subnet broadcast address."
        }
        _ => " Check that the interface is up and has a route to the destination.",
    };
    format!("could not send to {dest}: {e}.{hint}")
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckRequest {
    /// Host to check: the target's own IP or name, not the broadcast address.
    pub host: String,
    /// TCP ports, comma separated; empty uses common defaults.
    #[serde(default)]
    pub ports: String,
    pub timeout_secs: u64,
}

#[derive(Clone, Serialize)]
#[serde(
    tag = "type",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum CheckEvent {
    Started {
        host: String,
        ports: Vec<u16>,
    },
    /// One round of connection attempts found nothing yet.
    Waiting {
        elapsed_ms: u64,
    },
    /// The host answered: `open` (port accepted) or `refused` (port closed,
    /// but the host's stack replied, so it is up).
    Up {
        port: u16,
        answer: String,
        elapsed_ms: u64,
    },
    Done {
        reachable: bool,
        cancelled: bool,
        elapsed_ms: u64,
    },
}

/// Poll TCP ports on the target until one answers, the timeout passes or the
/// check is cancelled.
#[tauri::command]
pub async fn wol_check(
    registry: State<'_, WolRegistry>,
    run_id: u32,
    request: CheckRequest,
    on_event: Channel<CheckEvent>,
) -> Result<(), String> {
    let ports = core::parse_check_ports(&request.ports).map_err(|e| e.to_string())?;
    let ip = match core::parse_destination(&request.host).map_err(|e| e.to_string())? {
        Destination::Ip(ip) => ip,
        Destination::Host(name) => resolve_v4(&name).await?,
    };
    if ip == Ipv4Addr::BROADCAST || ip.is_multicast() || ip.is_unspecified() {
        return Err("check the target's own address, not a broadcast address".into());
    }
    let limit = Duration::from_secs(request.timeout_secs.clamp(5, MAX_CHECK_SECS));

    let cancel = Arc::new(AtomicBool::new(false));
    registry
        .inner
        .lock()
        .unwrap()
        .insert(run_id, cancel.clone());
    let _ = on_event.send(CheckEvent::Started {
        host: ip.to_string(),
        ports: ports.clone(),
    });

    let start = Instant::now();
    let elapsed = || start.elapsed().as_millis() as u64;
    let mut reachable = false;
    while start.elapsed() < limit && !cancel.load(Ordering::Relaxed) {
        let round = Instant::now();
        let attempts = ports.iter().map(|&p| probe(ip, p));
        if let Some((port, answer)) = futures_first(attempts).await {
            let _ = on_event.send(CheckEvent::Up {
                port,
                answer: answer.into(),
                elapsed_ms: elapsed(),
            });
            reachable = true;
            break;
        }
        let _ = on_event.send(CheckEvent::Waiting {
            elapsed_ms: elapsed(),
        });
        // Sleep out the rest of the interval in short steps so Stop is quick.
        while round.elapsed() < CHECK_INTERVAL
            && start.elapsed() < limit
            && !cancel.load(Ordering::Relaxed)
        {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    registry.inner.lock().unwrap().remove(&run_id);
    let _ = on_event.send(CheckEvent::Done {
        reachable,
        cancelled: cancel.load(Ordering::Relaxed),
        elapsed_ms: elapsed(),
    });
    Ok(())
}

/// Run all port probes concurrently; return the first that shows the host up.
async fn futures_first<F>(attempts: impl Iterator<Item = F>) -> Option<(u16, &'static str)>
where
    F: std::future::Future<Output = Option<(u16, &'static str)>> + Send + 'static,
{
    let mut set = tokio::task::JoinSet::new();
    for a in attempts {
        set.spawn(a);
    }
    while let Some(res) = set.join_next().await {
        if let Ok(Some(hit)) = res {
            set.abort_all();
            return Some(hit);
        }
    }
    None
}

/// One TCP connect. Accepted or refused both prove the host is up; timeouts
/// and unreachable errors do not.
async fn probe(ip: Ipv4Addr, port: u16) -> Option<(u16, &'static str)> {
    let attempt = async {
        let socket = TcpSocket::new_v4()?;
        #[cfg(windows)]
        crate::tools::port_scanner::commands::fast_refusal(&socket);
        socket.connect(SocketAddr::new(IpAddr::V4(ip), port)).await
    };
    match tokio::time::timeout(CONNECT_TIMEOUT, attempt).await {
        Ok(Ok(_)) => Some((port, "open")),
        Ok(Err(e)) if e.kind() == io::ErrorKind::ConnectionRefused => Some((port, "refused")),
        _ => None,
    }
}

/// Cancel a running reachability check.
#[tauri::command]
pub fn wol_stop(registry: State<'_, WolRegistry>, run_id: u32) {
    if let Some(flag) = registry.inner.lock().unwrap().get(&run_id) {
        flag.store(true, Ordering::Relaxed);
    }
}

fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn sends_magic_packet_to_a_local_listener() {
        let rx = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = rx.local_addr().unwrap().port();
        let res = wol_send(WolRequest {
            mac: "02:11:22:33:44:55".into(),
            destination: "127.0.0.1".into(),
            port: u32::from(port),
            interface: String::new(),
            repeats: 2,
            password: "1.2.3.4".into(),
        })
        .await
        .unwrap();
        assert_eq!(res.packets, 2);
        assert_eq!(res.bytes, core::MAGIC_LEN + 4);
        assert_eq!(res.delivery, DeliveryKind::Unicast);
        let mut buf = [0u8; 256];
        for _ in 0..2 {
            let (n, _) = tokio::time::timeout(Duration::from_secs(2), rx.recv_from(&mut buf))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                &buf[..n],
                core::magic_packet(&[2, 0x11, 0x22, 0x33, 0x44, 0x55], &[1, 2, 3, 4])
            );
        }
    }

    #[tokio::test]
    async fn bad_input_is_rejected_before_sending() {
        let req = |mac: &str, dest: &str, port: u32| WolRequest {
            mac: mac.into(),
            destination: dest.into(),
            port,
            interface: String::new(),
            repeats: 1,
            password: String::new(),
        };
        assert!(wol_send(req("zz", "127.0.0.1", 9)).await.is_err());
        assert!(
            wol_send(req("02:11:22:33:44:55", "999.1.1.1", 9))
                .await
                .is_err()
        );
        assert!(
            wol_send(req("02:11:22:33:44:55", "127.0.0.1", 0))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn probe_sees_open_and_refused_ports_as_up() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let open = listener.local_addr().unwrap().port();
        assert_eq!(probe(Ipv4Addr::LOCALHOST, open).await, Some((open, "open")));

        let tmp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let closed = tmp.local_addr().unwrap().port();
        drop(tmp);
        assert_eq!(
            probe(Ipv4Addr::LOCALHOST, closed).await,
            Some((closed, "refused"))
        );
    }
}
