//! Tauri commands for the DHCP monitor. Binds UDP 68 with address/port reuse
//! (no packet capture), broadcasts DHCPDISCOVERs with a random client MAC, and
//! streams every server reply it hears, including broadcast replies meant for
//! other clients. Probe mode sends one DISCOVER and listens briefly; monitor
//! mode re-probes on an interval until cancelled.

use std::collections::{HashMap, VecDeque};
use std::hash::{BuildHasher, Hasher};
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use socket2::{Domain, Protocol, Socket, Type};
use tauri::State;
use tauri::ipc::Channel;
use tokio::net::UdpSocket;

use super::core::{self, CLIENT_PORT, MAX_PACKET_LEN, SERVER_PORT, ServerRecord, ServerTracker};

#[derive(Default)]
pub struct DhcpRegistry {
    inner: Arc<Mutex<HashMap<u32, Arc<AtomicBool>>>>,
}

/// How often the receive loop wakes to check for cancel and probe timing.
const TICK: Duration = Duration::from_millis(250);
/// Reply events streamed per second at most; the rest are counted, not sent.
const MAX_EVENTS_PER_SEC: u32 = 50;
/// Transaction ids remembered as ours (monitor mode keeps probing).
const OUR_XIDS: usize = 64;
/// Consecutive receive errors before giving up.
const MAX_RECV_ERRORS: u32 = 100;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct DhcpConfig {
    /// Interface name; empty uses the default route.
    pub interface: String,
    /// Authorized server IPs, comma or whitespace separated.
    pub authorized: String,
    /// "probe" (one DISCOVER) or "monitor" (repeat until stopped).
    pub mode: String,
    /// Probe mode: how long to listen for replies.
    pub listen_secs: u64,
    /// Monitor mode: seconds between DISCOVERs.
    pub interval_secs: u64,
}

impl Default for DhcpConfig {
    fn default() -> Self {
        DhcpConfig {
            interface: String::new(),
            authorized: String::new(),
            mode: "probe".to_string(),
            listen_secs: 5,
            interval_secs: 30,
        }
    }
}

#[derive(Clone, Serialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum DhcpEvent {
    Started {
        interface: String,
    },
    Probe {
        n: u32,
        xid: String,
        client_mac: String,
    },
    Reply {
        record: ServerRecord,
        source: String,
        /// The reply answered one of our DISCOVERs (vs. another client's).
        ours: bool,
    },
    Warning {
        message: String,
    },
    Stopped {
        probes: u32,
        servers: usize,
        error: Option<String>,
    },
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NetInterface {
    pub name: String,
    pub ip: String,
    pub prefix: u8,
}

/// IPv4, non-loopback interfaces for the interface picker.
#[tauri::command]
pub fn dhcp_interfaces() -> Result<Vec<NetInterface>, String> {
    let mut list: Vec<NetInterface> = if_addrs::get_if_addrs()
        .map_err(|e| format!("could not list interfaces: {e}"))?
        .into_iter()
        .filter(|i| !i.is_loopback())
        .filter_map(|i| match i.addr {
            if_addrs::IfAddr::V4(v4) => Some(NetInterface {
                name: i.name,
                ip: v4.ip.to_string(),
                prefix: v4.prefixlen,
            }),
            if_addrs::IfAddr::V6(_) => None,
        })
        .collect();
    list.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(list)
}

/// Stop a running probe or monitor by id.
#[tauri::command]
pub fn dhcp_stop(registry: State<'_, DhcpRegistry>, run_id: u32) {
    if let Some(flag) = registry.inner.lock().unwrap().get(&run_id) {
        flag.store(true, Ordering::Relaxed);
    }
}

/// Probe for DHCP servers (or monitor continuously), streaming replies.
#[tauri::command]
pub async fn dhcp_monitor(
    registry: State<'_, DhcpRegistry>,
    run_id: u32,
    config: DhcpConfig,
    on_event: Channel<DhcpEvent>,
) -> Result<(), String> {
    let authorized = core::parse_authorized(&config.authorized).map_err(|e| e.to_string())?;
    let (socket, iface_label, warnings) = open_socket(config.interface.trim())?;

    let cancel = Arc::new(AtomicBool::new(false));
    let reg = registry.inner.clone();
    reg.lock().unwrap().insert(run_id, cancel.clone());

    let _ = on_event.send(DhcpEvent::Started {
        interface: iface_label,
    });
    for message in warnings {
        let _ = on_event.send(DhcpEvent::Warning { message });
    }

    let mut tracker = ServerTracker::new(authorized);
    let (probes, error) = run_loop(&socket, &config, &mut tracker, &on_event, &cancel).await;

    reg.lock().unwrap().remove(&run_id);
    let _ = on_event.send(DhcpEvent::Stopped {
        probes,
        servers: tracker.len(),
        error,
    });
    Ok(())
}

async fn run_loop(
    socket: &UdpSocket,
    config: &DhcpConfig,
    tracker: &mut ServerTracker,
    events: &Channel<DhcpEvent>,
    cancel: &AtomicBool,
) -> (u32, Option<String>) {
    let monitor = config.mode == "monitor";
    let listen = Duration::from_secs(config.listen_secs.clamp(1, 60));
    let interval = Duration::from_secs(config.interval_secs.clamp(5, 3600));
    let dest = SocketAddr::from((Ipv4Addr::BROADCAST, SERVER_PORT));

    let start = Instant::now();
    let mut next_probe = start;
    let mut probes = 0u32;
    let mut ours: VecDeque<u32> = VecDeque::with_capacity(OUR_XIDS);
    let mut buf = vec![0u8; MAX_PACKET_LEN + 1];
    let mut recv_errors = 0u32;
    let mut window = (Instant::now(), 0u32, 0u64); // (start, sent, dropped)
    let mut cap_warned = false;

    loop {
        if cancel.load(Ordering::Relaxed) {
            return (probes, None);
        }
        let now = Instant::now();
        if !monitor && now.duration_since(start) >= listen {
            return (probes, None);
        }
        if now >= next_probe && (monitor || probes == 0) {
            let seed = random_seed(probes);
            let xid = (seed >> 32) as u32 ^ seed as u32;
            let mac = core::client_mac_from_seed(seed);
            if let Err(e) = socket.send_to(&core::build_discover(xid, &mac), dest).await {
                return (probes, Some(send_error(&e)));
            }
            probes += 1;
            if ours.len() == OUR_XIDS {
                ours.pop_front();
            }
            ours.push_back(xid);
            let _ = events.send(DhcpEvent::Probe {
                n: probes,
                xid: format!("0x{xid:08x}"),
                client_mac: core::format_mac(&mac),
            });
            next_probe = now + interval;
        }

        let (len, src) = match tokio::time::timeout(TICK, socket.recv_from(&mut buf)).await {
            Err(_) => continue,
            Ok(Err(e)) => {
                // Windows reports ICMP port unreachable and oversize datagrams
                // as receive errors; skip them, but stop if it never recovers.
                recv_errors += 1;
                if recv_errors >= MAX_RECV_ERRORS {
                    return (probes, Some(format!("receive failed repeatedly: {e}")));
                }
                continue;
            }
            Ok(Ok(r)) => r,
        };
        recv_errors = 0;
        if len > MAX_PACKET_LEN {
            continue;
        }
        let IpAddr::V4(source) = src.ip() else {
            continue;
        };
        let Some(info) = core::parse_packet(&buf[..len])
            .ok()
            .as_ref()
            .and_then(core::summarize)
        else {
            continue;
        };
        let xid = u32::from_str_radix(info.xid.trim_start_matches("0x"), 16).unwrap_or(0);
        let is_ours = ours.contains(&xid);

        let Some(record) = tracker.record(source, info, unix_ms()) else {
            if !cap_warned {
                cap_warned = true;
                let _ = events.send(DhcpEvent::Warning {
                    message: format!(
                        "more than {} distinct servers seen; ignoring new ones (possible spoofing flood)",
                        core::MAX_SERVERS
                    ),
                });
            }
            continue;
        };

        // Rate-limit the event stream so a flood cannot swamp the UI.
        if window.0.elapsed() >= Duration::from_secs(1) {
            if window.2 > 0 {
                let _ = events.send(DhcpEvent::Warning {
                    message: format!("{} replies not shown (rate limit)", window.2),
                });
            }
            window = (Instant::now(), 0, 0);
        }
        if window.1 >= MAX_EVENTS_PER_SEC {
            window.2 += 1;
            continue;
        }
        window.1 += 1;
        let _ = events.send(DhcpEvent::Reply {
            record,
            source: source.to_string(),
            ours: is_ours,
        });
    }
}

/// Open UDP 68 with reuse and broadcast enabled, optionally pinned to an
/// interface. Returns the socket, a label for the UI, and non-fatal warnings.
fn open_socket(interface: &str) -> Result<(UdpSocket, String, Vec<String>), String> {
    let mut warnings = Vec::new();
    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
        .map_err(|e| format!("could not create socket: {e}"))?;
    sock.set_reuse_address(true)
        .map_err(|e| format!("could not set SO_REUSEADDR: {e}"))?;
    #[cfg(unix)]
    let _ = sock.set_reuse_port(true);
    sock.set_broadcast(true)
        .map_err(|e| format!("could not enable broadcast: {e}"))?;

    let label = if interface.is_empty() {
        "default route".to_string()
    } else {
        bind_interface(&sock, interface, &mut warnings);
        interface.to_string()
    };

    let addr = SocketAddr::from((Ipv4Addr::UNSPECIFIED, CLIENT_PORT));
    sock.bind(&addr.into()).map_err(|e| bind_error(&e))?;
    sock.set_nonblocking(true)
        .map_err(|e| format!("could not set non-blocking: {e}"))?;
    let std_sock: std::net::UdpSocket = sock.into();
    let socket = UdpSocket::from_std(std_sock).map_err(|e| format!("socket setup failed: {e}"))?;
    Ok((socket, label, warnings))
}

/// Pin the socket to an interface where the OS allows it without extra
/// privileges; otherwise fall back to the default route with a warning.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn bind_interface(sock: &Socket, name: &str, warnings: &mut Vec<String>) {
    let index = if_addrs::get_if_addrs()
        .ok()
        .and_then(|list| list.into_iter().find(|i| i.name == name))
        .and_then(|i| i.index)
        .and_then(std::num::NonZeroU32::new);
    let Some(index) = index else {
        warnings.push(format!(
            "interface {name} not found; using the default route"
        ));
        return;
    };
    if let Err(e) = sock.bind_device_by_index_v4(Some(index)) {
        let hint = if cfg!(target_os = "linux") {
            " (binding to an interface needs CAP_NET_RAW on Linux)"
        } else {
            ""
        };
        warnings.push(format!(
            "could not bind to {name}: {e}{hint}; using the default route"
        ));
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn bind_interface(_sock: &Socket, name: &str, warnings: &mut Vec<String>) {
    warnings.push(format!(
        "interface selection is not supported on this OS; probing via the default route, not {name}"
    ));
}

/// Explain a failure to bind UDP 68 in terms of what the user can do.
fn bind_error(e: &io::Error) -> String {
    match e.kind() {
        io::ErrorKind::PermissionDenied => {
            if cfg!(target_os = "linux") {
                let exe = std::env::current_exe()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|_| "<path to omnipacket>".to_string());
                format!(
                    "binding UDP {CLIENT_PORT} needs permission to use ports below 1024. \
                     Grant only that capability to the app binary:\n  \
                     sudo setcap cap_net_bind_service=+ep {exe}\n\
                     or allow unprivileged low ports system-wide:\n  \
                     sudo sysctl net.ipv4.ip_unprivileged_port_start=67"
                )
            } else {
                format!("permission denied binding UDP {CLIENT_PORT}: {e}")
            }
        }
        io::ErrorKind::AddrInUse => format!(
            "UDP {CLIENT_PORT} is held exclusively by another program, usually the OS DHCP \
             client or a local DHCP server. Close it or run the probe from another host."
        ),
        _ => format!("could not bind UDP {CLIENT_PORT}: {e}"),
    }
}

fn send_error(e: &io::Error) -> String {
    format!(
        "could not send the DHCPDISCOVER broadcast: {e}. Check that the interface is up and \
         has an IPv4 address."
    )
}

fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Unpredictable-enough seed for transaction ids and client MACs, from the
/// std hasher's per-process random keys plus time and a counter.
fn random_seed(counter: u32) -> u64 {
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write_u128(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
    );
    h.write_u32(counter);
    h.finish()
}
