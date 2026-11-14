//! Tauri command for the NTP checker. Each sample uses a fresh UDP socket
//! and a bounded wait; servers are queried in parallel.

use std::net::SocketAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tauri::ipc::Channel;
use tokio::net::{UdpSocket, lookup_host};

use super::core::{self, Summary};

const MAX_SERVERS: usize = 10;
const MAX_SAMPLES: u8 = 10;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NtpRequest {
    pub servers: Vec<String>,
    pub samples: u8,
    pub interval_ms: u64,
    pub timeout_ms: u64,
}

#[derive(Clone, Serialize)]
#[serde(
    tag = "type",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum NtpEvent {
    Resolved {
        server: String,
        addr: String,
    },
    Sample {
        server: String,
        seq: u8,
        at_ms: i64,
        offset_ms: Option<f64>,
        delay_ms: Option<f64>,
        stratum: Option<u8>,
        ref_id: String,
        version: Option<u8>,
        leap: Option<u8>,
        precision: Option<i8>,
        root_delay_ms: Option<i64>,
        root_dispersion_ms: Option<i64>,
        error: Option<String>,
    },
    Done {
        server: String,
        summary: Summary,
        error: Option<String>,
    },
}

fn now_ns() -> i128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as i128)
        .unwrap_or(0)
}

async fn resolve(s: &str) -> Result<SocketAddr, String> {
    let s = s.trim();
    let (host, port) = match s.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') || h.starts_with('[') => (
            h.trim_matches(['[', ']']),
            p.parse::<u16>().map_err(|_| format!("bad port in {s}"))?,
        ),
        _ => (s.trim_matches(['[', ']']), 123),
    };
    if host.is_empty() {
        return Err("empty server name".into());
    }
    let addrs: Vec<SocketAddr> =
        tokio::time::timeout(Duration::from_secs(5), lookup_host((host, port)))
            .await
            .map_err(|_| format!("resolving {host} timed out"))?
            .map_err(|e| format!("could not resolve {host}: {e}"))?
            .take(8)
            .collect();
    addrs
        .iter()
        .find(|a| a.is_ipv4())
        .or(addrs.first())
        .copied()
        .ok_or_else(|| format!("{host} has no addresses"))
}

/// One query. Returns (reply, offset_ns, delay_ns).
async fn query(addr: SocketAddr, timeout: Duration) -> Result<(core::Reply, i128, i128), String> {
    let bind: SocketAddr = if addr.is_ipv4() {
        "0.0.0.0:0".parse().unwrap_or(addr)
    } else {
        "[::]:0".parse().unwrap_or(addr)
    };
    let sock = UdpSocket::bind(bind)
        .await
        .map_err(|e| format!("socket: {e}"))?;
    sock.connect(addr)
        .await
        .map_err(|e| format!("connect: {e}"))?;
    let t1 = now_ns();
    let sent = core::to_ntp(t1);
    sock.send(&core::request(sent))
        .await
        .map_err(|e| format!("send: {e}"))?;
    let mut buf = [0u8; 512];
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let n = match tokio::time::timeout_at(deadline, sock.recv(&mut buf)).await {
            Ok(Ok(n)) => n,
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused || e.kind() == std::io::ErrorKind::ConnectionReset => {
                return Err("ICMP port unreachable: nothing answers NTP on that address".into());
            }
            Ok(Err(e)) => return Err(e.to_string()),
            Err(_) => return Err("no reply within the timeout (the server may be down, filtered, or rate-limiting; this alone does not prove which)".into()),
        };
        let t4 = now_ns();
        match core::parse(&buf[..n], sent) {
            Ok(r) => {
                let (o, d) = core::offset_delay(
                    t1,
                    core::from_ntp(r.receive),
                    core::from_ntp(r.transmit),
                    t4,
                );
                return Ok((r, o, d));
            }
            // A stray datagram that does not answer us: keep waiting.
            Err(e) if e.contains("mismatch") => continue,
            Err(e) => return Err(e),
        }
    }
}

async fn check_server(server: String, req: NtpRequest, ev: Channel<NtpEvent>) {
    let addr = match resolve(&server).await {
        Ok(a) => a,
        Err(e) => {
            let _ = ev.send(NtpEvent::Done {
                server,
                summary: core::summarize(0, &[]),
                error: Some(e),
            });
            return;
        }
    };
    let _ = ev.send(NtpEvent::Resolved {
        server: server.clone(),
        addr: addr.to_string(),
    });
    let samples = req.samples.clamp(1, MAX_SAMPLES);
    let timeout = Duration::from_millis(req.timeout_ms.clamp(200, 10_000));
    let interval = Duration::from_millis(req.interval_ms.clamp(200, 10_000));
    let mut answered = Vec::new();
    for seq in 1..=samples {
        let at_ms = (now_ns() / 1_000_000) as i64;
        let ev_sample = match query(addr, timeout).await {
            Ok((r, o, d)) => {
                answered.push((o, d));
                NtpEvent::Sample {
                    server: server.clone(),
                    seq,
                    at_ms,
                    offset_ms: Some(o as f64 / 1e6),
                    delay_ms: Some(d as f64 / 1e6),
                    stratum: Some(r.stratum),
                    ref_id: r.ref_id,
                    version: Some(r.version),
                    leap: Some(r.leap),
                    precision: Some(r.precision),
                    root_delay_ms: Some(r.root_delay_ms),
                    root_dispersion_ms: Some(r.root_dispersion_ms),
                    error: None,
                }
            }
            Err(e) => NtpEvent::Sample {
                server: server.clone(),
                seq,
                at_ms,
                offset_ms: None,
                delay_ms: None,
                stratum: None,
                ref_id: String::new(),
                version: None,
                leap: None,
                precision: None,
                root_delay_ms: None,
                root_dispersion_ms: None,
                error: Some(e),
            },
        };
        let _ = ev.send(ev_sample);
        if seq < samples {
            tokio::time::sleep(interval).await;
        }
    }
    let _ = ev.send(NtpEvent::Done {
        server,
        summary: core::summarize(samples as usize, &answered),
        error: None,
    });
}

/// Query each server `samples` times. Never changes the local clock.
#[tauri::command]
pub async fn ntp_check(req: NtpRequest, on_event: Channel<NtpEvent>) -> Result<(), String> {
    let servers: Vec<String> = req
        .servers
        .iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if servers.is_empty() {
        return Err("add at least one server".into());
    }
    if servers.len() > MAX_SERVERS {
        return Err(format!("at most {MAX_SERVERS} servers"));
    }
    let mut tasks = tokio::task::JoinSet::new();
    for s in servers {
        tasks.spawn(check_server(s, req.clone(), on_event.clone()));
    }
    while tasks.join_next().await.is_some() {}
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tauri::ipc::InvokeResponseBody;

    /// A local fake NTP server that answers with a fixed offset.
    async fn fake_server(offset_ns: i128) -> SocketAddr {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 48];
            while let Ok((n, peer)) = sock.recv_from(&mut buf).await {
                if n < 48 {
                    continue;
                }
                let origin = u64::from_be_bytes(buf[40..48].try_into().unwrap());
                let t = core::to_ntp(now_ns() + offset_ns);
                let mut r = [0u8; 48];
                r[0] = (4 << 3) | 4;
                r[1] = 2;
                r[12..16].copy_from_slice(&[192, 0, 2, 9]);
                r[24..32].copy_from_slice(&origin.to_be_bytes());
                r[32..40].copy_from_slice(&t.to_be_bytes());
                r[40..48].copy_from_slice(&t.to_be_bytes());
                let _ = sock.send_to(&r, peer).await;
            }
        });
        addr
    }

    #[tokio::test]
    async fn measures_offset_against_fake_server() {
        let addr = fake_server(250_000_000).await;
        let (r, o, d) = query(addr, Duration::from_secs(2)).await.unwrap();
        assert_eq!(r.stratum, 2);
        assert_eq!(r.ref_id, "192.0.2.9");
        assert!((o - 250_000_000).abs() < 20_000_000, "offset {o}");
        assert!((0..50_000_000).contains(&d), "delay {d}");
    }

    #[tokio::test]
    async fn streams_events_and_handles_silence() {
        let good = fake_server(-1_500_000_000).await;
        let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let silent_addr = silent.local_addr().unwrap();
        let log = Arc::new(Mutex::new(Vec::new()));
        let l = log.clone();
        let ch: Channel<NtpEvent> = Channel::new(move |b| {
            if let InvokeResponseBody::Json(s) = b {
                l.lock().unwrap().push(s);
            }
            Ok(())
        });
        let req = NtpRequest {
            servers: vec![good.to_string(), silent_addr.to_string()],
            samples: 2,
            interval_ms: 200,
            timeout_ms: 300,
        };
        ntp_check(req, ch).await.unwrap();
        let out = log.lock().unwrap().join("\n");
        assert_eq!(out.matches("\"type\":\"done\"").count(), 2);
        assert!(out.contains("no reply within the timeout"));
        assert!(out.contains("\"answered\":2"));
        drop(silent);
        assert!(resolve("").await.is_err());
        assert_eq!(resolve("192.0.2.1").await.unwrap().port(), 123);
        assert_eq!(resolve("192.0.2.1:1123").await.unwrap().port(), 1123);
    }
}
