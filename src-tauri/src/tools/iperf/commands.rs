//! Tauri commands for the throughput tester. Runs the user's own iperf3
//! (never bundled), streams its results to the panel, and stops it on
//! request or when a client test overruns.

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::Serialize;
use tauri::State;
use tauri::ipc::Channel;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::watch;

use super::core::{
    self, Chunk, ClientOpts, Parsed, Point, Reader, ServerOpts, Summary, TestInfo, Version,
};

/// Running iperf3 processes by run id; sending `true` stops one.
#[derive(Default)]
pub struct IperfRegistry {
    inner: Arc<Mutex<HashMap<u32, watch::Sender<bool>>>>,
}

/// An iperf3 binary that answered `--version`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Detected {
    pub path: String,
    pub version: String,
    pub json_stream: bool,
    pub bidir: bool,
}

#[derive(Clone, Serialize)]
#[serde(
    tag = "type",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum IperfEvent {
    /// The process started; `command` is shown for transparency.
    Started {
        command: String,
        live: bool,
    },
    /// A test began (in server mode, once per client).
    TestStart {
        info: TestInfo,
    },
    Interval {
        points: Vec<Point>,
    },
    Result {
        summary: Summary,
    },
    /// A non-JSON line from iperf3 (warnings, server messages).
    Log {
        line: String,
    },
    Error {
        message: String,
    },
    /// The process ended.
    Done {
        cancelled: bool,
        timed_out: bool,
    },
}

fn no_window(cmd: &mut Command) {
    #[cfg(windows)]
    {
        // CREATE_NO_WINDOW: no console window flashes up.
        cmd.creation_flags(0x0800_0000);
    }
    #[cfg(not(windows))]
    let _ = cmd;
}

/// Places iperf3 is commonly installed. GUI apps on macOS do not inherit the
/// shell's PATH, so Homebrew and MacPorts locations are listed explicitly.
fn candidates() -> Vec<String> {
    let mut v = vec![
        if cfg!(windows) {
            "iperf3.exe"
        } else {
            "iperf3"
        }
        .to_string(),
    ];
    if cfg!(target_os = "macos") {
        v.extend(
            [
                "/opt/homebrew/bin/iperf3",
                "/usr/local/bin/iperf3",
                "/opt/local/bin/iperf3",
            ]
            .map(String::from),
        );
    } else if cfg!(target_os = "linux") {
        v.extend(
            [
                "/usr/bin/iperf3",
                "/usr/local/bin/iperf3",
                "/snap/bin/iperf3",
            ]
            .map(String::from),
        );
    }
    v
}

/// Run `<path> --version` and parse it.
async fn probe(path: &str) -> Result<Version, String> {
    let mut cmd = Command::new(path);
    cmd.arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    no_window(&mut cmd);
    let out = tokio::time::timeout(Duration::from_secs(5), cmd.output())
        .await
        .map_err(|_| format!("{path}: no answer to --version"))?
        .map_err(|e| format!("{path}: {e}"))?;
    let text = String::from_utf8_lossy(&out.stdout[..out.stdout.len().min(4096)]).to_string()
        + &String::from_utf8_lossy(&out.stderr[..out.stderr.len().min(4096)]);
    core::parse_version(&text).ok_or_else(|| {
        let first = text.lines().next().unwrap_or("").trim();
        if first.starts_with("iperf version 2") || first.starts_with("iperf 2") {
            format!("{path} is iperf 2, which is not compatible; install iperf3")
        } else {
            format!("{path} does not look like iperf3")
        }
    })
}

/// Find iperf3: the user's chosen path if given, else the usual places.
#[tauri::command]
pub async fn iperf_detect(path: Option<String>) -> Result<Detected, String> {
    let list = match path.as_deref().map(str::trim).filter(|p| !p.is_empty()) {
        Some(p) => vec![p.to_string()],
        None => candidates(),
    };
    let mut errors = Vec::new();
    for p in &list {
        match probe(p).await {
            Ok(v) => {
                return Ok(Detected {
                    path: p.clone(),
                    version: v.to_string(),
                    json_stream: v.json_stream(),
                    bidir: v.bidir(),
                });
            }
            Err(e) => errors.push(e),
        }
    }
    if path.is_some() {
        return Err(errors.join("; "));
    }
    Err("iperf3 was not found. Install it (macOS: brew install iperf3; Debian/Ubuntu: sudo apt install iperf3; RHEL/Fedora: sudo dnf install iperf3; Windows: download a build and choose iperf3.exe) or choose its location.".into())
}

/// Start a client test.
#[tauri::command]
pub async fn iperf_client(
    registry: State<'_, IperfRegistry>,
    run_id: u32,
    path: String,
    opts: ClientOpts,
    on_event: Channel<IperfEvent>,
) -> Result<(), String> {
    let v = probe(&path).await?;
    let args = core::client_args(&opts, &v).map_err(|e| e.to_string())?;
    let deadline = Duration::from_secs(core::client_deadline_secs(&opts));
    let emit = move |e: IperfEvent| {
        let _ = on_event.send(e);
    };
    run(
        &registry,
        run_id,
        &path,
        args,
        v.json_stream(),
        Some(deadline),
        emit,
    )
    .await
}

/// Start iperf3 in server mode; runs until stopped (or after one test with
/// "one test only").
#[tauri::command]
pub async fn iperf_server(
    registry: State<'_, IperfRegistry>,
    run_id: u32,
    path: String,
    opts: ServerOpts,
    on_event: Channel<IperfEvent>,
) -> Result<(), String> {
    let v = probe(&path).await?;
    let args = core::server_args(&opts, &v).map_err(|e| e.to_string())?;
    let emit = move |e: IperfEvent| {
        let _ = on_event.send(e);
    };
    run(&registry, run_id, &path, args, v.json_stream(), None, emit).await
}

/// Stop a running client test or server.
#[tauri::command]
pub fn iperf_stop(registry: State<'_, IperfRegistry>, run_id: u32) {
    if let Some(tx) = registry
        .inner
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .get(&run_id)
    {
        let _ = tx.send(true);
    }
}

fn emit_parsed<F: Fn(IperfEvent)>(emit: &F, items: Vec<Parsed>) {
    for p in items {
        emit(match p {
            Parsed::Start(info) => IperfEvent::TestStart { info },
            Parsed::Interval(points) => IperfEvent::Interval { points },
            Parsed::End(summary) => IperfEvent::Result { summary },
            Parsed::Error(message) => IperfEvent::Error { message },
        });
    }
}

async fn run<F>(
    registry: &IperfRegistry,
    run_id: u32,
    path: &str,
    args: Vec<String>,
    live: bool,
    deadline: Option<Duration>,
    emit: F,
) -> Result<(), String>
where
    F: Fn(IperfEvent) + Clone + Send + 'static,
{
    let mut cmd = Command::new(PathBuf::from(path));
    cmd.args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    no_window(&mut cmd);
    let mut child = cmd
        .spawn()
        .map_err(|e| format!("could not start iperf3: {e}"))?;
    let mut stdout = child.stdout.take().ok_or("no output pipe")?;
    let stderr = child.stderr.take().ok_or("no error pipe")?;

    let (tx, mut rx) = watch::channel(false);
    let reg = registry.inner.clone();
    reg.lock()
        .unwrap_or_else(|p| p.into_inner())
        .insert(run_id, tx);
    emit(IperfEvent::Started {
        command: format!("iperf3 {}", args.join(" ")),
        live,
    });

    // stderr: plain lines (iperf3 errors in -J mode also land in the JSON).
    let err_emit = emit.clone();
    let err_task = tokio::spawn(async move {
        let mut lines = BufReader::new(stderr.take(1024 * 1024)).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            let line = line.trim();
            if !line.is_empty() {
                err_emit(IperfEvent::Log {
                    line: line.chars().take(500).collect(),
                });
            }
        }
    });

    let mut reader = Reader::default();
    let mut buf = vec![0u8; 64 * 1024];
    let sleep = tokio::time::sleep(deadline.unwrap_or(Duration::from_secs(365 * 86_400)));
    tokio::pin!(sleep);
    let (mut cancelled, mut timed_out) = (false, false);
    loop {
        tokio::select! {
            r = stdout.read(&mut buf) => {
                match r {
                    Ok(0) | Err(_) => break,
                    Ok(n) => match reader.push(&buf[..n]) {
                        Ok(chunks) => {
                            for c in chunks {
                                match c {
                                    Chunk::Json(v) => emit_parsed(&emit, core::parse_value(&v)),
                                    Chunk::Text(line) => emit(IperfEvent::Log { line }),
                                }
                            }
                        }
                        Err(e) => {
                            emit(IperfEvent::Error { message: e });
                            break;
                        }
                    },
                }
            }
            _ = rx.changed() => {
                cancelled = true;
                break;
            }
            _ = &mut sleep, if deadline.is_some() => {
                timed_out = true;
                break;
            }
        }
    }
    if cancelled || timed_out {
        let _ = child.start_kill();
    }
    if let Some(rest) = reader.finish() {
        emit(IperfEvent::Log { line: rest });
    }
    let _ = tokio::time::timeout(Duration::from_secs(5), child.wait()).await;
    let _ = tokio::time::timeout(Duration::from_secs(2), err_task).await;
    if timed_out {
        emit(IperfEvent::Error {
            message: "stopped: the test ran past its expected end (duration plus 30 s)".into(),
        });
    }
    reg.lock()
        .unwrap_or_else(|p| p.into_inner())
        .remove(&run_id);
    emit(IperfEvent::Done {
        cancelled,
        timed_out,
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn probe_rejects_missing_and_non_iperf() {
        assert!(probe("net3po-no-such-iperf3").await.is_err());
        #[cfg(unix)]
        {
            let e = probe("/bin/echo").await.unwrap_err();
            assert!(e.contains("does not look like iperf3"), "{e}");
        }
    }

    #[tokio::test]
    async fn detect_with_bad_path_names_it() {
        let e = iperf_detect(Some("net3po-no-such-iperf3".into()))
            .await
            .unwrap_err();
        assert!(e.contains("net3po-no-such-iperf3"), "{e}");
    }
    /// Runs the installed iperf3 as server and client on localhost. Skipped
    /// when iperf3 is not installed (CI runners do not have it).
    #[tokio::test]
    async fn live_localhost_tcp_and_udp() {
        let Ok(found) = iperf_detect(None).await else {
            eprintln!("iperf3 not installed; skipping");
            return;
        };
        let port = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        let reg = Arc::new(IperfRegistry::default());
        let server_events = Arc::new(Mutex::new(Vec::<IperfEvent>::new()));
        let (sreg, sev, spath) = (reg.clone(), server_events.clone(), found.path.clone());
        let server = tokio::spawn(async move {
            let v = probe(&spath).await.unwrap();
            let args = core::server_args(
                &ServerOpts {
                    port: port.into(),
                    one_off: false,
                },
                &v,
            )
            .unwrap();
            let sink = move |e: IperfEvent| sev.lock().unwrap().push(e);
            run(&sreg, 1, &spath, args, v.json_stream(), None, sink).await
        });
        tokio::time::sleep(Duration::from_millis(500)).await;

        let v = probe(&found.path).await.unwrap();
        for (protocol, direction) in [
            (core::Protocol::Tcp, core::Direction::Upload),
            (core::Protocol::Tcp, core::Direction::Download),
            (core::Protocol::Udp, core::Direction::Upload),
        ] {
            let opts = ClientOpts {
                host: "127.0.0.1".into(),
                port: port.into(),
                protocol,
                direction,
                duration: 2,
                parallel: 1,
                bitrate: if protocol == core::Protocol::Udp {
                    "10M".into()
                } else {
                    String::new()
                },
                omit: 0,
                family: core::Family::Auto,
            };
            let events = Arc::new(Mutex::new(Vec::<IperfEvent>::new()));
            let ev = events.clone();
            let sink = move |e: IperfEvent| ev.lock().unwrap().push(e);
            let args = core::client_args(&opts, &v).unwrap();
            run(
                &reg,
                2,
                &found.path,
                args,
                v.json_stream(),
                Some(Duration::from_secs(40)),
                sink,
            )
            .await
            .unwrap();
            let events = events.lock().unwrap();
            let intervals = events
                .iter()
                .filter(|e| matches!(e, IperfEvent::Interval { .. }))
                .count();
            assert!(
                intervals >= 2,
                "{protocol:?} {direction:?}: {intervals} intervals"
            );
            let summary = events.iter().find_map(|e| match e {
                IperfEvent::Result { summary } => Some(summary.clone()),
                _ => None,
            });
            let s = summary.unwrap_or_else(|| panic!("{protocol:?} {direction:?}: no result"));
            let d = &s.directions[0];
            assert_eq!(d.local_sends, direction == core::Direction::Upload);
            assert!(d.received_bps.unwrap_or(0.0) > 1e6, "{d:?}");
            if protocol == core::Protocol::Udp {
                assert!(d.jitter_ms.is_some() && d.packets.unwrap_or(0) > 0);
            }
            assert!(!events.iter().any(|e| matches!(e, IperfEvent::Error { .. })));
            assert!(matches!(
                events.last(),
                Some(IperfEvent::Done {
                    cancelled: false,
                    timed_out: false
                })
            ));
        }

        // Older iperf3 (before 3.17) has no --json-stream: the same test in
        // -J mode must give the same shape of results, all at the end.
        let opts = ClientOpts {
            host: "127.0.0.1".into(),
            port: port.into(),
            protocol: core::Protocol::Tcp,
            direction: core::Direction::Both,
            duration: 2,
            parallel: 2,
            bitrate: String::new(),
            omit: 0,
            family: core::Family::Auto,
        };
        let mut args = core::client_args(&opts, &v).unwrap();
        for a in args.iter_mut() {
            if a == "--json-stream" {
                *a = "-J".into();
            }
        }
        let events = Arc::new(Mutex::new(Vec::<IperfEvent>::new()));
        let ev = events.clone();
        let sink = move |e: IperfEvent| ev.lock().unwrap().push(e);
        run(
            &reg,
            4,
            &found.path,
            args,
            false,
            Some(Duration::from_secs(40)),
            sink,
        )
        .await
        .unwrap();
        {
            let events = events.lock().unwrap();
            assert!(events.iter().any(
                |e| matches!(e, IperfEvent::TestStart { info } if info.bidir && info.streams == 2)
            ));
            let pts: Vec<_> = events
                .iter()
                .filter_map(|e| match e {
                    IperfEvent::Interval { points } => Some(points.len()),
                    _ => None,
                })
                .collect();
            assert!(pts.len() >= 2 && pts.iter().all(|&n| n == 2), "{pts:?}");
            let s = events.iter().find_map(|e| match e {
                IperfEvent::Result { summary } => Some(summary.clone()),
                _ => None,
            });
            assert_eq!(s.expect("-J result").directions.len(), 2);
        }

        // Stop the server and check it reported each test.
        if let Some(tx) = reg.inner.lock().unwrap().get(&1) {
            let _ = tx.send(true);
        }
        server.await.unwrap().unwrap();
        let sev = server_events.lock().unwrap();
        let results = sev
            .iter()
            .filter(|e| matches!(e, IperfEvent::Result { .. }))
            .count();
        assert_eq!(results, 4, "server saw {results} results");
        assert!(matches!(
            sev.last(),
            Some(IperfEvent::Done {
                cancelled: true,
                ..
            })
        ));
    }

    #[tokio::test]
    async fn refused_connection_is_an_error_event() {
        let Ok(found) = iperf_detect(None).await else {
            return;
        };
        let v = probe(&found.path).await.unwrap();
        let port = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        let opts = ClientOpts {
            host: "127.0.0.1".into(),
            port: port.into(),
            protocol: core::Protocol::Tcp,
            direction: core::Direction::Upload,
            duration: 1,
            parallel: 1,
            bitrate: String::new(),
            omit: 0,
            family: core::Family::Auto,
        };
        let events = Arc::new(Mutex::new(Vec::<IperfEvent>::new()));
        let ev = events.clone();
        let sink = move |e: IperfEvent| ev.lock().unwrap().push(e);
        let reg = IperfRegistry::default();
        let args = core::client_args(&opts, &v).unwrap();
        run(
            &reg,
            3,
            &found.path,
            args,
            v.json_stream(),
            Some(Duration::from_secs(20)),
            sink,
        )
        .await
        .unwrap();
        let events = events.lock().unwrap();
        assert!(
            events
                .iter()
                .any(|e| matches!(e, IperfEvent::Error { message } if message.contains("refused"))),
            "no refused error"
        );
    }
}
