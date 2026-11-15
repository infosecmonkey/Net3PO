//! Take a snapshot by running the OS's own read-only commands. Nothing here
//! needs administrator rights. Each command runs with a timeout and an output
//! cap; a command that fails leaves its section empty and records why.

use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::process::Command;

use super::model::{Snapshot, Source};
#[allow(unused_imports)]
use super::parse;

/// Longest any one command may run.
const CMD_TIMEOUT: Duration = Duration::from_secs(30);
/// Most output read from one command.
const MAX_OUTPUT: u64 = 16 * 1024 * 1024;

/// Run a program and return its standard output as text.
async fn run(program: &str, args: &[&str]) -> Result<String, String> {
    let mut cmd = Command::new(program);
    cmd.args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
    #[cfg(windows)]
    {
        // CREATE_NO_WINDOW: no console window flashes up.
        cmd.creation_flags(0x0800_0000);
    }
    let mut child = cmd.spawn().map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => format!("{program} is not installed or not on PATH"),
        _ => format!("could not run {program}: {e}"),
    })?;
    let mut stdout = child
        .stdout
        .take()
        .ok_or("no output pipe")?
        .take(MAX_OUTPUT);
    let mut stderr = child.stderr.take().ok_or("no error pipe")?.take(64 * 1024);
    let work = async {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let (r1, r2) = tokio::join!(stdout.read_to_end(&mut out), stderr.read_to_end(&mut err));
        r1.map_err(|e| e.to_string())?;
        let _ = r2;
        let status = child.wait().await.map_err(|e| e.to_string())?;
        Ok::<_, String>((status, out, err))
    };
    let (status, out, err) = tokio::time::timeout(CMD_TIMEOUT, work)
        .await
        .map_err(|_| {
            format!(
                "{program} did not finish within {} s",
                CMD_TIMEOUT.as_secs()
            )
        })??;
    if !status.success() {
        let msg = String::from_utf8_lossy(&err);
        let msg = msg
            .lines()
            .find(|l| !l.trim().is_empty())
            .unwrap_or("")
            .trim();
        return Err(if msg.is_empty() {
            format!("{program} exited with {status}")
        } else {
            format!("{program}: {msg}")
        });
    }
    Ok(String::from_utf8_lossy(&out).into_owned())
}

/// Record a section's source, and pass the parsed rows through. (Windows
/// collects every section in one call and records sources itself.)
#[cfg_attr(windows, allow(dead_code))]
fn record<T: Default>(
    sources: &mut Vec<Source>,
    section: &str,
    command: &str,
    result: Result<T, String>,
    note: &str,
) -> T {
    match result {
        Ok(v) => {
            sources.push(Source {
                section: section.into(),
                command: command.into(),
                ok: true,
                note: note.into(),
            });
            v
        }
        Err(e) => {
            sources.push(Source {
                section: section.into(),
                command: command.into(),
                ok: false,
                note: e,
            });
            T::default()
        }
    }
}

/// This computer's host name.
fn host_name() -> String {
    #[cfg(unix)]
    {
        let mut buf = [0u8; 256];
        // SAFETY: the buffer is valid for its full length, and gethostname
        // writes at most that many bytes.
        let rc = unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) };
        if rc == 0 {
            let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
            return String::from_utf8_lossy(&buf[..end]).into_owned();
        }
        String::new()
    }
    #[cfg(windows)]
    {
        std::env::var("COMPUTERNAME").unwrap_or_default()
    }
}

/// Collect a snapshot of this computer. Never fails: sections that cannot be
/// read are left empty with the reason in `sources`.
pub async fn take() -> Snapshot {
    let mut s = Snapshot {
        host: host_name(),
        ..Default::default()
    };
    collect_os(&mut s).await;
    s
}

#[cfg(target_os = "macos")]
async fn collect_os(s: &mut Snapshot) {
    s.os = "macOS".into();
    // One `netstat -anv` for both protocols: with `-p tcp` some launch
    // environments get empty output.
    let (ifc, rt, arp, ndp, dns, socks) = tokio::join!(
        run("/sbin/ifconfig", &["-a"]),
        run("/usr/sbin/netstat", &["-rn"]),
        run("/usr/sbin/arp", &["-an"]),
        run("/usr/sbin/ndp", &["-an"]),
        run("/usr/sbin/scutil", &["--dns"]),
        run("/usr/sbin/netstat", &["-anv"]),
    );
    let src = &mut s.sources;
    s.interfaces = record(
        src,
        "Interfaces",
        "ifconfig -a",
        ifc.map(|t| parse::macos_ifconfig(&t)),
        "",
    );
    s.routes = record(
        src,
        "Routes",
        "netstat -rn",
        rt.map(|t| parse::macos_routes(&t)),
        "",
    );
    let mut n = record(
        src,
        "Neighbors",
        "arp -an",
        arp.map(|t| parse::macos_arp(&t)),
        "",
    );
    n.extend(record(
        src,
        "Neighbors",
        "ndp -an",
        ndp.map(|t| parse::macos_ndp(&t)),
        "",
    ));
    s.neighbors = n;
    s.dns = record(
        src,
        "DNS",
        "scutil --dns",
        dns.map(|t| parse::macos_dns(&t)),
        "",
    );
    s.listeners = match socks {
        Ok(t) if parse::macos_has_inet(&t) => record(
            src,
            "Listening ports",
            "netstat -anv",
            Ok(parse::macos_listeners(&t)),
            "",
        ),
        // Some launch contexts get no TCP/UDP rows from netstat at all. lsof
        // still works, but only for the user's own processes.
        other => {
            let why = match other {
                Err(e) => e,
                Ok(_) => "netstat returned no TCP or UDP sockets to this app".into(),
            };
            let lsof = run(
                "/usr/sbin/lsof",
                &["+c", "0", "-nP", "-iTCP", "-sTCP:LISTEN", "-iUDP", "-FpcPn"],
            )
            .await
            .map(|t| parse::macos_lsof(&t));
            let note = format!("{why}; listed from lsof, your own processes only");
            record(
                src,
                "Listening ports",
                "lsof -iTCP -sTCP:LISTEN -iUDP",
                lsof,
                &note,
            )
        }
    };
}

#[cfg(target_os = "linux")]
async fn collect_os(s: &mut Snapshot) {
    s.os = "Linux".into();
    let (addr, rt4, rt6, neigh, ss, rdns, rdom) = tokio::join!(
        run("ip", &["-j", "addr", "show"]),
        run("ip", &["-j", "route", "show"]),
        run("ip", &["-j", "-6", "route", "show"]),
        run("ip", &["-j", "neigh", "show"]),
        run("ss", &["-Hlntup"]),
        run("resolvectl", &["dns"]),
        run("resolvectl", &["domain"]),
    );
    let src = &mut s.sources;
    s.interfaces = record(
        src,
        "Interfaces",
        "ip -j addr show",
        addr.and_then(|t| parse::linux_addrs(&t)),
        "",
    );
    let mut r = record(
        src,
        "Routes",
        "ip -j route show",
        rt4.and_then(|t| parse::linux_routes(&t, "IPv4")),
        "main table",
    );
    r.extend(record(
        src,
        "Routes",
        "ip -j -6 route show",
        rt6.and_then(|t| parse::linux_routes(&t, "IPv6")),
        "main table",
    ));
    s.routes = r;
    s.neighbors = record(
        src,
        "Neighbors",
        "ip -j neigh show",
        neigh.and_then(|t| parse::linux_neighbors(&t)),
        "",
    );
    s.listeners = record(
        src,
        "Listening ports",
        "ss -Hlntup",
        ss.map(|t| parse::linux_listeners(&t)),
        "process names show only for your own sockets without root",
    );
    let mut dns = Vec::new();
    let conf = tokio::fs::read("/etc/resolv.conf")
        .await
        .map_err(|e| format!("could not read /etc/resolv.conf: {e}"))
        .map(|b| String::from_utf8_lossy(&b[..b.len().min(1024 * 1024)]).into_owned());
    dns.extend(record(
        src,
        "DNS",
        "/etc/resolv.conf",
        conf.map(|t| parse::resolv_conf(&t)),
        "",
    ));
    if let Ok(d) = rdns {
        let dom = rdom.unwrap_or_default();
        dns.extend(record(
            src,
            "DNS",
            "resolvectl dns / domain",
            Ok(parse::resolvectl(&d, &dom)),
            "systemd-resolved",
        ));
    }
    s.dns = dns;
}

#[cfg(windows)]
async fn collect_os(s: &mut Snapshot) {
    use base64::Engine as _;
    s.os = "Windows".into();
    // -EncodedCommand takes UTF-16LE Base64, which avoids all quoting issues.
    let utf16: Vec<u8> = parse::WINDOWS_SCRIPT
        .encode_utf16()
        .flat_map(|u| u.to_le_bytes())
        .collect();
    let encoded = base64::engine::general_purpose::STANDARD.encode(utf16);
    let out = run(
        "powershell.exe",
        &[
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-EncodedCommand",
            &encoded,
        ],
    )
    .await
    .and_then(|t| parse::windows_all(&t));
    let cmd = "PowerShell Get-NetAdapter, Get-NetIPAddress, Get-NetRoute, Get-DnsClientServerAddress, Get-NetNeighbor, Get-NetTCPConnection, Get-NetUDPEndpoint";
    match out {
        Ok(p) => {
            for section in super::model::SECTIONS {
                s.sources.push(Source {
                    section: section.into(),
                    command: cmd.into(),
                    ok: true,
                    note: String::new(),
                });
            }
            s.interfaces = p.interfaces;
            s.routes = p.routes;
            s.dns = p.dns;
            s.neighbors = p.neighbors;
            s.listeners = p.listeners;
        }
        Err(e) => s.sources.push(Source {
            section: "All".into(),
            command: cmd.into(),
            ok: false,
            note: e,
        }),
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
async fn collect_os(s: &mut Snapshot) {
    s.os = std::env::consts::OS.into();
    s.sources.push(Source {
        section: "All".into(),
        command: String::new(),
        ok: false,
        note: "network snapshots are supported on macOS, Linux and Windows".into(),
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn missing_program_is_a_clear_error() {
        let e = run("net3po-no-such-program", &[]).await.unwrap_err();
        assert!(e.contains("not installed"), "{e}");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn failing_command_reports_stderr() {
        let e = run("sh", &["-c", "echo boom >&2; exit 3"])
            .await
            .unwrap_err();
        assert!(e.contains("boom"), "{e}");
        let ok = run("sh", &["-c", "echo hi"]).await.unwrap();
        assert_eq!(ok.trim(), "hi");
    }

    #[tokio::test]
    async fn take_fills_os_and_sources() {
        let s = take().await;
        assert!(!s.os.is_empty());
        assert!(!s.sources.is_empty());
        // On CI runners (real macOS, Linux and Windows machines) every source
        // must work, which checks the live commands and not only the parsers.
        if std::env::var_os("CI").is_some() {
            let failed: Vec<_> = s.sources.iter().filter(|x| !x.ok).collect();
            assert!(failed.is_empty(), "failed sources: {failed:?}");
            assert!(!s.interfaces.is_empty(), "no interfaces");
            assert!(!s.routes.is_empty(), "no routes");
            assert!(
                s.interfaces.iter().any(|i| !i.addrs.is_empty()),
                "no addresses"
            );
            println!(
                "{}: {} interfaces, {} routes, {} dns, {} neighbors, {} listeners",
                s.os,
                s.interfaces.len(),
                s.routes.len(),
                s.dns.len(),
                s.neighbors.len(),
                s.listeners.len()
            );
        }
    }
}
