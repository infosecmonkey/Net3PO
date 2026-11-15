//! Tauri commands to find installed RDP and VNC clients and open one on a
//! target. The client runs as its own process; the app does not wait for it.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::core::{self, Candidate, Client, Protocol, Target};

/// How long a temporary `.rdp` file is kept for the client to read.
const RDP_FILE_LIFETIME: Duration = Duration::from_secs(120);

/// Clients found on this computer, per protocol.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Detected {
    pub rdp: Vec<Client>,
    pub vnc: Vec<Client>,
    /// Default custom argument templates.
    pub rdp_template: String,
    pub vnc_template: String,
}

/// Which client to use, from Settings.
#[derive(Debug, Deserialize)]
#[serde(
    tag = "mode",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum Choice {
    /// A detected client by id; the first one found when empty.
    Auto {
        #[serde(default)]
        id: String,
    },
    /// A program the user picked, with an argument template.
    Custom { path: String, args: String },
}

/// Expand `%SystemRoot%`, `%ProgramFiles%` and `%ProgramFiles(x86)%`.
fn expand_env(p: &str) -> Option<PathBuf> {
    let mut s = p.to_string();
    for var in ["SystemRoot", "ProgramFiles(x86)", "ProgramFiles"] {
        let key = format!("%{var}%");
        if s.contains(&key) {
            s = s.replace(&key, &std::env::var(var).ok()?);
        }
    }
    Some(PathBuf::from(s))
}

/// First match of a bare program name on PATH.
fn on_path(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|d| d.join(name))
        .find(|p| p.is_file())
}

fn locate(c: &Candidate) -> Option<PathBuf> {
    c.paths.iter().find_map(|p| {
        if p.contains('/') || p.contains('\\') {
            expand_env(p).filter(|x| x.exists())
        } else {
            on_path(p)
        }
    })
}

/// Detect the clients for this OS.
pub fn detect() -> Detected {
    let mut rdp = Vec::new();
    let mut vnc = Vec::new();
    for c in core::candidates(std::env::consts::OS) {
        let Some(path) = locate(&c) else { continue };
        let client = Client {
            id: c.id.to_string(),
            name: c.name.to_string(),
            path: path.display().to_string(),
            style: c.style,
            note: c.note.to_string(),
        };
        let list = match c.protocol {
            Protocol::Rdp => &mut rdp,
            Protocol::Vnc => &mut vnc,
        };
        if !list.iter().any(|x: &Client| x.id == client.id) {
            list.push(client);
        }
    }
    Detected {
        rdp,
        vnc,
        rdp_template: core::default_template(Protocol::Rdp).into(),
        vnc_template: core::default_template(Protocol::Vnc).into(),
    }
}

/// List the RDP and VNC clients installed on this computer.
#[tauri::command]
pub async fn remote_clients() -> Detected {
    tokio::task::spawn_blocking(detect)
        .await
        .unwrap_or_else(|_| Detected {
            rdp: Vec::new(),
            vnc: Vec::new(),
            rdp_template: core::default_template(Protocol::Rdp).into(),
            vnc_template: core::default_template(Protocol::Vnc).into(),
        })
}

static RDP_SEQ: AtomicU32 = AtomicU32::new(0);

/// Write a `.rdp` file the client can read; removed again after a while.
fn write_rdp_file(t: &Target) -> Result<PathBuf, String> {
    let dir = std::env::temp_dir().join("net3po-rdp");
    std::fs::create_dir_all(&dir)
        .map_err(|e| format!("could not create {}: {e}", dir.display()))?;
    let n = RDP_SEQ.fetch_add(1, Ordering::Relaxed);
    let safe: String = t
        .host
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let path = dir.join(format!("{safe}-{}-{n}.rdp", std::process::id()));
    std::fs::write(&path, core::rdp_file(t))
        .map_err(|e| format!("could not write {}: {e}", path.display()))?;
    let cleanup = path.clone();
    std::thread::spawn(move || {
        std::thread::sleep(RDP_FILE_LIFETIME);
        let _ = std::fs::remove_file(cleanup);
    });
    Ok(path)
}

/// Start the program without waiting for it; its exit is reaped in the
/// background so no zombie is left behind.
fn spawn(program: &str, args: &[String]) -> Result<(), String> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("could not start {program}: {e}"))?;
    std::thread::spawn(move || {
        let _ = child.wait();
    });
    Ok(())
}

/// A custom program: a file, or an app bundle on macOS.
fn custom_launch(path: &str, args: Vec<String>) -> Result<core::Launch, String> {
    let p = Path::new(path.trim());
    if !p.is_absolute() || !p.exists() {
        return Err(format!(
            "the custom client {path} was not found; check Settings"
        ));
    }
    if cfg!(target_os = "macos") && p.extension().is_some_and(|e| e == "app") {
        let mut a = vec![
            "-a".to_string(),
            p.display().to_string(),
            "--args".to_string(),
        ];
        a.extend(args);
        return Ok(core::Launch {
            program: "/usr/bin/open".into(),
            args: a,
        });
    }
    if !p.is_file() {
        return Err(format!("{path} is not a program"));
    }
    Ok(core::Launch {
        program: p.display().to_string(),
        args,
    })
}

/// Open an RDP or VNC session on `target` with the chosen client. Returns
/// the client's name.
#[tauri::command]
pub async fn remote_launch(
    protocol: Protocol,
    choice: Choice,
    target: Target,
) -> Result<String, String> {
    let t = core::validate(&target).map_err(|e| e.to_string())?;
    tokio::task::spawn_blocking(move || launch(protocol, choice, &t))
        .await
        .map_err(|e| e.to_string())?
}

fn launch(protocol: Protocol, choice: Choice, t: &Target) -> Result<String, String> {
    match choice {
        Choice::Auto { id } => {
            let found = detect();
            let list = match protocol {
                Protocol::Rdp => found.rdp,
                Protocol::Vnc => found.vnc,
            };
            let client = if id.is_empty() {
                list.into_iter().next()
            } else {
                list.into_iter().find(|c| c.id == id)
            }
            .ok_or_else(|| {
                "the client chosen in Settings is no longer installed; pick another in Settings"
                    .to_string()
            })?;
            let file = if core::needs_rdp_file(client.style, protocol) {
                Some(write_rdp_file(t)?.display().to_string())
            } else {
                None
            };
            let plan = core::plan(&client, protocol, t, file.as_deref());
            spawn(&plan.program, &plan.args)?;
            Ok(client.name)
        }
        Choice::Custom { path, args } => {
            let file = if protocol == Protocol::Rdp && args.contains("{file}") {
                Some(write_rdp_file(t)?.display().to_string())
            } else {
                None
            };
            let expanded =
                core::expand_template(&args, t, file.as_deref()).map_err(|e| e.to_string())?;
            let plan = custom_launch(&path, expanded)?;
            spawn(&plan.program, &plan.args)?;
            Ok(Path::new(&path)
                .file_stem()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or(path))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn choices_deserialize() {
        let c: Choice = serde_json::from_str(r#"{"mode":"auto","id":"mstsc"}"#).unwrap();
        assert!(matches!(c, Choice::Auto { id } if id == "mstsc"));
        let c: Choice = serde_json::from_str(r#"{"mode":"auto"}"#).unwrap();
        assert!(matches!(c, Choice::Auto { id } if id.is_empty()));
        let c: Choice =
            serde_json::from_str(r#"{"mode":"custom","path":"/x","args":"{host}"}"#).unwrap();
        assert!(matches!(c, Choice::Custom { .. }));
    }

    #[test]
    fn detection_never_fails() {
        let d = detect();
        for c in d.rdp.iter().chain(&d.vnc) {
            assert!(Path::new(&c.path).exists(), "{}", c.path);
        }
        #[cfg(target_os = "macos")]
        assert!(d.vnc.iter().any(|c| c.id == "screen-sharing"));
    }

    #[test]
    fn rdp_files_are_written_and_named_safely() {
        let t = core::validate(&Target {
            host: "2001:db8::1".into(),
            port: 3389,
            user: "jane".into(),
            fullscreen: false,
        })
        .unwrap();
        let p = write_rdp_file(&t).unwrap();
        let name = p.file_name().unwrap().to_string_lossy().into_owned();
        assert!(
            name.starts_with("2001_db8__1-") && name.ends_with(".rdp"),
            "{name}"
        );
        assert!(
            std::fs::read_to_string(&p)
                .unwrap()
                .contains("[2001:db8::1]:3389")
        );
        let _ = std::fs::remove_file(p);
    }

    #[test]
    fn custom_clients_must_exist() {
        assert!(custom_launch("relative/app", vec![]).is_err());
        assert!(custom_launch("/nonexistent/viewer", vec![]).is_err());
        let exe = std::env::current_exe().unwrap();
        let l = custom_launch(&exe.display().to_string(), vec!["a".into()]).unwrap();
        assert_eq!(l.args, ["a"]);
    }

    #[tokio::test]
    async fn bad_targets_are_refused_before_anything_runs() {
        let e = remote_launch(
            Protocol::Vnc,
            Choice::Custom {
                path: "/nonexistent".into(),
                args: "{host}".into(),
            },
            Target {
                host: "-bad".into(),
                port: 5900,
                user: String::new(),
                fullscreen: false,
            },
        )
        .await
        .unwrap_err();
        assert!(e.contains("not a valid host"), "{e}");
    }
}
