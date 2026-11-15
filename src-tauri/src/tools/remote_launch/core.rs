//! Pure logic for launching installed RDP and VNC clients: which clients to
//! look for on each OS, how each one takes a target on its command line, the
//! `.rdp` file for clients that read one, and validation. No processes or
//! Tauri types here.
//!
//! Passwords are never part of a launch: every client asks for them itself.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::tools::ssh::core::validate_host;

/// Longest user name accepted (Windows allows 104 with a domain prefix).
const MAX_USER: usize = 128;
/// Longest custom argument template.
const MAX_TEMPLATE: usize = 1024;
/// Most arguments a custom template may produce.
const MAX_ARGS: usize = 32;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum LaunchError {
    #[error("{0}")]
    Host(String),
    #[error("port must be 1 to 65535")]
    BadPort,
    #[error(
        "user name must be at most {MAX_USER} characters, without control characters, and not start with - or /"
    )]
    BadUser,
    #[error("the argument template is too long or has too many arguments")]
    BadTemplate,
    #[error(
        "unknown placeholder {0} in the argument template (use {{host}}, {{port}}, {{user}}, {{target}} or {{file}})"
    )]
    Placeholder(String),
}

/// Remote desktop protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Rdp,
    Vnc,
}

/// How a client takes its target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Style {
    /// Windows Remote Desktop Connection: `mstsc file.rdp`.
    Mstsc,
    /// macOS app that opens `.rdp` files: `open -a App file.rdp`.
    MacOpenFile,
    /// macOS URL handler: `open vnc://user@host:port` (Screen Sharing).
    MacOpenUrl,
    /// Remmina: `remmina -c rdp://user@host:port`.
    Remmina,
    /// KDE KRDC: `krdc rdp://user@host:port`.
    Krdc,
    /// FreeRDP: `/v:host:port /u:user [/f]`.
    FreeRdp,
    /// TigerVNC, TightVNC, RealVNC, UltraVNC viewers: `host::port`.
    VncViewer,
}

/// A client found on this computer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Client {
    /// Stable id for settings, for example `mstsc` or `remmina`.
    pub id: String,
    pub name: String,
    pub path: String,
    pub style: Style,
    /// Caveat to show next to it, if any.
    pub note: String,
}

/// Where to look for a client.
#[derive(Debug, Clone, Copy)]
pub struct Candidate {
    pub id: &'static str,
    pub name: &'static str,
    pub protocol: Protocol,
    pub style: Style,
    /// Absolute paths (with `%SystemRoot%`, `%ProgramFiles%` and
    /// `%ProgramFiles(x86)%` expanded on Windows), or bare program names
    /// searched on PATH.
    pub paths: &'static [&'static str],
    pub note: &'static str,
}

const FREERDP_NOTE: &str =
    "asks for the password on a terminal; Remmina is easier from a desktop launcher";

/// Clients to look for on `os` (`std::env::consts::OS`), in preference order.
pub fn candidates(os: &str) -> Vec<Candidate> {
    use Protocol::*;
    use Style::*;
    let c = |id, name, protocol, style, paths, note| Candidate {
        id,
        name,
        protocol,
        style,
        paths,
        note,
    };
    match os {
        "windows" => vec![
            c(
                "mstsc",
                "Remote Desktop Connection (built in)",
                Rdp,
                Mstsc,
                &[r"%SystemRoot%\System32\mstsc.exe"],
                "",
            ),
            c(
                "realvnc",
                "RealVNC Viewer",
                Vnc,
                VncViewer,
                &[
                    r"%ProgramFiles%\RealVNC\VNC Viewer\vncviewer.exe",
                    r"%ProgramFiles(x86)%\RealVNC\VNC Viewer\vncviewer.exe",
                ],
                "",
            ),
            c(
                "tigervnc",
                "TigerVNC Viewer",
                Vnc,
                VncViewer,
                &[
                    r"%ProgramFiles%\TigerVNC\vncviewer.exe",
                    r"%ProgramFiles(x86)%\TigerVNC\vncviewer.exe",
                ],
                "",
            ),
            c(
                "tightvnc",
                "TightVNC Viewer",
                Vnc,
                VncViewer,
                &[
                    r"%ProgramFiles%\TightVNC\tvnviewer.exe",
                    r"%ProgramFiles(x86)%\TightVNC\tvnviewer.exe",
                ],
                "",
            ),
            c(
                "ultravnc",
                "UltraVNC Viewer",
                Vnc,
                VncViewer,
                &[
                    r"%ProgramFiles%\uvnc bvba\UltraVNC\vncviewer.exe",
                    r"%ProgramFiles(x86)%\uvnc bvba\UltraVNC\vncviewer.exe",
                ],
                "",
            ),
        ],
        "macos" => vec![
            c(
                "windows-app",
                "Windows App",
                Rdp,
                MacOpenFile,
                &["/Applications/Windows App.app"],
                "",
            ),
            c(
                "ms-rdp",
                "Microsoft Remote Desktop",
                Rdp,
                MacOpenFile,
                &["/Applications/Microsoft Remote Desktop.app"],
                "",
            ),
            c(
                "screen-sharing",
                "Screen Sharing (built in)",
                Vnc,
                MacOpenUrl,
                &[
                    "/System/Applications/Utilities/Screen Sharing.app",
                    "/System/Library/CoreServices/Applications/Screen Sharing.app",
                ],
                "",
            ),
            c(
                "realvnc",
                "RealVNC Viewer",
                Vnc,
                MacOpenFile,
                &["/Applications/VNC Viewer.app"],
                "",
            ),
        ],
        _ => vec![
            c("remmina", "Remmina", Rdp, Remmina, &["remmina"], ""),
            c("krdc", "KRDC", Rdp, Krdc, &["krdc"], ""),
            c(
                "sdl-freerdp3",
                "FreeRDP (SDL)",
                Rdp,
                FreeRdp,
                &["sdl-freerdp3", "sdl-freerdp"],
                "",
            ),
            c(
                "xfreerdp",
                "FreeRDP (X11)",
                Rdp,
                FreeRdp,
                &["xfreerdp3", "xfreerdp"],
                FREERDP_NOTE,
            ),
            c("remmina", "Remmina", Vnc, Remmina, &["remmina"], ""),
            c(
                "tigervnc",
                "TigerVNC Viewer",
                Vnc,
                VncViewer,
                &["vncviewer", "xtigervncviewer"],
                "",
            ),
            c("krdc", "KRDC", Vnc, Krdc, &["krdc"], ""),
        ],
    }
}

/// What to connect to.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Target {
    pub host: String,
    pub port: u16,
    #[serde(default)]
    pub user: String,
    #[serde(default)]
    pub fullscreen: bool,
}

/// Validate a target; returns it with the host normalized (no brackets).
pub fn validate(t: &Target) -> Result<Target, LaunchError> {
    let host = validate_host(&t.host).map_err(|e| LaunchError::Host(e.to_string()))?;
    if t.port == 0 {
        return Err(LaunchError::BadPort);
    }
    let user = t.user.trim().to_string();
    if user.chars().count() > MAX_USER
        || user.chars().any(char::is_control)
        || user.starts_with('-')
        || user.starts_with('/')
    {
        return Err(LaunchError::BadUser);
    }
    Ok(Target {
        host,
        port: t.port,
        user,
        fullscreen: t.fullscreen,
    })
}

/// `host:port`, with IPv6 in brackets.
pub fn host_port(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// `host::port` as VNC viewers take a port (not a display number).
pub fn vnc_viewer_target(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]::{port}")
    } else {
        format!("{host}::{port}")
    }
}

/// Percent-encode a user name for a URL's userinfo.
fn encode_user(user: &str) -> String {
    let mut out = String::with_capacity(user.len());
    for b in user.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// `scheme://[user@]host:port`.
pub fn url(scheme: &str, t: &Target) -> String {
    let user = if t.user.is_empty() {
        String::new()
    } else {
        format!("{}@", encode_user(&t.user))
    };
    format!("{scheme}://{user}{}", host_port(&t.host, t.port))
}

/// A minimal `.rdp` file. No password: the client asks.
pub fn rdp_file(t: &Target) -> String {
    let mut s = format!("full address:s:{}\r\n", host_port(&t.host, t.port));
    if !t.user.is_empty() {
        s.push_str(&format!("username:s:{}\r\n", t.user));
    }
    s.push_str(&format!(
        "screen mode id:i:{}\r\n",
        if t.fullscreen { 2 } else { 1 }
    ));
    s.push_str("prompt for credentials:i:1\r\n");
    s
}

/// The program and arguments to run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Launch {
    pub program: String,
    pub args: Vec<String>,
}

/// Whether a client style needs a `.rdp` file written first.
pub fn needs_rdp_file(style: Style, protocol: Protocol) -> bool {
    protocol == Protocol::Rdp && matches!(style, Style::Mstsc | Style::MacOpenFile)
}

/// Build the launch for a detected client. `file` is the `.rdp` file when
/// [`needs_rdp_file`] says so.
pub fn plan(client: &Client, protocol: Protocol, t: &Target, file: Option<&str>) -> Launch {
    let one = |program: &str, args: Vec<String>| Launch {
        program: program.to_string(),
        args,
    };
    let scheme = match protocol {
        Protocol::Rdp => "rdp",
        Protocol::Vnc => "vnc",
    };
    match client.style {
        Style::Mstsc => one(&client.path, vec![file.unwrap_or_default().to_string()]),
        Style::MacOpenFile => {
            let arg = match protocol {
                Protocol::Rdp => file.unwrap_or_default().to_string(),
                Protocol::Vnc => vnc_viewer_target(&t.host, t.port),
            };
            match protocol {
                Protocol::Rdp => one("/usr/bin/open", vec!["-a".into(), client.path.clone(), arg]),
                Protocol::Vnc => one(
                    "/usr/bin/open",
                    vec!["-a".into(), client.path.clone(), "--args".into(), arg],
                ),
            }
        }
        Style::MacOpenUrl => one("/usr/bin/open", vec![url(scheme, t)]),
        Style::Remmina => one(&client.path, vec!["-c".into(), url(scheme, t)]),
        Style::Krdc => one(&client.path, vec![url(scheme, t)]),
        Style::FreeRdp => {
            let mut args = vec![format!("/v:{}", host_port(&t.host, t.port))];
            if !t.user.is_empty() {
                args.push(format!("/u:{}", t.user));
            }
            if t.fullscreen {
                args.push("/f".into());
            } else {
                args.push("/dynamic-resolution".into());
            }
            one(&client.path, args)
        }
        Style::VncViewer => one(&client.path, vec![vnc_viewer_target(&t.host, t.port)]),
    }
}

/// Default argument template for a custom client.
pub fn default_template(protocol: Protocol) -> &'static str {
    match protocol {
        Protocol::Rdp => "{file}",
        Protocol::Vnc => "{host}::{port}",
    }
}

/// Expand a custom argument template. It is split on spaces first, so a
/// value can never become more than one argument; an argument whose only
/// content was an empty `{user}` is dropped.
pub fn expand_template(
    template: &str,
    t: &Target,
    file: Option<&str>,
) -> Result<Vec<String>, LaunchError> {
    if template.len() > MAX_TEMPLATE {
        return Err(LaunchError::BadTemplate);
    }
    let mut out = Vec::new();
    for token in template.split_whitespace() {
        let mut arg = String::new();
        let mut rest = token;
        let mut had_value = false;
        let mut only_empty = true;
        while let Some(open) = rest.find('{') {
            arg.push_str(&rest[..open]);
            if open > 0 {
                only_empty = false;
            }
            let after = &rest[open..];
            let close = after
                .find('}')
                .ok_or_else(|| LaunchError::Placeholder(after.to_string()))?;
            let name = &after[1..close];
            let value = match name {
                "host" => t.host.clone(),
                "port" => t.port.to_string(),
                "user" => t.user.clone(),
                "target" => host_port(&t.host, t.port),
                "file" => file.unwrap_or_default().to_string(),
                other => return Err(LaunchError::Placeholder(format!("{{{other}}}"))),
            };
            if !value.is_empty() {
                only_empty = false;
            }
            had_value = true;
            arg.push_str(&value);
            rest = &after[close + 1..];
        }
        if !rest.is_empty() {
            only_empty = false;
        }
        arg.push_str(rest);
        if had_value && only_empty {
            continue;
        }
        out.push(arg);
        if out.len() > MAX_ARGS {
            return Err(LaunchError::BadTemplate);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(host: &str, port: u16, user: &str, fullscreen: bool) -> Target {
        Target {
            host: host.into(),
            port,
            user: user.into(),
            fullscreen,
        }
    }

    fn client(style: Style, path: &str) -> Client {
        Client {
            id: "x".into(),
            name: "X".into(),
            path: path.into(),
            style,
            note: String::new(),
        }
    }

    #[test]
    fn validates_targets() {
        let v = validate(&t(" [2001:db8::1] ", 3389, " admin ", false)).unwrap();
        assert_eq!(v.host, "2001:db8::1");
        assert_eq!(v.user, "admin");
        assert!(validate(&t("", 3389, "", false)).is_err());
        assert!(validate(&t("-oProxy", 3389, "", false)).is_err());
        assert_eq!(validate(&t("h", 0, "", false)), Err(LaunchError::BadPort));
        assert_eq!(validate(&t("h", 1, "-x", false)), Err(LaunchError::BadUser));
        assert_eq!(
            validate(&t("h", 1, "/p:x", false)),
            Err(LaunchError::BadUser)
        );
        assert_eq!(
            validate(&t("h", 1, "a\nb", false)),
            Err(LaunchError::BadUser)
        );
        assert!(validate(&t("h", 1, r"CORP\jane", false)).is_ok());
        assert!(validate(&t("h", 1, "jane doe", false)).is_ok());
    }

    #[test]
    fn rdp_files_have_no_password() {
        let f = rdp_file(&t("192.0.2.5", 3390, r"CORP\jane", true));
        assert_eq!(
            f,
            "full address:s:192.0.2.5:3390\r\nusername:s:CORP\\jane\r\nscreen mode id:i:2\r\nprompt for credentials:i:1\r\n"
        );
        let f = rdp_file(&t("2001:db8::1", 3389, "", false));
        assert!(f.starts_with("full address:s:[2001:db8::1]:3389\r\nscreen mode id:i:1"));
        assert!(!f.to_lowercase().contains("password"));
    }

    #[test]
    fn urls_encode_users() {
        assert_eq!(
            url("vnc", &t("192.0.2.5", 5900, "", false)),
            "vnc://192.0.2.5:5900"
        );
        assert_eq!(
            url("rdp", &t("2001:db8::1", 3389, r"CORP\jane d@x", false)),
            "rdp://CORP%5Cjane%20d%40x@[2001:db8::1]:3389"
        );
    }

    #[test]
    fn plans_each_style() {
        let target = t("host.example.net", 3389, "jane", false);
        let p = plan(
            &client(Style::Mstsc, r"C:\Windows\System32\mstsc.exe"),
            Protocol::Rdp,
            &target,
            Some(r"C:\t\a.rdp"),
        );
        assert_eq!(p.args, [r"C:\t\a.rdp"]);
        let p = plan(
            &client(Style::MacOpenFile, "/Applications/Windows App.app"),
            Protocol::Rdp,
            &target,
            Some("/tmp/a.rdp"),
        );
        assert_eq!(p.program, "/usr/bin/open");
        assert_eq!(
            p.args,
            ["-a", "/Applications/Windows App.app", "/tmp/a.rdp"]
        );
        let p = plan(
            &client(Style::Remmina, "/usr/bin/remmina"),
            Protocol::Rdp,
            &target,
            None,
        );
        assert_eq!(p.args, ["-c", "rdp://jane@host.example.net:3389"]);
        let p = plan(
            &client(Style::FreeRdp, "/usr/bin/xfreerdp"),
            Protocol::Rdp,
            &t("192.0.2.5", 3389, "jane", true),
            None,
        );
        assert_eq!(p.args, ["/v:192.0.2.5:3389", "/u:jane", "/f"]);
        let p = plan(
            &client(Style::FreeRdp, "/usr/bin/xfreerdp"),
            Protocol::Rdp,
            &t("192.0.2.5", 3389, "", false),
            None,
        );
        assert_eq!(p.args, ["/v:192.0.2.5:3389", "/dynamic-resolution"]);

        let vnc = t("192.0.2.9", 5901, "", false);
        let p = plan(
            &client(
                Style::MacOpenUrl,
                "/System/Applications/Utilities/Screen Sharing.app",
            ),
            Protocol::Vnc,
            &vnc,
            None,
        );
        assert_eq!(
            (p.program.as_str(), p.args.clone()),
            ("/usr/bin/open", vec!["vnc://192.0.2.9:5901".to_string()])
        );
        let p = plan(
            &client(Style::VncViewer, "vncviewer"),
            Protocol::Vnc,
            &vnc,
            None,
        );
        assert_eq!(p.args, ["192.0.2.9::5901"]);
        let p = plan(
            &client(Style::VncViewer, "vncviewer"),
            Protocol::Vnc,
            &t("2001:db8::9", 5900, "", false),
            None,
        );
        assert_eq!(p.args, ["[2001:db8::9]::5900"]);
        let p = plan(
            &client(Style::MacOpenFile, "/Applications/VNC Viewer.app"),
            Protocol::Vnc,
            &vnc,
            None,
        );
        assert_eq!(
            p.args,
            [
                "-a",
                "/Applications/VNC Viewer.app",
                "--args",
                "192.0.2.9::5901"
            ]
        );
        assert!(needs_rdp_file(Style::Mstsc, Protocol::Rdp));
        assert!(!needs_rdp_file(Style::MacOpenFile, Protocol::Vnc));
    }

    #[test]
    fn templates_expand_without_splitting_values() {
        let target = t("192.0.2.5", 3389, "jane doe", false);
        assert_eq!(
            expand_template("/v:{target} /u:{user} /cert:tofu", &target, None).unwrap(),
            ["/v:192.0.2.5:3389", "/u:jane doe", "/cert:tofu"]
        );
        assert_eq!(
            expand_template("{file}", &target, Some("/tmp/a b.rdp")).unwrap(),
            ["/tmp/a b.rdp"]
        );
        assert_eq!(
            expand_template("{host}::{port}", &target, None).unwrap(),
            ["192.0.2.5::3389"]
        );
        // An empty user drops an argument that is only the user.
        let anon = t("192.0.2.5", 3389, "", false);
        assert_eq!(
            expand_template("{host} {user}", &anon, None).unwrap(),
            ["192.0.2.5"]
        );
        assert_eq!(
            expand_template("{host} -u{user}", &anon, None).unwrap(),
            ["192.0.2.5", "-u"]
        );
        assert!(matches!(
            expand_template("{password}", &target, None),
            Err(LaunchError::Placeholder(_))
        ));
        assert!(matches!(
            expand_template("{host", &target, None),
            Err(LaunchError::Placeholder(_))
        ));
        assert_eq!(
            expand_template(&"a ".repeat(40), &target, None),
            Err(LaunchError::BadTemplate)
        );
        assert_eq!(
            expand_template(&"a".repeat(2000), &target, None),
            Err(LaunchError::BadTemplate)
        );
    }

    #[test]
    fn every_os_has_candidates_for_both() {
        for os in ["windows", "macos", "linux"] {
            let c = candidates(os);
            assert!(c.iter().any(|x| x.protocol == Protocol::Rdp), "{os}");
            assert!(c.iter().any(|x| x.protocol == Protocol::Vnc), "{os}");
            assert!(c.iter().all(|x| !x.paths.is_empty()));
        }
    }
}
