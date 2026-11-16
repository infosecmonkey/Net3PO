//! Read the opening of a VNC (RFB) handshake: the server's protocol version
//! and the security types it offers. Nothing is selected and no credentials
//! are sent; the connection is dropped after the offer. Used to explain
//! viewer errors such as "No supported authentication methods".

use serde::Serialize;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Longest failure reason read from the server.
const MAX_REASON: usize = 1024;

/// Why the handshake could not be read.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum RfbError {
    #[error("not a VNC server (no RFB greeting)")]
    NotRfb,
    #[error("the server closed the connection during the handshake")]
    Closed,
    #[error("{0}")]
    Io(String),
}

impl From<std::io::Error> for RfbError {
    fn from(e: std::io::Error) -> Self {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            RfbError::Closed
        } else {
            RfbError::Io(e.to_string())
        }
    }
}

/// One offered security type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SecType {
    pub id: u8,
    pub name: &'static str,
}

/// What the server offered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Offer {
    /// Server version as sent, for example "3.8", plus a hint for known
    /// vendor versions.
    pub version: String,
    pub types: Vec<SecType>,
    /// Reason given when the server offered nothing.
    pub reason: Option<String>,
    /// Plain-language advice on which viewers can log in.
    pub advice: Vec<String>,
}

/// Name of a security type (IANA RFB registry).
pub fn type_name(id: u8) -> &'static str {
    match id {
        0 => "Invalid",
        1 => "None (no password)",
        2 => "VNC password",
        3..=15 | 128..=255 => "RealVNC",
        16 => "Tight",
        17 => "Ultra",
        18 => "TLS",
        19 => "VeNCrypt (TLS)",
        20 => "SASL",
        21 => "MD5 hash",
        22 => "xvp",
        23 => "Secure Tunnel",
        24 => "Integrated SSH",
        30 => "Apple macOS login",
        31..=36 => "Apple",
        113 => "UltraVNC MS-Logon II",
        _ => "Unknown",
    }
}

fn parse_version(greeting: &[u8; 12]) -> Option<(u32, u32)> {
    let s = std::str::from_utf8(greeting).ok()?;
    let rest = s.strip_prefix("RFB ")?.strip_suffix('\n')?;
    let (major, minor) = rest.split_once('.')?;
    if major.len() != 3 || minor.len() != 3 {
        return None;
    }
    Some((major.parse().ok()?, minor.parse().ok()?))
}

fn version_label(major: u32, minor: u32) -> String {
    let base = format!("{major}.{minor}");
    match (major, minor) {
        (3, 889) => format!("{base} (Apple)"),
        (4, _) | (5, _) => format!("{base} (RealVNC)"),
        _ => base,
    }
}

async fn read_reason<S: AsyncRead + Unpin>(s: &mut S) -> Result<String, RfbError> {
    let len = s.read_u32().await? as usize;
    let mut buf = vec![0u8; len.min(MAX_REASON)];
    s.read_exact(&mut buf).await?;
    Ok(String::from_utf8_lossy(&buf)
        .chars()
        .filter(|c| !c.is_control())
        .collect())
}

/// Read the server's version and security types from `s`.
pub async fn read_offer<S: AsyncRead + AsyncWrite + Unpin>(s: &mut S) -> Result<Offer, RfbError> {
    let mut greeting = [0u8; 12];
    s.read_exact(&mut greeting).await?;
    let (major, minor) = parse_version(&greeting).ok_or(RfbError::NotRfb)?;
    let version = version_label(major, minor);

    // Answer with the highest version both understand. Apple (3.889) and
    // RealVNC (4.x, 5.x) servers accept 3.8.
    let legacy = major == 3 && minor < 7;
    let reply: &[u8] = match (major, minor) {
        _ if legacy => b"RFB 003.003\n",
        (3, 7) => b"RFB 003.007\n",
        _ => b"RFB 003.008\n",
    };
    s.write_all(reply).await?;
    s.flush().await?;

    let mut types = Vec::new();
    let mut reason = None;
    if legacy {
        // 3.3: the server picks one type, sent as a u32.
        match s.read_u32().await? {
            0 => reason = Some(read_reason(s).await?),
            t => {
                let id = u8::try_from(t).unwrap_or(0);
                types.push(SecType {
                    id,
                    name: type_name(id),
                });
            }
        }
    } else {
        let n = s.read_u8().await?;
        if n == 0 {
            reason = Some(read_reason(s).await?);
        } else {
            let mut ids = vec![0u8; n as usize];
            s.read_exact(&mut ids).await?;
            types = ids
                .into_iter()
                .map(|id| SecType {
                    id,
                    name: type_name(id),
                })
                .collect();
        }
    }
    let advice = advice(&types, reason.as_deref());
    Ok(Offer {
        version,
        types,
        reason,
        advice,
    })
}

/// Which viewers can log in, given the offered types.
pub fn advice(types: &[SecType], reason: Option<&str>) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(r) = reason {
        out.push(format!(
            "The server refused the connection before login: {}",
            if r.is_empty() { "no reason given" } else { r }
        ));
        return out;
    }
    let has = |f: &dyn Fn(u8) -> bool| types.iter().any(|t| f(t.id));
    if has(&|id| id == 1) {
        out.push("No password is required. Any VNC viewer can connect.".into());
    }
    if has(&|id| id == 2) {
        out.push("VNC password login is offered. Any VNC viewer can log in with it.".into());
    }
    if !out.is_empty() {
        return out;
    }
    if has(&|id| (30..=36).contains(&id)) {
        out.push(
            "Only Apple's macOS login is offered. Use macOS Screen Sharing or Remmina, or on the Mac \
             open System Settings > General > Sharing > Screen Sharing (i) and turn on \"VNC viewers may \
             control screen with password\" so other viewers can log in."
                .into(),
        );
    }
    if has(&|id| id == 18 || id == 19) {
        out.push(
            "TLS-protected login (VeNCrypt) is offered. TigerVNC Viewer and Remmina support it; \
             UltraVNC, TightVNC and RealVNC Viewer do not."
                .into(),
        );
    }
    if has(&|id| (3..=15).contains(&id) || id >= 128) {
        out.push(
            "RealVNC's own login is offered. Use RealVNC Viewer, or set the server's authentication \
             to VNC password and encryption to Prefer off."
                .into(),
        );
    }
    if has(&|id| id == 16) {
        out.push("Tight login is offered. TightVNC Viewer supports it.".into());
    }
    if has(&|id| id == 17 || id == 113) {
        out.push("UltraVNC login is offered. UltraVNC Viewer supports it.".into());
    }
    if out.is_empty() {
        out.push(
            "No standard login method is offered. Most viewers will fail with \"No supported \
             authentication methods\"."
                .into(),
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    /// Run `read_offer` against a scripted server that sends `greeting`,
    /// checks the client's version reply, then sends `rest`.
    async fn run(
        greeting: &'static [u8],
        expect_reply: &'static [u8],
        rest: Vec<u8>,
    ) -> Result<Offer, RfbError> {
        let (mut client, mut server) = duplex(4096);
        let srv = tokio::spawn(async move {
            server.write_all(greeting).await.unwrap();
            let mut reply = [0u8; 12];
            if server.read_exact(&mut reply).await.is_err() {
                return;
            }
            assert_eq!(&reply, expect_reply);
            server.write_all(&rest).await.unwrap();
        });
        let r = read_offer(&mut client).await;
        drop(client);
        let _ = srv.await;
        r
    }

    #[tokio::test]
    async fn lists_types_for_3_8() {
        let o = run(b"RFB 003.008\n", b"RFB 003.008\n", vec![2, 1, 2])
            .await
            .unwrap();
        assert_eq!(o.version, "3.8");
        assert_eq!(o.types.iter().map(|t| t.id).collect::<Vec<_>>(), [1, 2]);
        assert_eq!(o.advice.len(), 2);
    }

    #[tokio::test]
    async fn apple_only_explains_the_mac_setting() {
        let o = run(b"RFB 003.889\n", b"RFB 003.008\n", vec![4, 30, 33, 36, 35])
            .await
            .unwrap();
        assert_eq!(o.version, "3.889 (Apple)");
        assert_eq!(o.types[0].name, "Apple macOS login");
        assert!(o.advice[0].contains("VNC viewers may control screen with password"));
    }

    #[tokio::test]
    async fn vencrypt_only_names_viewers() {
        let o = run(b"RFB 003.008\n", b"RFB 003.008\n", vec![1, 19])
            .await
            .unwrap();
        assert!(o.advice[0].contains("TigerVNC"));
    }

    #[tokio::test]
    async fn realvnc_5_answered_with_3_8() {
        let o = run(b"RFB 005.000\n", b"RFB 003.008\n", vec![2, 13, 130])
            .await
            .unwrap();
        assert_eq!(o.version, "5.0 (RealVNC)");
        assert!(o.advice[0].contains("RealVNC Viewer"));
    }

    #[tokio::test]
    async fn legacy_3_3_single_type() {
        let o = run(b"RFB 003.003\n", b"RFB 003.003\n", vec![0, 0, 0, 2])
            .await
            .unwrap();
        assert_eq!(
            o.types,
            [SecType {
                id: 2,
                name: "VNC password"
            }]
        );
    }

    #[tokio::test]
    async fn refusal_reason_is_bounded_and_cleaned() {
        let mut rest = vec![0u8];
        let msg = "Too many security failures\u{7}".to_string() + &"x".repeat(5000);
        rest.extend((msg.len() as u32).to_be_bytes());
        rest.extend(msg.as_bytes());
        let o = run(b"RFB 003.008\n", b"RFB 003.008\n", rest).await.unwrap();
        let r = o.reason.unwrap();
        assert!(r.starts_with("Too many security failures"));
        assert!(r.len() <= MAX_REASON);
        assert!(!r.contains('\u{7}'));
        assert!(o.advice[0].contains("refused"));
    }

    #[tokio::test]
    async fn non_rfb_is_rejected() {
        let (mut client, mut server) = duplex(64);
        server.write_all(b"SSH-2.0-Open").await.unwrap();
        assert_eq!(read_offer(&mut client).await, Err(RfbError::NotRfb));
    }

    #[tokio::test]
    async fn early_close_is_reported() {
        let (mut client, mut server) = duplex(64);
        server.write_all(b"RFB 003.008\n").await.unwrap();
        tokio::spawn(async move {
            let mut b = [0u8; 12];
            let _ = server.read_exact(&mut b).await;
        });
        assert_eq!(read_offer(&mut client).await, Err(RfbError::Closed));
    }

    #[test]
    fn unknown_types_get_generic_advice() {
        let a = advice(
            &[SecType {
                id: 99,
                name: "Unknown",
            }],
            None,
        );
        assert!(a[0].contains("No standard login"));
    }
}
