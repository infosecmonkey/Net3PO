//! Pure SSH logic: validating connection parameters, deciding whether a
//! server's host key is trusted (trust on first use, with a hard stop when a
//! pinned key changes), and clamping terminal sizes. No network or Tauri
//! types here.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Longest host name accepted.
const MAX_HOST: usize = 253;
/// Longest user name accepted.
const MAX_USER: usize = 64;
/// Longest key file path accepted.
const MAX_PATH: usize = 4096;
/// Longest id used as a keychain account name.
const MAX_ID: usize = 64;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SshError {
    #[error("enter a host name or IP address")]
    NoHost,
    #[error("'{0}' is not a valid host name or IP address")]
    BadHost(String),
    #[error("port must be 1 to 65535")]
    BadPort,
    #[error("enter a user name")]
    NoUser,
    #[error("user name must be at most {MAX_USER} characters without spaces")]
    BadUser,
    #[error("choose a private key file")]
    NoKey,
    #[error("key file path is too long")]
    BadKeyPath,
    #[error("invalid connection id")]
    BadId,
}

/// How a connection authenticates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthKind {
    Password,
    Key,
}

/// What the UI sends to open a session. Secrets come from the keychain when
/// not supplied here, and are never sent back to the UI.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectParams {
    /// Saved connection id, used as the keychain account. None for a quick,
    /// unsaved connection.
    pub connection_id: Option<String>,
    pub host: String,
    pub port: u16,
    pub user: String,
    pub auth: AuthKind,
    /// Private key path, for key auth.
    #[serde(default)]
    pub key_path: String,
    /// Password, or key passphrase, typed for this connect only.
    #[serde(default)]
    pub secret: Option<String>,
    /// Store `secret` in the OS keychain after a successful login.
    #[serde(default)]
    pub save_secret: bool,
    /// A fingerprint the user has just confirmed for this host.
    #[serde(default)]
    pub trust_fingerprint: Option<String>,
}

/// A pinned host key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KnownHost {
    pub host: String,
    pub port: u16,
    pub algorithm: String,
    /// `SHA256:...` as OpenSSH prints it.
    pub fingerprint: String,
    /// Unix seconds when it was pinned.
    #[serde(default)]
    pub added: u64,
}

/// Trust decision for a presented host key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostKeyStatus {
    /// Matches the pinned key, or the one the user just confirmed.
    Trusted,
    /// No key pinned for this host and port yet.
    New,
    /// A different key is pinned: possible interception or a rebuilt server.
    Changed { previous: String },
}

fn valid_label(l: &str) -> bool {
    !l.is_empty()
        && l.len() <= 63
        && l.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        && !l.starts_with('-')
        && !l.ends_with('-')
}

/// A host name or IPv4/IPv6 literal (brackets allowed around IPv6).
pub fn validate_host(host: &str) -> Result<String, SshError> {
    let h = host.trim();
    if h.is_empty() {
        return Err(SshError::NoHost);
    }
    let bare = h
        .strip_prefix('[')
        .and_then(|x| x.strip_suffix(']'))
        .unwrap_or(h);
    if bare.parse::<std::net::IpAddr>().is_ok() {
        return Ok(bare.to_string());
    }
    let name = bare.trim_end_matches('.');
    if name.len() > MAX_HOST || !name.split('.').all(valid_label) {
        return Err(SshError::BadHost(h.to_string()));
    }
    Ok(name.to_ascii_lowercase())
}

pub fn validate_user(user: &str) -> Result<(), SshError> {
    if user.is_empty() {
        return Err(SshError::NoUser);
    }
    if user.chars().count() > MAX_USER || user.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        return Err(SshError::BadUser);
    }
    Ok(())
}

/// Ids used as keychain account names: letters, digits and dashes.
pub fn validate_id(id: &str) -> Result<(), SshError> {
    if id.is_empty()
        || id.len() > MAX_ID
        || !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        return Err(SshError::BadId);
    }
    Ok(())
}

/// Validate everything about a connect request; returns the normalized host.
pub fn validate(p: &ConnectParams) -> Result<String, SshError> {
    let host = validate_host(&p.host)?;
    if p.port == 0 {
        return Err(SshError::BadPort);
    }
    validate_user(&p.user)?;
    if let Some(id) = &p.connection_id {
        validate_id(id)?;
    }
    if p.auth == AuthKind::Key {
        if p.key_path.trim().is_empty() {
            return Err(SshError::NoKey);
        }
        if p.key_path.len() > MAX_PATH {
            return Err(SshError::BadKeyPath);
        }
    }
    Ok(host)
}

/// Decide whether `fingerprint` is trusted for host and port. `confirmed` is
/// a fingerprint the user accepted moments ago in the UI; it only counts if
/// it is exactly the key now presented.
pub fn host_key_status(
    known: &[KnownHost],
    host: &str,
    port: u16,
    fingerprint: &str,
    confirmed: Option<&str>,
) -> HostKeyStatus {
    if confirmed == Some(fingerprint) {
        return HostKeyStatus::Trusted;
    }
    match known
        .iter()
        .find(|k| k.host.eq_ignore_ascii_case(host) && k.port == port)
    {
        Some(k) if k.fingerprint == fingerprint => HostKeyStatus::Trusted,
        Some(k) => HostKeyStatus::Changed {
            previous: k.fingerprint.clone(),
        },
        None => HostKeyStatus::New,
    }
}

/// Pin a key for host and port, replacing any previous one.
pub fn pin(known: &mut Vec<KnownHost>, entry: KnownHost) {
    known.retain(|k| !(k.host.eq_ignore_ascii_case(&entry.host) && k.port == entry.port));
    known.push(entry);
}

/// Keep terminal dimensions sane.
pub fn clamp_size(cols: u32, rows: u32) -> (u32, u32) {
    (cols.clamp(2, 1000), rows.clamp(1, 500))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params() -> ConnectParams {
        ConnectParams {
            connection_id: Some("c0ffee-1".into()),
            host: "Router1.Example.com".into(),
            port: 22,
            user: "admin".into(),
            auth: AuthKind::Password,
            key_path: String::new(),
            secret: None,
            save_secret: false,
            trust_fingerprint: None,
        }
    }

    #[test]
    fn hosts() {
        assert_eq!(
            validate_host("Router1.Example.com.").unwrap(),
            "router1.example.com"
        );
        assert_eq!(validate_host("10.0.0.1").unwrap(), "10.0.0.1");
        assert_eq!(validate_host("[2001:db8::1]").unwrap(), "2001:db8::1");
        assert_eq!(validate_host("fw-01").unwrap(), "fw-01");
        assert_eq!(validate_host(" "), Err(SshError::NoHost));
        for bad in ["a b", "-x.com", "x..com", "host;rm", "a@b", &"a".repeat(64)] {
            assert!(
                matches!(validate_host(bad), Err(SshError::BadHost(_))),
                "{bad}"
            );
        }
    }

    #[test]
    fn params_validation() {
        assert_eq!(validate(&params()).unwrap(), "router1.example.com");
        let mut p = params();
        p.port = 0;
        assert_eq!(validate(&p), Err(SshError::BadPort));
        let mut p = params();
        p.user = "ad min".into();
        assert_eq!(validate(&p), Err(SshError::BadUser));
        let mut p = params();
        p.auth = AuthKind::Key;
        assert_eq!(validate(&p), Err(SshError::NoKey));
        let mut p = params();
        p.connection_id = Some("../x".into());
        assert_eq!(validate(&p), Err(SshError::BadId));
    }

    fn kh(host: &str, port: u16, fp: &str) -> KnownHost {
        KnownHost {
            host: host.into(),
            port,
            algorithm: "ssh-ed25519".into(),
            fingerprint: fp.into(),
            added: 0,
        }
    }

    #[test]
    fn host_key_trust_on_first_use() {
        let known = vec![kh("fw.example.com", 22, "SHA256:aaa")];
        assert_eq!(
            host_key_status(&known, "fw.example.com", 22, "SHA256:aaa", None),
            HostKeyStatus::Trusted
        );
        assert_eq!(
            host_key_status(&known, "FW.example.com", 22, "SHA256:aaa", None),
            HostKeyStatus::Trusted
        );
        assert_eq!(
            host_key_status(&known, "other", 22, "SHA256:bbb", None),
            HostKeyStatus::New
        );
        assert_eq!(
            host_key_status(&known, "fw.example.com", 2222, "SHA256:aaa", None),
            HostKeyStatus::New
        );
        assert_eq!(
            host_key_status(&known, "fw.example.com", 22, "SHA256:bbb", None),
            HostKeyStatus::Changed {
                previous: "SHA256:aaa".into()
            }
        );
        // A confirmation only covers the exact key presented.
        assert_eq!(
            host_key_status(
                &known,
                "fw.example.com",
                22,
                "SHA256:bbb",
                Some("SHA256:bbb")
            ),
            HostKeyStatus::Trusted
        );
        assert!(matches!(
            host_key_status(
                &known,
                "fw.example.com",
                22,
                "SHA256:ccc",
                Some("SHA256:bbb")
            ),
            HostKeyStatus::Changed { .. }
        ));
    }

    #[test]
    fn pinning_replaces() {
        let mut known = vec![kh("a", 22, "SHA256:1"), kh("b", 22, "SHA256:2")];
        pin(&mut known, kh("A", 22, "SHA256:3"));
        assert_eq!(known.len(), 2);
        assert!(known.iter().any(|k| k.fingerprint == "SHA256:3"));
        assert!(!known.iter().any(|k| k.fingerprint == "SHA256:1"));
    }

    #[test]
    fn sizes() {
        assert_eq!(clamp_size(0, 0), (2, 1));
        assert_eq!(clamp_size(100_000, 9999), (1000, 500));
        assert_eq!(clamp_size(120, 40), (120, 40));
    }
}
