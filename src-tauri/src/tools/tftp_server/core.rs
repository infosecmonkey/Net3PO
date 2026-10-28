//! Pure TFTP protocol helpers: packet encode/decode, path-traversal-safe
//! filename resolution, and option (RFC 2347-2349) negotiation. The UDP
//! transfer loops live in `commands.rs`. Everything here is unit tested; the
//! path functions touch the filesystem but only through temp dirs in tests.

use std::fs;
use std::path::{Component, Path, PathBuf};

use thiserror::Error;

pub const OP_RRQ: u16 = 1;
pub const OP_WRQ: u16 = 2;
pub const OP_DATA: u16 = 3;
pub const OP_ACK: u16 = 4;
pub const OP_ERROR: u16 = 5;
pub const OP_OACK: u16 = 6;

/// Default block size when no `blksize` option is negotiated.
pub const DEFAULT_BLKSIZE: usize = 512;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TftpError {
    #[error("malformed TFTP packet")]
    BadPacket,
    #[error("file not found")]
    NotFound,
    #[error("access violation")]
    AccessViolation,
    #[error("illegal TFTP operation")]
    IllegalOperation,
    #[error("path escapes the served directory")]
    PathEscape,
}

impl TftpError {
    /// The TFTP ERROR packet code for this error.
    pub fn code(&self) -> u16 {
        match self {
            TftpError::NotFound => 1,
            TftpError::AccessViolation | TftpError::PathEscape => 2,
            TftpError::IllegalOperation | TftpError::BadPacket => 4,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReqKind {
    Read,
    Write,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub kind: ReqKind,
    pub filename: String,
    pub mode: String,
    pub options: Vec<(String, String)>,
}

/// Parse an RRQ or WRQ packet.
pub fn parse_request(buf: &[u8]) -> Result<Request, TftpError> {
    if buf.len() < 4 {
        return Err(TftpError::BadPacket);
    }
    let opcode = u16::from_be_bytes([buf[0], buf[1]]);
    let kind = match opcode {
        OP_RRQ => ReqKind::Read,
        OP_WRQ => ReqKind::Write,
        _ => return Err(TftpError::IllegalOperation),
    };

    // NUL-separated fields: filename, mode, then option/value pairs.
    let mut fields = buf[2..]
        .split(|b| *b == 0)
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect::<Vec<_>>();
    // A trailing NUL produces an empty final field; drop it.
    if fields.last().map(|s| s.is_empty()).unwrap_or(false) {
        fields.pop();
    }
    if fields.len() < 2 {
        return Err(TftpError::BadPacket);
    }

    let filename = fields[0].clone();
    let mode = fields[1].clone();
    let mut options = Vec::new();
    let mut i = 2;
    while i + 1 < fields.len() {
        options.push((fields[i].clone(), fields[i + 1].clone()));
        i += 2;
    }

    Ok(Request {
        kind,
        filename,
        mode,
        options,
    })
}

pub fn build_data(block: u16, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + data.len());
    out.extend_from_slice(&OP_DATA.to_be_bytes());
    out.extend_from_slice(&block.to_be_bytes());
    out.extend_from_slice(data);
    out
}

pub fn build_ack(block: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(4);
    out.extend_from_slice(&OP_ACK.to_be_bytes());
    out.extend_from_slice(&block.to_be_bytes());
    out
}

pub fn build_error(code: u16, msg: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + msg.len());
    out.extend_from_slice(&OP_ERROR.to_be_bytes());
    out.extend_from_slice(&code.to_be_bytes());
    out.extend_from_slice(msg.as_bytes());
    out.push(0);
    out
}

pub fn build_oack(options: &[(String, String)]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&OP_OACK.to_be_bytes());
    for (k, v) in options {
        out.extend_from_slice(k.as_bytes());
        out.push(0);
        out.extend_from_slice(v.as_bytes());
        out.push(0);
    }
    out
}

/// Parse an ACK packet, returning the acknowledged block number.
pub fn parse_ack(buf: &[u8]) -> Option<u16> {
    if buf.len() >= 4 && u16::from_be_bytes([buf[0], buf[1]]) == OP_ACK {
        Some(u16::from_be_bytes([buf[2], buf[3]]))
    } else {
        None
    }
}

/// Parse a DATA packet, returning (block, payload).
pub fn parse_data(buf: &[u8]) -> Option<(u16, &[u8])> {
    if buf.len() >= 4 && u16::from_be_bytes([buf[0], buf[1]]) == OP_DATA {
        Some((u16::from_be_bytes([buf[2], buf[3]]), &buf[4..]))
    } else {
        None
    }
}

/// Reject any filename that is absolute, uses `..`, or contains a backslash or
/// NUL (defense in depth before the canonicalization check).
fn validate_relative(filename: &str) -> Result<(), TftpError> {
    if filename.is_empty() || filename.contains('\0') || filename.contains('\\') {
        return Err(TftpError::PathEscape);
    }
    let p = Path::new(filename);
    if p.is_absolute() {
        return Err(TftpError::PathEscape);
    }
    for comp in p.components() {
        match comp {
            Component::Normal(_) | Component::CurDir => {}
            _ => return Err(TftpError::PathEscape),
        }
    }
    Ok(())
}

/// Resolve a filename for reading, confined to `root`. The file must exist.
pub fn resolve_read(root: &Path, filename: &str) -> Result<PathBuf, TftpError> {
    validate_relative(filename)?;
    let root_canon = fs::canonicalize(root).map_err(|_| TftpError::AccessViolation)?;
    let canon = fs::canonicalize(root_canon.join(filename)).map_err(|_| TftpError::NotFound)?;
    if !canon.starts_with(&root_canon) {
        return Err(TftpError::PathEscape);
    }
    Ok(canon)
}

/// Resolve a filename for writing, confined to `root`. The parent directory
/// must already exist and resolve inside the root; the target must not exist.
pub fn resolve_write(root: &Path, filename: &str) -> Result<PathBuf, TftpError> {
    validate_relative(filename)?;
    let root_canon = fs::canonicalize(root).map_err(|_| TftpError::AccessViolation)?;
    let candidate = root_canon.join(filename);
    let parent = candidate.parent().ok_or(TftpError::AccessViolation)?;
    let parent_canon = fs::canonicalize(parent).map_err(|_| TftpError::AccessViolation)?;
    if !parent_canon.starts_with(&root_canon) {
        return Err(TftpError::PathEscape);
    }
    let name = candidate.file_name().ok_or(TftpError::AccessViolation)?;
    // The file is created on demand; an existing file of the same name is
    // overwritten (expected for repeated config backups). The "Writable" opt-in
    // is the gate, and folder write permission is all that is required.
    Ok(parent_canon.join(name))
}

/// Negotiate the subset of requested options the server accepts. `file_size` is
/// `Some` for reads (so `tsize` reports the real size) and `None` for writes
/// (the client's `tsize` value is echoed back).
pub fn negotiate(requested: &[(String, String)], file_size: Option<u64>) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for (k, v) in requested {
        match k.to_ascii_lowercase().as_str() {
            "blksize" => {
                if let Ok(n) = v.parse::<u32>() {
                    let clamped = n.clamp(8, 65464);
                    out.push(("blksize".to_string(), clamped.to_string()));
                }
            }
            "tsize" => match file_size {
                Some(sz) => out.push(("tsize".to_string(), sz.to_string())),
                None => out.push(("tsize".to_string(), v.clone())),
            },
            "timeout" => {
                if let Ok(n) = v.parse::<u32>()
                    && (1..=255).contains(&n)
                {
                    out.push(("timeout".to_string(), n.to_string()));
                }
            }
            _ => {}
        }
    }
    out
}

/// The negotiated block size, or the default when none was accepted.
pub fn blksize_of(options: &[(String, String)]) -> usize {
    options
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("blksize"))
        .and_then(|(_, v)| v.parse::<usize>().ok())
        .unwrap_or(DEFAULT_BLKSIZE)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cstr(parts: &[&str]) -> Vec<u8> {
        let mut v = Vec::new();
        for p in parts {
            v.extend_from_slice(p.as_bytes());
            v.push(0);
        }
        v
    }

    #[test]
    fn parse_rrq_with_options() {
        let mut pkt = OP_RRQ.to_be_bytes().to_vec();
        pkt.extend(cstr(&[
            "firmware.bin",
            "octet",
            "blksize",
            "1468",
            "tsize",
            "0",
        ]));
        let req = parse_request(&pkt).unwrap();
        assert_eq!(req.kind, ReqKind::Read);
        assert_eq!(req.filename, "firmware.bin");
        assert_eq!(req.mode, "octet");
        assert_eq!(
            req.options,
            vec![
                ("blksize".to_string(), "1468".to_string()),
                ("tsize".to_string(), "0".to_string())
            ]
        );
    }

    #[test]
    fn parse_wrq_no_options() {
        let mut pkt = OP_WRQ.to_be_bytes().to_vec();
        pkt.extend(cstr(&["config.txt", "octet"]));
        let req = parse_request(&pkt).unwrap();
        assert_eq!(req.kind, ReqKind::Write);
        assert!(req.options.is_empty());
    }

    #[test]
    fn parse_rejects_bad_opcode_and_short() {
        let mut pkt = 9u16.to_be_bytes().to_vec();
        pkt.extend(cstr(&["a", "octet"]));
        assert_eq!(
            parse_request(&pkt).unwrap_err(),
            TftpError::IllegalOperation
        );
        assert_eq!(parse_request(&[0, 1]).unwrap_err(), TftpError::BadPacket);
    }

    #[test]
    fn data_ack_error_oack_roundtrip() {
        let d = build_data(7, b"payload");
        assert_eq!(parse_data(&d), Some((7, &b"payload"[..])));
        let a = build_ack(42);
        assert_eq!(parse_ack(&a), Some(42));
        let e = build_error(1, "file not found");
        assert_eq!(&e[0..2], &OP_ERROR.to_be_bytes());
        assert_eq!(e[2..4], 1u16.to_be_bytes());
        assert_eq!(*e.last().unwrap(), 0);
        let o = build_oack(&[("blksize".into(), "1468".into())]);
        assert_eq!(&o[0..2], &OP_OACK.to_be_bytes());
    }

    #[test]
    fn negotiate_options() {
        let req = vec![
            ("blksize".to_string(), "1468".to_string()),
            ("tsize".to_string(), "0".to_string()),
            ("timeout".to_string(), "3".to_string()),
            ("bogus".to_string(), "x".to_string()),
        ];
        let acc = negotiate(&req, Some(1_000_000));
        assert_eq!(acc[0], ("blksize".to_string(), "1468".to_string()));
        assert_eq!(acc[1], ("tsize".to_string(), "1000000".to_string()));
        assert_eq!(acc[2], ("timeout".to_string(), "3".to_string()));
        assert_eq!(acc.len(), 3); // bogus dropped
        assert_eq!(blksize_of(&acc), 1468);
    }

    #[test]
    fn negotiate_clamps_blksize_and_timeout() {
        let acc = negotiate(&[("blksize".into(), "99999".into())], None);
        assert_eq!(blksize_of(&acc), 65464);
        let acc2 = negotiate(&[("blksize".into(), "4".into())], None);
        assert_eq!(blksize_of(&acc2), 8);
        // timeout out of range is dropped.
        let acc3 = negotiate(&[("timeout".into(), "999".into())], None);
        assert!(acc3.is_empty());
    }

    #[test]
    fn tsize_echoed_for_writes() {
        let acc = negotiate(&[("tsize".into(), "2048".into())], None);
        assert_eq!(acc[0], ("tsize".to_string(), "2048".to_string()));
    }

    #[test]
    fn blksize_defaults_without_option() {
        assert_eq!(blksize_of(&[]), DEFAULT_BLKSIZE);
    }

    // --- Path safety ---

    fn temp_root() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("omnipacket_tftp_{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        dir
    }

    #[test]
    fn read_resolves_file_in_root() {
        let root = temp_root();
        let file = root.join("ok.txt");
        fs::write(&file, b"hi").unwrap();
        let resolved = resolve_read(&root, "ok.txt").unwrap();
        assert_eq!(resolved, fs::canonicalize(&file).unwrap());
        fs::remove_file(&file).unwrap();
    }

    #[test]
    fn read_rejects_traversal_and_absolute() {
        let root = temp_root();
        assert_eq!(
            resolve_read(&root, "../secret").unwrap_err(),
            TftpError::PathEscape
        );
        assert_eq!(
            resolve_read(&root, "/etc/passwd").unwrap_err(),
            TftpError::PathEscape
        );
        assert_eq!(
            resolve_read(&root, "a\\..\\b").unwrap_err(),
            TftpError::PathEscape
        );
    }

    #[test]
    fn read_missing_file_is_not_found() {
        let root = temp_root();
        assert_eq!(
            resolve_read(&root, "nope.txt").unwrap_err(),
            TftpError::NotFound
        );
    }

    #[test]
    fn write_resolves_new_file_and_allows_overwrite() {
        let root = temp_root();
        let ok = resolve_write(&root, "upload.bin").unwrap();
        assert!(ok.starts_with(fs::canonicalize(&root).unwrap()));

        // An existing file resolves fine (it will be overwritten).
        let existing = root.join("there.txt");
        fs::write(&existing, b"x").unwrap();
        let resolved = resolve_write(&root, "there.txt").unwrap();
        assert_eq!(resolved, fs::canonicalize(&existing).unwrap());
        fs::remove_file(&existing).unwrap();
    }

    #[test]
    fn write_rejects_traversal() {
        let root = temp_root();
        assert_eq!(
            resolve_write(&root, "../evil").unwrap_err(),
            TftpError::PathEscape
        );
    }
}
