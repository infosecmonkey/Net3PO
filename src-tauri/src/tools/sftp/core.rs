//! Pure SFTP logic: remote (POSIX) path handling, turning a remote file name
//! into a safe local one, and formatting directory listings. No network or
//! Tauri types here.

use serde::Serialize;
use thiserror::Error;

/// Longest remote path accepted.
pub const MAX_PATH: usize = 4096;
/// Longest single file name, in bytes.
pub const MAX_NAME: usize = 255;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SftpError {
    #[error("enter a name")]
    NoName,
    #[error("'{0}' is not a valid name: no slashes, and not . or ..")]
    BadName(String),
    #[error("name is longer than {MAX_NAME} bytes")]
    LongName,
    #[error("path is empty")]
    NoPath,
    #[error("path is longer than {MAX_PATH} bytes or contains a NUL byte")]
    BadPath,
}

/// What a directory entry is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Dir,
    File,
    Link,
    Other,
}

/// One row in a remote listing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Entry {
    pub name: String,
    pub kind: Kind,
    /// A symlink that points at a directory: open it like one.
    pub link_dir: bool,
    pub size: Option<u64>,
    /// Unix seconds.
    pub mtime: Option<u32>,
    /// `drwxr-xr-x` style, or empty when the server sent no mode.
    pub perms: String,
}

/// A remote directory's contents.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Listing {
    /// The canonical path the server resolved.
    pub path: String,
    pub entries: Vec<Entry>,
    /// More entries than the cap; the rest are not shown.
    pub truncated: bool,
}

/// Kind from a POSIX mode (the S_IFMT bits).
pub fn kind(mode: Option<u32>) -> Kind {
    match mode.map(|m| m & 0o170000) {
        Some(0o040000) => Kind::Dir,
        Some(0o100000) => Kind::File,
        Some(0o120000) => Kind::Link,
        Some(_) => Kind::Other,
        None => Kind::File,
    }
}

/// `ls -l` style permissions, e.g. `drwxr-xr-x`.
pub fn perm_string(mode: Option<u32>) -> String {
    let Some(m) = mode else {
        return String::new();
    };
    let t = match kind(Some(m)) {
        Kind::Dir => 'd',
        Kind::Link => 'l',
        Kind::File => '-',
        Kind::Other => '?',
    };
    let mut s = String::with_capacity(10);
    s.push(t);
    for shift in [6u32, 3, 0] {
        let bits = (m >> shift) & 7;
        s.push(if bits & 4 != 0 { 'r' } else { '-' });
        s.push(if bits & 2 != 0 { 'w' } else { '-' });
        s.push(if bits & 1 != 0 { 'x' } else { '-' });
    }
    s
}

/// Directories (and links to them) first, then by name, case-insensitively.
pub fn sort_entries(entries: &mut [Entry]) {
    entries.sort_by(|a, b| {
        let da = a.kind == Kind::Dir || a.link_dir;
        let db = b.kind == Kind::Dir || b.link_dir;
        db.cmp(&da)
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
            .then_with(|| a.name.cmp(&b.name))
    });
}

/// A remote path from the UI: not empty, bounded, no NUL.
pub fn validate_path(path: &str) -> Result<(), SftpError> {
    if path.is_empty() {
        return Err(SftpError::NoPath);
    }
    if path.len() > MAX_PATH || path.contains('\0') {
        return Err(SftpError::BadPath);
    }
    Ok(())
}

/// A single name for a new folder or a rename.
pub fn validate_name(name: &str) -> Result<(), SftpError> {
    if name.is_empty() {
        return Err(SftpError::NoName);
    }
    if name.len() > MAX_NAME {
        return Err(SftpError::LongName);
    }
    if name == "." || name == ".." || name.contains('/') || name.contains('\0') {
        return Err(SftpError::BadName(name.to_string()));
    }
    Ok(())
}

/// Join a remote directory and a name with exactly one slash.
pub fn join(dir: &str, name: &str) -> String {
    if dir.is_empty() {
        name.to_string()
    } else if dir.ends_with('/') {
        format!("{dir}{name}")
    } else {
        format!("{dir}/{name}")
    }
}

/// The last component of a remote path.
pub fn base_name(path: &str) -> &str {
    let trimmed = path.trim_end_matches('/');
    trimmed.rsplit('/').next().unwrap_or(trimmed)
}

const RESERVED: &[&str] = &[
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

/// A file name that is safe to create in a local folder on any OS, from a
/// name the (untrusted) server chose. Path separators, `..`, control and
/// Windows-reserved characters and device names cannot escape the folder or
/// fail on Windows.
pub fn safe_local_name(remote: &str) -> Result<String, SftpError> {
    let mut s: String = remote
        .chars()
        .map(|c| match c {
            '/' | '\\' | '<' | '>' | ':' | '"' | '|' | '?' | '*' => '_',
            c if c.is_control() => '_',
            c => c,
        })
        .collect();
    // Windows drops trailing dots and spaces, which could change the name.
    while s.ends_with('.') || s.ends_with(' ') {
        s.pop();
    }
    if s.is_empty() || s.chars().all(|c| c == '.') {
        return Err(SftpError::BadName(remote.to_string()));
    }
    let stem = s.split('.').next().unwrap_or("").to_ascii_uppercase();
    if RESERVED.contains(&stem.as_str()) {
        s.insert(0, '_');
    }
    if s.len() > MAX_NAME {
        let mut end = MAX_NAME;
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        s.truncate(end);
    }
    Ok(s)
}

/// Temporary name used while uploading, renamed into place at the end.
pub fn upload_temp_name(name: &str) -> String {
    let mut base = name.to_string();
    let max = MAX_NAME - ".net3po-part".len() - 1;
    if base.len() > max {
        let mut end = max;
        while !base.is_char_boundary(end) {
            end -= 1;
        }
        base.truncate(end);
    }
    format!(".{base}.net3po-part")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kinds_and_perms() {
        assert_eq!(kind(Some(0o040755)), Kind::Dir);
        assert_eq!(kind(Some(0o100644)), Kind::File);
        assert_eq!(kind(Some(0o120777)), Kind::Link);
        assert_eq!(kind(Some(0o020666)), Kind::Other);
        assert_eq!(kind(None), Kind::File);
        assert_eq!(perm_string(Some(0o040755)), "drwxr-xr-x");
        assert_eq!(perm_string(Some(0o100640)), "-rw-r-----");
        assert_eq!(perm_string(Some(0o120777)), "lrwxrwxrwx");
        assert_eq!(perm_string(None), "");
    }

    #[test]
    fn paths() {
        assert_eq!(join("/home/admin", "x.cfg"), "/home/admin/x.cfg");
        assert_eq!(join("/", "etc"), "/etc");
        assert_eq!(join("", "x"), "x");

        assert_eq!(base_name("/a/b/c.txt"), "c.txt");
        assert_eq!(base_name("/a/b/"), "b");
        assert_eq!(base_name("c"), "c");
    }

    #[test]
    fn names() {
        assert!(validate_name("backup").is_ok());
        assert_eq!(validate_name(""), Err(SftpError::NoName));
        assert!(validate_name("..").is_err());
        assert!(validate_name("a/b").is_err());
        assert!(validate_name(&"x".repeat(256)).is_err());
        assert!(validate_path("/x").is_ok());
        assert!(validate_path("").is_err());
        assert!(validate_path("a\0b").is_err());
    }

    #[test]
    fn hostile_names_stay_in_the_folder() {
        assert_eq!(safe_local_name("config.txt").unwrap(), "config.txt");
        assert_eq!(
            safe_local_name("../../etc/passwd").unwrap(),
            ".._.._etc_passwd"
        );
        assert_eq!(safe_local_name("..\\..\\x").unwrap(), ".._.._x");
        assert_eq!(safe_local_name("a:b*c?.txt").unwrap(), "a_b_c_.txt");
        assert_eq!(safe_local_name("bell\u{7}.txt").unwrap(), "bell_.txt");
        assert_eq!(safe_local_name("CON.txt").unwrap(), "_CON.txt");
        assert_eq!(safe_local_name("lpt1").unwrap(), "_lpt1");
        assert_eq!(safe_local_name("name. . ").unwrap(), "name");
        assert!(safe_local_name("..").is_err());
        assert!(safe_local_name("").is_err());
        assert!(safe_local_name(" ").is_err());
        let long = "\u{e9}".repeat(200);
        let s = safe_local_name(&long).unwrap();
        assert!(s.len() <= MAX_NAME);
    }

    #[test]
    fn upload_temp_names_are_bounded() {
        assert_eq!(upload_temp_name("fw.out"), ".fw.out.net3po-part");
        assert!(upload_temp_name(&"x".repeat(255)).len() <= MAX_NAME);
    }

    #[test]
    fn directories_sort_first() {
        let e = |name: &str, kind, link_dir| Entry {
            name: name.into(),
            kind,
            link_dir,
            size: None,
            mtime: None,
            perms: String::new(),
        };
        let mut v = vec![
            e("b.txt", Kind::File, false),
            e("Zdir", Kind::Dir, false),
            e("a.txt", Kind::File, false),
            e("link", Kind::Link, true),
            e("adir", Kind::Dir, false),
        ];
        sort_entries(&mut v);
        let names: Vec<_> = v.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, ["adir", "link", "Zdir", "a.txt", "b.txt"]);
    }
}
