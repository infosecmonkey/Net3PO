//! Hashing: SHA-256, SHA-512, SHA-1 and MD5 over text or a byte stream, and
//! comparison against an expected digest. Bytes are hashed exactly as given.
//! MD5 and SHA-1 are labelled legacy: fine for spotting corruption, not for
//! proving a file was not tampered with.

use std::io::Read;

use md5::Md5;
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};

/// Read size for streaming.
pub const CHUNK: usize = 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Digests {
    pub sha256: String,
    pub sha512: String,
    pub sha1: String,
    pub md5: String,
    pub bytes: u64,
}

/// All four hashes, updated together so a file is read once.
#[derive(Default)]
pub struct Hasher {
    sha256: Sha256,
    sha512: Sha512,
    sha1: Sha1,
    md5: Md5,
    bytes: u64,
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

impl Hasher {
    pub fn update(&mut self, data: &[u8]) {
        self.sha256.update(data);
        self.sha512.update(data);
        self.sha1.update(data);
        self.md5.update(data);
        self.bytes += data.len() as u64;
    }

    pub fn finish(self) -> Digests {
        Digests {
            sha256: hex(&self.sha256.finalize()),
            sha512: hex(&self.sha512.finalize()),
            sha1: hex(&self.sha1.finalize()),
            md5: hex(&self.md5.finalize()),
            bytes: self.bytes,
        }
    }
}

pub fn hash_bytes(data: &[u8]) -> Digests {
    let mut h = Hasher::default();
    h.update(data);
    h.finish()
}

/// Hash a reader in chunks. `progress` gets bytes read so far and returns
/// false to stop; None means stopped.
pub fn hash_reader<R: Read>(
    mut r: R,
    mut progress: impl FnMut(u64) -> bool,
) -> std::io::Result<Option<Digests>> {
    let mut h = Hasher::default();
    let mut buf = vec![0u8; CHUNK];
    loop {
        let n = match r.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        h.update(&buf[..n]);
        if !progress(h.bytes) {
            return Ok(None);
        }
    }
    Ok(Some(h.finish()))
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Comparison {
    /// Algorithm whose digest matches, if any.
    pub matched: Option<String>,
    /// Algorithm the expected value's length points to.
    pub expected_kind: Option<String>,
    pub normalized: String,
    pub message: String,
}

/// Compare an expected digest (any case; spaces, colons and an
/// `algo:`/`algo=` prefix allowed) with the computed ones.
pub fn compare(expected: &str, d: &Digests) -> Comparison {
    let mut e = expected.trim().to_ascii_lowercase();
    // "SHA256 (file) = abc..." and "sha256:abc..." forms: keep the last field.
    if let Some(i) = e.rfind(['=', ':']).filter(|_| {
        e.chars()
            .any(|c| c.is_ascii_alphabetic() && !c.is_ascii_hexdigit())
    }) {
        e = e[i + 1..].to_string();
    }
    // `sha256sum` output: digest first, then the file name.
    if let Some(first) = e
        .split_whitespace()
        .next()
        .filter(|f| f.len() >= 32 && f.bytes().all(|b| b.is_ascii_hexdigit()))
    {
        e = first.to_string();
    }
    let normalized: String = e
        .chars()
        .filter(|c| !c.is_whitespace() && *c != ':')
        .collect();
    let kind = match normalized.len() {
        32 => Some("MD5"),
        40 => Some("SHA-1"),
        64 => Some("SHA-256"),
        128 => Some("SHA-512"),
        _ => None,
    };
    let all = [
        ("SHA-256", &d.sha256),
        ("SHA-512", &d.sha512),
        ("SHA-1", &d.sha1),
        ("MD5", &d.md5),
    ];
    let matched = all
        .iter()
        .find(|(_, v)| **v == normalized)
        .map(|(n, _)| n.to_string());
    let message = if normalized.is_empty() {
        String::new()
    } else if !normalized.bytes().all(|b| b.is_ascii_hexdigit()) {
        "The expected value is not hexadecimal.".into()
    } else if let Some(m) = &matched {
        format!(
            "Matches the {m} digest. A match shows the bytes are the same as whatever produced this digest; it says nothing about whether that source is trustworthy."
        )
    } else if let Some(k) = kind {
        format!("Does not match: the expected value looks like {k}, and the {k} digest differs.")
    } else {
        format!(
            "Does not match, and its length ({} hex digits) fits none of SHA-256, SHA-512, SHA-1 or MD5.",
            normalized.len()
        )
    };
    Comparison {
        matched,
        expected_kind: kind.map(str::to_string),
        normalized,
        message,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_vectors() {
        let d = hash_bytes(b"abc");
        assert_eq!(
            d.sha256,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(d.sha1, "a9993e364706816aba3e25717850c26c9cd0d89d");
        assert_eq!(d.md5, "900150983cd24fb0d6963f7d28e17f72");
        assert!(d.sha512.starts_with("ddaf35a193617aba"));
        assert_eq!(d.bytes, 3);
        assert_eq!(
            hash_bytes(b"").sha256,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn streaming_matches_one_shot() {
        let data: Vec<u8> = (0..(CHUNK * 2 + 777)).map(|i| (i % 251) as u8).collect();
        let mut calls = 0;
        let s = hash_reader(&data[..], |_| {
            calls += 1;
            true
        })
        .unwrap()
        .unwrap();
        assert_eq!(s, hash_bytes(&data));
        assert_eq!(calls, 3);
        let stopped = hash_reader(&data[..], |_| false).unwrap();
        assert!(stopped.is_none());
    }

    #[test]
    fn comparisons() {
        let d = hash_bytes(b"abc");
        assert_eq!(
            compare(
                "BA7816BF 8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD",
                &d
            )
            .matched
            .as_deref(),
            Some("SHA-256")
        );
        assert_eq!(
            compare(
                "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                &d
            )
            .matched
            .as_deref(),
            Some("SHA-256")
        );
        assert_eq!(compare("SHA256 (file.iso) = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", &d).matched.as_deref(), Some("SHA-256"));
        assert_eq!(
            compare(
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad  Net3PO.dmg",
                &d
            )
            .matched
            .as_deref(),
            Some("SHA-256")
        );
        assert_eq!(
            compare("90:01:50:98:3c:d2:4f:b0:d6:96:3f:7d:28:e1:7f:72", &d)
                .matched
                .as_deref(),
            Some("MD5")
        );
        let miss = compare(&"0".repeat(40), &d);
        assert!(miss.matched.is_none() && miss.message.contains("SHA-1"));
        assert!(compare("abc", &d).message.contains("fits none"));
        assert!(compare("zz", &d).message.contains("not hexadecimal"));
        assert!(compare("  ", &d).message.is_empty());
    }
}
