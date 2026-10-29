//! Decoding primitives matching Python's behavior closely enough for
//! deobfuscation: lenient base64 (non-alphabet characters dropped, like
//! `b64decode(validate=False)`), base32, base16/hex, base85, rot13, and
//! zlib/gzip/raw-deflate/xz/lzma decompression. Every decompressor stops at
//! [`MAX_OUTPUT`] so a decompression bomb cannot exhaust memory.

use std::io::{self, Read, Write};

use base64::Engine as _;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};

/// Largest output of any single decode step.
pub const MAX_OUTPUT: usize = 10 * 1024 * 1024;

fn lenient(alphabet: &base64::alphabet::Alphabet) -> GeneralPurpose {
    GeneralPurpose::new(
        alphabet,
        GeneralPurposeConfig::new()
            .with_decode_padding_mode(DecodePaddingMode::Indifferent)
            .with_decode_allow_trailing_bits(true),
    )
}

/// Base64 as Python decodes it by default: characters outside the alphabet
/// are discarded, padding is optional.
pub fn b64(data: &[u8], urlsafe: bool) -> Option<Vec<u8>> {
    let (a, b) = if urlsafe { (b'-', b'_') } else { (b'+', b'/') };
    let mut clean: Vec<u8> = data
        .iter()
        .copied()
        .filter(|c| c.is_ascii_alphanumeric() || *c == a || *c == b)
        .collect();
    // A dangling single character cannot decode; drop it like Python's
    // "incorrect padding" case would reject, but keep the rest usable.
    if clean.len() % 4 == 1 {
        clean.pop();
    }
    let engine = if urlsafe {
        lenient(&base64::alphabet::URL_SAFE)
    } else {
        lenient(&base64::alphabet::STANDARD)
    };
    engine.decode(&clean).ok()
}

/// RFC 4648 base32, case-insensitive like `b32decode(casefold=True)`.
pub fn b32(data: &[u8]) -> Option<Vec<u8>> {
    let clean: Vec<u8> = data
        .iter()
        .filter(|c| !c.is_ascii_whitespace())
        .map(|c| c.to_ascii_uppercase())
        .collect();
    data_encoding::BASE32.decode(&clean).ok()
}

/// Hex, ignoring whitespace (as `bytes.fromhex` does).
pub fn hex(data: &[u8]) -> Option<Vec<u8>> {
    let clean: Vec<u8> = data
        .iter()
        .filter(|c| !c.is_ascii_whitespace())
        .map(|c| c.to_ascii_lowercase())
        .collect();
    data_encoding::HEXLOWER_PERMISSIVE.decode(&clean).ok()
}

/// Python's `base64.b85decode` (the RFC 1924 alphabet).
pub fn b85(data: &[u8]) -> Option<Vec<u8>> {
    const ALPHABET: &[u8] =
        b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~";
    let mut table = [255u8; 256];
    for (i, c) in ALPHABET.iter().enumerate() {
        table[*c as usize] = i as u8;
    }
    let clean: Vec<u8> = data
        .iter()
        .copied()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();
    let pad = (5 - clean.len() % 5) % 5;
    let mut out = Vec::with_capacity(clean.len() * 4 / 5 + 4);
    for chunk in clean.chunks(5) {
        let mut acc: u64 = 0;
        for k in 0..5 {
            let c = chunk.get(k).copied().unwrap_or(b'~');
            let v = table[c as usize];
            if v == 255 {
                return None;
            }
            acc = acc * 85 + v as u64;
        }
        if acc > u32::MAX as u64 {
            return None;
        }
        out.extend_from_slice(&(acc as u32).to_be_bytes());
    }
    out.truncate(out.len() - pad);
    Some(out)
}

/// ROT13 on ASCII letters.
pub fn rot13(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'a'..='z' => (((c as u8 - b'a') + 13) % 26 + b'a') as char,
            'A'..='Z' => (((c as u8 - b'A') + 13) % 26 + b'A') as char,
            _ => c,
        })
        .collect()
}

/// A writer that errors once more than [`MAX_OUTPUT`] bytes arrive.
struct Capped(Vec<u8>);

impl Write for Capped {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.0.len() + buf.len() > MAX_OUTPUT {
            return Err(io::Error::other("output limit"));
        }
        self.0.extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn read_capped(mut r: impl Read) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    // Read one byte past the cap to detect overflow.
    let n = r
        .by_ref()
        .take(MAX_OUTPUT as u64 + 1)
        .read_to_end(&mut out)
        .ok()?;
    if n > MAX_OUTPUT {
        return None;
    }
    Some(out)
}

/// zlib.decompress: picks zlib, gzip or raw deflate by the header, the way
/// different `wbits` values would.
pub fn inflate(data: &[u8]) -> Option<Vec<u8>> {
    use flate2::read::{DeflateDecoder, GzDecoder, ZlibDecoder};
    if data.starts_with(&[0x1f, 0x8b]) {
        return read_capped(GzDecoder::new(data));
    }
    if data.len() >= 2
        && data[0] & 0x0f == 8
        && (u16::from(data[0]) << 8 | u16::from(data[1])) % 31 == 0
        && let Some(out) = read_capped(ZlibDecoder::new(data))
    {
        return Some(out);
    }
    read_capped(DeflateDecoder::new(data))
}

/// gzip.decompress.
pub fn gunzip(data: &[u8]) -> Option<Vec<u8>> {
    read_capped(flate2::read::GzDecoder::new(data))
}

/// lzma.decompress in its default auto mode: xz or legacy .lzma.
pub fn unlzma(data: &[u8]) -> Option<Vec<u8>> {
    let mut input = io::BufReader::new(data);
    let mut out = Capped(Vec::new());
    let ok = if data.starts_with(&[0xfd, b'7', b'z', b'X', b'Z', 0x00]) {
        lzma_rs::xz_decompress(&mut input, &mut out).is_ok()
    } else {
        lzma_rs::lzma_decompress(&mut input, &mut out).is_ok()
    };
    ok.then_some(out.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn base64_variants() {
        assert_eq!(b64(b"aGVsbG8=", false).unwrap(), b"hello");
        assert_eq!(b64(b"aGVsbG8", false).unwrap(), b"hello");
        // Whitespace and junk are dropped like Python's default.
        assert_eq!(b64(b"aGVs\nbG8=!", false).unwrap(), b"hello");
        assert_eq!(b64(b"-_8=", true).unwrap(), [0xfb, 0xff]);
    }

    #[test]
    fn base32_hex_b85() {
        assert_eq!(b32(b"nbswy3dp").unwrap(), b"hello");
        assert_eq!(hex(b"68 65 6C6c6f").unwrap(), b"hello");
        assert!(hex(b"6").is_none());
        // Python: base64.b85encode(b"hello") == b"Xk~0{Zv"
        assert_eq!(b85(b"Xk~0{Zv").unwrap(), b"hello");
        assert!(b85(b"\"\"\"").is_none());
    }

    #[test]
    fn rot13_round_trip() {
        assert_eq!(rot13("Hello, World"), "Uryyb, Jbeyq");
        assert_eq!(rot13(&rot13("abcXYZ")), "abcXYZ");
    }

    #[test]
    fn inflate_formats() {
        let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        z.write_all(b"print('hi')").unwrap();
        assert_eq!(inflate(&z.finish().unwrap()).unwrap(), b"print('hi')");

        let mut g = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        g.write_all(b"gz").unwrap();
        let gz = g.finish().unwrap();
        assert_eq!(inflate(&gz).unwrap(), b"gz");
        assert_eq!(gunzip(&gz).unwrap(), b"gz");

        let mut d = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        d.write_all(b"raw").unwrap();
        assert_eq!(inflate(&d.finish().unwrap()).unwrap(), b"raw");

        assert!(inflate(b"not compressed").is_none());
    }

    #[test]
    fn decompression_bomb_is_capped() {
        let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
        let zeros = vec![0u8; 1024 * 1024];
        for _ in 0..12 {
            z.write_all(&zeros).unwrap();
        }
        let bomb = z.finish().unwrap();
        assert!(bomb.len() < 100_000);
        assert!(inflate(&bomb).is_none());
    }

    #[test]
    fn lzma_formats() {
        let mut xz = Vec::new();
        lzma_rs::xz_compress(&mut &b"xz data"[..], &mut xz).unwrap();
        assert_eq!(unlzma(&xz).unwrap(), b"xz data");
        let mut alone = Vec::new();
        lzma_rs::lzma_compress(&mut &b"alone"[..], &mut alone).unwrap();
        assert_eq!(unlzma(&alone).unwrap(), b"alone");
        assert!(unlzma(b"junk").is_none());
    }
}
