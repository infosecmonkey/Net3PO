//! Minimal BER reader and DER writer for the structures the certificate
//! converter handles itself (PKCS#7 certificate bags, private key wrappers).
//! The reader accepts BER indefinite lengths, as Windows writes in .p7b
//! files, and bounds nesting depth and length sizes.

use thiserror::Error;

/// Deepest nesting the reader follows.
const MAX_DEPTH: usize = 32;

pub const SEQUENCE: u8 = 0x30;
pub const SET: u8 = 0x31;
pub const INTEGER: u8 = 0x02;
pub const BIT_STRING: u8 = 0x03;
pub const OCTET_STRING: u8 = 0x04;
pub const NULL: u8 = 0x05;
pub const OID: u8 = 0x06;
/// `[0]` constructed (explicit or implicit SET/SEQUENCE).
pub const CTX0: u8 = 0xA0;
/// `[1]` constructed.
pub const CTX1: u8 = 0xA1;

/// Encoded object identifier contents.
pub mod oid {
    pub const SIGNED_DATA: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02];
    pub const DATA: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01];
    pub const RSA: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01];
    pub const EC_PUBLIC_KEY: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
    pub const P256: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
    pub const P384: &[u8] = &[0x2B, 0x81, 0x04, 0x00, 0x22];
    pub const P521: &[u8] = &[0x2B, 0x81, 0x04, 0x00, 0x23];
    pub const ED25519: &[u8] = &[0x2B, 0x65, 0x70];
    pub const ED448: &[u8] = &[0x2B, 0x65, 0x71];
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DerError {
    #[error("truncated ASN.1 data")]
    Truncated,
    #[error("unsupported ASN.1 encoding")]
    Unsupported,
    #[error("ASN.1 nested too deeply")]
    TooDeep,
    #[error("unexpected ASN.1 structure")]
    Unexpected,
}

/// One tag-length-value element.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tlv<'a> {
    pub tag: u8,
    /// The value bytes (for indefinite lengths, without the end marker).
    pub content: &'a [u8],
    /// The whole element including header.
    pub raw: &'a [u8],
}

impl<'a> Tlv<'a> {
    /// Child elements of a constructed element.
    pub fn children(&self) -> Result<Vec<Tlv<'a>>, DerError> {
        children(self.content, 1)
    }

    /// Expect this tag.
    pub fn expect(self, tag: u8) -> Result<Self, DerError> {
        if self.tag == tag {
            Ok(self)
        } else {
            Err(DerError::Unexpected)
        }
    }
}

/// Parse one element at the start of `input`; returns it and the rest.
pub fn read(input: &[u8]) -> Result<(Tlv<'_>, &[u8]), DerError> {
    read_at(input, 0)
}

/// Parse `input` as exactly one element (trailing bytes are an error).
pub fn read_one(input: &[u8]) -> Result<Tlv<'_>, DerError> {
    let (t, rest) = read(input)?;
    if rest.is_empty() {
        Ok(t)
    } else {
        Err(DerError::Unexpected)
    }
}

fn read_at(input: &[u8], depth: usize) -> Result<(Tlv<'_>, &[u8]), DerError> {
    if depth > MAX_DEPTH {
        return Err(DerError::TooDeep);
    }
    let tag = *input.first().ok_or(DerError::Truncated)?;
    if tag & 0x1F == 0x1F {
        // High tag numbers do not occur in the structures read here.
        return Err(DerError::Unsupported);
    }
    let first = *input.get(1).ok_or(DerError::Truncated)?;
    let mut pos = 2;
    if first == 0x80 {
        // Indefinite length: children until an end-of-contents marker.
        if tag & 0x20 == 0 {
            return Err(DerError::Unsupported);
        }
        let start = pos;
        loop {
            let rest = input.get(pos..).ok_or(DerError::Truncated)?;
            if rest.len() >= 2 && rest[0] == 0 && rest[1] == 0 {
                let content = &input[start..pos];
                let raw = &input[..pos + 2];
                return Ok((Tlv { tag, content, raw }, &input[pos + 2..]));
            }
            let (child, after) = read_at(rest, depth + 1)?;
            pos += child.raw.len();
            debug_assert_eq!(input.len() - pos, after.len());
        }
    }
    let len = if first & 0x80 == 0 {
        usize::from(first)
    } else {
        let n = usize::from(first & 0x7F);
        if n == 0 || n > 4 {
            return Err(DerError::Unsupported);
        }
        let bytes = input.get(2..2 + n).ok_or(DerError::Truncated)?;
        pos += n;
        bytes
            .iter()
            .fold(0usize, |acc, b| (acc << 8) | usize::from(*b))
    };
    let end = pos.checked_add(len).ok_or(DerError::Truncated)?;
    let content = input.get(pos..end).ok_or(DerError::Truncated)?;
    Ok((
        Tlv {
            tag,
            content,
            raw: &input[..end],
        },
        &input[end..],
    ))
}

fn children(mut content: &[u8], depth: usize) -> Result<Vec<Tlv<'_>>, DerError> {
    let mut out = Vec::new();
    while !content.is_empty() {
        let (t, rest) = read_at(content, depth)?;
        out.push(t);
        content = rest;
    }
    Ok(out)
}

/// Encode a definite-length element.
pub fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len() + 6);
    out.push(tag);
    let len = content.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let skip = bytes.iter().take_while(|b| **b == 0).count();
        out.push(0x80 | (bytes.len() - skip) as u8);
        out.extend_from_slice(&bytes[skip..]);
    }
    out.extend_from_slice(content);
    out
}

/// Encode a constructed element from already encoded parts.
pub fn cons(tag: u8, parts: &[&[u8]]) -> Vec<u8> {
    tlv(tag, &parts.concat())
}

/// A small non-negative INTEGER.
pub fn small_int(v: u8) -> Vec<u8> {
    tlv(INTEGER, &[v])
}

/// Strip leading zero bytes of a big-endian unsigned integer.
pub fn trim_int(b: &[u8]) -> &[u8] {
    let skip = b.iter().take_while(|x| **x == 0).count();
    &b[skip.min(b.len().saturating_sub(1))..]
}

/// Bit length of a big-endian unsigned integer.
pub fn bit_len(b: &[u8]) -> usize {
    let t = trim_int(b);
    match t.first() {
        None | Some(0) => 0,
        Some(f) => (t.len() - 1) * 8 + (8 - f.leading_zeros() as usize),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_definite() {
        let inner = cons(SEQUENCE, &[&small_int(1), &tlv(OCTET_STRING, &[0xAA; 200])]);
        let t = read_one(&inner).unwrap();
        assert_eq!(t.tag, SEQUENCE);
        let kids = t.children().unwrap();
        assert_eq!(kids.len(), 2);
        assert_eq!(kids[1].content.len(), 200);
        assert_eq!(&inner[..3], &[0x30, 0x81, 0xCE]);
    }

    #[test]
    fn indefinite_length() {
        // SEQUENCE (indefinite) { INTEGER 5, OCTET STRING "hi" } EOC, then 0x05 0x00.
        let b = [
            0x30, 0x80, 0x02, 0x01, 0x05, 0x04, 0x02, b'h', b'i', 0, 0, 0x05, 0x00,
        ];
        let (t, rest) = read(&b).unwrap();
        assert_eq!(rest, &[0x05, 0x00]);
        assert_eq!(t.raw.len(), 11);
        let kids = t.children().unwrap();
        assert_eq!(kids[1].content, b"hi");
    }

    #[test]
    fn hostile_input() {
        assert_eq!(read(&[0x30]), Err(DerError::Truncated));
        assert_eq!(read(&[0x30, 0x05, 0x01]), Err(DerError::Truncated));
        assert_eq!(
            read(&[0x30, 0x85, 1, 1, 1, 1, 1]),
            Err(DerError::Unsupported)
        );
        assert_eq!(read(&[0x04, 0x80, 0, 0]), Err(DerError::Unsupported));
        assert_eq!(read(&[0x1F, 0x01, 0x00]), Err(DerError::Unsupported));
        assert_eq!(read(&[0x30, 0x80, 0x02, 0x01]), Err(DerError::Truncated));
        // Deep nesting of indefinite sequences.
        let mut deep = vec![];
        for _ in 0..40 {
            deep.extend_from_slice(&[0x30, 0x80]);
        }
        assert_eq!(read(&deep), Err(DerError::TooDeep));
        assert_eq!(read_one(&[0x05, 0x00, 0x05]), Err(DerError::Unexpected));
    }

    #[test]
    fn integers() {
        assert_eq!(trim_int(&[0, 0, 1, 2]), &[1, 2]);
        assert_eq!(trim_int(&[0]), &[0]);
        assert_eq!(bit_len(&[0x00, 0x80, 0x00]), 16);
        assert_eq!(bit_len(&[0x01]), 1);
        assert_eq!(bit_len(&[]), 0);
    }
}
