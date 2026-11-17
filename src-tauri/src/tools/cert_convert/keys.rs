//! Private keys: normalize PKCS#1, SEC1 and PKCS#8 (plain or encrypted) to
//! PKCS#8, work out the public key, match it to certificates, and write the
//! traditional formats back out.

use aes::{Aes128, Aes192, Aes256};
use cbc::cipher::block_padding::Pkcs7;
use cbc::cipher::{BlockModeDecrypt, KeyIvInit};
use md5::{Digest, Md5};
use thiserror::Error;
use x509_parser::prelude::*;
use x509_parser::public_key::PublicKey;

use super::der::{self, CTX0, CTX1, INTEGER, NULL, OCTET_STRING, OID, SEQUENCE, oid};

#[derive(Debug, Error, PartialEq, Eq)]
pub enum KeyError {
    #[error("not a private key this tool understands")]
    Unrecognized,
    #[error("EC private key without a named curve")]
    NoCurve,
    #[error("the key is encrypted; enter its password")]
    NeedPassword,
    #[error("wrong password for the encrypted key")]
    WrongPassword,
    #[error("unsupported key encryption: {0}")]
    UnsupportedCipher(String),
    #[error("{0} keys have no traditional format; use PKCS#8")]
    NoTraditional(&'static str),
}

impl From<der::DerError> for KeyError {
    fn from(_: der::DerError) -> Self {
        KeyError::Unrecognized
    }
}

/// Public key, normalized for comparison.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicId {
    Rsa {
        n: Vec<u8>,
        e: Vec<u8>,
    },
    /// Uncompressed SEC1 point.
    Ec {
        curve: Vec<u8>,
        point: Vec<u8>,
    },
    Ed25519(Vec<u8>),
}

/// A private key, held as PKCS#8 DER.
#[derive(Clone, PartialEq, Eq)]
pub struct Key {
    pub pkcs8: Vec<u8>,
    /// "RSA 2048", "EC P-256", "Ed25519".
    pub description: String,
    pub algorithm: &'static str,
    pub public: Option<PublicId>,
}

impl std::fmt::Debug for Key {
    // Never print key material.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Key")
            .field("description", &self.description)
            .finish_non_exhaustive()
    }
}

fn curve_name(c: &[u8]) -> &'static str {
    match c {
        oid::P256 => "P-256",
        oid::P384 => "P-384",
        oid::P521 => "P-521",
        _ => "unknown curve",
    }
}

/// Uncompressed form of an EC point on a curve we can do arithmetic on;
/// other curves are returned as given.
fn normalize_point(curve: &[u8], point: &[u8]) -> Vec<u8> {
    use p256::elliptic_curve::sec1::ToSec1Point;
    match curve {
        oid::P256 => p256::PublicKey::from_sec1_bytes(point)
            .map(|p| p.to_sec1_point(false).as_bytes().to_vec())
            .unwrap_or_else(|_| point.to_vec()),
        oid::P384 => p384::PublicKey::from_sec1_bytes(point)
            .map(|p| p.to_sec1_point(false).as_bytes().to_vec())
            .unwrap_or_else(|_| point.to_vec()),
        _ => point.to_vec(),
    }
}

fn derive_ec_public(curve: &[u8], d: &[u8]) -> Option<Vec<u8>> {
    use p256::elliptic_curve::sec1::ToSec1Point;
    match curve {
        oid::P256 => p256::SecretKey::from_slice(d)
            .ok()
            .map(|k| k.public_key().to_sec1_point(false).as_bytes().to_vec()),
        oid::P384 => p384::SecretKey::from_slice(d)
            .ok()
            .map(|k| k.public_key().to_sec1_point(false).as_bytes().to_vec()),
        _ => None,
    }
}

/// Parse a SEC1 ECPrivateKey; returns (private scalar, curve, public point).
/// Private scalar, curve OID (if present), public point (if present).
type Sec1Parts = (Vec<u8>, Option<Vec<u8>>, Option<Vec<u8>>);

fn parse_sec1(der: &[u8]) -> Result<Sec1Parts, KeyError> {
    let seq = der::read_one(der)?.expect(SEQUENCE)?.children()?;
    let version = seq.first().ok_or(KeyError::Unrecognized)?.expect(INTEGER)?;
    if version.content != [1] {
        return Err(KeyError::Unrecognized);
    }
    let d = seq
        .get(1)
        .ok_or(KeyError::Unrecognized)?
        .expect(OCTET_STRING)?
        .content
        .to_vec();
    let mut curve = None;
    let mut public = None;
    for t in &seq[2..] {
        match t.tag {
            CTX0 => curve = Some(der::read_one(t.content)?.expect(OID)?.content.to_vec()),
            CTX1 => {
                let bits = der::read_one(t.content)?.expect(der::BIT_STRING)?;
                // First byte is the unused-bits count.
                public = bits.content.get(1..).map(<[u8]>::to_vec);
            }
            _ => {}
        }
    }
    Ok((d, curve, public))
}

/// Parse PKCS#8 PrivateKeyInfo.
pub fn from_pkcs8(der: &[u8]) -> Result<Key, KeyError> {
    let seq = der::read_one(der)?.expect(SEQUENCE)?.children()?;
    if seq.len() < 3 {
        return Err(KeyError::Unrecognized);
    }
    let version = seq[0].expect(INTEGER)?;
    if version.content != [0] && version.content != [1] {
        return Err(KeyError::Unrecognized);
    }
    let alg = seq[1].expect(SEQUENCE)?.children()?;
    let alg_oid = alg
        .first()
        .ok_or(KeyError::Unrecognized)?
        .expect(OID)?
        .content;
    let private = seq[2].expect(OCTET_STRING)?.content;
    let (description, algorithm, public) = match alg_oid {
        oid::RSA => {
            let rsa = der::read_one(private)?.expect(SEQUENCE)?.children()?;
            let n = der::trim_int(
                rsa.get(1)
                    .ok_or(KeyError::Unrecognized)?
                    .expect(INTEGER)?
                    .content,
            )
            .to_vec();
            let e = der::trim_int(
                rsa.get(2)
                    .ok_or(KeyError::Unrecognized)?
                    .expect(INTEGER)?
                    .content,
            )
            .to_vec();
            (
                format!("RSA {}", der::bit_len(&n)),
                "RSA",
                Some(PublicId::Rsa { n, e }),
            )
        }
        oid::EC_PUBLIC_KEY => {
            let param_curve = match alg.get(1) {
                Some(t) if t.tag == OID => Some(t.content.to_vec()),
                _ => None,
            };
            let (d, inner_curve, point) = parse_sec1(private)?;
            let curve = param_curve.or(inner_curve).ok_or(KeyError::NoCurve)?;
            let point = match point {
                Some(p) => Some(normalize_point(&curve, &p)),
                None => derive_ec_public(&curve, &d),
            };
            let public = point.map(|point| PublicId::Ec {
                curve: curve.clone(),
                point,
            });
            (format!("EC {}", curve_name(&curve)), "EC", public)
        }
        oid::ED25519 => {
            let seed = der::read_one(private)?.expect(OCTET_STRING)?.content;
            let public = ring::signature::Ed25519KeyPair::from_seed_unchecked(seed)
                .ok()
                .map(|kp| {
                    PublicId::Ed25519(ring::signature::KeyPair::public_key(&kp).as_ref().to_vec())
                });
            ("Ed25519".to_string(), "Ed25519", public)
        }
        oid::ED448 => ("Ed448".to_string(), "Ed448", None),
        _ => ("Unknown algorithm".to_string(), "unknown", None),
    };
    Ok(Key {
        pkcs8: der.to_vec(),
        description,
        algorithm,
        public,
    })
}

/// Wrap a PKCS#1 RSAPrivateKey into PKCS#8.
pub fn from_pkcs1(der: &[u8]) -> Result<Key, KeyError> {
    let seq = der::read_one(der)?.expect(SEQUENCE)?.children()?;
    if seq.len() < 9 || seq.iter().any(|t| t.tag != INTEGER) {
        return Err(KeyError::Unrecognized);
    }
    let alg = der::cons(SEQUENCE, &[&der::tlv(OID, oid::RSA), &der::tlv(NULL, &[])]);
    from_pkcs8(&der::cons(
        SEQUENCE,
        &[&der::small_int(0), &alg, &der::tlv(OCTET_STRING, der)],
    ))
}

/// Wrap a SEC1 ECPrivateKey (with its curve) into PKCS#8.
pub fn from_sec1(der: &[u8]) -> Result<Key, KeyError> {
    let (_, curve, _) = parse_sec1(der)?;
    let curve = curve.ok_or(KeyError::NoCurve)?;
    let alg = der::cons(
        SEQUENCE,
        &[&der::tlv(OID, oid::EC_PUBLIC_KEY), &der::tlv(OID, &curve)],
    );
    from_pkcs8(&der::cons(
        SEQUENCE,
        &[&der::small_int(0), &alg, &der::tlv(OCTET_STRING, der)],
    ))
}

/// Decrypt a PKCS#8 EncryptedPrivateKeyInfo (PBES2).
pub fn from_encrypted_pkcs8(der: &[u8], password: &str) -> Result<Key, KeyError> {
    if password.is_empty() {
        return Err(KeyError::NeedPassword);
    }
    let enc =
        pkcs8::EncryptedPrivateKeyInfoRef::try_from(der).map_err(|_| KeyError::Unrecognized)?;
    let doc = enc.decrypt(password).map_err(|e| match e {
        pkcs8::Error::EncryptedPrivateKey(pkcs8::pkcs5::Error::UnsupportedAlgorithm { oid }) => {
            KeyError::UnsupportedCipher(oid.to_string())
        }
        _ => KeyError::WrongPassword,
    })?;
    from_pkcs8(doc.as_bytes()).map_err(|_| KeyError::WrongPassword)
}

/// Decrypt the body of a legacy OpenSSL encrypted PEM key ("Proc-Type:
/// 4,ENCRYPTED" with "DEK-Info: <cipher>,<iv>").
pub fn decrypt_legacy_pem(
    body: &[u8],
    dek_info: &str,
    password: &str,
) -> Result<Vec<u8>, KeyError> {
    if password.is_empty() {
        return Err(KeyError::NeedPassword);
    }
    let (cipher, iv_hex) = dek_info
        .split_once(',')
        .ok_or(KeyError::UnsupportedCipher(dek_info.into()))?;
    let cipher = cipher.trim().to_ascii_uppercase();
    let iv = hex_decode(iv_hex.trim()).ok_or(KeyError::UnsupportedCipher(dek_info.into()))?;
    let (key_len, iv_len) = match cipher.as_str() {
        "AES-128-CBC" => (16, 16),
        "AES-192-CBC" => (24, 16),
        "AES-256-CBC" => (32, 16),
        "DES-EDE3-CBC" => (24, 8),
        _ => return Err(KeyError::UnsupportedCipher(cipher)),
    };
    if iv.len() != iv_len {
        return Err(KeyError::UnsupportedCipher(cipher));
    }
    let key = evp_bytes_to_key(password.as_bytes(), &iv[..8], key_len);
    let out = match cipher.as_str() {
        "AES-128-CBC" => cbc::Decryptor::<Aes128>::new_from_slices(&key, &iv)
            .map_err(|_| KeyError::WrongPassword)?
            .decrypt_padded_vec::<Pkcs7>(body),
        "AES-192-CBC" => cbc::Decryptor::<Aes192>::new_from_slices(&key, &iv)
            .map_err(|_| KeyError::WrongPassword)?
            .decrypt_padded_vec::<Pkcs7>(body),
        "AES-256-CBC" => cbc::Decryptor::<Aes256>::new_from_slices(&key, &iv)
            .map_err(|_| KeyError::WrongPassword)?
            .decrypt_padded_vec::<Pkcs7>(body),
        _ => cbc::Decryptor::<des::TdesEde3>::new_from_slices(&key, &iv)
            .map_err(|_| KeyError::WrongPassword)?
            .decrypt_padded_vec::<Pkcs7>(body),
    };
    out.map_err(|_| KeyError::WrongPassword)
}

/// OpenSSL's EVP_BytesToKey with MD5 and one iteration.
fn evp_bytes_to_key(password: &[u8], salt: &[u8], len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len + 16);
    let mut prev: Vec<u8> = Vec::new();
    while out.len() < len {
        let mut h = Md5::new();
        h.update(&prev);
        h.update(password);
        h.update(salt);
        prev = h.finalize().to_vec();
        out.extend_from_slice(&prev);
    }
    out.truncate(len);
    out
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) || s.len() > 64 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

/// Public key of a certificate, normalized for comparison.
pub fn cert_public(cert_der: &[u8]) -> Option<PublicId> {
    let (_, cert) = X509Certificate::from_der(cert_der).ok()?;
    cert_public_from_spki(cert.public_key())
}

/// Normalized public key from a SubjectPublicKeyInfo.
pub fn cert_public_from_spki(spki: &SubjectPublicKeyInfo) -> Option<PublicId> {
    let alg_oid = spki.algorithm.algorithm.as_bytes();
    if alg_oid == oid::ED25519 {
        return Some(PublicId::Ed25519(spki.subject_public_key.data.to_vec()));
    }
    match spki.parsed().ok()? {
        PublicKey::RSA(r) => Some(PublicId::Rsa {
            n: der::trim_int(r.modulus).to_vec(),
            e: der::trim_int(r.exponent).to_vec(),
        }),
        PublicKey::EC(p) => {
            let curve = spki
                .algorithm
                .parameters
                .as_ref()?
                .as_oid()
                .ok()?
                .as_bytes()
                .to_vec();
            let point = normalize_point(&curve, p.data());
            Some(PublicId::Ec { curve, point })
        }
        _ => None,
    }
}

/// The PKCS#8 private key bytes inside a key's PrivateKeyInfo.
fn inner_private(pkcs8: &[u8]) -> Result<(Vec<u8>, Option<Vec<u8>>), KeyError> {
    let seq = der::read_one(pkcs8)?.children()?;
    let alg = seq.get(1).ok_or(KeyError::Unrecognized)?.children()?;
    let curve = match alg.get(1) {
        Some(t) if t.tag == OID => Some(t.content.to_vec()),
        _ => None,
    };
    let private = seq
        .get(2)
        .ok_or(KeyError::Unrecognized)?
        .expect(OCTET_STRING)?
        .content
        .to_vec();
    Ok((private, curve))
}

/// Traditional encoding: PEM label and DER (PKCS#1 for RSA, SEC1 with the
/// curve for EC).
pub fn traditional(key: &Key) -> Result<(&'static str, Vec<u8>), KeyError> {
    let (private, curve) = inner_private(&key.pkcs8)?;
    match key.algorithm {
        "RSA" => Ok(("RSA PRIVATE KEY", private)),
        "EC" => {
            let curve = curve.ok_or(KeyError::NoCurve)?;
            let seq = der::read_one(&private)?.expect(SEQUENCE)?.children()?;
            let mut parts: Vec<Vec<u8>> = Vec::new();
            let mut has_curve = false;
            for t in &seq {
                if t.tag == CTX0 {
                    has_curve = true;
                }
                if t.tag == CTX1 && !has_curve {
                    parts.push(der::tlv(CTX0, &der::tlv(OID, &curve)));
                    has_curve = true;
                }
                parts.push(t.raw.to_vec());
            }
            if !has_curve {
                parts.push(der::tlv(CTX0, &der::tlv(OID, &curve)));
            }
            let refs: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
            Ok(("EC PRIVATE KEY", der::cons(SEQUENCE, &refs)))
        }
        "Ed25519" => Err(KeyError::NoTraditional("Ed25519")),
        "Ed448" => Err(KeyError::NoTraditional("Ed448")),
        _ => Err(KeyError::NoTraditional("These")),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use p256::elliptic_curve::sec1::ToSec1Point;

    /// A fixed P-256 test scalar (not a real key).
    pub(crate) const D: [u8; 32] = [7u8; 32];

    pub(crate) fn sec1(with_curve: bool, with_public: bool) -> Vec<u8> {
        let sk = p256::SecretKey::from_slice(&D).unwrap();
        let point = sk.public_key().to_sec1_point(false).as_bytes().to_vec();
        let mut parts: Vec<Vec<u8>> = vec![der::small_int(1), der::tlv(OCTET_STRING, &D)];
        if with_curve {
            parts.push(der::tlv(CTX0, &der::tlv(OID, oid::P256)));
        }
        if with_public {
            let mut bits = vec![0u8];
            bits.extend_from_slice(&point);
            parts.push(der::tlv(CTX1, &der::tlv(der::BIT_STRING, &bits)));
        }
        let refs: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
        der::cons(SEQUENCE, &refs)
    }

    /// A toy PKCS#1 RSA key (tiny numbers; only n and e matter here).
    pub(crate) fn pkcs1() -> Vec<u8> {
        let ints: Vec<Vec<u8>> = [
            &[0u8][..],
            &[0x00, 0xC9, 0x01],
            &[0x01, 0x00, 0x01],
            &[5],
            &[7],
            &[11],
            &[13],
            &[17],
            &[19],
        ]
        .iter()
        .map(|b| der::tlv(INTEGER, b))
        .collect();
        let refs: Vec<&[u8]> = ints.iter().map(Vec::as_slice).collect();
        der::cons(SEQUENCE, &refs)
    }

    #[test]
    fn ec_key_forms_agree() {
        let a = from_sec1(&sec1(true, true)).unwrap();
        let b = from_sec1(&sec1(true, false)).unwrap();
        assert_eq!(a.description, "EC P-256");
        assert!(a.public.is_some());
        assert_eq!(
            a.public, b.public,
            "derived public key matches the embedded one"
        );
        assert_eq!(from_sec1(&sec1(false, true)), Err(KeyError::NoCurve));
        // Traditional output puts the curve back.
        let (label, trad) = traditional(&b).unwrap();
        assert_eq!(label, "EC PRIVATE KEY");
        assert_eq!(from_sec1(&trad).unwrap().public, a.public);
    }

    #[test]
    fn rsa_key_round_trip() {
        let k = from_pkcs1(&pkcs1()).unwrap();
        assert_eq!(k.description, "RSA 16");
        assert_eq!(
            k.public,
            Some(PublicId::Rsa {
                n: vec![0xC9, 0x01],
                e: vec![1, 0, 1]
            })
        );
        let (label, trad) = traditional(&k).unwrap();
        assert_eq!(label, "RSA PRIVATE KEY");
        assert_eq!(trad, pkcs1());
        assert_eq!(from_pkcs8(&k.pkcs8).unwrap(), k);
    }

    #[test]
    fn ed25519_public_from_seed() {
        let seed = [9u8; 32];
        let inner = der::tlv(OCTET_STRING, &seed);
        let alg = der::cons(SEQUENCE, &[&der::tlv(OID, oid::ED25519)]);
        let p8 = der::cons(
            SEQUENCE,
            &[&der::small_int(0), &alg, &der::tlv(OCTET_STRING, &inner)],
        );
        let k = from_pkcs8(&p8).unwrap();
        assert_eq!(k.description, "Ed25519");
        assert!(matches!(k.public, Some(PublicId::Ed25519(ref p)) if p.len() == 32));
        assert_eq!(traditional(&k), Err(KeyError::NoTraditional("Ed25519")));
    }

    #[test]
    fn junk_is_rejected() {
        assert_eq!(from_pkcs8(b"nope"), Err(KeyError::Unrecognized));
        assert_eq!(
            from_pkcs1(&der::cons(SEQUENCE, &[&der::small_int(0)])),
            Err(KeyError::Unrecognized)
        );
        assert_eq!(from_encrypted_pkcs8(b"x", ""), Err(KeyError::NeedPassword));
        assert_eq!(
            from_encrypted_pkcs8(b"x", "pw"),
            Err(KeyError::Unrecognized)
        );
        assert!(format!("{:?}", from_pkcs1(&pkcs1()).unwrap()).contains("RSA"));
        assert!(!format!("{:?}", from_pkcs1(&pkcs1()).unwrap()).contains("pkcs8"));
    }

    #[test]
    fn legacy_pem_decrypt() {
        use cbc::cipher::BlockModeEncrypt;
        let plain = pkcs1();
        let iv = [3u8; 16];
        let key = evp_bytes_to_key(b"secret", &iv[..8], 32);
        let ct = cbc::Encryptor::<Aes256>::new_from_slices(&key, &iv)
            .unwrap()
            .encrypt_padded_vec::<Pkcs7>(&plain);
        let dek = format!("AES-256-CBC,{}", "03".repeat(16));
        assert_eq!(decrypt_legacy_pem(&ct, &dek, "secret").unwrap(), plain);
        assert_eq!(
            decrypt_legacy_pem(&ct, &dek, ""),
            Err(KeyError::NeedPassword)
        );
        assert!(decrypt_legacy_pem(&ct, &dek, "wrong").is_err());
        assert!(matches!(
            decrypt_legacy_pem(&ct, "BF-CBC,00", "x"),
            Err(KeyError::UnsupportedCipher(_))
        ));
    }

    #[test]
    fn evp_known_answer() {
        // openssl enc -aes-256-cbc -k password -S 0102030405060708 -P -md md5
        let k = evp_bytes_to_key(b"password", &[1, 2, 3, 4, 5, 6, 7, 8], 32);
        assert_eq!(
            hex_decode("E7B0971E52CA5CC8D0539FB3412F6316F7BA2E6EE293D9F3457B99436B51CE02").unwrap(),
            k
        );
    }
}
