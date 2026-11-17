//! Certificate converter core: read certificates, chains, keys and CSRs from
//! PEM, DER, PKCS#7 and PKCS#12 input, order the chain, match keys, and write
//! PEM, DER, P7B, PFX and key files. No Tauri types; everything is in memory.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use p12_keystore::{
    Certificate, EncryptionAlgorithm, KeyStore, KeyStoreEntry, LocalKeyId, MacAlgorithm,
    Pkcs12Archive, PrivateKey, PrivateKeyChain,
};
use serde::Deserialize;
use thiserror::Error;
use x509_parser::prelude::*;

use super::der::{self, CTX0, INTEGER, OID, SEQUENCE, SET, oid};
use super::keys::{self, Key, KeyError, PublicId};

/// Largest single input.
pub const MAX_INPUT: usize = 10 * 1024 * 1024;
/// Most inputs per request.
pub const MAX_INPUTS: usize = 20;
/// Most certificates kept.
const MAX_CERTS: usize = 200;
/// Most keys kept.
const MAX_KEYS: usize = 20;
/// Most PEM blocks read from one input.
const MAX_BLOCKS: usize = 400;
/// PBKDF2 / MAC iterations for written PFX files (OpenSSL's default).
const PFX_ITERATIONS: u32 = 2048;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ConvertError {
    #[error("no certificate found")]
    NoCert,
    #[error("no private key found")]
    NoKey,
    #[error("several private keys and none matches the certificate; remove the extra keys")]
    AmbiguousKey,
    #[error("the private key does not match the certificate")]
    KeyMismatch,
    #[error("can not check that the {0} key matches the certificate")]
    KeyUnchecked(String),
    #[error("a PFX needs a password")]
    PfxPassword,
    #[error("{0}")]
    Key(#[from] KeyError),
    #[error("PFX: {0}")]
    Pfx(String),
}

/// One input file or pasted text.
#[derive(Debug, Clone)]
pub struct Input {
    pub name: String,
    pub data: Vec<u8>,
}

/// Something found in the inputs, with where it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Found<T> {
    pub value: T,
    pub source: String,
}

/// Everything read from the inputs.
#[derive(Debug, Default)]
pub struct Parsed {
    pub certs: Vec<Found<Vec<u8>>>,
    pub keys: Vec<Found<Key>>,
    pub csrs: Vec<Found<Vec<u8>>>,
    pub warnings: Vec<String>,
    /// An encrypted key or PFX needs a password.
    pub needs_password: bool,
    /// A password was given but did not open something.
    pub wrong_password: bool,
}

impl Parsed {
    fn add_cert(&mut self, der: Vec<u8>, source: &str) {
        if self.certs.iter().any(|c| c.value == der) {
            return;
        }
        if self.certs.len() >= MAX_CERTS {
            self.warn(format!("stopped after {MAX_CERTS} certificates"));
            return;
        }
        if X509Certificate::from_der(&der).is_err() {
            self.warn(format!("{source}: a certificate could not be parsed"));
            return;
        }
        self.certs.push(Found {
            value: der,
            source: source.into(),
        });
    }

    fn add_key(&mut self, r: Result<Key, KeyError>, source: &str) {
        match r {
            Ok(k) => {
                if self.keys.iter().any(|x| x.value.pkcs8 == k.pkcs8) {
                    return;
                }
                if self.keys.len() >= MAX_KEYS {
                    self.warn(format!("stopped after {MAX_KEYS} keys"));
                    return;
                }
                self.keys.push(Found {
                    value: k,
                    source: source.into(),
                });
            }
            Err(KeyError::NeedPassword) => self.needs_password = true,
            Err(KeyError::WrongPassword) => {
                self.needs_password = true;
                self.wrong_password = true;
            }
            Err(e) => self.warn(format!("{source}: {e}")),
        }
    }

    fn warn(&mut self, w: String) {
        if !self.warnings.contains(&w) && self.warnings.len() < 50 {
            self.warnings.push(w);
        }
    }
}

/// A PEM block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PemBlock {
    pub label: String,
    pub headers: Vec<(String, String)>,
    pub der: Vec<u8>,
}

/// Split text into PEM blocks. Text outside blocks is ignored. Blocks with
/// bad base64 are returned as errors.
pub fn pem_blocks(text: &str) -> Vec<Result<PemBlock, String>> {
    let mut out = Vec::new();
    let mut lines = text.lines();
    while let Some(line) = lines.next() {
        let line = line.trim();
        let Some(label) = line
            .strip_prefix("-----BEGIN ")
            .and_then(|l| l.strip_suffix("-----"))
        else {
            continue;
        };
        if out.len() >= MAX_BLOCKS {
            break;
        }
        let label = label.to_string();
        let end = format!("-----END {label}-----");
        let mut headers = Vec::new();
        let mut body = String::new();
        let mut closed = false;
        let mut in_headers = true;
        for l in lines.by_ref() {
            let l = l.trim();
            if l == end {
                closed = true;
                break;
            }
            if in_headers && let Some((k, v)) = l.split_once(':') {
                headers.push((k.trim().to_string(), v.trim().to_string()));
                continue;
            }
            in_headers = false;
            body.push_str(l);
        }
        if !closed {
            out.push(Err(format!("{label} block has no END line")));
            break;
        }
        let body: String = body.chars().filter(|c| !c.is_whitespace()).collect();
        match STANDARD.decode(body.as_bytes()) {
            Ok(der) => out.push(Ok(PemBlock {
                label,
                headers,
                der,
            })),
            Err(_) => out.push(Err(format!("{label} block is not valid base64"))),
        }
    }
    out
}

/// Encode PEM with 64-character lines.
pub fn to_pem(label: &str, der: &[u8]) -> String {
    let b64 = STANDARD.encode(der);
    let mut s = format!("-----BEGIN {label}-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        s.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        s.push('\n');
    }
    s.push_str(&format!("-----END {label}-----\n"));
    s
}

/// Read every input.
pub fn parse(inputs: &[Input], password: &str) -> Parsed {
    let mut p = Parsed::default();
    for input in inputs.iter().take(MAX_INPUTS) {
        if input.data.len() > MAX_INPUT {
            p.warn(format!("{}: larger than 10 MB; skipped", input.name));
            continue;
        }
        parse_one(&mut p, input, password);
    }
    if inputs.len() > MAX_INPUTS {
        p.warn(format!("only the first {MAX_INPUTS} inputs were read"));
    }
    p
}

fn parse_one(p: &mut Parsed, input: &Input, password: &str) {
    let name = input.name.as_str();
    let text = std::str::from_utf8(&input.data).ok();
    if let Some(t) = text.filter(|t| t.contains("-----BEGIN ")) {
        for block in pem_blocks(t) {
            match block {
                Ok(b) => pem_block(p, &b, name, password),
                Err(e) => p.warn(format!("{name}: {e}")),
            }
        }
        return;
    }
    // Bare base64 (for example a PFX pasted from a script).
    if let Some(t) = text {
        let compact: String = t.chars().filter(|c| !c.is_whitespace()).collect();
        if compact.len() >= 64
            && compact
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=')
            && let Ok(der) = STANDARD.decode(compact.as_bytes())
        {
            der_input(p, &der, name, password);
            return;
        }
        if !t.trim().is_empty()
            && t.bytes()
                .all(|b| b.is_ascii_graphic() || b.is_ascii_whitespace())
        {
            p.warn(format!("{name}: text without PEM blocks"));
            return;
        }
    }
    der_input(p, &input.data, name, password);
}

fn pem_block(p: &mut Parsed, b: &PemBlock, name: &str, password: &str) {
    let encrypted = b
        .headers
        .iter()
        .any(|(k, v)| k.eq_ignore_ascii_case("Proc-Type") && v.contains("ENCRYPTED"));
    let dek = b
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("DEK-Info"))
        .map(|(_, v)| v.as_str());
    match b.label.as_str() {
        "CERTIFICATE" | "X509 CERTIFICATE" | "TRUSTED CERTIFICATE" => {
            // TRUSTED CERTIFICATE appends OpenSSL trust settings after the cert.
            match der::read(&b.der) {
                Ok((t, _)) => p.add_cert(t.raw.to_vec(), name),
                Err(_) => p.warn(format!("{name}: a certificate could not be parsed")),
            }
        }
        "CERTIFICATE REQUEST" | "NEW CERTIFICATE REQUEST" => p.csrs.push(Found {
            value: b.der.clone(),
            source: name.into(),
        }),
        "PRIVATE KEY" => p.add_key(keys::from_pkcs8(&b.der), name),
        "ENCRYPTED PRIVATE KEY" => p.add_key(keys::from_encrypted_pkcs8(&b.der, password), name),
        "RSA PRIVATE KEY" | "EC PRIVATE KEY" => {
            let der = if encrypted {
                match keys::decrypt_legacy_pem(&b.der, dek.unwrap_or(""), password) {
                    Ok(d) => d,
                    Err(e) => return p.add_key(Err(e), name),
                }
            } else {
                b.der.clone()
            };
            let r = if b.label.starts_with("RSA") {
                keys::from_pkcs1(&der)
            } else {
                keys::from_sec1(&der)
            };
            // A wrong legacy password often still unpads; the parse then fails.
            let r = match r {
                Err(KeyError::Unrecognized) if encrypted => Err(KeyError::WrongPassword),
                other => other,
            };
            p.add_key(r, name);
        }
        "PKCS7" | "CERTIFICATE CHAIN" => pkcs7(p, &b.der, name),
        "EC PARAMETERS" => {}
        other => p.warn(format!("{name}: skipped a {other} block")),
    }
}

/// Detect and read a binary input.
fn der_input(p: &mut Parsed, data: &[u8], name: &str, password: &str) {
    let Ok((top, _)) = der::read(data) else {
        return p.warn(format!(
            "{name}: not a certificate, key, PKCS#7 or PKCS#12 file"
        ));
    };
    let kids = if top.tag == SEQUENCE {
        top.children().unwrap_or_default()
    } else {
        Vec::new()
    };
    let first = kids.first().map(|k| (k.tag, k.content));
    // PKCS#12: SEQUENCE { INTEGER 3, ContentInfo, MacData }
    if first == Some((INTEGER, &[3][..])) && kids.len() >= 2 {
        return pfx(p, data, name, password);
    }
    // PKCS#7 ContentInfo: SEQUENCE { OID signedData, [0] ... }
    if first == Some((OID, oid::SIGNED_DATA)) {
        return pkcs7(p, data, name);
    }
    if X509Certificate::from_der(top.raw).is_ok() {
        return p.add_cert(top.raw.to_vec(), name);
    }
    if X509CertificationRequest::from_der(top.raw).is_ok() {
        return p.csrs.push(Found {
            value: top.raw.to_vec(),
            source: name.into(),
        });
    }
    if let Ok(k) = keys::from_pkcs8(top.raw) {
        return p.add_key(Ok(k), name);
    }
    if let Ok(k) = keys::from_pkcs1(top.raw) {
        return p.add_key(Ok(k), name);
    }
    if let Ok(k) = keys::from_sec1(top.raw) {
        return p.add_key(Ok(k), name);
    }
    // EncryptedPrivateKeyInfo: SEQUENCE { AlgorithmIdentifier, OCTET STRING }
    if kids.len() == 2 && kids[0].tag == SEQUENCE && kids[1].tag == der::OCTET_STRING {
        return p.add_key(keys::from_encrypted_pkcs8(top.raw, password), name);
    }
    p.warn(format!(
        "{name}: not a certificate, key, PKCS#7 or PKCS#12 file"
    ));
}

/// Read the certificates of a PKCS#7 SignedData (P7B).
fn pkcs7(p: &mut Parsed, data: &[u8], name: &str) {
    let certs = (|| -> Result<Vec<Vec<u8>>, der::DerError> {
        let ci = der::read(data)?.0.expect(SEQUENCE)?.children()?;
        if ci.first().map(|t| t.content) != Some(oid::SIGNED_DATA) {
            return Err(der::DerError::Unexpected);
        }
        let explicit = ci.get(1).ok_or(der::DerError::Unexpected)?.expect(CTX0)?;
        let sd = explicit
            .children()?
            .into_iter()
            .next()
            .ok_or(der::DerError::Unexpected)?
            .expect(SEQUENCE)?;
        let mut out = Vec::new();
        for field in sd.children()? {
            if field.tag == CTX0 {
                for c in field.children()? {
                    if c.tag == SEQUENCE {
                        out.push(c.raw.to_vec());
                    }
                }
            }
        }
        Ok(out)
    })();
    match certs {
        Ok(c) if c.is_empty() => p.warn(format!("{name}: PKCS#7 file holds no certificates")),
        Ok(c) => {
            for der in c {
                p.add_cert(der, name);
            }
        }
        Err(_) => p.warn(format!("{name}: not a valid PKCS#7 file")),
    }
}

/// Read a PKCS#12 (PFX) file.
fn pfx(p: &mut Parsed, data: &[u8], name: &str, password: &str) {
    match Pkcs12Archive::from_pkcs12(data, password) {
        Ok(a) => {
            for c in a.certs {
                p.add_cert(c.cert.as_der().to_vec(), name);
            }
            for k in a.keys {
                p.add_key(keys::from_pkcs8(k.key.as_der()), name);
            }
        }
        Err(p12_keystore::error::Error::MacError(_) | p12_keystore::error::Error::UnpadError) => {
            p.needs_password = true;
            if !password.is_empty() {
                p.wrong_password = true;
            }
        }
        Err(
            e @ (p12_keystore::error::Error::UnsupportedEncryptionScheme
            | p12_keystore::error::Error::UnsupportedMacAlgorithm),
        ) => p.warn(format!("{name}: {e}")),
        Err(_) if password.is_empty() => p.needs_password = true,
        Err(e) => p.warn(format!("{name}: could not read the PFX ({e})")),
    }
}

/// The certificates in chain order, and how complete the chain is.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Chain {
    /// Indexes into `Parsed::certs`, leaf first.
    pub order: Vec<usize>,
    /// The last certificate is self-issued (a root).
    pub ends_at_root: bool,
    /// Issuer of the last certificate when it is not in the input.
    pub missing_issuer: Option<String>,
}

struct Names {
    subject: Vec<u8>,
    issuer: Vec<u8>,
    issuer_text: String,
    ski: Option<Vec<u8>>,
    aki: Option<Vec<u8>>,
    is_ca: bool,
}

fn names(der: &[u8]) -> Option<Names> {
    let (_, c) = X509Certificate::from_der(der).ok()?;
    let mut ski = None;
    let mut aki = None;
    for ext in c.extensions() {
        match ext.parsed_extension() {
            ParsedExtension::SubjectKeyIdentifier(k) => ski = Some(k.0.to_vec()),
            ParsedExtension::AuthorityKeyIdentifier(a) => {
                aki = a.key_identifier.as_ref().map(|k| k.0.to_vec())
            }
            _ => {}
        }
    }
    Some(Names {
        subject: c.subject().as_raw().to_vec(),
        issuer: c.issuer().as_raw().to_vec(),
        issuer_text: c.issuer().to_string(),
        ski,
        aki,
        is_ca: c.is_ca(),
    })
}

/// Index of the certificate each key matches, if any.
pub fn key_matches(certs: &[Found<Vec<u8>>], key: &Key) -> Vec<usize> {
    let Some(pk) = &key.public else {
        return Vec::new();
    };
    certs
        .iter()
        .enumerate()
        .filter(|(_, c)| keys::cert_public(&c.value).as_ref() == Some(pk))
        .map(|(i, _)| i)
        .collect()
}

/// Work out the chain: start at the certificate a key matches (else the one
/// nothing else is issued by), then follow issuers.
pub fn chain(p: &Parsed) -> Chain {
    let info: Vec<Option<Names>> = p.certs.iter().map(|c| names(&c.value)).collect();
    if p.certs.is_empty() {
        return Chain::default();
    }
    let issues_other = |i: usize| {
        info.iter().enumerate().any(|(j, n)| {
            j != i && matches!((&info[i], n), (Some(a), Some(b)) if a.subject == b.issuer && b.subject != b.issuer)
        })
    };
    let keyed = p
        .keys
        .iter()
        .flat_map(|k| key_matches(&p.certs, &k.value))
        .next();
    let leaf = keyed
        .or_else(|| {
            (0..p.certs.len())
                .find(|&i| !issues_other(i) && !info[i].as_ref().is_some_and(|n| n.is_ca))
        })
        .or_else(|| (0..p.certs.len()).find(|&i| !issues_other(i)))
        .unwrap_or(0);
    let mut order = vec![leaf];
    let mut ends_at_root = false;
    let mut missing_issuer = None;
    loop {
        let cur = *order.last().expect("non-empty");
        let Some(n) = &info[cur] else { break };
        if n.subject == n.issuer {
            ends_at_root = true;
            break;
        }
        let candidates: Vec<usize> = (0..p.certs.len())
            .filter(|&j| {
                !order.contains(&j) && info[j].as_ref().is_some_and(|m| m.subject == n.issuer)
            })
            .collect();
        let next = candidates
            .iter()
            .copied()
            .find(|&j| {
                n.aki.is_some() && info[j].as_ref().and_then(|m| m.ski.as_ref()) == n.aki.as_ref()
            })
            .or_else(|| candidates.first().copied());
        match next {
            Some(j) => order.push(j),
            None => {
                missing_issuer = Some(n.issuer_text.clone());
                break;
            }
        }
    }
    Chain {
        order,
        ends_at_root,
        missing_issuer,
    }
}

/// What to write.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(
    tag = "format",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum Output {
    /// Leaf and intermediates (optionally the root), PEM.
    PemChain {
        include_root: bool,
    },
    PemLeaf,
    DerLeaf,
    /// PKCS#7 certificate bag, DER or PEM.
    P7b {
        include_root: bool,
        pem: bool,
    },
    /// PKCS#12 with key, leaf and chain.
    Pfx {
        password: String,
        legacy: bool,
        include_root: bool,
        name: String,
    },
    KeyPkcs8Pem,
    KeyTraditionalPem,
    KeyDer,
}

impl Output {
    /// Output holds a private key.
    pub fn has_key(&self) -> bool {
        matches!(
            self,
            Output::Pfx { .. } | Output::KeyPkcs8Pem | Output::KeyTraditionalPem | Output::KeyDer
        )
    }

    /// Output is text.
    pub fn is_text(&self) -> bool {
        matches!(
            self,
            Output::PemChain { .. }
                | Output::PemLeaf
                | Output::KeyPkcs8Pem
                | Output::KeyTraditionalPem
                | Output::P7b { pem: true, .. }
        )
    }
}

fn chain_certs<'a>(p: &'a Parsed, c: &Chain, include_root: bool) -> Vec<&'a [u8]> {
    let n = c.order.len();
    c.order
        .iter()
        .enumerate()
        .filter(|(i, _)| include_root || !(c.ends_at_root && *i == n - 1 && n > 1))
        .map(|(_, &j)| p.certs[j].value.as_slice())
        .collect()
}

/// The key for the leaf: the one that matches it, or the only key.
fn leaf_key<'a>(p: &'a Parsed, c: &Chain) -> Result<&'a Key, ConvertError> {
    if p.keys.is_empty() {
        return Err(ConvertError::NoKey);
    }
    if let Some(&leaf) = c.order.first()
        && let Some(k) = p
            .keys
            .iter()
            .find(|k| key_matches(&p.certs, &k.value).contains(&leaf))
    {
        return Ok(&k.value);
    }
    if p.keys.len() == 1 {
        Ok(&p.keys[0].value)
    } else {
        Err(ConvertError::AmbiguousKey)
    }
}

/// Build a degenerate PKCS#7 SignedData holding `certs`.
pub fn p7b(certs: &[&[u8]]) -> Vec<u8> {
    let certs_field = der::tlv(CTX0, &certs.concat());
    let sd = der::cons(
        SEQUENCE,
        &[
            &der::small_int(1),
            &der::tlv(SET, &[]),
            &der::cons(SEQUENCE, &[&der::tlv(OID, oid::DATA)]),
            &certs_field,
            &der::tlv(SET, &[]),
        ],
    );
    der::cons(
        SEQUENCE,
        &[&der::tlv(OID, oid::SIGNED_DATA), &der::tlv(CTX0, &sd)],
    )
}

/// Produce the requested output.
pub fn export(p: &Parsed, out: &Output) -> Result<Vec<u8>, ConvertError> {
    let c = chain(p);
    let need_cert = || {
        if c.order.is_empty() {
            Err(ConvertError::NoCert)
        } else {
            Ok(())
        }
    };
    match out {
        Output::PemChain { include_root } => {
            need_cert()?;
            Ok(chain_certs(p, &c, *include_root)
                .iter()
                .map(|d| to_pem("CERTIFICATE", d))
                .collect::<String>()
                .into_bytes())
        }
        Output::PemLeaf => {
            need_cert()?;
            Ok(to_pem("CERTIFICATE", &p.certs[c.order[0]].value).into_bytes())
        }
        Output::DerLeaf => {
            need_cert()?;
            Ok(p.certs[c.order[0]].value.clone())
        }
        Output::P7b { include_root, pem } => {
            need_cert()?;
            let d = p7b(&chain_certs(p, &c, *include_root));
            Ok(if *pem {
                to_pem("PKCS7", &d).into_bytes()
            } else {
                d
            })
        }
        Output::Pfx {
            password,
            legacy,
            include_root,
            name,
        } => {
            need_cert()?;
            if password.is_empty() {
                return Err(ConvertError::PfxPassword);
            }
            let key = leaf_key(p, &c)?;
            let leaf = &p.certs[c.order[0]].value;
            match (&key.public, keys::cert_public(leaf)) {
                (Some(a), Some(b)) if *a == b => {}
                (Some(_), Some(_)) => return Err(ConvertError::KeyMismatch),
                _ => return Err(ConvertError::KeyUnchecked(key.algorithm.into())),
            }
            let certs = chain_certs(p, &c, *include_root)
                .into_iter()
                .map(Certificate::from_der)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| ConvertError::Pfx(e.to_string()))?;
            let pk =
                PrivateKey::from_der(&key.pkcs8).map_err(|e| ConvertError::Pfx(e.to_string()))?;
            let id = ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, leaf);
            let mut ks = KeyStore::new();
            let alias = if name.trim().is_empty() {
                "certificate"
            } else {
                name.trim()
            };
            ks.add_entry(
                alias,
                KeyStoreEntry::PrivateKeyChain(PrivateKeyChain::new(
                    LocalKeyId::from(id.as_ref()),
                    pk,
                    certs,
                )),
            );
            let (enc, mac) = if *legacy {
                (
                    EncryptionAlgorithm::PbeWithShaAnd3KeyTripleDesCbc,
                    MacAlgorithm::HmacSha1,
                )
            } else {
                (
                    EncryptionAlgorithm::PbeWithHmacSha256AndAes256,
                    MacAlgorithm::HmacSha256,
                )
            };
            ks.writer(password)
                .encryption_algorithm(enc)
                .encryption_iterations(PFX_ITERATIONS)
                .mac_algorithm(mac)
                .mac_iterations(PFX_ITERATIONS)
                .write()
                .map_err(|e| ConvertError::Pfx(e.to_string()))
        }
        Output::KeyPkcs8Pem => Ok(to_pem("PRIVATE KEY", &leaf_key(p, &c)?.pkcs8).into_bytes()),
        Output::KeyTraditionalPem => {
            let (label, d) = keys::traditional(leaf_key(p, &c)?)?;
            Ok(to_pem(label, &d).into_bytes())
        }
        Output::KeyDer => Ok(leaf_key(p, &c)?.pkcs8.clone()),
    }
}

/// Whether a public key from a CSR matches a key (for display).
pub fn csr_public(der: &[u8]) -> Option<PublicId> {
    let (_, csr) = X509CertificationRequest::from_der(der).ok()?;
    let spki = &csr.certification_request_info.subject_pki;
    keys::cert_public_from_spki(spki)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::cert_convert::keys::tests::{D, pkcs1, sec1};
    use p256::elliptic_curve::sec1::ToSec1Point;

    const ECDSA_SHA256: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02];

    fn name(cn: &str) -> Vec<u8> {
        let atv = der::cons(
            SEQUENCE,
            &[
                &der::tlv(OID, &[0x55, 0x04, 0x03]),
                &der::tlv(0x0C, cn.as_bytes()),
            ],
        );
        der::cons(SEQUENCE, &[&der::tlv(SET, &atv)])
    }

    /// A certificate with a P-256 key from scalar `d` and a dummy signature.
    fn cert(subject: &str, issuer: &str, d: [u8; 32], serial: u8) -> Vec<u8> {
        let point = p256::SecretKey::from_slice(&d)
            .unwrap()
            .public_key()
            .to_sec1_point(false)
            .as_bytes()
            .to_vec();
        let mut bits = vec![0u8];
        bits.extend_from_slice(&point);
        let spki = der::cons(
            SEQUENCE,
            &[
                &der::cons(
                    SEQUENCE,
                    &[
                        &der::tlv(OID, oid::EC_PUBLIC_KEY),
                        &der::tlv(OID, oid::P256),
                    ],
                ),
                &der::tlv(der::BIT_STRING, &bits),
            ],
        );
        let alg = der::cons(SEQUENCE, &[&der::tlv(OID, ECDSA_SHA256)]);
        let validity = der::cons(
            SEQUENCE,
            &[
                &der::tlv(0x17, b"250101000000Z"),
                &der::tlv(0x17, b"350101000000Z"),
            ],
        );
        let tbs = der::cons(
            SEQUENCE,
            &[
                &der::tlv(CTX0, &der::small_int(2)),
                &der::small_int(serial),
                &alg,
                &name(issuer),
                &validity,
                &name(subject),
                &spki,
            ],
        );
        let sig = der::cons(SEQUENCE, &[&der::small_int(1), &der::small_int(1)]);
        let mut sig_bits = vec![0u8];
        sig_bits.extend_from_slice(&sig);
        der::cons(
            SEQUENCE,
            &[&tbs, &alg, &der::tlv(der::BIT_STRING, &sig_bits)],
        )
    }

    fn input(name: &str, data: Vec<u8>) -> Input {
        Input {
            name: name.into(),
            data,
        }
    }

    /// Leaf (key D) issued by "Test Intermediate", issued by "Test Root".
    fn bundle() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        (
            cert("leaf.example", "Test Intermediate", D, 1),
            cert("Test Intermediate", "Test Root", [8u8; 32], 2),
            cert("Test Root", "Test Root", [9u8; 32], 3),
        )
    }

    #[test]
    fn pem_parsing() {
        let (leaf, _, _) = bundle();
        let text = format!(
            "junk\n{}more junk\n{}",
            to_pem("CERTIFICATE", &leaf),
            "-----BEGIN X-----\n!!\n-----END X-----\n"
        );
        let blocks = pem_blocks(&text);
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0].as_ref().unwrap().der, leaf);
        assert!(blocks[1].is_err());
        assert!(pem_blocks("-----BEGIN A-----\nAAAA\n")[0].is_err());
        let hdr = pem_blocks(
            "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-256-CBC,00\n\nAAAA\n-----END RSA PRIVATE KEY-----",
        );
        assert_eq!(hdr[0].as_ref().unwrap().headers.len(), 2);
    }

    #[test]
    fn chain_order_and_key_match_from_mixed_inputs() {
        let (leaf, int, root) = bundle();
        // Shuffled, mixed formats: root as DER, intermediate and leaf PEM, key SEC1 PEM.
        let pem = format!(
            "{}{}",
            to_pem("CERTIFICATE", &int),
            to_pem("CERTIFICATE", &leaf)
        );
        let p = parse(
            &[
                input("root.cer", root.clone()),
                input("bundle.pem", pem.into_bytes()),
                input(
                    "key.pem",
                    to_pem("EC PRIVATE KEY", &sec1(true, false)).into_bytes(),
                ),
            ],
            "",
        );
        assert_eq!(p.certs.len(), 3, "{:?}", p.warnings);
        assert_eq!(p.keys.len(), 1);
        let c = chain(&p);
        let order: Vec<&[u8]> = c
            .order
            .iter()
            .map(|&i| p.certs[i].value.as_slice())
            .collect();
        assert_eq!(order, [&leaf[..], &int[..], &root[..]]);
        assert!(c.ends_at_root);
        assert_eq!(key_matches(&p.certs, &p.keys[0].value), vec![c.order[0]]);
    }

    #[test]
    fn missing_issuer_is_reported() {
        let (leaf, _, _) = bundle();
        let p = parse(
            &[input("leaf.pem", to_pem("CERTIFICATE", &leaf).into_bytes())],
            "",
        );
        let c = chain(&p);
        assert_eq!(c.order.len(), 1);
        assert!(c.missing_issuer.unwrap().contains("Test Intermediate"));
    }

    #[test]
    fn p7b_round_trip_and_root_option() {
        let (leaf, int, root) = bundle();
        let p = parse(
            &[
                input("a", leaf.clone()),
                input("b", int.clone()),
                input("c", root.clone()),
            ],
            "",
        );
        let out = export(
            &p,
            &Output::P7b {
                include_root: false,
                pem: false,
            },
        )
        .unwrap();
        let back = parse(&[input("x.p7b", out)], "");
        assert_eq!(
            back.certs
                .iter()
                .map(|c| c.value.clone())
                .collect::<Vec<_>>(),
            vec![leaf.clone(), int.clone()]
        );
        let pem = export(
            &p,
            &Output::P7b {
                include_root: true,
                pem: true,
            },
        )
        .unwrap();
        assert!(String::from_utf8_lossy(&pem).starts_with("-----BEGIN PKCS7-----"));
        assert_eq!(parse(&[input("y.p7b", pem)], "").certs.len(), 3);
    }

    #[test]
    fn indefinite_length_p7b_is_read() {
        let (leaf, int, _) = bundle();
        // Same structure as p7b() but with BER indefinite lengths, as Windows writes.
        let indef = |tag: u8, parts: &[&[u8]]| {
            let mut v = vec![tag, 0x80];
            for p in parts {
                v.extend_from_slice(p);
            }
            v.extend_from_slice(&[0, 0]);
            v
        };
        let certs = indef(CTX0, &[&leaf, &int]);
        let sd = indef(
            SEQUENCE,
            &[
                &der::small_int(1),
                &der::tlv(SET, &[]),
                &der::cons(SEQUENCE, &[&der::tlv(OID, oid::DATA)]),
                &certs,
                &der::tlv(SET, &[]),
            ],
        );
        let ci = indef(
            SEQUENCE,
            &[&der::tlv(OID, oid::SIGNED_DATA), &indef(CTX0, &[&sd])],
        );
        let p = parse(&[input("win.p7b", ci)], "");
        assert_eq!(p.certs.len(), 2, "{:?}", p.warnings);
    }

    #[test]
    fn pfx_round_trip_modern_and_legacy() {
        let (leaf, int, root) = bundle();
        let key = to_pem("EC PRIVATE KEY", &sec1(true, true)).into_bytes();
        let p = parse(
            &[
                input("l", leaf.clone()),
                input("i", int.clone()),
                input("r", root),
                input("k", key),
            ],
            "",
        );
        for legacy in [false, true] {
            let out = Output::Pfx {
                password: "pw1234".into(),
                legacy,
                include_root: false,
                name: "web".into(),
            };
            let pfx = export(&p, &out).unwrap();
            let none = parse(&[input("x.pfx", pfx.clone())], "");
            assert!(none.needs_password && !none.wrong_password);
            let wrong = parse(&[input("x.pfx", pfx.clone())], "nope");
            assert!(wrong.wrong_password, "legacy={legacy}");
            let back = parse(&[input("x.pfx", pfx)], "pw1234");
            assert_eq!(back.keys.len(), 1, "legacy={legacy} {:?}", back.warnings);
            assert_eq!(back.keys[0].value.public, p.keys[0].value.public);
            let mut got: Vec<Vec<u8>> = back.certs.iter().map(|c| c.value.clone()).collect();
            got.sort();
            let mut want = vec![leaf.clone(), int.clone()];
            want.sort();
            assert_eq!(got, want);
        }
    }

    #[test]
    fn pfx_checks_key_and_password() {
        let (leaf, _, _) = bundle();
        let wrong_key = parse(
            &[
                input("l", leaf.clone()),
                input("k", to_pem("RSA PRIVATE KEY", &pkcs1()).into_bytes()),
            ],
            "",
        );
        let out = Output::Pfx {
            password: "pw".into(),
            legacy: false,
            include_root: false,
            name: String::new(),
        };
        assert_eq!(export(&wrong_key, &out), Err(ConvertError::KeyMismatch));
        let no_key = parse(&[input("l", leaf)], "");
        assert_eq!(export(&no_key, &out), Err(ConvertError::NoKey));
        let blank = Output::Pfx {
            password: String::new(),
            legacy: false,
            include_root: false,
            name: String::new(),
        };
        assert_eq!(export(&no_key, &blank), Err(ConvertError::PfxPassword));
        assert_eq!(
            export(&Parsed::default(), &Output::PemLeaf),
            Err(ConvertError::NoCert)
        );
    }

    #[test]
    fn key_outputs() {
        let p = parse(&[input("k.der", sec1(true, false))], "");
        assert_eq!(p.keys.len(), 1, "{:?}", p.warnings);
        let p8 = export(&p, &Output::KeyPkcs8Pem).unwrap();
        assert!(String::from_utf8_lossy(&p8).starts_with("-----BEGIN PRIVATE KEY-----"));
        let again = parse(&[input("p8.pem", p8)], "");
        assert_eq!(again.keys[0].value.public, p.keys[0].value.public);
        let trad = export(&p, &Output::KeyTraditionalPem).unwrap();
        assert!(String::from_utf8_lossy(&trad).starts_with("-----BEGIN EC PRIVATE KEY-----"));
        let rsa = parse(
            &[input(
                "r.pem",
                to_pem("RSA PRIVATE KEY", &pkcs1()).into_bytes(),
            )],
            "",
        );
        assert_eq!(rsa.keys[0].value.description, "RSA 16");
        assert_eq!(
            export(&rsa, &Output::KeyDer).unwrap(),
            rsa.keys[0].value.pkcs8
        );
    }

    #[test]
    fn encrypted_legacy_pem_key_needs_password() {
        let text = "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00112233445566778899AABBCCDDEEFF\n\nAAAAAAAAAAAAAAAAAAAAAA==\n-----END RSA PRIVATE KEY-----\n";
        let p = parse(&[input("k.pem", text.as_bytes().to_vec())], "");
        assert!(p.needs_password && !p.wrong_password);
        let p = parse(&[input("k.pem", text.as_bytes().to_vec())], "guess");
        assert!(p.wrong_password);
    }

    #[test]
    fn junk_and_limits() {
        let p = parse(
            &[
                input("a.bin", vec![1, 2, 3]),
                input("b.txt", b"hello world".to_vec()),
            ],
            "",
        );
        assert_eq!(p.warnings.len(), 2, "{:?}", p.warnings);
        let big = parse(&[input("big", vec![0u8; MAX_INPUT + 1])], "");
        assert!(big.warnings[0].contains("10 MB"));
        let (leaf, _, _) = bundle();
        let dup = parse(&[input("a", leaf.clone()), input("b", leaf.clone())], "");
        assert_eq!(dup.certs.len(), 1);
        // Bare base64 of a DER certificate.
        let b64 = STANDARD.encode(&leaf);
        assert_eq!(parse(&[input("b64", b64.into_bytes())], "").certs.len(), 1);
    }

    #[test]
    fn real_fixtures_from_tls_inspector() {
        let ca = include_str!("../tls_inspector/testdata/ca.pem");
        let leaf = include_str!("../tls_inspector/testdata/leaf.pem");
        let p = parse(
            &[
                input("ca.pem", ca.as_bytes().to_vec()),
                input("leaf.pem", leaf.as_bytes().to_vec()),
            ],
            "",
        );
        assert_eq!(p.certs.len(), 2);
        let c = chain(&p);
        assert_eq!(c.order.len(), 2);
        assert!(c.ends_at_root);
        assert_eq!(p.certs[c.order[0]].source, "leaf.pem");
    }

    /// Interop with files made by OpenSSL. Set CERT_INTEROP_DIR and run
    /// with `--ignored`; writes this tool's outputs back for OpenSSL to read.
    #[test]
    #[ignore]
    fn openssl_interop() {
        let Ok(dir) = std::env::var("CERT_INTEROP_DIR") else {
            return;
        };
        let dir = std::path::Path::new(&dir);
        let rd = |n: &str| input(n, std::fs::read(dir.join(n)).unwrap());
        let show = |label: &str, p: &Parsed| {
            let c = chain(p);
            let keys: Vec<String> = p
                .keys
                .iter()
                .map(|k| {
                    format!(
                        "{} matches {:?}",
                        k.value.description,
                        key_matches(&p.certs, &k.value)
                    )
                })
                .collect();
            println!(
                "{label:<16} certs={} keys={keys:?} chain={:?} pw={}/{} warn={:?}",
                p.certs.len(),
                c.order,
                p.needs_password,
                p.wrong_password,
                p.warnings
            );
        };
        for (label, files, pw) in [
            ("rsa pem", vec!["rsa.crt", "rsa.key"], ""),
            ("ec pem+der", vec!["ec.der", "ec.key"], ""),
            ("ed25519", vec!["ed.crt", "ed.key"], ""),
            ("modern pfx", vec!["modern.pfx"], "Secret1"),
            ("modern nopw", vec!["modern.pfx"], ""),
            ("legacy pfx", vec!["legacy.pfx"], "Secret1"),
            ("enc pkcs8", vec!["rsa.crt", "rsa-enc-p8.pem"], "Secret1"),
            ("enc pkcs8 bad", vec!["rsa-enc-p8.pem"], "nope"),
            (
                "enc trad rsa",
                vec!["rsa.crt", "rsa-enc-trad.pem"],
                "Secret1",
            ),
            ("enc trad ec", vec!["ec.crt", "ec-enc-trad.pem"], "Secret1"),
            ("p7b", vec!["both.p7b"], ""),
        ] {
            let inputs: Vec<Input> = files.iter().map(|f| rd(f)).collect();
            show(label, &parse(&inputs, pw));
        }
        let rsa = parse(&[rd("rsa.crt"), rd("rsa.key")], "");
        for (name, out) in [
            (
                "out-modern.pfx",
                Output::Pfx {
                    password: "Secret1".into(),
                    legacy: false,
                    include_root: true,
                    name: "rsa".into(),
                },
            ),
            (
                "out-legacy.pfx",
                Output::Pfx {
                    password: "Secret1".into(),
                    legacy: true,
                    include_root: true,
                    name: "rsa".into(),
                },
            ),
            (
                "out.p7b",
                Output::P7b {
                    include_root: true,
                    pem: false,
                },
            ),
            ("out-trad.key", Output::KeyTraditionalPem),
            ("out-p8.key", Output::KeyPkcs8Pem),
        ] {
            std::fs::write(dir.join(name), export(&rsa, &out).unwrap()).unwrap();
        }
        let ec = parse(&[rd("ec.crt"), rd("ec.key")], "");
        std::fs::write(
            dir.join("out-ec-trad.key"),
            export(&ec, &Output::KeyTraditionalPem).unwrap(),
        )
        .unwrap();
        std::fs::write(
            dir.join("out-ec.pfx"),
            export(
                &ec,
                &Output::Pfx {
                    password: "Secret1".into(),
                    legacy: false,
                    include_root: true,
                    name: String::new(),
                },
            )
            .unwrap(),
        )
        .unwrap();
    }
}
