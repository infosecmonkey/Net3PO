//! Offline decoding of X.509 certificates and PKCS#10 CSRs from PEM or DER.
//! Decoding shows what a certificate says; it does not establish trust or
//! check revocation. Private keys are detected and refused, never parsed.

use serde::Serialize;
use x509_parser::certification_request::X509CertificationRequest;
use x509_parser::extensions::{DistributionPointName, GeneralName, ParsedExtension};
use x509_parser::pem::Pem;
use x509_parser::prelude::{FromDer, X509Certificate};
use x509_parser::x509::{AlgorithmIdentifier, SubjectPublicKeyInfo};

use super::names;

/// Largest input accepted for decoding.
pub const MAX_INPUT: usize = 1024 * 1024;
/// Most certificates or CSRs decoded from one input.
pub const MAX_ITEMS: usize = 50;
/// Most names of one kind kept from a certificate.
const MAX_NAMES: usize = 500;

#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Sans {
    pub dns: Vec<String>,
    pub ip: Vec<String>,
    pub email: Vec<String>,
    pub uri: Vec<String>,
}

impl Sans {
    fn push(&mut self, g: &GeneralName) {
        let (list, v) = match g {
            GeneralName::DNSName(s) => (&mut self.dns, s.to_string()),
            GeneralName::RFC822Name(s) => (&mut self.email, s.to_string()),
            GeneralName::URI(s) => (&mut self.uri, s.to_string()),
            GeneralName::IPAddress(b) => (&mut self.ip, names::ip_bytes(b)),
            _ => return,
        };
        if list.len() < MAX_NAMES {
            list.push(v);
        }
    }

    fn is_empty(&self) -> bool {
        self.dns.is_empty() && self.ip.is_empty() && self.email.is_empty() && self.uri.is_empty()
    }
}

/// Public key summary.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct KeyInfo {
    /// "RSA", "EC", "Ed25519" and so on.
    pub algorithm: String,
    pub bits: usize,
    /// Named curve for EC keys.
    pub curve: String,
    /// SHA-256 of the SubjectPublicKeyInfo, for pinning.
    pub spki_sha256: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum Validity {
    NotYetValid,
    Valid,
    Expired,
}

/// Everything shown for one certificate.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CertInfo {
    pub subject: String,
    pub subject_cn: String,
    pub issuer: String,
    pub serial: String,
    pub version: u32,
    pub not_before_ms: i64,
    pub not_after_ms: i64,
    pub validity: Validity,
    /// Whole days left (negative once expired).
    pub days_left: i64,
    pub sans: Sans,
    pub key: KeyInfo,
    pub signature_algorithm: String,
    pub is_ca: bool,
    pub path_len: Option<u32>,
    pub key_usage: Vec<String>,
    pub extended_key_usage: Vec<String>,
    pub subject_key_id: String,
    pub authority_key_id: String,
    pub ocsp: Vec<String>,
    pub ca_issuers: Vec<String>,
    pub crl: Vec<String>,
    /// Subject equals issuer and the signature verifies with its own key.
    pub self_signed: bool,
    pub sha256: String,
    pub sha1: String,
    /// Observations worth a look (weak key, SHA-1 signature, no SANs, ...).
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CsrInfo {
    pub subject: String,
    pub subject_cn: String,
    pub sans: Sans,
    pub key: KeyInfo,
    pub signature_algorithm: String,
    /// The CSR is signed by the key it carries (proof of possession).
    pub signature_valid: bool,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum Decoded {
    Certificate { label: String, cert: Box<CertInfo> },
    Csr { label: String, csr: Box<CsrInfo> },
}

#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DecodeResult {
    pub items: Vec<Decoded>,
    pub warnings: Vec<String>,
    /// A private key was present and ignored.
    pub private_key_skipped: bool,
}

fn hex(bytes: &[u8], sep: &str) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(sep)
}

pub fn sha256_hex(der: &[u8]) -> String {
    hex(
        ring::digest::digest(&ring::digest::SHA256, der).as_ref(),
        ":",
    )
}

fn sha1_hex(der: &[u8]) -> String {
    hex(
        ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, der).as_ref(),
        ":",
    )
}

fn common_name(name: &x509_parser::x509::X509Name) -> String {
    name.iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .unwrap_or_default()
        .to_string()
}

fn key_info(spki: &SubjectPublicKeyInfo) -> KeyInfo {
    let oid = spki.algorithm.algorithm.to_id_string();
    let algorithm = names::key_algorithm(&oid).to_string();
    let curve = spki
        .algorithm
        .parameters
        .as_ref()
        .and_then(|p| p.as_oid().ok())
        .map(|o| names::curve(&o.to_id_string()).to_string())
        .unwrap_or_default();
    let bits = match oid.as_str() {
        names::OID_ED25519 => 256,
        names::OID_ED448 => 456,
        _ => spki.parsed().map(|k| k.key_size()).unwrap_or(0),
    };
    KeyInfo {
        algorithm,
        bits,
        curve,
        spki_sha256: sha256_hex(spki.raw),
    }
}

fn sig_name(alg: &AlgorithmIdentifier) -> String {
    names::signature_algorithm(&alg.algorithm.to_id_string())
}

fn key_notes(key: &KeyInfo, sig: &str, notes: &mut Vec<String>) {
    if key.algorithm == "RSA" && key.bits > 0 && key.bits < 2048 {
        notes.push(format!(
            "RSA key is {} bits; 2048 is the minimum browsers accept",
            key.bits
        ));
    }
    if sig.contains("SHA-1") || sig.contains("MD5") {
        notes.push(format!(
            "Signed with {sig}, which is no longer trusted for TLS"
        ));
    }
}

/// Decode one DER certificate. `now_ms` decides the validity status.
pub fn decode_cert(der: &[u8], now_ms: i64) -> Result<CertInfo, String> {
    let (rest, c) =
        X509Certificate::from_der(der).map_err(|e| format!("not a certificate: {e}"))?;
    let der = &der[..der.len() - rest.len()];
    let mut sans = Sans::default();
    let mut key_usage = Vec::new();
    let mut eku = Vec::new();
    let (mut ski, mut aki) = (String::new(), String::new());
    let (mut ocsp, mut ca_issuers, mut crl) = (Vec::new(), Vec::new(), Vec::new());
    let mut path_len = None;
    let mut is_ca = false;

    for ext in c.extensions() {
        match ext.parsed_extension() {
            ParsedExtension::SubjectAlternativeName(san) => {
                for g in &san.general_names {
                    sans.push(g);
                }
            }
            ParsedExtension::KeyUsage(ku) => {
                key_usage = ku.to_string().split(", ").map(str::to_string).collect();
            }
            ParsedExtension::ExtendedKeyUsage(e) => {
                for (on, name) in [
                    (e.server_auth, "TLS server"),
                    (e.client_auth, "TLS client"),
                    (e.code_signing, "Code signing"),
                    (e.email_protection, "Email"),
                    (e.time_stamping, "Time stamping"),
                    (e.ocsp_signing, "OCSP signing"),
                    (e.any, "Any"),
                ] {
                    if on {
                        eku.push(name.to_string());
                    }
                }
                eku.extend(e.other.iter().take(20).map(|o| o.to_id_string()));
            }
            ParsedExtension::BasicConstraints(b) => {
                is_ca = b.ca;
                path_len = b.path_len_constraint;
            }
            ParsedExtension::SubjectKeyIdentifier(k) => ski = hex(k.0, ":"),
            ParsedExtension::AuthorityKeyIdentifier(a) => {
                if let Some(k) = &a.key_identifier {
                    aki = hex(k.0, ":");
                }
            }
            ParsedExtension::AuthorityInfoAccess(aia) => {
                for d in aia.accessdescs.iter().take(20) {
                    if let GeneralName::URI(u) = d.access_location {
                        match d.access_method.to_id_string().as_str() {
                            "1.3.6.1.5.5.7.48.1" => ocsp.push(u.to_string()),
                            "1.3.6.1.5.5.7.48.2" => ca_issuers.push(u.to_string()),
                            _ => {}
                        }
                    }
                }
            }
            ParsedExtension::CRLDistributionPoints(points) => {
                for p in points.points.iter().take(20) {
                    if let Some(DistributionPointName::FullName(names)) = &p.distribution_point {
                        for n in names {
                            if let GeneralName::URI(u) = n {
                                crl.push(u.to_string());
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }

    let nb = c.validity().not_before.timestamp() * 1000;
    let na = c.validity().not_after.timestamp() * 1000;
    let validity = if now_ms < nb {
        Validity::NotYetValid
    } else if now_ms > na {
        Validity::Expired
    } else {
        Validity::Valid
    };
    let days_left = (na - now_ms).div_euclid(86_400_000);
    let key = key_info(c.public_key());
    let signature_algorithm = sig_name(&c.signature_algorithm);
    let self_signed = c.subject() == c.issuer() && c.verify_signature(None).is_ok();

    let mut notes = Vec::new();
    match validity {
        Validity::Expired => notes.push(format!("Expired {} days ago", -days_left)),
        Validity::NotYetValid => notes.push("Not valid yet; check the clock on both ends".into()),
        Validity::Valid if days_left < 30 => notes.push(format!("Expires in {days_left} days")),
        Validity::Valid => {}
    }
    key_notes(&key, &signature_algorithm, &mut notes);
    if !is_ca && sans.is_empty() {
        notes.push(
            "No subject alternative names; browsers ignore the CN for hostname checks".into(),
        );
    }
    if na - nb > 398 * 86_400_000 && !is_ca && !self_signed {
        notes.push(
            "Validity is longer than 398 days, the limit for publicly trusted TLS certificates"
                .into(),
        );
    }

    Ok(CertInfo {
        subject: c.subject().to_string(),
        subject_cn: common_name(c.subject()),
        issuer: c.issuer().to_string(),
        serial: hex(c.raw_serial(), ":"),
        version: c.version().0 + 1,
        not_before_ms: nb,
        not_after_ms: na,
        validity,
        days_left,
        sans,
        key,
        signature_algorithm,
        is_ca,
        path_len,
        key_usage,
        extended_key_usage: eku,
        subject_key_id: ski,
        authority_key_id: aki,
        ocsp,
        ca_issuers,
        crl,
        self_signed,
        sha256: sha256_hex(der),
        sha1: sha1_hex(der),
        notes,
    })
}

/// Decode one DER CSR.
pub fn decode_csr(der: &[u8]) -> Result<CsrInfo, String> {
    let (_, r) = X509CertificationRequest::from_der(der).map_err(|e| format!("not a CSR: {e}"))?;
    let info = &r.certification_request_info;
    let mut sans = Sans::default();
    if let Some(exts) = r.requested_extensions() {
        for e in exts {
            if let ParsedExtension::SubjectAlternativeName(san) = e {
                for g in &san.general_names {
                    sans.push(g);
                }
            }
        }
    }
    let key = key_info(&info.subject_pki);
    let signature_algorithm = sig_name(&r.signature_algorithm);
    let signature_valid = r.verify_signature().is_ok();
    let mut notes = Vec::new();
    if !signature_valid {
        notes.push("The CSR signature does not verify with its own key (or the algorithm is not supported here)".into());
    }
    key_notes(&key, &signature_algorithm, &mut notes);
    if sans.is_empty() {
        notes.push("No subject alternative names requested; most CAs add the CN, but check".into());
    }
    Ok(CsrInfo {
        subject: info.subject.to_string(),
        subject_cn: common_name(&info.subject),
        sans,
        key,
        signature_algorithm,
        signature_valid,
        notes,
    })
}

fn decode_der(label: &str, der: &[u8], now_ms: i64, out: &mut DecodeResult) {
    let as_cert = |der: &[u8]| {
        decode_cert(der, now_ms).map(|cert| Decoded::Certificate {
            label: label.to_string(),
            cert: Box::new(cert),
        })
    };
    let as_csr = |der: &[u8]| {
        decode_csr(der).map(|csr| Decoded::Csr {
            label: label.to_string(),
            csr: Box::new(csr),
        })
    };
    let res = if label.contains("REQUEST") {
        as_csr(der)
    } else if label.is_empty() {
        // Unlabelled DER: a certificate, or failing that a CSR.
        as_cert(der).or_else(|e| as_csr(der).map_err(|_| e))
    } else {
        as_cert(der)
    };
    match res {
        Ok(d) => out.items.push(d),
        Err(e) => out.warnings.push(e),
    }
}

/// Decode every certificate and CSR in `input` (PEM text, possibly several
/// blocks, or a single DER blob).
pub fn decode(input: &[u8], now_ms: i64) -> DecodeResult {
    let mut out = DecodeResult::default();
    if input.len() > MAX_INPUT {
        out.warnings
            .push("input larger than 1 MB; not decoded".into());
        return out;
    }
    let text = String::from_utf8_lossy(input);
    if text.contains("-----BEGIN") {
        for pem in Pem::iter_from_buffer(input) {
            if out.items.len() >= MAX_ITEMS {
                out.warnings
                    .push(format!("stopped after {MAX_ITEMS} items"));
                break;
            }
            match pem {
                Ok(p) if p.label.contains("PRIVATE KEY") => out.private_key_skipped = true,
                Ok(p) if p.label.contains("CERTIFICATE") => {
                    let label = if p.label.contains("REQUEST") {
                        "CERTIFICATE REQUEST"
                    } else {
                        "CERTIFICATE"
                    };
                    decode_der(label, &p.contents, now_ms, &mut out);
                }
                Ok(p) => out.warnings.push(format!("skipped a {} block", p.label)),
                Err(e) => {
                    out.warnings.push(format!("PEM error: {e}"));
                    break;
                }
            }
        }
        if text.contains("PRIVATE KEY-----") {
            out.private_key_skipped = true;
        }
    } else {
        decode_der("", input, now_ms, &mut out);
    }
    if out.items.is_empty() && out.warnings.is_empty() && !out.private_key_skipped {
        out.warnings.push("no certificate or CSR found".into());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const CA: &str = include_str!("testdata/ca.pem");
    const LEAF: &str = include_str!("testdata/leaf.pem");
    const CSR: &str = include_str!("testdata/leaf.csr");
    const WEAK: &str = include_str!("testdata/weak.pem");
    /// 2027-01-01, inside every fixture's validity except the one-day cert.
    const NOW: i64 = 1_798_761_600_000;

    fn cert(r: &DecodeResult, i: usize) -> &CertInfo {
        match &r.items[i] {
            Decoded::Certificate { cert, .. } => cert,
            other => panic!("not a certificate: {other:?}"),
        }
    }

    #[test]
    fn leaf_fields() {
        let r = decode(LEAF.as_bytes(), NOW);
        assert!(r.warnings.is_empty(), "{:?}", r.warnings);
        let c = cert(&r, 0);
        assert_eq!(c.subject_cn, "www.example.com");
        assert!(c.issuer.contains("Example Test Root CA"));
        assert_eq!(c.sans.dns, vec!["www.example.com", "*.api.example.com"]);
        assert_eq!(c.sans.ip, vec!["192.0.2.10"]);
        assert_eq!(c.key.algorithm, "RSA");
        assert_eq!(c.key.bits, 2048);
        assert_eq!(c.signature_algorithm, "ECDSA with SHA-256");
        assert!(!c.is_ca && !c.self_signed);
        assert_eq!(c.extended_key_usage, vec!["TLS server"]);
        assert!(c.key_usage.iter().any(|k| k.contains("Digital Signature")));
        assert_eq!(c.ocsp, vec!["http://ocsp.example.com"]);
        assert_eq!(c.ca_issuers, vec!["http://ca.example.com/root.crt"]);
        assert_eq!(c.crl, vec!["http://crl.example.com/root.crl"]);
        assert_eq!(c.validity, Validity::Valid);
        assert_eq!(c.sha256.len(), 32 * 3 - 1);
        assert!(c.notes.iter().any(|n| n.contains("398 days")));
    }

    #[test]
    fn ca_bundle_and_self_signed() {
        let bundle = format!("{LEAF}\n{CA}");
        let r = decode(bundle.as_bytes(), NOW);
        assert_eq!(r.items.len(), 2);
        let ca = cert(&r, 1);
        assert!(ca.is_ca && ca.self_signed);
        assert_eq!(ca.key.algorithm, "EC");
        assert_eq!(ca.key.curve, "P-256");
        // The leaf's AKI is the CA's SKI.
        assert_eq!(cert(&r, 0).authority_key_id, ca.subject_key_id);
        let notes = super::super::live::chain_notes(&[cert(&r, 0).clone(), ca.clone()]);
        assert_eq!(
            notes,
            vec!["The server sends its root certificate; harmless but unnecessary"]
        );
        let reversed = super::super::live::chain_notes(&[ca.clone(), cert(&r, 0).clone()]);
        assert!(reversed[0].contains("out of order"));
    }

    #[test]
    fn weak_and_expired() {
        let r = decode(WEAK.as_bytes(), NOW);
        let c = cert(&r, 0);
        assert_eq!(c.validity, Validity::Expired);
        assert!(c.days_left < 0);
        assert!(c.notes.iter().any(|n| n.contains("1024 bits")));
        assert!(c.notes.iter().any(|n| n.contains("SHA-1")));
        // OpenSSL marks a self-signed certificate as a CA, so no SAN note.
        assert!(c.is_ca && c.self_signed);
        let early = decode(WEAK.as_bytes(), 0);
        assert_eq!(cert(&early, 0).validity, Validity::NotYetValid);
    }

    #[test]
    fn csr() {
        let r = decode(CSR.as_bytes(), NOW);
        let Decoded::Csr { csr, .. } = &r.items[0] else {
            panic!()
        };
        assert_eq!(csr.subject_cn, "www.example.com");
        assert_eq!(csr.sans.dns, vec!["www.example.com", "*.api.example.com"]);
        assert!(csr.signature_valid);
        assert_eq!(csr.key.bits, 2048);
    }

    #[test]
    fn der_input() {
        let pem = Pem::iter_from_buffer(LEAF.as_bytes())
            .next()
            .unwrap()
            .unwrap();
        let r = decode(&pem.contents, NOW);
        assert_eq!(cert(&r, 0).subject_cn, "www.example.com");
        let csr = Pem::iter_from_buffer(CSR.as_bytes())
            .next()
            .unwrap()
            .unwrap();
        assert!(matches!(
            decode(&csr.contents, NOW).items[0],
            Decoded::Csr { .. }
        ));
    }

    #[test]
    fn private_keys_and_garbage() {
        let key = "-----BEGIN PRIVATE KEY-----\nMIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEA\n-----END PRIVATE KEY-----\n";
        let r = decode(format!("{key}{LEAF}").as_bytes(), NOW);
        assert!(r.private_key_skipped);
        assert_eq!(r.items.len(), 1);
        let r = decode(b"hello", NOW);
        assert!(r.items.is_empty() && !r.warnings.is_empty());
        let r = decode(&vec![b'a'; MAX_INPUT + 1], NOW);
        assert!(r.warnings[0].contains("1 MB"));
        let broken = LEAF.replace("MII", "XXX");
        assert!(decode(broken.as_bytes(), NOW).items.is_empty());
        let many = LEAF.repeat(MAX_ITEMS + 5);
        assert_eq!(decode(many.as_bytes(), NOW).items.len(), MAX_ITEMS);
    }
}
