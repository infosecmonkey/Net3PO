//! Live TLS handshakes. The handshake accepts whatever chain the server
//! presents so it can be shown even when it is broken; trust is then
//! evaluated separately against the bundled Mozilla root store, and the
//! hostname separately against the leaf's SANs. Handshake signatures are
//! still verified, so a server must hold the key for the certificate it
//! sent.

use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};

use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    CertificateError, ClientConfig, ClientConnection, DigitallySignedStruct, RootCertStore,
    SignatureScheme, SupportedCipherSuite,
};
use serde::{Deserialize, Serialize};

use super::cert::{self, CertInfo};
use super::names;
use super::starttls::{self, StartTls, Transcript};

/// Budget for the TCP connect and for each read or write after it.
const IO_TIMEOUT: Duration = Duration::from_secs(8);
/// Most certificates kept from a presented chain.
const MAX_CHAIN: usize = 10;

pub(crate) static ROOTS: LazyLock<Arc<RootCertStore>> = LazyLock::new(|| {
    Arc::new(RootCertStore::from_iter(
        webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),
    ))
});

pub(crate) fn provider() -> CryptoProvider {
    rustls::crypto::ring::default_provider()
}

/// Accepts any chain (recorded for display) but checks handshake signatures.
#[derive(Debug)]
pub(crate) struct Recorder(pub(crate) WebPkiSupportedAlgorithms);

impl ServerCertVerifier for Recorder {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.0)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.0)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.supported_schemes()
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LiveRequest {
    /// Hostname or IP; also a `host:port` or URL.
    pub target: String,
    pub port: Option<u16>,
    /// Connect to this address instead of resolving the host, keeping the
    /// hostname for SNI and checks (load balancer or VIP testing).
    #[serde(default)]
    pub connect_ip: String,
    /// Send SNI. Ignored for IP targets, which never send it.
    #[serde(default = "yes")]
    pub sni: bool,
    pub starttls: StartTls,
}

fn yes() -> bool {
    true
}

/// Host and optional port from what the user typed: `host`, `host:443`,
/// `[2001:db8::1]:443`, `https://host/path`.
pub fn parse_target(input: &str) -> Result<(String, Option<u16>), String> {
    let mut s = input.trim();
    if let Some((_, rest)) = s.split_once("://") {
        s = rest;
    }
    let s = s.split(['/', '?', '#']).next().unwrap_or("");
    let s = s.rsplit_once('@').map(|(_, h)| h).unwrap_or(s);
    if s.is_empty() {
        return Err("enter a hostname or IP address".into());
    }
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Ok((ip.to_string(), None));
    }
    let (host, port) = if let Some(rest) = s.strip_prefix('[') {
        let (h, tail) = rest.split_once(']').ok_or("unclosed [ in address")?;
        let port = tail.strip_prefix(':').map(str::to_string);
        (h.to_string(), port)
    } else if let Some((h, p)) = s.rsplit_once(':') {
        (h.to_string(), Some(p.to_string()))
    } else {
        (s.to_string(), None)
    };
    let port = match port {
        Some(p) => Some(
            p.parse::<u16>()
                .ok()
                .filter(|&p| p > 0)
                .ok_or("invalid port")?,
        ),
        None => None,
    };
    let valid = host.len() <= 253
        && (host.parse::<IpAddr>().is_ok()
            || host.split('.').all(|l| {
                !l.is_empty()
                    && l.len() <= 63
                    && l.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            }));
    if !valid {
        return Err(format!("not a valid hostname: {host}"));
    }
    Ok((host.to_ascii_lowercase(), port))
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Timing {
    pub connect_ms: u64,
    pub starttls_ms: Option<u64>,
    pub handshake_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Trust {
    /// The presented chain leads to a root in the bundled Mozilla store.
    pub chain_trusted: bool,
    pub chain_error: String,
    /// The SAN that covers the hostname, when one does.
    pub name_match: Option<String>,
    /// What was checked against the SANs.
    pub checked_name: String,
    pub store: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LiveResult {
    pub host: String,
    pub port: u16,
    pub address: String,
    pub sni_sent: Option<String>,
    pub starttls: StartTls,
    pub transcript: Transcript,
    pub protocol: String,
    pub cipher_suite: String,
    pub key_exchange: String,
    pub alpn: String,
    pub timing: Timing,
    /// Certificates in the order the server sent them.
    pub chain: Vec<CertInfo>,
    pub chain_notes: Vec<String>,
    pub trust: Trust,
}

fn ms(d: Duration) -> u64 {
    d.as_millis() as u64
}

/// Resolve and connect, trying each address until one answers.
fn connect(host: &str, connect_ip: &str, port: u16) -> Result<(TcpStream, SocketAddr), String> {
    let addrs: Vec<SocketAddr> = if !connect_ip.trim().is_empty() {
        let ip: IpAddr = connect_ip
            .trim()
            .parse()
            .map_err(|_| format!("not an IP address: {connect_ip}"))?;
        vec![SocketAddr::new(ip, port)]
    } else {
        (host, port)
            .to_socket_addrs()
            .map_err(|e| format!("could not resolve {host}: {e}"))?
            .take(8)
            .collect()
    };
    let mut last = String::from("no addresses");
    for a in addrs {
        match TcpStream::connect_timeout(&a, IO_TIMEOUT) {
            Ok(s) => {
                s.set_read_timeout(Some(IO_TIMEOUT)).ok();
                s.set_write_timeout(Some(IO_TIMEOUT)).ok();
                s.set_nodelay(true).ok();
                return Ok((s, a));
            }
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
                last = format!("{a}: connection refused");
            }
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
                last = format!("{a}: no answer within {} s", IO_TIMEOUT.as_secs());
            }
            Err(e) => last = format!("{a}: {e}"),
        }
    }
    Err(last)
}

pub(crate) fn server_name(host: &str) -> Result<ServerName<'static>, String> {
    ServerName::try_from(host.to_string()).map_err(|e| format!("{host}: {e}"))
}

/// Explain a rustls error in practitioner terms.
pub fn explain(e: &rustls::Error) -> String {
    use rustls::AlertDescription as A;
    match e {
        rustls::Error::AlertReceived(A::HandshakeFailure) => {
            "the server refused the handshake (no shared version, cipher or curve)".into()
        }
        rustls::Error::AlertReceived(A::ProtocolVersion) => {
            "the server does not support this TLS version".into()
        }
        rustls::Error::AlertReceived(A::UnrecognisedName) => {
            "the server does not recognise the SNI name".into()
        }
        rustls::Error::InvalidCertificate(c) => cert_error(c),
        rustls::Error::InvalidMessage(_) | rustls::Error::InappropriateMessage { .. } => {
            "the server did not answer with TLS (wrong port, or STARTTLS needed?)".into()
        }
        other => other.to_string(),
    }
}

fn cert_error(c: &CertificateError) -> String {
    match c {
        CertificateError::UnknownIssuer => {
            "no path to a trusted root (self-signed, private CA, or a missing intermediate)".into()
        }
        CertificateError::Expired | CertificateError::ExpiredContext { .. } => {
            "a certificate in the chain is expired".into()
        }
        CertificateError::NotValidYet | CertificateError::NotValidYetContext { .. } => {
            "a certificate in the chain is not valid yet".into()
        }
        CertificateError::BadSignature => "a signature in the chain does not verify".into(),
        CertificateError::InvalidPurpose | CertificateError::InvalidPurposeContext { .. } => {
            "the certificate is not allowed for TLS server use".into()
        }
        other => format!("{other:?}"),
    }
}

/// Did any of these name errors come from the hostname check alone?
fn is_name_error(e: &rustls::Error) -> bool {
    matches!(
        e,
        rustls::Error::InvalidCertificate(
            CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. }
        )
    )
}

/// Order and completeness observations on the presented chain.
pub fn chain_notes(chain: &[CertInfo]) -> Vec<String> {
    let mut notes = Vec::new();
    if chain.is_empty() {
        return notes;
    }
    for (i, pair) in chain.windows(2).enumerate() {
        if pair[0].issuer != pair[1].subject {
            notes.push(format!(
                "Certificate {} was not issued by certificate {}; the chain is out of order or has an unrelated certificate",
                i + 1,
                i + 2
            ));
        }
    }
    let last = &chain[chain.len() - 1];
    if chain.len() > 1 && last.self_signed {
        notes.push("The server sends its root certificate; harmless but unnecessary".into());
    }
    if chain.len() == 1 && !chain[0].self_signed {
        notes.push(
            "Only the leaf was sent; clients without the intermediate cached will fail".into(),
        );
    }
    notes
}

fn base_config(
    provider: CryptoProvider,
    versions: &[&'static rustls::SupportedProtocolVersion],
) -> Result<ClientConfig, String> {
    let algs = provider.signature_verification_algorithms;
    let provider = Arc::new(provider);
    let mut cfg = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(versions)
        .map_err(|e| e.to_string())?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(Recorder(algs)))
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(cfg)
}

/// Drive the handshake to completion on an already connected socket.
pub(crate) fn handshake(
    sock: &mut TcpStream,
    cfg: ClientConfig,
    name: ServerName<'static>,
) -> Result<ClientConnection, rustls::Error> {
    let mut conn = ClientConnection::new(Arc::new(cfg), name)?;
    while conn.is_handshaking() {
        match conn.complete_io(sock) {
            Ok(_) => {}
            Err(e) => {
                // A TLS error surfaces as io::Error wrapping rustls::Error.
                if let Some(inner) = e.get_ref().and_then(|i| i.downcast_ref::<rustls::Error>()) {
                    return Err(inner.clone());
                }
                return Err(rustls::Error::General(match e.kind() {
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => {
                        "timed out during the handshake".into()
                    }
                    std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::ConnectionReset => {
                        "the server closed the connection during the handshake".into()
                    }
                    _ => e.to_string(),
                }));
            }
        }
    }
    Ok(conn)
}

fn trust(chain: &[CertificateDer<'static>], host: &str, leaf: Option<&CertInfo>) -> Trust {
    let store = format!(
        "Mozilla root store bundled with Net3PO ({} roots)",
        ROOTS.len()
    );
    let checked_name = host.to_string();
    let name_match = leaf.and_then(|l| names::matching_name(&l.sans.dns, &l.sans.ip, host));
    let Some((leaf_der, rest)) = chain.split_first() else {
        return Trust {
            chain_trusted: false,
            chain_error: "no certificate presented".into(),
            name_match,
            checked_name,
            store,
        };
    };
    let verifier =
        match WebPkiServerVerifier::builder_with_provider(ROOTS.clone(), Arc::new(provider()))
            .build()
        {
            Ok(v) => v,
            Err(e) => {
                return Trust {
                    chain_trusted: false,
                    chain_error: e.to_string(),
                    name_match,
                    checked_name,
                    store,
                };
            }
        };
    let (chain_trusted, chain_error) = match server_name(host) {
        Ok(sn) => match verifier.verify_server_cert(leaf_der, rest, &sn, &[], UnixTime::now()) {
            Ok(_) => (true, String::new()),
            // The chain verified; only the name failed, which is reported separately.
            Err(e) if is_name_error(&e) => (true, String::new()),
            Err(e) => (false, explain(&e)),
        },
        Err(e) => (false, e),
    };
    Trust {
        chain_trusted,
        chain_error,
        name_match,
        checked_name,
        store,
    }
}

/// Connect, optionally STARTTLS, handshake, and report everything.
pub fn inspect(req: &LiveRequest) -> Result<LiveResult, String> {
    let (host, typed_port) = parse_target(&req.target)?;
    let port = req
        .port
        .or(typed_port)
        .unwrap_or(req.starttls.default_port());
    let is_ip = host.parse::<IpAddr>().is_ok();

    let t0 = Instant::now();
    let (mut sock, addr) = connect(&host, &req.connect_ip, port)?;
    let connect_ms = ms(t0.elapsed());

    let mut transcript = Vec::new();
    let mut starttls_ms = None;
    if req.starttls != StartTls::None {
        let t = Instant::now();
        starttls::upgrade(&mut sock, req.starttls, &mut transcript)
            .map_err(|e| format!("STARTTLS: {e}"))?;
        starttls_ms = Some(ms(t.elapsed()));
    }

    let mut cfg = base_config(provider(), rustls::ALL_VERSIONS)?;
    cfg.enable_sni = req.sni;
    let sni_sent = (req.sni && !is_ip).then(|| host.clone());
    let t = Instant::now();
    let conn = handshake(&mut sock, cfg, server_name(&host)?)
        .map_err(|e| format!("TLS handshake failed: {}", explain(&e)))?;
    let handshake_ms = ms(t.elapsed());

    let ders: Vec<CertificateDer<'static>> = conn
        .peer_certificates()
        .unwrap_or_default()
        .iter()
        .take(MAX_CHAIN)
        .cloned()
        .collect();
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or_default();
    let chain: Vec<CertInfo> = ders
        .iter()
        .filter_map(|d| cert::decode_cert(d.as_ref(), now_ms).ok())
        .collect();
    let trust = trust(&ders, &host, chain.first());
    let protocol = conn
        .protocol_version()
        .map(|v| format!("{v:?}").replace("TLSv1_", "TLS 1."))
        .unwrap_or_default();
    let cipher_suite = conn
        .negotiated_cipher_suite()
        .map(|s| format!("{:?}", s.suite()))
        .unwrap_or_default();
    let key_exchange = conn
        .negotiated_key_exchange_group()
        .map(|g| format!("{:?}", g.name()))
        .unwrap_or_default();
    let alpn = conn
        .alpn_protocol()
        .map(|a| String::from_utf8_lossy(a).into_owned())
        .unwrap_or_default();
    // Close politely; errors here do not matter.
    let mut conn = conn;
    conn.send_close_notify();
    let _ = conn.write_tls(&mut sock);
    let _ = sock.flush();
    let _ = sock.read(&mut [0u8; 0]);

    Ok(LiveResult {
        host,
        port,
        address: addr.to_string(),
        sni_sent,
        starttls: req.starttls,
        transcript,
        protocol,
        cipher_suite,
        key_exchange,
        alpn,
        timing: Timing {
            connect_ms,
            starttls_ms,
            handshake_ms,
        },
        chain_notes: chain_notes(&chain),
        chain,
        trust,
    })
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum Support {
    Accepted,
    Rejected,
    Error,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SuiteResult {
    pub version: String,
    pub suite: String,
    pub support: Support,
    pub detail: String,
}

/// The versions and suites this build can test: what rustls implements.
pub fn testable_suites() -> Vec<SupportedCipherSuite> {
    provider().cipher_suites
}

fn version_name(s: &SupportedCipherSuite) -> &'static str {
    match s {
        SupportedCipherSuite::Tls13(_) => "TLS 1.3",
        SupportedCipherSuite::Tls12(_) => "TLS 1.2",
    }
}

/// Try one suite: a full connection and handshake offering only it.
fn try_suite(req: &LiveRequest, host: &str, port: u16, suite: SupportedCipherSuite) -> SuiteResult {
    let version = version_name(&suite).to_string();
    let name = format!("{:?}", suite.suite());
    let result = |support, detail: String| SuiteResult {
        version: version.clone(),
        suite: name.clone(),
        support,
        detail,
    };
    let (mut sock, _) = match connect(host, &req.connect_ip, port) {
        Ok(s) => s,
        Err(e) => return result(Support::Error, e),
    };
    if req.starttls != StartTls::None {
        let mut log = Vec::new();
        if let Err(e) = starttls::upgrade(&mut sock, req.starttls, &mut log) {
            return result(Support::Error, format!("STARTTLS: {e}"));
        }
    }
    let mut p = provider();
    p.cipher_suites = vec![suite];
    let versions: &[&'static rustls::SupportedProtocolVersion] = match suite {
        SupportedCipherSuite::Tls13(_) => &[&rustls::version::TLS13],
        SupportedCipherSuite::Tls12(_) => &[&rustls::version::TLS12],
    };
    let mut cfg = match base_config(p, versions) {
        Ok(c) => c,
        Err(e) => return result(Support::Error, e),
    };
    cfg.enable_sni = req.sni;
    let sn = match server_name(host) {
        Ok(s) => s,
        Err(e) => return result(Support::Error, e),
    };
    match handshake(&mut sock, cfg, sn) {
        Ok(_) => result(Support::Accepted, String::new()),
        Err(rustls::Error::AlertReceived(a)) => result(Support::Rejected, format!("alert: {a:?}")),
        Err(rustls::Error::General(g)) if g.contains("closed the connection") => result(
            Support::Rejected,
            "connection closed (common way to refuse)".into(),
        ),
        Err(e) => result(Support::Error, explain(&e)),
    }
}

/// Separate active test: one handshake per suite this build supports, in
/// parallel. TLS 1.0/1.1, CBC and static-RSA suites cannot be offered by
/// this TLS library and are not tested.
pub fn test_suites(req: &LiveRequest) -> Result<Vec<SuiteResult>, String> {
    let (host, typed_port) = parse_target(&req.target)?;
    let port = req
        .port
        .or(typed_port)
        .unwrap_or(req.starttls.default_port());
    let suites = testable_suites();
    let results = std::thread::scope(|s| {
        let handles: Vec<_> = suites
            .iter()
            .map(|&suite| {
                let host = &host;
                s.spawn(move || try_suite(req, host, port, suite))
            })
            .collect();
        handles
            .into_iter()
            .filter_map(|h| h.join().ok())
            .collect::<Vec<_>>()
    });
    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn targets() {
        assert_eq!(
            parse_target("Example.com").unwrap(),
            ("example.com".into(), None)
        );
        assert_eq!(
            parse_target("example.com:8443").unwrap(),
            ("example.com".into(), Some(8443))
        );
        assert_eq!(
            parse_target("https://user@www.example.com:444/a?b").unwrap(),
            ("www.example.com".into(), Some(444))
        );
        assert_eq!(
            parse_target("192.0.2.1").unwrap(),
            ("192.0.2.1".into(), None)
        );
        assert_eq!(
            parse_target("2001:db8::1").unwrap(),
            ("2001:db8::1".into(), None)
        );
        assert_eq!(
            parse_target("[2001:db8::1]:443").unwrap(),
            ("2001:db8::1".into(), Some(443))
        );
        assert!(parse_target("").is_err());
        assert!(parse_target("bad host").is_err());
        assert!(parse_target("example.com:0").is_err());
        assert!(parse_target("example.com:99999").is_err());
        assert!(parse_target("exa;mple.com").is_err());
    }

    #[test]
    fn suites_are_modern_only() {
        let s = testable_suites();
        assert!(
            s.iter()
                .any(|x| matches!(x, SupportedCipherSuite::Tls13(_)))
        );
        assert!(
            s.iter()
                .any(|x| matches!(x, SupportedCipherSuite::Tls12(_)))
        );
        assert!(s.len() <= 12);
    }

    #[test]
    fn roots_are_bundled() {
        assert!(ROOTS.len() > 100);
    }
}
