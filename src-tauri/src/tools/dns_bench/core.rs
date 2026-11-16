//! Pure logic for the DNS benchmark: the built-in resolver list, resolver
//! validation, query building and response parsing, and latency statistics.

use std::net::IpAddr;

use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RecordType};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Most resolvers one run may test.
pub const MAX_RESOLVERS: usize = 32;
/// Most measured queries of each kind per resolver and transport.
pub const MAX_ROUNDS: u32 = 50;
/// Longest accepted resolver name, DoH URL or DoT host.
const MAX_FIELD: usize = 256;
/// EDNS payload size advertised in queries (DNS flag day 2020).
const EDNS_PAYLOAD: u16 = 1232;

/// Names a busy resolver should already have cached.
pub const CACHED_NAMES: &[&str] = &[
    "google.com",
    "youtube.com",
    "facebook.com",
    "wikipedia.org",
    "amazon.com",
    "microsoft.com",
    "apple.com",
    "github.com",
];

/// Large zones that are not DNSSEC signed, so a random name under them can
/// not be answered from cached NSEC records (RFC 8198) and forces a trip to
/// their authoritative servers.
pub const UNCACHED_ZONES: &[&str] = &["google.com", "microsoft.com", "amazon.com", "facebook.com"];

/// A DNSSEC-signed name: validating resolvers set AD on its answer.
pub const SIGNED_NAME: &str = "cloudflare.com";
/// A name with deliberately broken DNSSEC: validating resolvers answer
/// SERVFAIL.
pub const BROKEN_DNSSEC_NAME: &str = "dnssec-failed.org";

/// Errors from validating a resolver or a response.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum BenchError {
    #[error("resolver {0}: not an IP address")]
    BadIp(String),
    #[error("resolver {0}: DoH URL must start with https:// and have a host")]
    BadDoh(String),
    #[error("resolver {0}: DoT host must be a host name")]
    BadDot(String),
    #[error("resolver {0}: value too long")]
    TooLong(String),
    #[error("pick at least one resolver")]
    NoResolvers,
    #[error("at most {MAX_RESOLVERS} resolvers per run")]
    TooManyResolvers,
    #[error("pick at least one transport")]
    NoTransports,
    #[error("malformed response: {0}")]
    BadResponse(String),
    #[error("response ID does not match the query")]
    WrongId,
}

/// How queries reach the resolver.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    Udp,
    Tcp,
    /// DNS over TLS, port 853.
    Dot,
    /// DNS over HTTPS, port 443.
    Doh,
}

/// A resolver to test, as sent by the UI.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ResolverSpec {
    pub id: String,
    pub name: String,
    pub ip: String,
    #[serde(default)]
    pub doh: String,
    #[serde(default)]
    pub dot: String,
}

/// A validated resolver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolver {
    pub id: String,
    pub name: String,
    pub ip: IpAddr,
    /// DoH URL, when the resolver offers DoH.
    pub doh: Option<String>,
    /// TLS name for DoT, when the resolver offers DoT.
    pub dot: Option<String>,
}

impl Resolver {
    /// Whether this resolver can be tested over `t`.
    pub fn supports(&self, t: Transport) -> bool {
        match t {
            Transport::Udp | Transport::Tcp => true,
            Transport::Dot => self.dot.is_some(),
            Transport::Doh => self.doh.is_some(),
        }
    }
}

/// A built-in public resolver.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Provider {
    pub id: &'static str,
    pub name: &'static str,
    pub note: &'static str,
    pub ipv4: &'static [&'static str],
    pub ipv6: &'static [&'static str],
    pub doh: &'static str,
    pub dot: &'static str,
}

/// Public resolvers offered by default. Addresses and endpoints are the
/// providers' published ones.
pub fn providers() -> Vec<Provider> {
    vec![
        Provider {
            id: "cloudflare",
            name: "Cloudflare",
            note: "No filtering",
            ipv4: &["1.1.1.1", "1.0.0.1"],
            ipv6: &["2606:4700:4700::1111", "2606:4700:4700::1001"],
            doh: "https://cloudflare-dns.com/dns-query",
            dot: "one.one.one.one",
        },
        Provider {
            id: "cloudflare-security",
            name: "Cloudflare Security",
            note: "Blocks malware",
            ipv4: &["1.1.1.2", "1.0.0.2"],
            ipv6: &["2606:4700:4700::1112", "2606:4700:4700::1002"],
            doh: "https://security.cloudflare-dns.com/dns-query",
            dot: "security.cloudflare-dns.com",
        },
        Provider {
            id: "google",
            name: "Google Public DNS",
            note: "No filtering",
            ipv4: &["8.8.8.8", "8.8.4.4"],
            ipv6: &["2001:4860:4860::8888", "2001:4860:4860::8844"],
            doh: "https://dns.google/dns-query",
            dot: "dns.google",
        },
        Provider {
            id: "quad9",
            name: "Quad9",
            note: "Blocks malware; DoH needs HTTP/2, not tested",
            ipv4: &["9.9.9.9", "149.112.112.112"],
            ipv6: &["2620:fe::fe", "2620:fe::9"],
            doh: "",
            dot: "dns.quad9.net",
        },
        Provider {
            id: "opendns",
            name: "OpenDNS",
            note: "Cisco; blocks phishing",
            ipv4: &["208.67.222.222", "208.67.220.220"],
            ipv6: &["2620:119:35::35", "2620:119:53::53"],
            doh: "https://doh.opendns.com/dns-query",
            dot: "",
        },
        Provider {
            id: "adguard",
            name: "AdGuard DNS",
            note: "Blocks ads and trackers",
            ipv4: &["94.140.14.14", "94.140.15.15"],
            ipv6: &["2a10:50c0::ad1:ff", "2a10:50c0::ad2:ff"],
            doh: "https://dns.adguard-dns.com/dns-query",
            dot: "dns.adguard-dns.com",
        },
        Provider {
            id: "cleanbrowsing",
            name: "CleanBrowsing Security",
            note: "Blocks malware and phishing",
            ipv4: &["185.228.168.9", "185.228.169.9"],
            ipv6: &["2a0d:2a00:1::2", "2a0d:2a00:2::2"],
            doh: "https://doh.cleanbrowsing.org/doh/security-filter/",
            dot: "security-filter-dns.cleanbrowsing.org",
        },
        Provider {
            id: "controld",
            name: "Control D",
            note: "Free unfiltered",
            ipv4: &["76.76.2.0", "76.76.10.0"],
            ipv6: &["2606:1a40::", "2606:1a40:1::"],
            doh: "https://freedns.controld.com/p0",
            dot: "",
        },
    ]
}

fn host_of_url(url: &str) -> Option<&str> {
    let rest = url.strip_prefix("https://")?;
    let host = rest.split(['/', '?', '#']).next()?;
    let host = host.rsplit_once('@').map_or(host, |(_, h)| h);
    let host = if host.starts_with('[') {
        host
    } else {
        host.split(':').next()?
    };
    (!host.is_empty()).then_some(host)
}

fn valid_hostname(h: &str) -> bool {
    !h.is_empty()
        && h.len() <= 253
        && h.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
                && !l.starts_with('-')
                && !l.ends_with('-')
        })
}

/// Validate one resolver from the UI.
pub fn validate_resolver(s: &ResolverSpec) -> Result<Resolver, BenchError> {
    let label = if s.name.trim().is_empty() {
        s.ip.trim()
    } else {
        s.name.trim()
    };
    let label: String = label.chars().filter(|c| !c.is_control()).take(80).collect();
    if [&s.id, &s.name, &s.ip, &s.doh, &s.dot]
        .iter()
        .any(|v| v.len() > MAX_FIELD)
    {
        return Err(BenchError::TooLong(label));
    }
    let ip_text = s.ip.trim().trim_start_matches('[').trim_end_matches(']');
    let ip: IpAddr = ip_text
        .parse()
        .map_err(|_| BenchError::BadIp(label.clone()))?;
    let doh = s.doh.trim();
    let doh = if doh.is_empty() {
        None
    } else {
        if host_of_url(doh).is_none() || doh.chars().any(|c| c.is_whitespace() || c.is_control()) {
            return Err(BenchError::BadDoh(label));
        }
        Some(doh.to_string())
    };
    let dot = s.dot.trim().trim_end_matches('.');
    let dot = if dot.is_empty() {
        None
    } else {
        if !valid_hostname(dot) {
            return Err(BenchError::BadDot(label));
        }
        Some(dot.to_ascii_lowercase())
    };
    Ok(Resolver {
        id: s.id.chars().filter(|c| !c.is_control()).collect(),
        name: label,
        ip,
        doh,
        dot,
    })
}

/// Validate a run's resolver list and transports.
pub fn validate_run(
    specs: &[ResolverSpec],
    transports: &[Transport],
) -> Result<(Vec<Resolver>, Vec<Transport>), BenchError> {
    if specs.is_empty() {
        return Err(BenchError::NoResolvers);
    }
    if specs.len() > MAX_RESOLVERS {
        return Err(BenchError::TooManyResolvers);
    }
    let mut ts: Vec<Transport> = Vec::new();
    for t in transports {
        if !ts.contains(t) {
            ts.push(*t);
        }
    }
    if ts.is_empty() {
        return Err(BenchError::NoTransports);
    }
    let resolvers = specs
        .iter()
        .map(validate_resolver)
        .collect::<Result<_, _>>()?;
    Ok((resolvers, ts))
}

/// A random lowercase label of `len` characters from `bytes`.
pub fn random_label(bytes: &[u8]) -> String {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    bytes
        .iter()
        .map(|b| ALPHABET[usize::from(*b) % ALPHABET.len()] as char)
        .collect()
}

/// Build a recursive query for `name`/`rtype`. With `dnssec`, sets the DO and
/// AD bits so validating resolvers report validation in AD.
pub fn build_query(
    id: u16,
    name: &str,
    rtype: RecordType,
    dnssec: bool,
) -> Result<Vec<u8>, BenchError> {
    let name = Name::from_ascii(name).map_err(|e| BenchError::BadResponse(e.to_string()))?;
    let mut m = Message::new(id, MessageType::Query, OpCode::Query);
    m.metadata.recursion_desired = true;
    m.metadata.authentic_data = dnssec;
    m.add_query(Query::query(name, rtype));
    let mut edns = Edns::new();
    edns.set_max_payload(EDNS_PAYLOAD);
    edns.set_dnssec_ok(dnssec);
    m.set_edns(edns);
    m.to_vec()
        .map_err(|e| BenchError::BadResponse(e.to_string()))
}

/// The parts of a response the benchmark looks at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answer {
    pub rcode: ResponseCode,
    pub authentic: bool,
    /// A or AAAA records in the answer section.
    pub addresses: usize,
    pub truncated: bool,
}

/// Parse a response. `expect_id` is checked unless `None` (DoH uses ID 0).
pub fn parse_answer(bytes: &[u8], expect_id: Option<u16>) -> Result<Answer, BenchError> {
    let m = Message::from_vec(bytes).map_err(|e| BenchError::BadResponse(e.to_string()))?;
    if m.metadata.message_type != MessageType::Response {
        return Err(BenchError::BadResponse("not a response".into()));
    }
    if let Some(id) = expect_id
        && m.metadata.id != id
    {
        return Err(BenchError::WrongId);
    }
    let addresses = m
        .answers
        .iter()
        .filter(|r| matches!(r.record_type(), RecordType::A | RecordType::AAAA))
        .count();
    Ok(Answer {
        rcode: m.metadata.response_code,
        authentic: m.metadata.authentic_data,
        addresses,
        truncated: m.metadata.truncation,
    })
}

/// Latency summary for one kind of query.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Stats {
    pub sent: u32,
    pub ok: u32,
    pub median_ms: Option<f64>,
    pub p90_ms: Option<f64>,
    pub min_ms: Option<f64>,
    /// Percent of queries with no usable answer.
    pub loss_pct: f64,
}

fn round1(v: f64) -> f64 {
    (v * 10.0).round() / 10.0
}

/// Summarize `samples` (milliseconds of the successful queries) out of `sent`.
pub fn stats(samples: &[f64], sent: u32) -> Stats {
    let mut s: Vec<f64> = samples.iter().copied().filter(|v| v.is_finite()).collect();
    s.sort_by(f64::total_cmp);
    let ok = s.len() as u32;
    let pick = |q: f64| -> Option<f64> {
        if s.is_empty() {
            return None;
        }
        // Nearest rank.
        let rank = ((q * s.len() as f64).ceil() as usize).clamp(1, s.len());
        Some(round1(s[rank - 1]))
    };
    let median = if s.is_empty() {
        None
    } else if s.len() % 2 == 1 {
        Some(round1(s[s.len() / 2]))
    } else {
        Some(round1((s[s.len() / 2 - 1] + s[s.len() / 2]) / 2.0))
    };
    let loss = if sent == 0 {
        0.0
    } else {
        round1(100.0 * f64::from(sent.saturating_sub(ok)) / f64::from(sent))
    };
    Stats {
        sent,
        ok,
        median_ms: median,
        p90_ms: pick(0.9),
        min_ms: s.first().copied().map(round1),
        loss_pct: loss,
    }
}

/// DNSSEC validation verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Dnssec {
    /// AD on a signed name and SERVFAIL on a broken one.
    Validating,
    /// Answers names with broken signatures.
    NotValidating,
    /// Could not tell (errors or mixed results).
    Unknown,
}

/// Decide DNSSEC validation from the two probe answers.
pub fn dnssec_verdict(signed: Option<&Answer>, broken: Option<&Answer>) -> Dnssec {
    match (signed, broken) {
        (Some(s), Some(b)) if s.authentic && b.rcode == ResponseCode::ServFail => {
            Dnssec::Validating
        }
        (_, Some(b)) if b.rcode == ResponseCode::NoError && b.addresses > 0 => {
            Dnssec::NotValidating
        }
        _ => Dnssec::Unknown,
    }
}

/// Whether an answer to a name that can not exist shows NXDOMAIN hijacking
/// (the resolver returned addresses instead of NXDOMAIN).
pub fn is_hijack(a: &Answer) -> bool {
    a.rcode == ResponseCode::NoError && a.addresses > 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::{RData, Record, rdata::A};

    fn spec(ip: &str, doh: &str, dot: &str) -> ResolverSpec {
        ResolverSpec {
            id: "x".into(),
            name: "Test".into(),
            ip: ip.into(),
            doh: doh.into(),
            dot: dot.into(),
        }
    }

    #[test]
    fn providers_are_valid() {
        for p in providers() {
            for ip in p.ipv4.iter().chain(p.ipv6) {
                let r = validate_resolver(&spec(ip, p.doh, p.dot)).unwrap();
                assert_eq!(r.doh.is_some(), !p.doh.is_empty());
                assert_eq!(r.dot.is_some(), !p.dot.is_empty());
            }
        }
    }

    #[test]
    fn validates_fields() {
        assert!(validate_resolver(&spec("[2606:4700:4700::1111]", "", "")).is_ok());
        assert_eq!(
            validate_resolver(&spec("one.one.one.one", "", "")),
            Err(BenchError::BadIp("Test".into()))
        );
        assert!(matches!(
            validate_resolver(&spec("1.1.1.1", "http://x/dns-query", "")),
            Err(BenchError::BadDoh(_))
        ));
        assert!(matches!(
            validate_resolver(&spec("1.1.1.1", "https:///x", "")),
            Err(BenchError::BadDoh(_))
        ));
        assert!(matches!(
            validate_resolver(&spec("1.1.1.1", "", "bad host")),
            Err(BenchError::BadDot(_))
        ));
        assert!(matches!(
            validate_resolver(&spec(&"1".repeat(300), "", "")),
            Err(BenchError::TooLong(_))
        ));
        let r = validate_resolver(&spec("9.9.9.9", "", "DNS.Quad9.net.")).unwrap();
        assert_eq!(r.dot.as_deref(), Some("dns.quad9.net"));
    }

    #[test]
    fn url_host() {
        assert_eq!(
            host_of_url("https://dns.google/dns-query"),
            Some("dns.google")
        );
        assert_eq!(host_of_url("https://h:8443/q"), Some("h"));
        assert_eq!(
            host_of_url("https://[2001:db8::1]/q"),
            Some("[2001:db8::1]")
        );
        assert_eq!(host_of_url("ftp://h/"), None);
    }

    #[test]
    fn run_limits() {
        assert_eq!(
            validate_run(&[], &[Transport::Udp]),
            Err(BenchError::NoResolvers)
        );
        let many = vec![spec("1.1.1.1", "", ""); MAX_RESOLVERS + 1];
        assert_eq!(
            validate_run(&many, &[Transport::Udp]),
            Err(BenchError::TooManyResolvers)
        );
        assert_eq!(validate_run(&many[..1], &[]), Err(BenchError::NoTransports));
        let (_, ts) = validate_run(
            &many[..1],
            &[Transport::Udp, Transport::Udp, Transport::Doh],
        )
        .unwrap();
        assert_eq!(ts, [Transport::Udp, Transport::Doh]);
    }

    #[test]
    fn supports_transports() {
        let r = validate_resolver(&spec("1.1.1.1", "", "")).unwrap();
        assert!(r.supports(Transport::Udp) && r.supports(Transport::Tcp));
        assert!(!r.supports(Transport::Dot) && !r.supports(Transport::Doh));
    }

    #[test]
    fn query_round_trips() {
        let q = build_query(0x1234, "example.com", RecordType::A, true).unwrap();
        let m = Message::from_vec(&q).unwrap();
        assert_eq!(m.metadata.id, 0x1234);
        assert!(m.metadata.recursion_desired && m.metadata.authentic_data);
        assert!(m.edns.as_ref().unwrap().flags().dnssec_ok);
        assert_eq!(m.queries[0].query_type, RecordType::A);
    }

    fn response(id: u16, rcode: ResponseCode, ad: bool, addrs: usize) -> Vec<u8> {
        let mut m = Message::new(id, MessageType::Response, OpCode::Query);
        m.metadata.response_code = rcode;
        m.metadata.authentic_data = ad;
        for i in 0..addrs {
            m.add_answer(Record::from_rdata(
                Name::from_ascii("x.example.").unwrap(),
                60,
                RData::A(A::new(192, 0, 2, i as u8)),
            ));
        }
        m.to_vec().unwrap()
    }

    #[test]
    fn parses_answers() {
        let a = parse_answer(&response(7, ResponseCode::NoError, true, 2), Some(7)).unwrap();
        assert_eq!(a.addresses, 2);
        assert!(a.authentic);
        assert_eq!(
            parse_answer(&response(7, ResponseCode::NoError, false, 0), Some(8)),
            Err(BenchError::WrongId)
        );
        assert!(parse_answer(&response(7, ResponseCode::NoError, false, 0), None).is_ok());
        assert!(parse_answer(b"\x00\x01", None).is_err());
        let q = build_query(1, "example.com", RecordType::A, false).unwrap();
        assert!(matches!(
            parse_answer(&q, Some(1)),
            Err(BenchError::BadResponse(_))
        ));
    }

    #[test]
    fn stats_median_p90_loss() {
        let s = stats(&[10.0, 30.0, 20.0, 40.0], 5);
        assert_eq!(s.median_ms, Some(25.0));
        assert_eq!(s.p90_ms, Some(40.0));
        assert_eq!(s.min_ms, Some(10.0));
        assert_eq!(s.loss_pct, 20.0);
        let s = stats(&(1..=10).map(f64::from).collect::<Vec<_>>(), 10);
        assert_eq!(s.p90_ms, Some(9.0));
        assert_eq!(s.median_ms, Some(5.5));
        let e = stats(&[], 3);
        assert_eq!((e.median_ms, e.loss_pct), (None, 100.0));
        assert_eq!(stats(&[], 0).loss_pct, 0.0);
    }

    #[test]
    fn dnssec_and_hijack() {
        let ans = |rcode, ad, n| Answer {
            rcode,
            authentic: ad,
            addresses: n,
            truncated: false,
        };
        let signed = ans(ResponseCode::NoError, true, 1);
        let fail = ans(ResponseCode::ServFail, false, 0);
        let open = ans(ResponseCode::NoError, false, 1);
        assert_eq!(
            dnssec_verdict(Some(&signed), Some(&fail)),
            Dnssec::Validating
        );
        assert_eq!(
            dnssec_verdict(Some(&open), Some(&open)),
            Dnssec::NotValidating
        );
        assert_eq!(dnssec_verdict(None, None), Dnssec::Unknown);
        assert!(is_hijack(&open));
        assert!(!is_hijack(&ans(ResponseCode::NXDomain, false, 0)));
    }

    #[test]
    fn random_labels() {
        let l = random_label(&[0, 25, 26, 35, 36, 255]);
        assert_eq!(l.len(), 6);
        assert!(
            l.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        );
        assert!(validate_resolver(&spec("1.1.1.1", "", &format!("{l}.example"))).is_ok());
    }
}
