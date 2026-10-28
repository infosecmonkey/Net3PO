//! Tauri command for the DNS analyzer. Orchestrates the lookups and feeds the
//! results to the pure scoring in `core`.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::str::FromStr;
use std::time::Duration;

use hickory_resolver::TokioAsyncResolver;
use hickory_resolver::config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts};
use hickory_resolver::proto::rr::{Name, RecordType};

use super::core::{self, AnalysisReport, Finding, Section, Severity, Spf};

/// Maximum nameservers to probe for SOA agreement.
const MAX_NS: usize = 8;
/// Upper bound on SPF lookups to follow before declaring it over the limit.
const SPF_LOOKUP_CAP: u32 = 25;

/// Analyze a domain's SPF, DMARC, DKIM, DNSSEC, and NS posture.
#[tauri::command]
pub async fn dns_analyze(
    domain: String,
    server: String,
    dkim_selectors: Vec<String>,
) -> Result<AnalysisReport, String> {
    let domain = domain.trim().trim_end_matches('.').to_string();
    if domain.is_empty() {
        return Err("enter a domain to analyze".to_string());
    }
    let root = Name::from_str(&domain).map_err(|_| format!("'{domain}' is not a valid domain"))?;

    let (resolver, server_label) = build_resolver(server.trim())?;

    let spf = analyze_spf(&resolver, &root).await;
    let dmarc = analyze_dmarc(&resolver, &domain).await;
    let dkim = analyze_dkim(&resolver, &domain, &dkim_selectors).await;
    let dnssec = analyze_dnssec(&resolver, &root).await;
    let ns = analyze_ns(&resolver, &root, &domain).await;

    Ok(AnalysisReport {
        domain,
        server: server_label,
        sections: vec![spf, dmarc, dkim, dnssec, ns],
    })
}

/// Build a resolver from an override IP, or the system configuration.
fn build_resolver(server: &str) -> Result<(TokioAsyncResolver, String), String> {
    let mut opts = ResolverOpts::default();
    opts.timeout = Duration::from_secs(5);
    opts.attempts = 2;

    if server.is_empty() {
        let resolver = TokioAsyncResolver::tokio_from_system_conf()
            .map_err(|e| format!("could not read system DNS config: {e}"))?;
        return Ok((resolver, "system resolver".to_string()));
    }

    let addr = core_parse_server(server)?;
    let mut config = ResolverConfig::new();
    for protocol in [Protocol::Udp, Protocol::Tcp] {
        config.add_name_server(NameServerConfig {
            socket_addr: addr,
            protocol,
            tls_dns_name: None,
            trust_negative_responses: true,
            bind_addr: None,
        });
    }
    Ok((TokioAsyncResolver::tokio(config, opts), addr.to_string()))
}

fn core_parse_server(s: &str) -> Result<SocketAddr, String> {
    if let Ok(sock) = s.parse::<SocketAddr>() {
        return Ok(sock);
    }
    if let Ok(ip) = s.parse::<std::net::IpAddr>() {
        return Ok(SocketAddr::new(ip, 53));
    }
    Err(format!(
        "server '{s}' must be an IP address, optionally with :port"
    ))
}

/// Fetch TXT records for a name, returning the concatenated strings. Any lookup
/// error (including no-such-record) yields an empty list.
async fn txt_records(resolver: &TokioAsyncResolver, name: &str) -> Vec<String> {
    let Ok(n) = Name::from_str(name) else {
        return Vec::new();
    };
    match resolver.txt_lookup(n).await {
        Ok(lookup) => lookup
            .iter()
            .map(|txt| {
                txt.txt_data()
                    .iter()
                    .map(|b| String::from_utf8_lossy(b))
                    .collect::<String>()
            })
            .collect(),
        Err(_) => Vec::new(),
    }
}

/// True if any record of `rtype` exists for `name`.
async fn has_records(resolver: &TokioAsyncResolver, name: Name, rtype: RecordType) -> bool {
    match resolver.lookup(name, rtype).await {
        Ok(lookup) => lookup.record_iter().next().is_some(),
        Err(_) => false,
    }
}

async fn analyze_spf(resolver: &TokioAsyncResolver, root: &Name) -> Section {
    let records = txt_records(resolver, &root.to_string()).await;
    let mut findings = core::spf_record_findings(&records);

    // If there is exactly one SPF record, follow includes/redirect to count the
    // true DNS-lookup total.
    let spf_records: Vec<&String> = records.iter().filter(|r| core::is_spf(r)).collect();
    if spf_records.len() == 1
        && let Some(spf) = core::parse_spf(spf_records[0])
    {
        let (total, capped) = spf_lookup_count(resolver, &spf).await;
        findings.push(core::spf_lookup_finding(total, capped));
    }

    let raw: Vec<String> = records.into_iter().filter(|r| core::is_spf(r)).collect();
    Section::new("SPF", findings, raw)
}

/// Follow include/redirect targets to count the recursive SPF lookup total.
async fn spf_lookup_count(resolver: &TokioAsyncResolver, root: &Spf) -> (u32, bool) {
    let mut total =
        root.direct_lookups + root.includes.len() as u32 + root.redirect.is_some() as u32;
    let mut queue: Vec<String> = root.includes.clone();
    if let Some(r) = &root.redirect {
        queue.push(r.clone());
    }
    let mut visited: HashSet<String> = HashSet::new();

    while let Some(target) = queue.pop() {
        if !visited.insert(target.clone()) {
            continue;
        }
        if total > SPF_LOOKUP_CAP {
            return (total, true);
        }
        let records = txt_records(resolver, &target).await;
        if let Some(spf) = records
            .iter()
            .find(|r| core::is_spf(r))
            .and_then(|r| core::parse_spf(r))
        {
            total += spf.direct_lookups + spf.includes.len() as u32 + spf.redirect.is_some() as u32;
            queue.extend(spf.includes);
            if let Some(r) = spf.redirect {
                queue.push(r);
            }
        }
    }
    (total, false)
}

async fn analyze_dmarc(resolver: &TokioAsyncResolver, domain: &str) -> Section {
    let name = format!("_dmarc.{domain}");
    let records = txt_records(resolver, &name).await;
    let findings = core::dmarc_findings(&records);
    let raw: Vec<String> = records.into_iter().filter(|r| core::is_dmarc(r)).collect();
    Section::new("DMARC", findings, raw)
}

async fn analyze_dkim(
    resolver: &TokioAsyncResolver,
    domain: &str,
    user_selectors: &[String],
) -> Section {
    // User-supplied selectors first, then the common probe list, de-duplicated.
    let mut selectors: Vec<String> = Vec::new();
    for s in user_selectors
        .iter()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
    {
        selectors.push(s.to_string());
    }
    for s in core::COMMON_SELECTORS {
        if !selectors.iter().any(|x| x == s) {
            selectors.push(s.to_string());
        }
    }

    let mut findings = Vec::new();
    let mut raw = Vec::new();
    for selector in &selectors {
        let name = format!("{selector}._domainkey.{domain}");
        let records = txt_records(resolver, &name).await;
        if let Some(rec) = records.iter().find(|r| core::is_dkim(r)) {
            findings.extend(core::dkim_findings(selector, rec));
            raw.push(format!("{selector}: {rec}"));
        }
    }
    if findings.is_empty() {
        findings.push(Finding::new(
            Severity::Warn,
            "No DKIM records found for the supplied or common selectors. If you know your selector, add it.",
        ));
    }
    Section::new("DKIM", findings, raw)
}

async fn analyze_dnssec(resolver: &TokioAsyncResolver, root: &Name) -> Section {
    let has_ds = has_records(resolver, root.clone(), RecordType::DS).await;
    let has_dnskey = has_records(resolver, root.clone(), RecordType::DNSKEY).await;
    Section::new(
        "DNSSEC",
        core::dnssec_findings(has_ds, has_dnskey),
        Vec::new(),
    )
}

async fn analyze_ns(resolver: &TokioAsyncResolver, root: &Name, domain: &str) -> Section {
    let ns_names: Vec<Name> = match resolver.lookup(root.clone(), RecordType::NS).await {
        Ok(lookup) => lookup
            .record_iter()
            .filter_map(|r| r.data().and_then(|d| d.as_ns()).map(|ns| ns.0.clone()))
            .collect(),
        Err(_) => Vec::new(),
    };

    if ns_names.is_empty() {
        return Section::new(
            "NS",
            vec![Finding::new(
                Severity::Fail,
                "No NS records found for the domain.",
            )],
            Vec::new(),
        );
    }

    let query_name = Name::from_str(domain).unwrap_or_else(|_| root.clone());
    let mut serials: Vec<(String, Option<u32>)> = Vec::new();
    for ns in ns_names.iter().take(MAX_NS) {
        let serial = soa_serial_from_ns(resolver, ns, &query_name).await;
        serials.push((ns.to_string(), serial));
    }

    let raw: Vec<String> = ns_names.iter().map(|n| n.to_string()).collect();
    Section::new("NS", core::ns_findings(&serials), raw)
}

/// Resolve a nameserver to an IP and ask it directly for the zone's SOA serial.
async fn soa_serial_from_ns(resolver: &TokioAsyncResolver, ns: &Name, zone: &Name) -> Option<u32> {
    let ip = resolver.lookup_ip(ns.clone()).await.ok()?.iter().next()?;
    let addr = SocketAddr::new(ip, 53);
    let serial = query_soa_serial(addr, zone.clone());
    tokio::time::timeout(Duration::from_secs(3), serial)
        .await
        .ok()
        .flatten()
}

/// Query a specific server for the SOA of `zone` and return its serial.
async fn query_soa_serial(server: SocketAddr, zone: Name) -> Option<u32> {
    use hickory_client::client::{AsyncClient, ClientHandle};
    use hickory_client::proto::rr::DNSClass;
    use hickory_client::udp::UdpClientStream;
    use tokio::net::UdpSocket;

    let stream = UdpClientStream::<UdpSocket>::new(server);
    let (mut client, bg) = AsyncClient::connect(stream).await.ok()?;
    let handle = tokio::spawn(bg);
    let resp = client.query(zone, DNSClass::IN, RecordType::SOA).await.ok();
    handle.abort();

    resp?
        .answers()
        .iter()
        .find_map(|r| r.data().and_then(|d| d.as_soa()).map(|soa| soa.serial()))
}
