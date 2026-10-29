//! Tauri command for the DNS analyzer. Orchestrates the lookups and feeds the
//! results to the pure scoring in `core`.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::str::FromStr;
use std::time::Duration;

use hickory_net::runtime::TokioRuntimeProvider;
use hickory_proto::rr::{Name, RData, RecordType};
use hickory_resolver::TokioResolver;
use hickory_resolver::config::{ConnectionConfig, NameServerConfig, ResolverConfig, ResolverOpts};
use hickory_resolver::lookup::Lookup;
use tokio::task::JoinSet;

use super::core::{self, AnalysisReport, Finding, MxEntry, Section, Severity, Spf};

/// Maximum nameservers to probe for SOA agreement.
const MAX_NS: usize = 8;
/// Upper bound on SPF lookups to follow before declaring it over the limit.
const SPF_LOOKUP_CAP: u32 = 25;

/// Most MX exchangers resolved.
const MAX_MX: usize = 16;

/// Analyze a domain's SPF, DMARC, DKIM, MX, DNSSEC, and NS posture.
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
    let mx = analyze_mx(&resolver, &root).await;
    let dnssec = analyze_dnssec(&resolver, &root).await;
    let ns = analyze_ns(&resolver, &root, &domain).await;

    Ok(AnalysisReport {
        domain,
        server: server_label,
        sections: vec![spf, dmarc, dkim, mx, dnssec, ns],
    })
}

/// Build a resolver from an override IP, or the system configuration.
fn build_resolver(server: &str) -> Result<(TokioResolver, String), String> {
    if server.is_empty() {
        let resolver = TokioResolver::builder_tokio()
            .and_then(|b| b.build())
            .map_err(|e| format!("could not read system DNS config: {e}"))?;
        return Ok((resolver, "system resolver".to_string()));
    }

    let mut opts = ResolverOpts::default();
    opts.timeout = Duration::from_secs(5);
    opts.attempts = 2;

    let addr = core_parse_server(server)?;
    let connections = [ConnectionConfig::udp(), ConnectionConfig::tcp()]
        .into_iter()
        .map(|mut c| {
            c.port = addr.port();
            c
        })
        .collect();
    let config = ResolverConfig::from_name_servers(vec![NameServerConfig::new(
        addr.ip(),
        true,
        connections,
    )]);
    let resolver = TokioResolver::builder_with_config(config, TokioRuntimeProvider::default())
        .with_options(opts)
        .build()
        .map_err(|e| format!("could not build resolver: {e}"))?;
    Ok((resolver, addr.to_string()))
}

/// Record data of the answers in a lookup.
fn rdata(lookup: &Lookup) -> impl Iterator<Item = &RData> {
    lookup.answers().iter().map(|r| &r.data)
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
async fn txt_records(resolver: &TokioResolver, name: &str) -> Vec<String> {
    let Ok(n) = Name::from_str(name) else {
        return Vec::new();
    };
    match resolver.txt_lookup(n).await {
        Ok(lookup) => rdata(&lookup)
            .filter_map(|d| match d {
                RData::TXT(txt) => Some(txt),
                _ => None,
            })
            .map(|txt| {
                txt.txt_data
                    .iter()
                    .map(|b| String::from_utf8_lossy(b))
                    .collect::<String>()
            })
            .collect(),
        Err(_) => Vec::new(),
    }
}

/// A and AAAA addresses of a host, as strings, IPv4 first.
async fn resolve_host(resolver: &TokioResolver, host: Name) -> Vec<String> {
    let (v4, v6) = tokio::join!(
        resolver.ipv4_lookup(host.clone()),
        resolver.ipv6_lookup(host)
    );
    let mut out: Vec<String> = Vec::new();
    for l in [v4, v6].into_iter().flatten() {
        out.extend(rdata(&l).filter_map(|d| match d {
            RData::A(a) => Some(a.0.to_string()),
            RData::AAAA(a) => Some(a.0.to_string()),
            _ => None,
        }));
    }
    out
}

/// True if any record of `rtype` exists for `name`.
async fn has_records(resolver: &TokioResolver, name: Name, rtype: RecordType) -> bool {
    match resolver.lookup(name, rtype).await {
        Ok(lookup) => !lookup.answers().is_empty(),
        Err(_) => false,
    }
}

async fn analyze_spf(resolver: &TokioResolver, root: &Name) -> Section {
    let records = txt_records(resolver, &root.to_string()).await;
    let mut findings = core::spf_record_findings(&records);

    // If there is exactly one SPF record, follow includes/redirect to count the
    // true DNS-lookup total.
    let spf_records: Vec<&String> = records.iter().filter(|r| core::is_spf(r)).collect();
    if spf_records.len() == 1
        && let Some(spf) = core::parse_spf(spf_records[0])
    {
        let walk = spf_lookup_count(resolver, &spf).await;
        findings.push(core::spf_lookup_finding(walk.total, walk.capped));
        findings.extend(core::spf_extra_findings(
            &walk.voids,
            walk.uses_ptr,
            spf_records[0].len(),
        ));
    }

    let raw: Vec<String> = records.into_iter().filter(|r| core::is_spf(r)).collect();
    Section::new("SPF", findings, raw)
}

/// Result of walking an SPF record's include and redirect chain.
struct SpfWalk {
    total: u32,
    capped: bool,
    /// Include or redirect targets with no SPF record.
    voids: Vec<String>,
    /// `ptr` appears anywhere in the chain.
    uses_ptr: bool,
}

/// Follow include/redirect targets to count the recursive SPF lookup total,
/// void lookups, and `ptr` use.
async fn spf_lookup_count(resolver: &TokioResolver, root: &Spf) -> SpfWalk {
    let mut total =
        root.direct_lookups + root.includes.len() as u32 + root.redirect.is_some() as u32;
    let mut voids = Vec::new();
    let mut uses_ptr = root.uses_ptr;
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
            return SpfWalk {
                total,
                capped: true,
                voids,
                uses_ptr,
            };
        }
        let records = txt_records(resolver, &target).await;
        match records
            .iter()
            .find(|r| core::is_spf(r))
            .and_then(|r| core::parse_spf(r))
        {
            Some(spf) => {
                total +=
                    spf.direct_lookups + spf.includes.len() as u32 + spf.redirect.is_some() as u32;
                uses_ptr |= spf.uses_ptr;
                queue.extend(spf.includes);
                if let Some(r) = spf.redirect {
                    queue.push(r);
                }
            }
            None => voids.push(target),
        }
    }
    SpfWalk {
        total,
        capped: false,
        voids,
        uses_ptr,
    }
}

async fn analyze_dmarc(resolver: &TokioResolver, domain: &str) -> Section {
    let name = format!("_dmarc.{domain}");
    let records = txt_records(resolver, &name).await;
    let findings = core::dmarc_findings(&records);
    let raw: Vec<String> = records.into_iter().filter(|r| core::is_dmarc(r)).collect();
    Section::new("DMARC", findings, raw)
}

async fn analyze_dkim(
    resolver: &TokioResolver,
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

    // A selector nobody would use: an answer means a wildcard record.
    let sentinel = format!(
        "omnipacket-probe-{:x}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() & 0xffff_ffff)
            .unwrap_or(0)
    );
    let wildcard = txt_records(resolver, &format!("{sentinel}._domainkey.{domain}"))
        .await
        .into_iter()
        .find(|r| core::is_dkim(r));
    if wildcard.is_some() {
        // Only the user's own selectors can still say something.
        selectors.retain(|s| user_selectors.iter().any(|u| u.trim() == s));
    }

    // Probe every selector in parallel, then report in list order.
    let mut set = JoinSet::new();
    for (i, selector) in selectors.iter().enumerate() {
        let resolver = resolver.clone();
        let name = format!("{selector}._domainkey.{domain}");
        set.spawn(async move { (i, txt_records(&resolver, &name).await) });
    }
    let mut hits: Vec<(usize, String)> = Vec::new();
    while let Some(Ok((i, records))) = set.join_next().await {
        if let Some(rec) = records.into_iter().find(|r| core::is_dkim(r)) {
            hits.push((i, rec));
        }
    }
    hits.sort_by_key(|(i, _)| *i);

    let mut findings = Vec::new();
    let mut raw = Vec::new();
    if let Some(w) = &wildcard {
        findings.push(core::dkim_wildcard_finding(w));
        raw.push(format!("*: {w}"));
    }
    for (i, rec) in &hits {
        if wildcard.as_deref() == Some(rec.as_str()) {
            continue;
        }
        let selector = &selectors[*i];
        findings.extend(core::dkim_findings(selector, rec));
        raw.push(format!("{selector}: {rec}"));
    }
    if findings.is_empty() {
        findings.push(Finding::new(
            Severity::Warn,
            format!(
                "No DKIM records found for {} supplied or common selectors. Selectors are chosen by the sender; if you know yours, add it.",
                selectors.len()
            ),
        ));
    }
    Section::new("DKIM", findings, raw)
}

async fn analyze_mx(resolver: &TokioResolver, root: &Name) -> Section {
    let records = match resolver.mx_lookup(root.clone()).await {
        Ok(l) => rdata(&l)
            .filter_map(|d| match d {
                RData::MX(mx) => Some((mx.preference, mx.exchange.clone())),
                _ => None,
            })
            .collect::<Vec<_>>(),
        Err(e) if e.is_no_records_found() => Vec::new(),
        Err(e) => {
            return Section::new(
                "MX",
                vec![Finding::new(
                    Severity::Warn,
                    format!("MX lookup failed: {e}"),
                )],
                Vec::new(),
            );
        }
    };

    let mut entries = Vec::new();
    for (pref, exchange) in records.into_iter().take(MAX_MX) {
        let host = exchange.to_string().trim_end_matches('.').to_string();
        let null = pref == 0 && exchange.is_root();
        let addresses = if null || host.is_empty() {
            Vec::new()
        } else {
            resolve_host(resolver, exchange).await
        };
        entries.push(MxEntry {
            preference: pref,
            host: if null { ".".to_string() } else { host },
            addresses,
        });
    }
    entries.sort_by(|a, b| a.preference.cmp(&b.preference).then(a.host.cmp(&b.host)));

    // Senders fall back to the apex address when there is no MX.
    let apex = if entries.is_empty() {
        resolve_host(resolver, root.clone()).await
    } else {
        Vec::new()
    };

    let raw = entries
        .iter()
        .map(|e| {
            if e.addresses.is_empty() {
                format!("{} {}", e.preference, e.host)
            } else {
                format!("{} {} ({})", e.preference, e.host, e.addresses.join(", "))
            }
        })
        .collect();
    Section::new("MX", core::mx_findings(&entries, &apex), raw)
}

async fn analyze_dnssec(resolver: &TokioResolver, root: &Name) -> Section {
    let has_ds = has_records(resolver, root.clone(), RecordType::DS).await;
    let has_dnskey = has_records(resolver, root.clone(), RecordType::DNSKEY).await;
    Section::new(
        "DNSSEC",
        core::dnssec_findings(has_ds, has_dnskey),
        Vec::new(),
    )
}

async fn analyze_ns(resolver: &TokioResolver, root: &Name, domain: &str) -> Section {
    let ns_names: Vec<Name> = match resolver.lookup(root.clone(), RecordType::NS).await {
        Ok(lookup) => rdata(&lookup)
            .filter_map(|d| match d {
                RData::NS(ns) => Some(ns.0.clone()),
                _ => None,
            })
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
    let mut hosts: Vec<(String, Vec<String>)> = Vec::new();
    for ns in ns_names.iter().take(MAX_NS) {
        let addrs = resolve_host(resolver, ns.clone()).await;
        let serial = soa_serial_from_ns(&addrs, &query_name).await;
        let host = ns.to_string().trim_end_matches('.').to_string();
        serials.push((host.clone(), serial));
        hosts.push((host, addrs));
    }

    let mut findings = core::ns_findings(&serials);
    findings.extend(core::ns_host_findings(&hosts));
    let raw: Vec<String> = hosts
        .iter()
        .map(|(h, a)| {
            if a.is_empty() {
                format!("{h} (does not resolve)")
            } else {
                format!("{h} ({})", a.join(", "))
            }
        })
        .collect();
    Section::new("NS", findings, raw)
}

/// Ask a nameserver directly for the zone's SOA serial, preferring IPv4.
async fn soa_serial_from_ns(addrs: &[String], zone: &Name) -> Option<u32> {
    let ip: std::net::IpAddr = addrs.first()?.parse().ok()?;
    let addr = SocketAddr::new(ip, 53);
    let serial = query_soa_serial(addr, zone.clone());
    tokio::time::timeout(Duration::from_secs(3), serial)
        .await
        .ok()
        .flatten()
}

/// Query a specific server for the SOA of `zone` and return its serial.
async fn query_soa_serial(server: SocketAddr, zone: Name) -> Option<u32> {
    use hickory_net::client::{Client, ClientHandle};
    use hickory_net::udp::UdpClientStream;
    use hickory_proto::rr::DNSClass;

    let stream = UdpClientStream::builder(server, TokioRuntimeProvider::default()).build();
    let (mut client, bg) = Client::<TokioRuntimeProvider>::from_sender(stream);
    let handle = tokio::spawn(bg);
    let resp = client.query(zone, DNSClass::IN, RecordType::SOA).await.ok();
    handle.abort();

    resp?.answers.iter().find_map(|r| match &r.data {
        RData::SOA(soa) => Some(soa.serial),
        _ => None,
    })
}
