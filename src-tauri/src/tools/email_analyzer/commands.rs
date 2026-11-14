//! Tauri commands for the Email Header Analyzer. Analysis is local. The two
//! online checks (who owns an IP, and blocklist status) run only when the
//! user asks, use the system DNS resolver, and are bounded by timeouts.

use std::net::IpAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hickory_proto::rr::RData;
use hickory_resolver::TokioResolver;
use serde::Serialize;

use super::core::{self, EmailAnalysis};
use super::domains::is_non_public;
use super::lookup::{self, Blocklist, CymruOrigin, ListingStatus};

/// Budget for each DNS query.
const QUERY_TIMEOUT: Duration = Duration::from_secs(5);
/// Most blocklists checked at once.
const MAX_ZONES: usize = 12;

/// Analyze pasted header text or a whole message.
#[tauri::command]
pub async fn email_analyze(text: String, known: Vec<String>) -> Result<EmailAnalysis, String> {
    let known = clean_known(known);
    tokio::task::spawn_blocking(move || core::analyze(text.as_bytes(), &known))
        .await
        .map_err(|e| format!("analysis failed: {e}"))?
        .map_err(|e| e.to_string())
}

/// Read and analyze a .eml file chosen in the native open dialog.
#[tauri::command]
pub async fn email_open(path: String, known: Vec<String>) -> Result<EmailAnalysis, String> {
    let known = clean_known(known);
    tokio::task::spawn_blocking(move || {
        let meta = std::fs::metadata(&path).map_err(|e| format!("could not read {path}: {e}"))?;
        if meta.len() > core::MAX_INPUT as u64 {
            return Err(core::EmailError::TooLarge(meta.len() as usize).to_string());
        }
        let bytes = std::fs::read(&path).map_err(|e| format!("could not read {path}: {e}"))?;
        core::analyze(&bytes, &known).map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| format!("analysis failed: {e}"))?
}

fn clean_known(known: Vec<String>) -> Vec<String> {
    known
        .into_iter()
        .map(|k| k.trim().to_string())
        .filter(|k| !k.is_empty() && k.len() <= 253)
        .take(100)
        .collect()
}

/// Blocklists offered by default.
#[tauri::command]
pub fn email_blocklists() -> Vec<Blocklist> {
    lookup::BLOCKLISTS.to_vec()
}

fn resolver() -> Result<TokioResolver, String> {
    TokioResolver::builder_tokio()
        .and_then(|b| b.build())
        .map_err(|e| format!("could not read system DNS config: {e}"))
}

fn public_ip(ip: &str) -> Result<IpAddr, String> {
    let ip: IpAddr = ip
        .trim()
        .parse()
        .map_err(|_| format!("'{ip}' is not an IP address"))?;
    if is_non_public(&ip) {
        return Err(format!(
            "{ip} is a private or reserved address; there is nothing to look up"
        ));
    }
    Ok(ip)
}

fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

async fn txt(resolver: &TokioResolver, name: &str) -> Result<Vec<String>, String> {
    let lookup = tokio::time::timeout(QUERY_TIMEOUT, resolver.txt_lookup(name))
        .await
        .map_err(|_| format!("{name}: timed out"))?
        .map_err(|e| format!("{name}: {e}"))?;
    Ok(lookup
        .answers()
        .iter()
        .filter_map(|r| match &r.data {
            RData::TXT(t) => Some(
                t.txt_data
                    .iter()
                    .map(|b| String::from_utf8_lossy(b).into_owned())
                    .collect::<String>(),
            ),
            _ => None,
        })
        .collect())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IpOwner {
    pub ip: String,
    /// Reverse DNS names.
    pub ptr: Vec<String>,
    pub origin: Option<CymruOrigin>,
    pub as_name: String,
    pub source: String,
    pub looked_up_ms: u64,
    pub errors: Vec<String>,
}

/// Who announces an IP: ASN, prefix, registry and AS name from Team Cymru's
/// DNS service, plus reverse DNS. Routing data, not registration records.
#[tauri::command]
pub async fn email_ip_owner(ip: String) -> Result<IpOwner, String> {
    let ip = public_ip(&ip)?;
    let resolver = resolver()?;
    let mut errors = Vec::new();

    let ptr_lookup = tokio::time::timeout(QUERY_TIMEOUT, resolver.reverse_lookup(ip));
    let origin_name = lookup::cymru_origin_name(ip);
    let origin_lookup = txt(&resolver, &origin_name);
    let (ptr_res, origin_res) = tokio::join!(ptr_lookup, origin_lookup);

    let ptr = match ptr_res {
        Ok(Ok(l)) => l
            .answers()
            .iter()
            .filter_map(|r| match &r.data {
                RData::PTR(p) => Some(p.0.to_utf8().trim_end_matches('.').to_string()),
                _ => None,
            })
            .take(10)
            .collect(),
        Ok(Err(e)) if e.is_no_records_found() || e.is_nx_domain() => Vec::new(),
        Ok(Err(e)) => {
            errors.push(format!("reverse DNS: {e}"));
            Vec::new()
        }
        Err(_) => {
            errors.push("reverse DNS: timed out".into());
            Vec::new()
        }
    };
    let origin = match origin_res {
        Ok(answers) => answers.iter().find_map(|a| lookup::parse_cymru_origin(a)),
        Err(e) => {
            errors.push(format!("ASN lookup: {e}"));
            None
        }
    };
    let mut as_name = String::new();
    if let Some(asn) = origin.as_ref().and_then(|o| o.asns.first()) {
        match txt(&resolver, &format!("AS{asn}.asn.cymru.com")).await {
            Ok(a) => {
                as_name = a
                    .iter()
                    .find_map(|t| lookup::parse_cymru_as_name(t))
                    .unwrap_or_default()
            }
            Err(e) => errors.push(format!("AS name: {e}")),
        }
    }
    Ok(IpOwner {
        ip: ip.to_string(),
        ptr,
        origin,
        as_name,
        source: "Team Cymru IP-to-ASN (DNS) and reverse DNS".into(),
        looked_up_ms: unix_ms(),
        errors,
    })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BlocklistResult {
    pub zone: String,
    pub status: ListingStatus,
    pub detail: String,
    /// TXT reason published by the list, when listed.
    pub reason: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BlocklistReport {
    pub ip: String,
    pub results: Vec<BlocklistResult>,
    pub looked_up_ms: u64,
}

/// Check an IPv4 address against the chosen DNS blocklists.
#[tauri::command]
pub async fn email_blocklist_check(
    ip: String,
    zones: Vec<String>,
) -> Result<BlocklistReport, String> {
    let ip = match public_ip(&ip)? {
        IpAddr::V4(v4) => v4,
        IpAddr::V6(_) => {
            return Err("blocklist checks here cover IPv4 only; most DNS blocklists do not list IPv6 senders".into());
        }
    };
    let zones: Vec<String> = zones
        .into_iter()
        .map(|z| z.trim().trim_end_matches('.').to_ascii_lowercase())
        .filter(|z| lookup::valid_zone(z))
        .take(MAX_ZONES)
        .collect();
    if zones.is_empty() {
        return Err("choose at least one blocklist".into());
    }
    let resolver = resolver()?;
    let reversed = lookup::reversed_v4(ip);
    let mut set = tokio::task::JoinSet::new();
    for (i, zone) in zones.iter().enumerate() {
        let resolver = resolver.clone();
        let name = format!("{reversed}.{zone}.");
        let zone = zone.clone();
        set.spawn(async move { (i, check_zone(&resolver, &zone, &name).await) });
    }
    let mut results: Vec<(usize, BlocklistResult)> = Vec::new();
    while let Some(Ok(r)) = set.join_next().await {
        results.push(r);
    }
    results.sort_by_key(|(i, _)| *i);
    Ok(BlocklistReport {
        ip: ip.to_string(),
        results: results.into_iter().map(|(_, r)| r).collect(),
        looked_up_ms: unix_ms(),
    })
}

async fn check_zone(resolver: &TokioResolver, zone: &str, name: &str) -> BlocklistResult {
    let answer = tokio::time::timeout(QUERY_TIMEOUT, resolver.ipv4_lookup(name)).await;
    let (status, detail) = match answer {
        Err(_) => (ListingStatus::Error, "Timed out".to_string()),
        Ok(Err(e)) if e.is_no_records_found() || e.is_nx_domain() => {
            lookup::interpret_dnsbl(zone, &[])
        }
        Ok(Err(e)) => (ListingStatus::Error, format!("Lookup failed: {e}")),
        Ok(Ok(l)) => {
            let ips: Vec<_> = l
                .answers()
                .iter()
                .filter_map(|r| match &r.data {
                    RData::A(a) => Some(a.0),
                    _ => None,
                })
                .collect();
            lookup::interpret_dnsbl(zone, &ips)
        }
    };
    let reason = if status == ListingStatus::Listed {
        txt(resolver, name).await.unwrap_or_default().join(" ")
    } else {
        String::new()
    };
    BlocklistResult {
        zone: zone.to_string(),
        status,
        detail,
        reason: reason.chars().take(500).collect(),
    }
}
