//! Tauri command for DNS lookups, built on hickory-net. Queries a specific
//! server over UDP and retries over TCP if the answer is truncated. Every query
//! is bounded by a timeout.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use hickory_net::client::{Client, ClientHandle};
use hickory_net::runtime::TokioRuntimeProvider;
use hickory_net::tcp::TcpClientStream;
use hickory_net::udp::UdpClientStream;
use hickory_proto::op::{DnsResponse, MessageType};
use hickory_proto::rr::{DNSClass, Name, RecordType};

use super::core::{self, DigResponse};

const QUERY_TIMEOUT: Duration = Duration::from_secs(5);

/// Look up `name` of `record_type` against `server` (blank = system resolver).
#[tauri::command]
pub async fn dig_query(
    name: String,
    record_type: String,
    server: String,
) -> Result<DigResponse, String> {
    let rtype = core::parse_record_type(&record_type).map_err(|e| e.to_string())?;
    let qname = core::query_name(&name, rtype).map_err(|e| e.to_string())?;
    let addr = resolve_server(&server)?;

    let start = Instant::now();
    let (resp, protocol) =
        match tokio::time::timeout(QUERY_TIMEOUT, run_query(addr, qname.clone(), rtype)).await {
            Err(_) => return Err(format!("query to {addr} timed out after 5s")),
            Ok(inner) => inner?,
        };
    let query_time_ms = start.elapsed().as_millis() as u64;

    let meta = &resp.metadata;
    let mut flags: Vec<String> = Vec::new();
    if meta.message_type == MessageType::Response {
        flags.push("qr".into());
    }
    for (set, flag) in [
        (meta.authoritative, "aa"),
        (meta.truncation, "tc"),
        (meta.recursion_desired, "rd"),
        (meta.recursion_available, "ra"),
        (meta.authentic_data, "ad"),
    ] {
        if set {
            flags.push(flag.into());
        }
    }

    Ok(DigResponse {
        server: addr.to_string(),
        protocol: protocol.to_string(),
        rcode: core::rcode_str(meta.response_code),
        flags,
        query_time_ms,
        question: format!("{qname} IN {rtype}"),
        answers: resp.answers.iter().map(core::to_record).collect(),
        authority: resp.authorities.iter().map(core::to_record).collect(),
        additional: resp.additionals.iter().map(core::to_record).collect(),
    })
}

/// Pick the server: explicit override, else the first system resolver, else a
/// public fallback.
fn resolve_server(server: &str) -> Result<SocketAddr, String> {
    let s = server.trim();
    if !s.is_empty() {
        return core::parse_server(s).map_err(|e| e.to_string());
    }
    if let Ok((cfg, _opts)) = hickory_resolver::system_conf::read_system_conf()
        && let Some(ns) = cfg.name_servers().first()
    {
        let port = ns.connections.first().map_or(core::DNS_PORT, |c| c.port);
        return Ok(SocketAddr::new(ns.ip, port));
    }
    Ok(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
        core::DNS_PORT,
    ))
}

/// Query over UDP, retrying over TCP when the response is truncated.
async fn run_query(
    server: SocketAddr,
    name: Name,
    rtype: RecordType,
) -> Result<(DnsResponse, &'static str), String> {
    let udp = query_udp(server, name.clone(), rtype).await?;
    if udp.metadata.truncation {
        let tcp = query_tcp(server, name, rtype).await?;
        return Ok((tcp, "TCP"));
    }
    Ok((udp, "UDP"))
}

async fn query_udp(
    server: SocketAddr,
    name: Name,
    rtype: RecordType,
) -> Result<DnsResponse, String> {
    let stream = UdpClientStream::builder(server, TokioRuntimeProvider::default())
        .with_timeout(Some(QUERY_TIMEOUT))
        .build();
    let (mut client, bg) = Client::<TokioRuntimeProvider>::from_sender(stream);
    let handle = tokio::spawn(bg);
    let res = client
        .query(name, DNSClass::IN, rtype)
        .await
        .map_err(|e| format!("query {server} (UDP): {e}"));
    handle.abort();
    res
}

async fn query_tcp(
    server: SocketAddr,
    name: Name,
    rtype: RecordType,
) -> Result<DnsResponse, String> {
    let (connect, sender) = TcpClientStream::new(
        server,
        None,
        Some(QUERY_TIMEOUT),
        TokioRuntimeProvider::default(),
    );
    let stream = connect
        .await
        .map_err(|e| format!("connect {server} (TCP): {e}"))?;
    let (mut client, bg) = Client::<TokioRuntimeProvider>::new(stream, sender);
    let handle = tokio::spawn(bg);
    let res = client
        .query(name, DNSClass::IN, rtype)
        .await
        .map_err(|e| format!("query {server} (TCP): {e}"));
    handle.abort();
    res
}
