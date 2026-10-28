//! Tauri command for DNS lookups, built on hickory-client. Queries a specific
//! server over UDP and retries over TCP if the answer is truncated. Every query
//! is bounded by a timeout.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use hickory_client::client::{AsyncClient, ClientHandle};
use hickory_client::proto::iocompat::AsyncIoTokioAsStd;
use hickory_client::proto::op::MessageType;
use hickory_client::proto::rr::{DNSClass, Name, RecordType};
use hickory_client::proto::xfer::DnsResponse;
use hickory_client::tcp::TcpClientStream;
use hickory_client::udp::UdpClientStream;
use tokio::net::{TcpStream, UdpSocket};

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

    let header = resp.header();
    let mut flags: Vec<String> = Vec::new();
    if header.message_type() == MessageType::Response {
        flags.push("qr".into());
    }
    if header.authoritative() {
        flags.push("aa".into());
    }
    if header.truncated() {
        flags.push("tc".into());
    }
    if header.recursion_desired() {
        flags.push("rd".into());
    }
    if header.recursion_available() {
        flags.push("ra".into());
    }
    if header.authentic_data() {
        flags.push("ad".into());
    }

    Ok(DigResponse {
        server: addr.to_string(),
        protocol: protocol.to_string(),
        rcode: core::rcode_str(resp.response_code()),
        flags,
        query_time_ms,
        question: format!("{qname} IN {rtype}"),
        answers: resp.answers().iter().map(core::to_record).collect(),
        authority: resp.name_servers().iter().map(core::to_record).collect(),
        additional: resp.additionals().iter().map(core::to_record).collect(),
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
        return Ok(ns.socket_addr);
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
    if udp.truncated() {
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
    let stream = UdpClientStream::<UdpSocket>::new(server);
    let (mut client, bg) = AsyncClient::connect(stream)
        .await
        .map_err(|e| format!("connect {server} (UDP): {e}"))?;
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
    let (stream, sender) = TcpClientStream::<AsyncIoTokioAsStd<TcpStream>>::new(server);
    let (mut client, bg) = AsyncClient::new(stream, sender, None)
        .await
        .map_err(|e| format!("connect {server} (TCP): {e}"))?;
    let handle = tokio::spawn(bg);
    let res = client
        .query(name, DNSClass::IN, rtype)
        .await
        .map_err(|e| format!("query {server} (TCP): {e}"));
    handle.abort();
    res
}
