//! Pure DHCP logic for the DHCP monitor: build a DHCPDISCOVER, parse server
//! replies (bounded, hostile-input safe), summarize offers, and track which
//! servers answered and whether they are authorized. No sockets here; the
//! network I/O is in `commands.rs`.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use serde::Serialize;
use thiserror::Error;

/// UDP port DHCP servers listen on.
pub const SERVER_PORT: u16 = 67;
/// UDP port DHCP clients listen on.
pub const CLIENT_PORT: u16 = 68;

/// Fixed BOOTP header length before the magic cookie.
const BOOTP_HEADER_LEN: usize = 236;
const MAGIC_COOKIE: [u8; 4] = [99, 130, 83, 99];
/// BOOTP minimum message size; some servers drop shorter requests.
const MIN_REQUEST_LEN: usize = 300;
/// Largest reply we accept; anything bigger is not a sane DHCP packet.
pub const MAX_PACKET_LEN: usize = 1500;

const BOOTREQUEST: u8 = 1;
const BOOTREPLY: u8 = 2;
const HTYPE_ETHERNET: u8 = 1;
const FLAG_BROADCAST: u16 = 0x8000;

mod opt {
    pub const PAD: u8 = 0;
    pub const SUBNET_MASK: u8 = 1;
    pub const ROUTER: u8 = 3;
    pub const DNS: u8 = 6;
    pub const DOMAIN: u8 = 15;
    pub const BROADCAST: u8 = 28;
    pub const LEASE_TIME: u8 = 51;
    pub const OVERLOAD: u8 = 52;
    pub const MESSAGE_TYPE: u8 = 53;
    pub const SERVER_ID: u8 = 54;
    pub const PARAM_LIST: u8 = 55;
    pub const RENEWAL: u8 = 58;
    pub const REBINDING: u8 = 59;
    pub const CLIENT_ID: u8 = 61;
    pub const END: u8 = 255;
}

/// DHCP message types (option 53).
pub mod msg {
    pub const DISCOVER: u8 = 1;
    pub const OFFER: u8 = 2;
    pub const ACK: u8 = 5;
    pub const NAK: u8 = 6;
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DhcpError {
    #[error("packet too short for a DHCP message ({0} bytes)")]
    TooShort(usize),
    #[error("packet larger than {MAX_PACKET_LEN} bytes")]
    TooLong,
    #[error("missing DHCP magic cookie")]
    NoCookie,
    #[error("option {0} runs past the end of the packet")]
    TruncatedOption(u8),
    #[error("invalid IPv4 address '{0}'")]
    BadAddress(String),
}

/// Build a DHCPDISCOVER with the broadcast flag set, so servers broadcast
/// their offers back to UDP 68 instead of unicasting to an address we do not
/// own.
pub fn build_discover(xid: u32, mac: &[u8; 6]) -> Vec<u8> {
    let mut p = vec![0u8; BOOTP_HEADER_LEN];
    p[0] = BOOTREQUEST;
    p[1] = HTYPE_ETHERNET;
    p[2] = 6;
    p[4..8].copy_from_slice(&xid.to_be_bytes());
    p[10..12].copy_from_slice(&FLAG_BROADCAST.to_be_bytes());
    p[28..34].copy_from_slice(mac);
    p.extend_from_slice(&MAGIC_COOKIE);

    p.extend_from_slice(&[opt::MESSAGE_TYPE, 1, msg::DISCOVER]);
    p.extend_from_slice(&[opt::CLIENT_ID, 7, HTYPE_ETHERNET]);
    p.extend_from_slice(mac);
    let params = [
        opt::SUBNET_MASK,
        opt::ROUTER,
        opt::DNS,
        opt::DOMAIN,
        opt::BROADCAST,
        opt::LEASE_TIME,
        opt::SERVER_ID,
        opt::RENEWAL,
        opt::REBINDING,
    ];
    p.extend_from_slice(&[opt::PARAM_LIST, params.len() as u8]);
    p.extend_from_slice(&params);
    p.push(opt::END);
    if p.len() < MIN_REQUEST_LEN {
        p.resize(MIN_REQUEST_LEN, 0);
    }
    p
}

/// A parsed BOOTP/DHCP message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DhcpPacket {
    pub op: u8,
    pub xid: u32,
    pub yiaddr: Ipv4Addr,
    pub siaddr: Ipv4Addr,
    pub giaddr: Ipv4Addr,
    pub chaddr: [u8; 6],
    /// Options in wire order (code, value).
    pub options: Vec<(u8, Vec<u8>)>,
}

impl DhcpPacket {
    /// First value of an option.
    pub fn option(&self, code: u8) -> Option<&[u8]> {
        self.options
            .iter()
            .find(|(c, _)| *c == code)
            .map(|(_, v)| v.as_slice())
    }

    /// DHCP message type (option 53).
    pub fn message_type(&self) -> Option<u8> {
        self.option(opt::MESSAGE_TYPE)
            .and_then(|v| v.first().copied())
    }
}

/// Parse a DHCP message. Every length is checked against the buffer, so
/// malformed or hostile packets return an error instead of panicking.
pub fn parse_packet(buf: &[u8]) -> Result<DhcpPacket, DhcpError> {
    if buf.len() > MAX_PACKET_LEN {
        return Err(DhcpError::TooLong);
    }
    if buf.len() < BOOTP_HEADER_LEN + MAGIC_COOKIE.len() {
        return Err(DhcpError::TooShort(buf.len()));
    }
    if buf[BOOTP_HEADER_LEN..BOOTP_HEADER_LEN + 4] != MAGIC_COOKIE {
        return Err(DhcpError::NoCookie);
    }
    let ip = |at: usize| Ipv4Addr::new(buf[at], buf[at + 1], buf[at + 2], buf[at + 3]);
    let mut chaddr = [0u8; 6];
    chaddr.copy_from_slice(&buf[28..34]);

    let mut options = Vec::new();
    parse_options(&buf[BOOTP_HEADER_LEN + 4..], &mut options)?;

    // Option overload (52): the file (1), sname (2), or both (3) fields carry
    // more options.
    let overload = options
        .iter()
        .find(|(c, _)| *c == opt::OVERLOAD)
        .and_then(|(_, v)| v.first().copied())
        .unwrap_or(0);
    if overload & 1 != 0 {
        parse_options(&buf[108..236], &mut options)?;
    }
    if overload & 2 != 0 {
        parse_options(&buf[44..108], &mut options)?;
    }

    Ok(DhcpPacket {
        op: buf[0],
        xid: u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]),
        yiaddr: ip(16),
        siaddr: ip(20),
        giaddr: ip(24),
        chaddr,
        options,
    })
}

fn parse_options(mut data: &[u8], out: &mut Vec<(u8, Vec<u8>)>) -> Result<(), DhcpError> {
    while let Some((&code, rest)) = data.split_first() {
        match code {
            opt::PAD => data = rest,
            opt::END => break,
            _ => {
                let (&len, rest) = rest.split_first().ok_or(DhcpError::TruncatedOption(code))?;
                let len = len as usize;
                if rest.len() < len {
                    return Err(DhcpError::TruncatedOption(code));
                }
                out.push((code, rest[..len].to_vec()));
                data = &rest[len..];
            }
        }
    }
    Ok(())
}

/// What a server reply says, in display form.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct OfferInfo {
    pub message_type: String,
    pub xid: String,
    pub client_mac: String,
    pub offered_ip: Option<Ipv4Addr>,
    pub server_id: Option<Ipv4Addr>,
    pub subnet_mask: Option<Ipv4Addr>,
    pub routers: Vec<Ipv4Addr>,
    pub dns: Vec<Ipv4Addr>,
    pub domain: Option<String>,
    pub lease_secs: Option<u32>,
    /// Relay agent (giaddr) when the reply came through a relay.
    pub relay: Option<Ipv4Addr>,
    /// Next server (siaddr), typically a TFTP/PXE boot server.
    pub next_server: Option<Ipv4Addr>,
}

/// Summarize a server reply. Returns None for anything that is not an
/// Ethernet BOOTREPLY carrying OFFER, ACK, or NAK.
pub fn summarize(p: &DhcpPacket) -> Option<OfferInfo> {
    if p.op != BOOTREPLY {
        return None;
    }
    let message_type = match p.message_type()? {
        msg::OFFER => "OFFER",
        msg::ACK => "ACK",
        msg::NAK => "NAK",
        _ => return None,
    };
    let nonzero = |a: Ipv4Addr| (!a.is_unspecified()).then_some(a);
    Some(OfferInfo {
        message_type: message_type.to_string(),
        xid: format!("0x{:08x}", p.xid),
        client_mac: format_mac(&p.chaddr),
        offered_ip: nonzero(p.yiaddr),
        server_id: p.option(opt::SERVER_ID).and_then(first_addr),
        subnet_mask: p.option(opt::SUBNET_MASK).and_then(first_addr),
        routers: p.option(opt::ROUTER).map(addrs).unwrap_or_default(),
        dns: p.option(opt::DNS).map(addrs).unwrap_or_default(),
        domain: p.option(opt::DOMAIN).map(|v| {
            String::from_utf8_lossy(v)
                .trim_end_matches('\0')
                .trim()
                .to_string()
        }),
        lease_secs: p
            .option(opt::LEASE_TIME)
            .and_then(|v| <[u8; 4]>::try_from(v).ok())
            .map(u32::from_be_bytes),
        relay: nonzero(p.giaddr),
        next_server: nonzero(p.siaddr),
    })
}

fn first_addr(v: &[u8]) -> Option<Ipv4Addr> {
    addrs(v).into_iter().next()
}

fn addrs(v: &[u8]) -> Vec<Ipv4Addr> {
    v.as_chunks::<4>()
        .0
        .iter()
        .map(|c| Ipv4Addr::from(*c))
        .collect()
}

/// Uppercase colon form.
pub fn format_mac(mac: &[u8; 6]) -> String {
    mac.iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// A random-looking client MAC from a seed, marked locally administered and
/// unicast so it can never collide with a real vendor address.
pub fn client_mac_from_seed(seed: u64) -> [u8; 6] {
    let b = seed.to_be_bytes();
    let mut mac = [b[2], b[3], b[4], b[5], b[6], b[7]];
    mac[0] = (mac[0] & 0xfc) | 0x02;
    mac
}

/// Parse a list of authorized server addresses separated by commas, spaces,
/// or newlines.
pub fn parse_authorized(text: &str) -> Result<Vec<Ipv4Addr>, DhcpError> {
    text.split(|c: char| c == ',' || c.is_whitespace())
        .filter(|s| !s.is_empty())
        .map(|s| {
            s.parse::<Ipv4Addr>()
                .map_err(|_| DhcpError::BadAddress(s.to_string()))
        })
        .collect()
}

/// Whether a server is on the authorized list.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum ServerStatus {
    Authorized,
    Rogue,
    /// No authorized list was given.
    Unverified,
}

/// Everything seen from one DHCP server.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ServerRecord {
    /// Server identifier (option 54), or the packet source when absent.
    pub server: Ipv4Addr,
    /// Last packet source address (the relay when relayed).
    pub source: Ipv4Addr,
    pub status: ServerStatus,
    pub replies: u64,
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
    pub last: OfferInfo,
}

/// Most distinct servers tracked; a spoofed flood cannot grow the table past this.
pub const MAX_SERVERS: usize = 256;

/// Tracks servers by identity across probes.
#[derive(Debug, Default)]
pub struct ServerTracker {
    authorized: Vec<Ipv4Addr>,
    servers: BTreeMap<Ipv4Addr, ServerRecord>,
}

impl ServerTracker {
    pub fn new(authorized: Vec<Ipv4Addr>) -> Self {
        ServerTracker {
            authorized,
            servers: BTreeMap::new(),
        }
    }

    /// Classify a server by its identifier or source address.
    pub fn classify(&self, server: Ipv4Addr, source: Ipv4Addr) -> ServerStatus {
        if self.authorized.is_empty() {
            ServerStatus::Unverified
        } else if self.authorized.contains(&server) || self.authorized.contains(&source) {
            ServerStatus::Authorized
        } else {
            ServerStatus::Rogue
        }
    }

    /// Record a reply from `source` at `now_ms`; returns the updated record,
    /// or None when it is a new server and the table is full.
    pub fn record(
        &mut self,
        source: Ipv4Addr,
        info: OfferInfo,
        now_ms: u64,
    ) -> Option<ServerRecord> {
        let server = info.server_id.unwrap_or(source);
        if !self.servers.contains_key(&server) && self.servers.len() >= MAX_SERVERS {
            return None;
        }
        let status = self.classify(server, source);
        let rec = self
            .servers
            .entry(server)
            .and_modify(|r| {
                r.replies += 1;
                r.last_seen_ms = now_ms;
                r.source = source;
                r.last = info.clone();
            })
            .or_insert_with(|| ServerRecord {
                server,
                source,
                status,
                replies: 1,
                first_seen_ms: now_ms,
                last_seen_ms: now_ms,
                last: info,
            });
        Some(rec.clone())
    }

    pub fn len(&self) -> usize {
        self.servers.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAC: [u8; 6] = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];

    /// Build a server reply for tests.
    fn reply(msg_type: u8, xid: u32, extra: &[(u8, &[u8])]) -> Vec<u8> {
        let mut p = vec![0u8; BOOTP_HEADER_LEN];
        p[0] = BOOTREPLY;
        p[1] = 1;
        p[2] = 6;
        p[4..8].copy_from_slice(&xid.to_be_bytes());
        p[16..20].copy_from_slice(&[10, 0, 0, 50]);
        p[28..34].copy_from_slice(&MAC);
        p.extend_from_slice(&MAGIC_COOKIE);
        p.extend_from_slice(&[opt::MESSAGE_TYPE, 1, msg_type]);
        for (code, val) in extra {
            p.push(*code);
            p.push(val.len() as u8);
            p.extend_from_slice(val);
        }
        p.push(opt::END);
        p
    }

    #[test]
    fn discover_layout() {
        let d = build_discover(0xdeadbeef, &MAC);
        assert_eq!(d.len(), MIN_REQUEST_LEN);
        assert_eq!(d[0], BOOTREQUEST);
        assert_eq!(&d[4..8], &[0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(&d[10..12], &[0x80, 0x00]);
        assert_eq!(&d[28..34], &MAC);
        let p = parse_packet(&d).unwrap();
        assert_eq!(p.message_type(), Some(msg::DISCOVER));
        assert_eq!(p.option(opt::CLIENT_ID).unwrap()[1..], MAC);
        assert!(p.option(opt::PARAM_LIST).unwrap().contains(&opt::SERVER_ID));
    }

    #[test]
    fn parse_offer_fields() {
        let buf = reply(
            msg::OFFER,
            7,
            &[
                (opt::SERVER_ID, &[10, 0, 0, 1]),
                (opt::SUBNET_MASK, &[255, 255, 255, 0]),
                (opt::ROUTER, &[10, 0, 0, 1]),
                (opt::DNS, &[1, 1, 1, 1, 8, 8, 8, 8]),
                (opt::DOMAIN, b"lab.local\0"),
                (opt::LEASE_TIME, &[0, 1, 0x51, 0x80]),
            ],
        );
        let info = summarize(&parse_packet(&buf).unwrap()).unwrap();
        assert_eq!(info.message_type, "OFFER");
        assert_eq!(info.xid, "0x00000007");
        assert_eq!(info.client_mac, "02:11:22:33:44:55");
        assert_eq!(info.offered_ip, Some(Ipv4Addr::new(10, 0, 0, 50)));
        assert_eq!(info.server_id, Some(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(info.subnet_mask, Some(Ipv4Addr::new(255, 255, 255, 0)));
        assert_eq!(info.dns.len(), 2);
        assert_eq!(info.domain.as_deref(), Some("lab.local"));
        assert_eq!(info.lease_secs, Some(86_400));
        assert_eq!(info.relay, None);
        assert_eq!(info.next_server, None);
    }

    #[test]
    fn requests_and_other_types_are_not_summarized() {
        let d = parse_packet(&build_discover(1, &MAC)).unwrap();
        assert!(summarize(&d).is_none());
        let inform = parse_packet(&reply(8, 1, &[])).unwrap();
        assert!(summarize(&inform).is_none());
        let nak = parse_packet(&reply(msg::NAK, 1, &[])).unwrap();
        assert_eq!(summarize(&nak).unwrap().message_type, "NAK");
    }

    #[test]
    fn rejects_short_long_and_cookieless() {
        assert_eq!(parse_packet(&[0; 10]), Err(DhcpError::TooShort(10)));
        assert_eq!(parse_packet(&[0; 2000]), Err(DhcpError::TooLong));
        assert_eq!(parse_packet(&[0; 300]), Err(DhcpError::NoCookie));
    }

    #[test]
    fn rejects_truncated_option() {
        let mut buf = reply(msg::OFFER, 1, &[]);
        buf.pop(); // drop END
        buf.extend_from_slice(&[opt::DNS, 8, 1, 1]);
        assert_eq!(
            parse_packet(&buf),
            Err(DhcpError::TruncatedOption(opt::DNS))
        );
        // Length byte itself missing.
        let mut buf = reply(msg::OFFER, 1, &[]);
        buf.pop();
        buf.push(opt::DNS);
        assert_eq!(
            parse_packet(&buf),
            Err(DhcpError::TruncatedOption(opt::DNS))
        );
    }

    #[test]
    fn fuzz_like_inputs_never_panic() {
        let base = reply(msg::OFFER, 1, &[(opt::SERVER_ID, &[10, 0, 0, 1])]);
        for cut in 0..base.len() {
            let _ = parse_packet(&base[..cut]);
        }
        let mut junk = base.clone();
        for b in junk.iter_mut().skip(240) {
            *b = 0xfe;
        }
        let _ = parse_packet(&junk);
    }

    #[test]
    fn option_overload_reads_file_field() {
        let mut buf = reply(msg::OFFER, 1, &[(opt::OVERLOAD, &[1])]);
        buf[108..114].copy_from_slice(&[opt::SERVER_ID, 4, 10, 9, 9, 9]);
        buf[114] = opt::END;
        let info = summarize(&parse_packet(&buf).unwrap()).unwrap();
        assert_eq!(info.server_id, Some(Ipv4Addr::new(10, 9, 9, 9)));
    }

    #[test]
    fn relay_and_next_server() {
        let mut buf = reply(msg::OFFER, 1, &[]);
        buf[20..24].copy_from_slice(&[10, 0, 0, 9]);
        buf[24..28].copy_from_slice(&[10, 1, 0, 1]);
        let info = summarize(&parse_packet(&buf).unwrap()).unwrap();
        assert_eq!(info.next_server, Some(Ipv4Addr::new(10, 0, 0, 9)));
        assert_eq!(info.relay, Some(Ipv4Addr::new(10, 1, 0, 1)));
    }

    #[test]
    fn client_mac_is_local_unicast() {
        for seed in [0u64, 1, u64::MAX, 0x0123_4567_89ab_cdef] {
            let m = client_mac_from_seed(seed);
            assert_eq!(m[0] & 0x01, 0, "unicast");
            assert_eq!(m[0] & 0x02, 0x02, "locally administered");
        }
    }

    #[test]
    fn authorized_list_parsing() {
        assert_eq!(
            parse_authorized("10.0.0.1, 10.0.0.2\n10.0.0.3")
                .unwrap()
                .len(),
            3
        );
        assert!(parse_authorized("").unwrap().is_empty());
        assert_eq!(
            parse_authorized("10.0.0.1 nope"),
            Err(DhcpError::BadAddress("nope".into()))
        );
    }

    fn info(server_id: Option<[u8; 4]>) -> OfferInfo {
        let mut buf = reply(msg::OFFER, 1, &[]);
        if let Some(id) = server_id {
            buf.pop();
            buf.extend_from_slice(&[opt::SERVER_ID, 4]);
            buf.extend_from_slice(&id);
            buf.push(opt::END);
        }
        summarize(&parse_packet(&buf).unwrap()).unwrap()
    }

    #[test]
    fn tracker_classifies_and_aggregates() {
        let good = Ipv4Addr::new(10, 0, 0, 1);
        let mut t = ServerTracker::new(vec![good]);
        let r = t.record(good, info(Some([10, 0, 0, 1])), 100).unwrap();
        assert_eq!(r.status, ServerStatus::Authorized);
        let r = t.record(good, info(Some([10, 0, 0, 1])), 200).unwrap();
        assert_eq!((r.replies, r.first_seen_ms, r.last_seen_ms), (2, 100, 200));

        let r = t
            .record(Ipv4Addr::new(10, 0, 0, 66), info(None), 300)
            .unwrap();
        assert_eq!(r.status, ServerStatus::Rogue);
        assert_eq!(r.server, Ipv4Addr::new(10, 0, 0, 66));
        assert_eq!(t.len(), 2);
    }

    #[test]
    fn tracker_relay_source_matches_authorized_server_id() {
        // Relayed reply: source is the relay, server id is the real server.
        let mut t = ServerTracker::new(vec![Ipv4Addr::new(10, 0, 0, 1)]);
        let r = t
            .record(Ipv4Addr::new(10, 5, 0, 1), info(Some([10, 0, 0, 1])), 1)
            .unwrap();
        assert_eq!(r.status, ServerStatus::Authorized);
    }

    #[test]
    fn tracker_caps_distinct_servers() {
        let mut t = ServerTracker::new(vec![]);
        for i in 0..MAX_SERVERS as u32 {
            let src = Ipv4Addr::from(0x0a00_0000 + i);
            assert!(t.record(src, info(None), 1).is_some());
        }
        assert!(
            t.record(Ipv4Addr::new(192, 0, 2, 1), info(None), 2)
                .is_none()
        );
        // Known servers still update.
        assert!(
            t.record(Ipv4Addr::from(0x0a00_0000), info(None), 3)
                .is_some()
        );
    }

    #[test]
    fn tracker_without_list_is_unverified() {
        let mut t = ServerTracker::new(vec![]);
        let r = t.record(Ipv4Addr::new(10, 0, 0, 1), info(None), 1).unwrap();
        assert_eq!(r.status, ServerStatus::Unverified);
    }
}
