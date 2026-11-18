//! Read a PCAP or PCAPNG capture in one streaming pass: per-packet summaries
//! (bounded), plus protocol, conversation, talker and DNS statistics over
//! every packet. Each summary remembers where its bytes sit so a packet's
//! detail is read back on demand instead of kept in memory.

use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom};
use std::net::IpAddr;

use serde::Serialize;

use super::decode::{self, Decoded};
use super::packets;

/// Summaries kept for browsing; statistics still cover every packet.
pub const MAX_SUMMARIES: usize = 200_000;
/// Distinct conversations, talkers and DNS names tracked.
const MAX_KEYS: usize = 50_000;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Summary {
    pub index: u32,
    /// Nanoseconds since the Unix epoch.
    pub ts_ns: i64,
    pub orig_len: u32,
    pub cap_len: u32,
    pub src: String,
    pub dst: String,
    pub proto: String,
    pub info: String,
    pub truncated: bool,
    pub malformed: bool,
    pub encrypted: bool,
    #[serde(skip)]
    pub offset: u64,
    #[serde(skip)]
    pub link: i32,
    #[serde(skip)]
    pub l4: Option<(u8, u16, u16)>,
    #[serde(skip)]
    pub ips: Option<(IpAddr, IpAddr)>,
}

#[derive(Debug, Clone, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Count {
    pub name: String,
    pub packets: u64,
    pub bytes: u64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Conversation {
    pub proto: String,
    pub a: String,
    pub b: String,
    pub packets: u64,
    pub bytes: u64,
    pub first_ns: i64,
    pub last_ns: i64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DnsName {
    pub name: String,
    pub qtype: String,
    pub queries: u64,
    pub responses: u64,
    /// Response codes other than NOERROR, with counts.
    pub errors: Vec<(String, u64)>,
}

#[derive(Debug, Clone, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Stats {
    pub packets: u64,
    pub bytes: u64,
    pub first_ns: Option<i64>,
    pub last_ns: Option<i64>,
    pub truncated: u64,
    pub malformed: u64,
    pub encrypted: u64,
    pub link_types: Vec<String>,
    pub protocols: Vec<Count>,
    pub talkers: Vec<Count>,
    pub conversations: Vec<Conversation>,
    pub dns: Vec<DnsName>,
    pub tcp_syn: u64,
    pub tcp_rst: u64,
    pub icmp_unreachable: u64,
    /// Statistics stopped tracking new keys after the limit.
    pub keys_capped: bool,
}

pub struct Scan {
    pub summaries: Vec<Summary>,
    pub stats: Stats,
    pub format: String,
    pub warnings: Vec<String>,
    pub cancelled: bool,
}

/// (protocol, endpoint a, endpoint b) to (packets, bytes, first, last).
type ConvMap = HashMap<(String, String, String), (u64, u64, i64, i64)>;
/// (name, type) to (queries, responses, error codes).
type DnsMap = HashMap<(String, String), (u64, u64, HashMap<String, u64>)>;

#[derive(Default)]
struct Acc {
    protos: HashMap<String, (u64, u64)>,
    talkers: HashMap<IpAddr, (u64, u64)>,
    convs: ConvMap,
    dns: DnsMap,
    capped: bool,
}

impl Acc {
    fn add(&mut self, d: &Decoded, len: u64, ts: i64, st: &mut Stats) {
        let e = self.protos.entry(d.proto.clone()).or_default();
        e.0 += 1;
        e.1 += len;
        if let Some((s, t)) = d.ips {
            for ip in [s, t] {
                if self.talkers.len() < MAX_KEYS || self.talkers.contains_key(&ip) {
                    let e = self.talkers.entry(ip).or_default();
                    e.0 += 1;
                    e.1 += len;
                } else {
                    self.capped = true;
                }
            }
            let (proto, sp, dp) = match d.l4 {
                Some((6, sp, dp)) => ("TCP".to_string(), Some(sp), Some(dp)),
                Some((17, sp, dp)) => ("UDP".to_string(), Some(sp), Some(dp)),
                Some((n, _, _)) => (format!("IP/{n}"), None, None),
                None => ("IP".to_string(), None, None),
            };
            let end = |ip: IpAddr, p: Option<u16>| match (ip, p) {
                (IpAddr::V6(a), Some(p)) => format!("[{a}]:{p}"),
                (a, Some(p)) => format!("{a}:{p}"),
                (a, None) => a.to_string(),
            };
            let (x, y) = (end(s, sp), end(t, dp));
            let key = if x <= y { (proto, x, y) } else { (proto, y, x) };
            if self.convs.len() < MAX_KEYS || self.convs.contains_key(&key) {
                let e = self.convs.entry(key).or_insert((0, 0, ts, ts));
                e.0 += 1;
                e.1 += len;
                e.2 = e.2.min(ts);
                e.3 = e.3.max(ts);
            } else {
                self.capped = true;
            }
        }
        if let Some(dns) = &d.dns {
            for (name, qt) in &dns.questions {
                let key = (name.to_ascii_lowercase(), qt.clone());
                if self.dns.len() < MAX_KEYS || self.dns.contains_key(&key) {
                    let e = self.dns.entry(key).or_default();
                    if dns.response {
                        e.1 += 1;
                        if dns.rcode != "No Error"
                            && dns.rcode != "NoError"
                            && dns.rcode != "NOERROR"
                        {
                            *e.2.entry(dns.rcode.clone()).or_default() += 1;
                        }
                    } else {
                        e.0 += 1;
                    }
                } else {
                    self.capped = true;
                }
            }
        }
        if d.tcp_flags & 0x02 != 0 && d.tcp_flags & 0x10 == 0 {
            st.tcp_syn += 1;
        }
        if d.tcp_flags & 0x04 != 0 {
            st.tcp_rst += 1;
        }
        if d.info.starts_with("destination unreachable") {
            st.icmp_unreachable += 1;
        }
    }

    fn finish(self, st: &mut Stats) {
        let mut protos: Vec<Count> = self
            .protos
            .into_iter()
            .map(|(name, (p, b))| Count {
                name,
                packets: p,
                bytes: b,
            })
            .collect();
        protos.sort_by_key(|x| std::cmp::Reverse(x.packets));
        let mut talkers: Vec<Count> = self
            .talkers
            .into_iter()
            .map(|(ip, (p, b))| Count {
                name: ip.to_string(),
                packets: p,
                bytes: b,
            })
            .collect();
        talkers.sort_by_key(|x| std::cmp::Reverse(x.bytes));
        talkers.truncate(500);
        let mut convs: Vec<Conversation> = self
            .convs
            .into_iter()
            .map(|((proto, a, b), (p, by, f, l))| Conversation {
                proto,
                a,
                b,
                packets: p,
                bytes: by,
                first_ns: f,
                last_ns: l,
            })
            .collect();
        convs.sort_by_key(|x| std::cmp::Reverse(x.bytes));
        convs.truncate(1000);
        let mut dns: Vec<DnsName> = self
            .dns
            .into_iter()
            .map(|((name, qtype), (q, r, errs))| {
                let mut errors: Vec<(String, u64)> = errs.into_iter().collect();
                errors.sort();
                DnsName {
                    name,
                    qtype,
                    queries: q,
                    responses: r,
                    errors,
                }
            })
            .collect();
        dns.sort_by_key(|x| std::cmp::Reverse(x.queries + x.responses));
        dns.truncate(2000);
        st.protocols = protos;
        st.talkers = talkers;
        st.conversations = convs;
        st.dns = dns;
        st.keys_capped = self.capped;
    }
}

/// Scan a capture. `progress(bytes_read)` returns false to stop.
pub fn scan<R: Read + Send>(input: R, progress: impl FnMut(u64) -> bool) -> Result<Scan, String> {
    let mut summaries = Vec::new();
    let mut st = Stats::default();
    let mut acc = Acc::default();
    let mut warnings: Vec<String> = Vec::new();
    let mut links_seen: Vec<i32> = Vec::new();
    let mut index: u32 = 0;

    let info = packets::each_packet(
        input,
        |r| {
            if !links_seen.contains(&r.link) {
                links_seen.push(r.link);
                if decode::link_name(r.link).is_none() {
                    warnings.push(format!(
                        "link type {} is not decoded; packets are counted but not dissected",
                        r.link
                    ));
                }
            }
            let d = decode::decode(r.link, r.data, false);
            let cap = r.data.len() as u32;
            let truncated = cap < r.orig;
            st.packets += 1;
            st.bytes += r.orig as u64;
            if r.ts_ns != 0 {
                st.first_ns = Some(st.first_ns.map_or(r.ts_ns, |f| f.min(r.ts_ns)));
                st.last_ns = Some(st.last_ns.map_or(r.ts_ns, |l| l.max(r.ts_ns)));
            }
            if truncated {
                st.truncated += 1;
            }
            if d.malformed.is_some() {
                st.malformed += 1;
            }
            if d.encrypted {
                st.encrypted += 1;
            }
            acc.add(&d, r.orig as u64, r.ts_ns, &mut st);
            if summaries.len() < MAX_SUMMARIES {
                summaries.push(Summary {
                    index,
                    ts_ns: r.ts_ns,
                    orig_len: r.orig,
                    cap_len: cap,
                    src: d.src,
                    dst: d.dst,
                    proto: d.proto,
                    info: d.info,
                    truncated,
                    malformed: d.malformed.is_some(),
                    encrypted: d.encrypted,
                    offset: r.offset,
                    link: r.link,
                    l4: d.l4,
                    ips: d.ips,
                });
            }
            index = index.saturating_add(1);
            true
        },
        progress,
    )?;
    warnings.extend(info.warnings);
    let format = info.format;
    let cancelled = info.cancelled;
    if summaries.len() as u64 != st.packets {
        warnings.push(format!(
            "{} packets read; the first {} are listed, statistics cover all of them",
            st.packets,
            summaries.len()
        ));
    }
    st.link_types = links_seen
        .iter()
        .map(|l| {
            decode::link_name(*l)
                .map(|n| format!("{n} ({l})"))
                .unwrap_or_else(|| format!("linktype {l}"))
        })
        .collect();
    acc.finish(&mut st);
    Ok(Scan {
        summaries,
        stats: st,
        format,
        warnings,
        cancelled,
    })
}

/// Read one packet's captured bytes back from `src`.
pub fn read_packet<S: Read + Seek>(src: &mut S, s: &Summary) -> Result<Vec<u8>, String> {
    src.seek(SeekFrom::Start(s.offset))
        .map_err(|e| e.to_string())?;
    let mut buf = vec![0u8; s.cap_len as usize];
    src.read_exact(&mut buf)
        .map_err(|e| format!("could not read the packet: {e}"))?;
    Ok(buf)
}

#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Filter {
    /// Matches source, destination, protocol and info, case-insensitive.
    pub text: String,
    pub proto: String,
    pub ip: String,
    pub port: Option<u16>,
    pub only_flagged: bool,
}

pub fn matches(s: &Summary, f: &Filter) -> bool {
    if !f.proto.is_empty() && !s.proto.eq_ignore_ascii_case(&f.proto) {
        return false;
    }
    if !f.ip.trim().is_empty() {
        let ip = f.ip.trim();
        let hit = s
            .ips
            .is_some_and(|(a, b)| a.to_string() == ip || b.to_string() == ip)
            || s.src == ip
            || s.dst == ip;
        if !hit {
            return false;
        }
    }
    if let Some(p) = f.port
        && !s.l4.is_some_and(|(_, a, b)| a == p || b == p)
    {
        return false;
    }
    if f.only_flagged && !(s.truncated || s.malformed) {
        return false;
    }
    if !f.text.trim().is_empty() {
        let t = f.text.trim().to_ascii_lowercase();
        let hay = format!("{} {} {} {}", s.src, s.dst, s.proto, s.info).to_ascii_lowercase();
        if !hay.contains(&t) {
            return false;
        }
    }
    true
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use etherparse::PacketBuilder;
    use std::io::Cursor;

    const A: [u8; 6] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
    const B: [u8; 6] = [0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb];

    pub fn tcp(sp: u16, dp: u16, syn: bool, rst: bool, payload: &[u8]) -> Vec<u8> {
        let mut b = PacketBuilder::ethernet2(A, B)
            .ipv4([10, 0, 0, 1], [192, 0, 2, 7], 64)
            .tcp(sp, dp, 1000, 64240);
        if syn {
            b = b.syn();
        }
        if rst {
            b = b.rst();
        }
        let mut out = Vec::new();
        b.write(&mut out, payload).unwrap();
        out
    }

    pub fn udp(sp: u16, dp: u16, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        PacketBuilder::ethernet2(A, B)
            .ipv4([10, 0, 0, 1], [10, 0, 0, 53], 64)
            .udp(sp, dp)
            .write(&mut out, payload)
            .unwrap();
        out
    }

    pub fn dns_query(name: &str) -> Vec<u8> {
        use hickory_proto::op::{Message, Query};
        use hickory_proto::rr::{Name, RecordType};
        let mut m = Message::query();
        m.add_query(Query::query(Name::from_ascii(name).unwrap(), RecordType::A));
        m.to_vec().unwrap()
    }

    /// A ClientHello carrying an SNI extension.
    pub fn client_hello(sni: &str) -> Vec<u8> {
        let n = sni.as_bytes();
        let mut ext = Vec::new();
        ext.extend_from_slice(&[0, 0]); // server_name
        let list_len = 3 + n.len();
        ext.extend_from_slice(&((list_len + 2) as u16).to_be_bytes());
        ext.extend_from_slice(&(list_len as u16).to_be_bytes());
        ext.push(0);
        ext.extend_from_slice(&(n.len() as u16).to_be_bytes());
        ext.extend_from_slice(n);
        let mut body = vec![3, 3];
        body.extend_from_slice(&[0u8; 32]);
        body.push(0); // session id
        body.extend_from_slice(&[0, 2, 0x13, 0x01]); // one cipher suite
        body.extend_from_slice(&[1, 0]); // compression
        body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext);
        let mut hs = vec![1];
        hs.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        hs.extend_from_slice(&body);
        let mut rec = vec![22, 3, 1];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    /// Legacy pcap, microsecond, Ethernet. `snap` truncates captured bytes.
    pub fn pcap(frames: &[Vec<u8>], snap: usize) -> Vec<u8> {
        let mut o = Vec::new();
        o.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes());
        o.extend_from_slice(&2u16.to_le_bytes());
        o.extend_from_slice(&4u16.to_le_bytes());
        o.extend_from_slice(&[0u8; 8]);
        o.extend_from_slice(&65535u32.to_le_bytes());
        o.extend_from_slice(&1u32.to_le_bytes());
        for (i, f) in frames.iter().enumerate() {
            let cap = f.len().min(snap);
            o.extend_from_slice(&(1_794_614_400u32 + i as u32).to_le_bytes());
            o.extend_from_slice(&250_000u32.to_le_bytes());
            o.extend_from_slice(&(cap as u32).to_le_bytes());
            o.extend_from_slice(&(f.len() as u32).to_le_bytes());
            o.extend_from_slice(&f[..cap]);
        }
        o
    }

    fn pcapng(frames: &[Vec<u8>]) -> Vec<u8> {
        let mut o = Vec::new();
        // Section header block.
        o.extend_from_slice(&0x0a0d0d0au32.to_le_bytes());
        o.extend_from_slice(&28u32.to_le_bytes());
        o.extend_from_slice(&0x1a2b3c4du32.to_le_bytes());
        o.extend_from_slice(&1u16.to_le_bytes());
        o.extend_from_slice(&0u16.to_le_bytes());
        o.extend_from_slice(&(-1i64).to_le_bytes());
        o.extend_from_slice(&28u32.to_le_bytes());
        // Interface description block, Ethernet, default microseconds.
        o.extend_from_slice(&1u32.to_le_bytes());
        o.extend_from_slice(&20u32.to_le_bytes());
        o.extend_from_slice(&1u16.to_le_bytes());
        o.extend_from_slice(&0u16.to_le_bytes());
        o.extend_from_slice(&65535u32.to_le_bytes());
        o.extend_from_slice(&20u32.to_le_bytes());
        for f in frames {
            let pad = (4 - f.len() % 4) % 4;
            let len = 32 + f.len() + pad;
            let ts: u64 = 1_794_614_400_000_000;
            o.extend_from_slice(&6u32.to_le_bytes());
            o.extend_from_slice(&(len as u32).to_le_bytes());
            o.extend_from_slice(&0u32.to_le_bytes());
            o.extend_from_slice(&((ts >> 32) as u32).to_le_bytes());
            o.extend_from_slice(&(ts as u32).to_le_bytes());
            o.extend_from_slice(&(f.len() as u32).to_le_bytes());
            o.extend_from_slice(&(f.len() as u32).to_le_bytes());
            o.extend_from_slice(f);
            o.extend_from_slice(&vec![0u8; pad]);
            o.extend_from_slice(&(len as u32).to_le_bytes());
        }
        o
    }

    fn sample() -> Vec<Vec<u8>> {
        vec![
            tcp(51000, 443, true, false, &[]),
            tcp(51000, 443, false, false, &client_hello("www.example.com")),
            udp(53000, 53, &dns_query("example.org.")),
            tcp(51001, 22, false, true, &[]),
        ]
    }

    #[test]
    fn scans_legacy_pcap() {
        let s = scan(Cursor::new(pcap(&sample(), 65535)), |_| true).unwrap();
        assert_eq!(s.stats.packets, 4);
        assert_eq!(s.summaries.len(), 4);
        assert_eq!(s.summaries[0].proto, "HTTPS");
        assert!(s.summaries[0].info.contains("[SYN]"));
        assert_eq!(s.summaries[1].proto, "TLS");
        assert!(
            s.summaries[1].info.contains("SNI www.example.com"),
            "{}",
            s.summaries[1].info
        );
        assert_eq!(s.summaries[2].proto, "DNS");
        assert!(
            s.summaries[2].info.contains("query A example.org"),
            "{}",
            s.summaries[2].info
        );
        assert_eq!(s.stats.tcp_syn, 1);
        assert_eq!(s.stats.tcp_rst, 1);
        assert_eq!(s.stats.dns[0].name, "example.org");
        assert_eq!(s.stats.first_ns, Some(1_794_614_400_250_000_000));
        assert!(
            s.stats
                .conversations
                .iter()
                .any(|c| c.proto == "TCP" && c.a.contains(":51000") || c.b.contains(":51000"))
        );
        assert_eq!(s.format, "PCAP");
    }

    #[test]
    fn scans_pcapng_and_reads_back() {
        let bytes = pcapng(&sample());
        let s = scan(Cursor::new(bytes.clone()), |_| true).unwrap();
        assert_eq!(s.format, "PCAPNG");
        assert_eq!(s.stats.packets, 4);
        let raw = read_packet(&mut Cursor::new(bytes), &s.summaries[2]).unwrap();
        let d = decode::decode(1, &raw, true);
        assert_eq!(d.proto, "DNS");
        assert!(
            d.fields
                .iter()
                .any(|f| f.layer == "UDP" && f.name == "Destination port" && f.value == "53")
        );
    }

    #[test]
    fn truncation_damage_and_garbage() {
        let s = scan(Cursor::new(pcap(&sample(), 40)), |_| true).unwrap();
        assert_eq!(s.stats.truncated, 4);
        assert!(s.summaries.iter().all(|x| x.truncated));
        let mut cut = pcap(&sample(), 65535);
        cut.truncate(cut.len() - 10);
        let s = scan(Cursor::new(cut), |_| true).unwrap();
        assert_eq!(s.stats.packets, 3);
        assert!(s.warnings.iter().any(|w| w.contains("ends in the middle")));
        assert!(
            scan(Cursor::new(b"hello world, not a capture".to_vec()), |_| {
                true
            })
            .is_err()
        );
        let s = scan(
            Cursor::new(pcap(&[vec![0u8; 5], vec![0xffu8; 60]], 65535)),
            |_| true,
        )
        .unwrap();
        assert_eq!(s.stats.packets, 2);
        assert!(s.stats.malformed >= 1);
    }

    #[test]
    fn filters() {
        let s = scan(Cursor::new(pcap(&sample(), 65535)), |_| true).unwrap();
        let count = |f: Filter| s.summaries.iter().filter(|x| matches(x, &f)).count();
        assert_eq!(
            count(Filter {
                proto: "DNS".into(),
                ..Default::default()
            }),
            1
        );
        assert_eq!(
            count(Filter {
                port: Some(443),
                ..Default::default()
            }),
            2
        );
        assert_eq!(
            count(Filter {
                ip: "10.0.0.53".into(),
                ..Default::default()
            }),
            1
        );
        assert_eq!(
            count(Filter {
                text: "example.com".into(),
                ..Default::default()
            }),
            1
        );
        assert_eq!(count(Filter::default()), 4);
    }

    #[test]
    fn cancel_stops() {
        let frames: Vec<Vec<u8>> = (0..12_000)
            .map(|i| udp(1000 + (i % 100) as u16, 9999, b"x"))
            .collect();
        let s = scan(Cursor::new(pcap(&frames, 65535)), |_| false).unwrap();
        assert!(s.cancelled);
        assert!(s.stats.packets < 12_000);
    }
}
