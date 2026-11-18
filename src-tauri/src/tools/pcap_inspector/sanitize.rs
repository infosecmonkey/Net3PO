//! Write a cleaned copy of a capture for sharing: cut packets down to their
//! headers, and replace IP and MAC addresses with keyed fakes that keep
//! subnets and vendor prefixes (the Obfuscator's engine). Checksums are
//! adjusted for the new addresses. Frames whose contents cannot be cleaned
//! are cut to their link header, and link types that cannot be parsed are
//! dropped, so nothing passes through unexamined. Output is PCAPNG with
//! nanosecond timestamps.

use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};

use super::packets;
use crate::report::fake::{self, FakeKey};

/// Most address pairs returned for the preview.
const MAX_MAPPING: usize = 2000;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Options {
    /// Keep only link, IP and transport headers.
    pub strip_payload: bool,
    pub addresses: bool,
    pub macs: bool,
    /// Hex session key (from the Obfuscator, to match its fakes); empty for new.
    pub key: String,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            strip_payload: true,
            addresses: true,
            macs: true,
            key: String::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MapEntry {
    pub kind: String,
    pub original: String,
    pub fake: String,
}

#[derive(Debug, Clone, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Report {
    pub packets: u64,
    pub written: u64,
    /// Packets dropped because their link type cannot be parsed.
    pub dropped: u64,
    /// Packets whose payload was removed.
    pub stripped: u64,
    pub bytes_removed: u64,
    /// Non-IP frames (LLDP, CDP, STP and others) cut to their link header.
    pub other_cut: u64,
    pub addresses: usize,
    pub macs: usize,
    pub mapping: Vec<MapEntry>,
    pub key: String,
    pub format: String,
    pub warnings: Vec<String>,
    pub cancelled: bool,
}

// ------------------------------------------------------------- checksums

fn sum16(data: &[u8]) -> u32 {
    data.chunks(2)
        .map(|c| u32::from(u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)])))
        .sum()
}

fn fold(mut s: u32) -> u16 {
    while s > 0xffff {
        s = (s & 0xffff) + (s >> 16);
    }
    s as u16
}

/// RFC 1624: adjust a checksum for `old` bytes replaced by `new` (even length).
fn csum_adjust(csum: u16, old: &[u8], new: &[u8]) -> u16 {
    let mut s = u32::from(!csum);
    for c in old.chunks(2) {
        s += u32::from(!u16::from_be_bytes([c[0], c[1]]));
    }
    s += sum16(new);
    !fold(s)
}

fn ipv4_header_checksum(b: &mut [u8], off: usize, ihl: usize) {
    b[off + 10] = 0;
    b[off + 11] = 0;
    let c = !fold(sum16(&b[off..off + ihl]));
    b[off + 10..off + 12].copy_from_slice(&c.to_be_bytes());
}

/// Apply an address change to the checksum at `at`, if it was captured.
/// `zero_means_none`: UDP over IPv4, where 0 means no checksum.
fn fix_l4(b: &mut [u8], at: usize, changes: &[(Vec<u8>, Vec<u8>)], zero_means_none: bool) {
    if at + 2 > b.len() {
        return;
    }
    let mut c = u16::from_be_bytes([b[at], b[at + 1]]);
    if zero_means_none && c == 0 {
        return;
    }
    for (old, new) in changes {
        c = csum_adjust(c, old, new);
    }
    if zero_means_none && c == 0 {
        c = 0xffff;
    }
    b[at..at + 2].copy_from_slice(&c.to_be_bytes());
}

// ------------------------------------------------------------- rewriting

struct Cleaner {
    opts: Options,
    key: FakeKey,
    seen_ip: HashSet<Vec<u8>>,
    seen_mac: HashSet<[u8; 6]>,
    report: Report,
}

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(at)?, *b.get(at + 1)?]))
}

impl Cleaner {
    fn record(&mut self, kind: &str, original: String, fake: String) {
        if self.report.mapping.len() < MAX_MAPPING {
            self.report.mapping.push(MapEntry {
                kind: kind.into(),
                original,
                fake,
            });
        }
    }

    /// Replace a MAC at `at`; returns (old, new) when it changed.
    fn mac(&mut self, b: &mut [u8], at: usize) -> Option<(Vec<u8>, Vec<u8>)> {
        if !self.opts.macs || at + 6 > b.len() {
            return None;
        }
        let old: [u8; 6] = b[at..at + 6].try_into().ok()?;
        let text = old
            .iter()
            .map(|x| format!("{x:02x}"))
            .collect::<Vec<_>>()
            .join(":");
        let fake = fake::fake_mac(&self.key, &text)?;
        let new: Vec<u8> = fake
            .split(':')
            .filter_map(|h| u8::from_str_radix(h, 16).ok())
            .collect();
        if new.len() != 6 || new == old {
            return None;
        }
        b[at..at + 6].copy_from_slice(&new);
        if self.seen_mac.insert(old) {
            self.report.macs += 1;
            self.record("mac", text, fake);
        }
        Some((old.to_vec(), new))
    }

    fn v4(&mut self, b: &mut [u8], at: usize) -> Option<(Vec<u8>, Vec<u8>)> {
        if !self.opts.addresses || at + 4 > b.len() {
            return None;
        }
        let old: [u8; 4] = b[at..at + 4].try_into().ok()?;
        let ip = Ipv4Addr::from(old);
        let fake = fake::fake_v4(&self.key, ip);
        if fake == ip {
            return None;
        }
        b[at..at + 4].copy_from_slice(&fake.octets());
        if self.seen_ip.insert(old.to_vec()) {
            self.report.addresses += 1;
            self.record("ip", ip.to_string(), fake.to_string());
        }
        Some((old.to_vec(), fake.octets().to_vec()))
    }

    fn v6(&mut self, b: &mut [u8], at: usize) -> Option<(Vec<u8>, Vec<u8>)> {
        if !self.opts.addresses || at + 16 > b.len() {
            return None;
        }
        let old: [u8; 16] = b[at..at + 16].try_into().ok()?;
        let ip = Ipv6Addr::from(old);
        let fake = fake::fake_v6(&self.key, ip);
        if fake == ip {
            return None;
        }
        b[at..at + 16].copy_from_slice(&fake.octets());
        if self.seen_ip.insert(old.to_vec()) {
            self.report.addresses += 1;
            self.record("ip", ip.to_string(), fake.to_string());
        }
        Some((old.to_vec(), fake.octets().to_vec()))
    }

    /// Clean one packet. None drops it.
    fn packet(&mut self, link: i32, data: &[u8]) -> Option<Vec<u8>> {
        let mut b = data.to_vec();
        let (ethertype, l3) = match link {
            1 => {
                self.mac(&mut b, 0);
                self.mac(&mut b, 6);
                let mut off = 12;
                let mut et = u16_at(&b, off);
                let mut tags = 0;
                while matches!(et, Some(0x8100 | 0x88a8 | 0x9100)) && tags < 4 {
                    off += 4;
                    tags += 1;
                    et = u16_at(&b, off);
                }
                match et {
                    Some(et) => (et, off + 2),
                    None => (0, b.len().min(12)),
                }
            }
            113 => {
                if u16_at(&b, 4) == Some(6) {
                    self.mac(&mut b, 6);
                }
                (u16_at(&b, 14).unwrap_or(0), 16)
            }
            276 => {
                if b.get(11) == Some(&6) {
                    self.mac(&mut b, 12);
                }
                (u16_at(&b, 0).unwrap_or(0), 20)
            }
            12 | 14 | 101 | 228 | 229 => match b.first().map(|v| v >> 4) {
                Some(4) => (0x0800, 0),
                Some(6) => (0x86dd, 0),
                _ => (0, 0),
            },
            0 | 108 => {
                let fam = b.get(..4)?;
                let le = u32::from_le_bytes([fam[0], fam[1], fam[2], fam[3]]);
                let be = u32::from_be_bytes([fam[0], fam[1], fam[2], fam[3]]);
                let et = if le == 2 || be == 2 {
                    0x0800
                } else if [24, 28, 30].contains(&le) || [24, 28, 30].contains(&be) {
                    0x86dd
                } else {
                    0
                };
                (et, 4)
            }
            _ => return None,
        };
        let l3 = l3.min(b.len());
        let keep = match ethertype {
            0x0800 => self.ipv4(&mut b, l3, false),
            0x86dd => self.ipv6(&mut b, l3, false),
            0x0806 => self.arp(&mut b, l3),
            _ => {
                if b.len() > l3 {
                    self.report.other_cut += 1;
                }
                l3
            }
        };
        if keep < b.len() {
            self.report.bytes_removed += (b.len() - keep) as u64;
            if matches!(ethertype, 0x0800 | 0x86dd) {
                self.report.stripped += 1;
            }
            b.truncate(keep);
        }
        Some(b)
    }

    fn arp(&mut self, b: &mut [u8], off: usize) -> usize {
        let ipv4_eth = u16_at(b, off) == Some(1)
            && u16_at(b, off + 2) == Some(0x0800)
            && b.get(off + 4) == Some(&6)
            && b.get(off + 5) == Some(&4);
        if !ipv4_eth {
            self.report.other_cut += 1;
            return off;
        }
        self.mac(b, off + 8);
        self.v4(b, off + 14);
        self.mac(b, off + 18);
        self.v4(b, off + 24);
        (off + 28).min(b.len())
    }

    /// Returns how many bytes to keep. `inner`: an IP header quoted inside an
    /// ICMP error; rewritten, never cut.
    fn ipv4(&mut self, b: &mut [u8], off: usize, inner: bool) -> usize {
        if off + 20 > b.len() {
            return off;
        }
        let ihl = usize::from(b[off] & 0x0f) * 4;
        if ihl < 20 || off + ihl > b.len() {
            return off;
        }
        let proto = b[off + 9];
        let frag = u16_at(b, off + 6).unwrap_or(0) & 0x1fff;
        let mut changes = Vec::new();
        changes.extend(self.v4(b, off + 12));
        changes.extend(self.v4(b, off + 16));
        if !changes.is_empty() {
            ipv4_header_checksum(b, off, ihl);
        }
        let l4 = off + ihl;
        // Padding after the IP datagram is never needed.
        let ip_end = u16_at(b, off + 2)
            .map(|t| (off + usize::from(t)).clamp(l4, b.len()))
            .unwrap_or(b.len());
        if frag != 0 {
            return if self.opts.strip_payload && !inner {
                l4
            } else {
                ip_end
            };
        }
        let hdr_end = match proto {
            6 => {
                if !changes.is_empty() {
                    fix_l4(b, l4 + 16, &changes, false);
                }
                b.get(l4 + 12)
                    .map(|d| l4 + usize::from(d >> 4) * 4)
                    .unwrap_or(l4)
            }
            17 => {
                if !changes.is_empty() {
                    fix_l4(b, l4 + 6, &changes, true);
                }
                l4 + 8
            }
            1 => {
                let ty = b.get(l4).copied().unwrap_or(0);
                if !self.opts.strip_payload && !inner && matches!(ty, 3 | 5 | 11 | 12) {
                    self.ipv4(b, l4 + 8, true);
                    self.icmp4_checksum(b, l4, ip_end);
                }
                l4 + 8
            }
            _ => l4,
        };
        if self.opts.strip_payload && !inner {
            hdr_end.min(ip_end)
        } else {
            ip_end
        }
    }

    /// ICMPv4 checksums cover the whole message; recompute when it is all here.
    fn icmp4_checksum(&self, b: &mut [u8], l4: usize, end: usize) {
        if l4 + 4 > end || end > b.len() {
            return;
        }
        b[l4 + 2] = 0;
        b[l4 + 3] = 0;
        let c = !fold(sum16(&b[l4..end]));
        b[l4 + 2..l4 + 4].copy_from_slice(&c.to_be_bytes());
    }

    fn ipv6(&mut self, b: &mut [u8], off: usize, inner: bool) -> usize {
        if off + 40 > b.len() {
            return off;
        }
        let mut changes = Vec::new();
        changes.extend(self.v6(b, off + 8));
        changes.extend(self.v6(b, off + 24));
        let payload_len = u16_at(b, off + 4).map(usize::from).unwrap_or(0);
        let ip_end = (off + 40 + payload_len).clamp(off + 40, b.len());
        let mut nh = b[off + 6];
        let mut p = off + 40;
        let mut fragmented = false;
        for _ in 0..8 {
            match nh {
                0 | 43 | 60 => match (b.get(p), b.get(p + 1)) {
                    (Some(n), Some(l)) => {
                        nh = *n;
                        p += (usize::from(*l) + 1) * 8;
                    }
                    _ => break,
                },
                44 => match (b.get(p), u16_at(b, p + 2)) {
                    (Some(n), Some(fo)) => {
                        nh = *n;
                        fragmented = fo >> 3 != 0;
                        p += 8;
                    }
                    _ => break,
                },
                51 => match (b.get(p), b.get(p + 1)) {
                    (Some(n), Some(l)) => {
                        nh = *n;
                        p += (usize::from(*l) + 2) * 4;
                    }
                    _ => break,
                },
                _ => break,
            }
        }
        let l4 = p.min(ip_end);
        if fragmented {
            return if self.opts.strip_payload && !inner {
                l4
            } else {
                ip_end
            };
        }
        let hdr_end = match nh {
            6 => {
                if !changes.is_empty() {
                    fix_l4(b, l4 + 16, &changes, false);
                }
                b.get(l4 + 12)
                    .map(|d| l4 + usize::from(d >> 4) * 4)
                    .unwrap_or(l4)
            }
            17 => {
                if !changes.is_empty() {
                    fix_l4(b, l4 + 6, &changes, false);
                }
                l4 + 8
            }
            58 => {
                let ty = b.get(l4).copied().unwrap_or(0);
                let mut ch = changes.clone();
                if !self.opts.strip_payload && !inner {
                    ch.extend(self.icmp6_body(b, l4, ip_end, ty));
                }
                if !ch.is_empty() {
                    fix_l4(b, l4 + 2, &ch, false);
                }
                l4 + 8
            }
            _ => l4,
        };
        if self.opts.strip_payload && !inner {
            hdr_end.min(ip_end)
        } else {
            ip_end
        }
    }

    /// Addresses inside ICMPv6 messages: quoted packets in errors, and
    /// target addresses and link-layer options in neighbor discovery.
    fn icmp6_body(
        &mut self,
        b: &mut [u8],
        l4: usize,
        end: usize,
        ty: u8,
    ) -> Vec<(Vec<u8>, Vec<u8>)> {
        let mut ch = Vec::new();
        match ty {
            1..=4 => {
                // The quoted header's own changes do not reach our checksum
                // through the pseudo header, but they change the body.
                let start = l4 + 8;
                if start < end {
                    let before = b[start..end].to_vec();
                    self.ipv6(b, start, true);
                    let after = b[start..end].to_vec();
                    if before != after {
                        let even = before.len() & !1;
                        ch.push((before[..even].to_vec(), after[..even].to_vec()));
                        if before.len() % 2 == 1 {
                            ch.push((vec![before[even], 0], vec![after[even], 0]));
                        }
                    }
                }
            }
            133..=137 => {
                let (targets, opts_at): (&[usize], usize) = match ty {
                    133 => (&[], l4 + 8),
                    134 => (&[], l4 + 16),
                    135 | 136 => (&[l4 + 8], l4 + 24),
                    _ => (&[l4 + 8, l4 + 24], l4 + 40),
                };
                for t in targets {
                    if t + 16 <= end {
                        ch.extend(self.v6(b, *t));
                    }
                }
                let mut o = opts_at;
                for _ in 0..32 {
                    let (Some(&kind), Some(&len)) = (b.get(o), b.get(o + 1)) else {
                        break;
                    };
                    if len == 0 || o + usize::from(len) * 8 > end {
                        break;
                    }
                    if matches!(kind, 1 | 2) && len == 1 {
                        ch.extend(self.mac(b, o + 2));
                    }
                    o += usize::from(len) * 8;
                }
            }
            _ => {}
        }
        ch
    }
}

// ------------------------------------------------------------- PCAPNG out

struct NgWriter<W: Write> {
    w: W,
    ifaces: HashMap<i32, u32>,
}

impl<W: Write> NgWriter<W> {
    fn new(mut w: W) -> std::io::Result<Self> {
        let mut shb = Vec::with_capacity(28);
        shb.extend_from_slice(&0x0a0d_0d0au32.to_le_bytes());
        shb.extend_from_slice(&28u32.to_le_bytes());
        shb.extend_from_slice(&0x1a2b_3c4du32.to_le_bytes());
        shb.extend_from_slice(&1u16.to_le_bytes());
        shb.extend_from_slice(&0u16.to_le_bytes());
        shb.extend_from_slice(&(-1i64).to_le_bytes());
        shb.extend_from_slice(&28u32.to_le_bytes());
        w.write_all(&shb)?;
        Ok(NgWriter {
            w,
            ifaces: HashMap::new(),
        })
    }

    fn iface(&mut self, link: i32) -> std::io::Result<u32> {
        if let Some(i) = self.ifaces.get(&link) {
            return Ok(*i);
        }
        let id = self.ifaces.len() as u32;
        let mut idb = Vec::with_capacity(32);
        idb.extend_from_slice(&1u32.to_le_bytes());
        idb.extend_from_slice(&32u32.to_le_bytes());
        idb.extend_from_slice(&(link as u16).to_le_bytes());
        idb.extend_from_slice(&0u16.to_le_bytes());
        idb.extend_from_slice(&0u32.to_le_bytes());
        // if_tsresol = 9: nanoseconds.
        idb.extend_from_slice(&9u16.to_le_bytes());
        idb.extend_from_slice(&1u16.to_le_bytes());
        idb.extend_from_slice(&[9, 0, 0, 0]);
        idb.extend_from_slice(&[0, 0, 0, 0]);
        idb.extend_from_slice(&32u32.to_le_bytes());
        self.w.write_all(&idb)?;
        self.ifaces.insert(link, id);
        Ok(id)
    }

    fn packet(&mut self, link: i32, ts_ns: i64, orig: u32, data: &[u8]) -> std::io::Result<()> {
        let id = self.iface(link)?;
        let pad = (4 - data.len() % 4) % 4;
        let total = (32 + data.len() + pad) as u32;
        let ts = ts_ns.max(0) as u64;
        let mut h = Vec::with_capacity(28);
        h.extend_from_slice(&6u32.to_le_bytes());
        h.extend_from_slice(&total.to_le_bytes());
        h.extend_from_slice(&id.to_le_bytes());
        h.extend_from_slice(&((ts >> 32) as u32).to_le_bytes());
        h.extend_from_slice(&(ts as u32).to_le_bytes());
        h.extend_from_slice(&(data.len() as u32).to_le_bytes());
        h.extend_from_slice(&orig.max(data.len() as u32).to_le_bytes());
        self.w.write_all(&h)?;
        self.w.write_all(data)?;
        self.w.write_all(&[0u8; 3][..pad])?;
        self.w.write_all(&total.to_le_bytes())
    }
}

/// Read a capture and write the cleaned copy to `out`.
pub fn sanitize<R: Read + Send, W: Write>(
    input: R,
    out: W,
    opts: &Options,
    progress: impl FnMut(u64) -> bool,
) -> Result<Report, String> {
    let key = FakeKey::from_hex(&opts.key).unwrap_or_else(FakeKey::generate);
    let mut c = Cleaner {
        opts: opts.clone(),
        key: key.clone(),
        seen_ip: HashSet::new(),
        seen_mac: HashSet::new(),
        report: Report {
            key: key.to_hex(),
            ..Default::default()
        },
    };
    let mut w = NgWriter::new(out).map_err(|e| format!("could not write: {e}"))?;
    let mut write_err: Option<String> = None;
    let mut dropped_links: Vec<i32> = Vec::new();
    let info = packets::each_packet(
        input,
        |p| {
            c.report.packets += 1;
            match c.packet(p.link, p.data) {
                Some(bytes) => {
                    if let Err(e) = w.packet(p.link, p.ts_ns, p.orig, &bytes) {
                        write_err = Some(format!("could not write: {e}"));
                        return false;
                    }
                    c.report.written += 1;
                }
                None => {
                    c.report.dropped += 1;
                    if !dropped_links.contains(&p.link) {
                        dropped_links.push(p.link);
                    }
                }
            }
            true
        },
        progress,
    )?;
    if let Some(e) = write_err {
        return Err(e);
    }
    w.w.flush().map_err(|e| format!("could not write: {e}"))?;
    let mut report = c.report;
    report.format = info.format;
    report.cancelled = info.cancelled;
    report.warnings = info.warnings;
    for l in dropped_links {
        report.warnings.push(format!(
            "link type {l} cannot be cleaned; its packets were left out"
        ));
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::super::core::tests::{dns_query, pcap, tcp, udp};
    use super::*;
    use etherparse::{PacketBuilder, SlicedPacket, TransportSlice};
    use std::io::Cursor;

    const KEY: &str = "0202020202020202020202020202020202020202020202020202020202020202";

    fn run(frames: &[Vec<u8>], opts: Options) -> (Report, Vec<(i32, Vec<u8>, u32)>) {
        let input = pcap(frames, 65535);
        let mut out = Vec::new();
        let r = sanitize(Cursor::new(input), &mut out, &opts, |_| true).unwrap();
        let mut pk = Vec::new();
        packets::each_packet(
            Cursor::new(out),
            |p| {
                pk.push((p.link, p.data.to_vec(), p.orig));
                true
            },
            |_| true,
        )
        .unwrap();
        (r, pk)
    }

    fn opts(strip: bool) -> Options {
        Options {
            strip_payload: strip,
            key: KEY.into(),
            ..Default::default()
        }
    }

    /// Verify TCP/UDP checksums of an Ethernet frame.
    fn checksums_ok(frame: &[u8]) -> bool {
        let s = SlicedPacket::from_ethernet(frame).unwrap();
        let Some(etherparse::NetSlice::Ipv4(ip)) = &s.net else {
            return true;
        };
        let h = ip.header().to_header();
        let hdr_ok = h.calc_header_checksum() == h.header_checksum;
        let l4_ok = match &s.transport {
            Some(TransportSlice::Tcp(t)) => {
                t.to_header().calc_checksum_ipv4(&h, t.payload()).unwrap() == t.checksum()
            }
            Some(TransportSlice::Udp(u)) => {
                u.to_header().calc_checksum_ipv4(&h, u.payload()).unwrap() == u.checksum()
            }
            _ => true,
        };
        hdr_ok && l4_ok
    }

    #[test]
    fn anonymizes_and_keeps_checksums_valid() {
        let frames = vec![
            tcp(
                51000,
                443,
                false,
                false,
                b"GET / HTTP/1.1\r\nHost: x\r\n\r\n",
            ),
            udp(5353, 53, &dns_query("a.example")),
        ];
        let (r, pk) = run(&frames, opts(false));
        assert_eq!((r.packets, r.written, r.dropped), (2, 2, 0));
        assert_eq!(r.stripped, 0);
        for (_, data, _) in &pk {
            assert!(checksums_ok(data), "bad checksum");
            let s = SlicedPacket::from_ethernet(data).unwrap();
            let Some(etherparse::NetSlice::Ipv4(ip)) = &s.net else {
                panic!()
            };
            let src = ip.header().source_addr();
            assert_ne!(src, Ipv4Addr::new(10, 0, 0, 1));
            assert_eq!(src.octets()[0], 10, "private stays private");
            // 10.0.0.x: only the host octet can change.
            assert_eq!(src.octets()[..3], [10, 0, 0]);
        }
        // Same original, same fake, across packets.
        let src = |d: &[u8]| d[26..30].to_vec();
        assert_eq!(src(&pk[0].1), src(&pk[1].1));
        // Documentation range 192.0.2.7 is kept.
        assert_eq!(&pk[0].1[30..34], &[192, 0, 2, 7]);
        // MACs keep their vendor prefix.
        assert_eq!(&pk[0].1[0..3], &[0x66, 0x77, 0x88]);
        assert_ne!(&pk[0].1[0..6], &[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]);
        assert!(r.addresses >= 2 && r.macs == 2);
        assert!(r.mapping.iter().any(|m| m.original == "10.0.0.1"));
        assert_eq!(r.key, KEY);
    }

    #[test]
    fn strips_payloads_to_headers() {
        let payload = b"secret application data";
        let frames = vec![
            tcp(51000, 80, false, false, payload),
            udp(5353, 53, &dns_query("host.example")),
        ];
        let (r, pk) = run(&frames, opts(true));
        assert_eq!(r.stripped, 2);
        assert_eq!(pk[0].1.len(), 14 + 20 + 20);
        assert_eq!(pk[1].1.len(), 14 + 20 + 8);
        // The wire length is kept, so tools show the packets as cut short.
        assert_eq!(pk[0].2 as usize, frames[0].len());
        assert!(
            !pk.iter()
                .any(|(_, d, _)| d.windows(6).any(|w| w == b"secret"))
        );
        assert!(r.bytes_removed > 0);
    }

    #[test]
    fn arp_ipv6_and_other_frames() {
        // ARP request.
        let mut arp = vec![0xff; 6];
        arp.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x08, 0x06]);
        arp.extend_from_slice(&[0, 1, 8, 0, 6, 4, 0, 1]);
        arp.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 10, 9, 9, 1]);
        arp.extend_from_slice(&[0, 0, 0, 0, 0, 0, 10, 9, 9, 2]);
        // LLDP frame with a system name.
        let mut lldp = vec![
            0x01, 0x80, 0xc2, 0, 0, 0x0e, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x88, 0xcc,
        ];
        lldp.extend_from_slice(b"\x0a\x08core-sw1");
        // IPv6 UDP.
        let mut v6 = Vec::new();
        PacketBuilder::ethernet2(
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            [0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb],
        )
        .ipv6(
            [
                0x26, 0, 0x1f, 0x18, 0xaa, 0xaa, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0x10,
            ],
            [
                0x26, 0, 0x1f, 0x18, 0xaa, 0xaa, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0x20,
            ],
            64,
        )
        .udp(1000, 2000)
        .write(&mut v6, b"hello")
        .unwrap();
        let (r, pk) = run(&[arp, lldp, v6], opts(false));
        // ARP sender IP rewritten, broadcast target MAC kept.
        assert_ne!(&pk[0].1[28..32], &[10, 9, 9, 1]);
        assert_eq!(&pk[0].1[0..6], &[0xff; 6]);
        assert_eq!(pk[0].1.len(), 42);
        // LLDP cut to the Ethernet header.
        assert_eq!(pk[1].1.len(), 14);
        assert_eq!(r.other_cut, 1);
        // IPv6 rewritten with a valid UDP checksum.
        let s = SlicedPacket::from_ethernet(&pk[2].1).unwrap();
        let Some(etherparse::NetSlice::Ipv6(ip)) = &s.net else {
            panic!()
        };
        let h = ip.header().to_header();
        assert_ne!(h.source[15], 0, "interface id kept nonzero");
        assert_ne!(
            h.source,
            [
                0x26, 0, 0x1f, 0x18, 0xaa, 0xaa, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0x10
            ]
        );
        assert_eq!(h.source[..8], h.destination[..8], "same /64");
        let Some(TransportSlice::Udp(u)) = &s.transport else {
            panic!()
        };
        assert_eq!(
            u.to_header().calc_checksum_ipv6(&h, u.payload()).unwrap(),
            u.checksum()
        );
    }

    #[test]
    fn unknown_links_are_dropped_and_junk_is_safe() {
        // Link type 147 (user-defined) cannot be cleaned.
        let mut input = pcap(&[vec![1, 2, 3]], 65535);
        input[20..24].copy_from_slice(&147u32.to_le_bytes());
        let mut out = Vec::new();
        let r = sanitize(Cursor::new(input), &mut out, &opts(true), |_| true).unwrap();
        assert_eq!((r.packets, r.written, r.dropped), (1, 0, 1));
        assert!(r.warnings.iter().any(|w| w.contains("147")));
        // Truncated and hostile Ethernet frames never panic.
        let frames: Vec<Vec<u8>> = vec![
            vec![],
            vec![0; 13],
            {
                let mut f = vec![0u8; 14];
                f[12] = 0x08;
                f.extend_from_slice(&[0x4f, 0, 0, 0]);
                f
            },
            {
                let mut f = vec![0u8; 14];
                f[12] = 0x86;
                f[13] = 0xdd;
                f.extend_from_slice(&[0x60; 45]);
                f
            },
        ];
        for strip in [true, false] {
            let (r, _) = run(&frames, opts(strip));
            assert_eq!(r.written, 4);
        }
        assert!(
            sanitize(
                Cursor::new(b"nope".to_vec()),
                Vec::new(),
                &opts(true),
                |_| true
            )
            .is_err()
        );
    }

    #[test]
    fn checksum_math() {
        let data = [
            0x45u8, 0x00, 0x00, 0x1c, 0, 0, 0, 0, 64, 17, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2,
        ];
        let mut a = data;
        ipv4_header_checksum(&mut a, 0, 20);
        let c0 = u16::from_be_bytes([a[10], a[11]]);
        let mut b = data;
        b[12..16].copy_from_slice(&[10, 9, 9, 9]);
        ipv4_header_checksum(&mut b, 0, 20);
        let c1 = u16::from_be_bytes([b[10], b[11]]);
        assert_eq!(csum_adjust(c0, &[10, 0, 0, 1], &[10, 9, 9, 9]), c1);
    }

    /// Clean PCAP_IN into PCAP_OUT (PCAP_STRIP=1 to remove payloads), for checks with Wireshark.
    #[test]
    #[ignore = "writes a file; run by hand"]
    fn dump() {
        let (Ok(src), Ok(dst)) = (std::env::var("PCAP_IN"), std::env::var("PCAP_OUT")) else {
            return;
        };
        let o = Options {
            strip_payload: std::env::var("PCAP_STRIP").is_ok_and(|v| v == "1"),
            ..Default::default()
        };
        let r = sanitize(
            std::fs::File::open(src).unwrap(),
            std::fs::File::create(dst).unwrap(),
            &o,
            |_| true,
        )
        .unwrap();
        eprintln!("{r:?}");
    }
}
