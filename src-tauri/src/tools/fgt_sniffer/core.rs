//! Pure FortiGate sniffer to PCAP logic. No Tauri types and no external
//! binaries: the pcap bytes are written directly here, so it is fully unit
//! testable. Ported from Manny's fgt2eth.py, with the text2pcap/Wireshark
//! dependency replaced by a built-in pcap writer.

use regex::Regex;
use serde::Deserialize;

/// Options controlling the conversion.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Options {
    /// Drop packets captured on the internal `eth0` interface (noise).
    pub skip_eth0: bool,
}

impl Default for Options {
    fn default() -> Self {
        Options { skip_eth0: true }
    }
}

/// A packet's timestamp as parsed from the sniffer output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParsedTime {
    /// Relative capture time: seconds and microseconds since capture start.
    Relative { secs: u64, usec: u32 },
    /// Absolute wall-clock time, as a Unix epoch (treated as UTC).
    Absolute { secs: u64, usec: u32 },
}

/// One parsed packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    pub interface: Option<String>,
    pub direction: Option<String>,
    pub time: ParsedTime,
    pub bytes: Vec<u8>,
    /// Bytes reported missing by a "truncated-ip" marker, added to orig_len.
    pub orig_extra: u32,
}

/// Result of parsing the whole input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseOutput {
    pub packets: Vec<Packet>,
    pub skipped_eth0: usize,
}

/// Parse FortiGate `diagnose sniffer packet` verbose output.
pub fn parse(input: &str, opts: &Options) -> ParseOutput {
    let re_rel = Regex::new(r"^(\d+)\.(\d+)\s").unwrap();
    let re_abs =
        Regex::new(r"^(\d{1,4})-(\d{1,2})-(\d{1,2}) (\d{1,2}):(\d{1,2}):(\d{1,2})\.(\d+)").unwrap();

    let lines: Vec<&str> = input.lines().collect();
    let mut packets = Vec::new();
    let mut skipped_eth0 = 0;
    let mut i = 0;

    while i < lines.len() {
        let line = lines[i];
        let Some(time) = parse_time(line, &re_rel, &re_abs) else {
            i += 1;
            continue;
        };

        let (interface, direction) = parse_intf_dir(line);
        let orig_extra = parse_truncated_missing(line);
        i += 1;

        // Gather the hex dump lines that follow, up to a blank line or the
        // next timestamp header. Non-hex lines inside the block are skipped,
        // not treated as the end: `any` captures at verbose 6 print a
        // "linux cooked capture, ..." descriptor line between the header and
        // the hex.
        let mut bytes = Vec::new();
        while i < lines.len() {
            let l = lines[i];
            if l.trim().is_empty() || parse_time(l, &re_rel, &re_abs).is_some() {
                break;
            }
            if let Some(rest) = strip_hex_offset(l) {
                bytes.extend(parse_hex_bytes(rest));
            }
            i += 1;
        }

        let is_eth0 = interface.as_deref() == Some("eth0");
        if opts.skip_eth0 && is_eth0 {
            skipped_eth0 += 1;
            continue;
        }
        if bytes.is_empty() {
            continue;
        }

        adjust_packet(&mut bytes);
        packets.push(Packet {
            interface,
            direction,
            time,
            bytes,
            orig_extra,
        });
    }

    ParseOutput {
        packets,
        skipped_eth0,
    }
}

fn parse_time(line: &str, re_rel: &Regex, re_abs: &Regex) -> Option<ParsedTime> {
    if let Some(c) = re_abs.captures(line) {
        let y: i64 = c[1].parse().ok()?;
        let mo: u32 = c[2].parse().ok()?;
        let d: u32 = c[3].parse().ok()?;
        let h: u64 = c[4].parse().ok()?;
        let mi: u64 = c[5].parse().ok()?;
        let s: u64 = c[6].parse().ok()?;
        let usec = frac_to_usec(&c[7]);
        let days = days_from_civil(y, mo, d);
        let secs = (days * 86400 + (h * 3600 + mi * 60 + s) as i64) as u64;
        return Some(ParsedTime::Absolute { secs, usec });
    }
    if let Some(c) = re_rel.captures(line) {
        let secs: u64 = c[1].parse().ok()?;
        let usec = frac_to_usec(&c[2]);
        return Some(ParsedTime::Relative { secs, usec });
    }
    None
}

/// Normalize a fractional-seconds digit string to microseconds (6 digits).
fn frac_to_usec(frac: &str) -> u32 {
    let mut s: String = frac.chars().take(6).collect();
    while s.len() < 6 {
        s.push('0');
    }
    s.parse().unwrap_or(0)
}

/// Interface and direction from the header line: the token before `in`/`out`.
fn parse_intf_dir(line: &str) -> (Option<String>, Option<String>) {
    let tokens: Vec<&str> = line.split_whitespace().collect();
    for (idx, tok) in tokens.iter().enumerate() {
        if (*tok == "in" || *tok == "out") && idx > 0 {
            return (Some(tokens[idx - 1].to_string()), Some(tok.to_string()));
        }
    }
    (None, None)
}

fn parse_truncated_missing(line: &str) -> u32 {
    // "truncated-ip - 1480 bytes missing!"
    let marker = "truncated-ip - ";
    if let Some(pos) = line.find(marker) {
        let rest = &line[pos + marker.len()..];
        let num: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
        return num.parse().unwrap_or(0);
    }
    0
}

/// If the line is a hex dump line (`0x0000  ...`), return everything after the
/// offset token.
fn strip_hex_offset(line: &str) -> Option<&str> {
    let trimmed = line.trim_start();
    if !(trimmed.starts_with("0x") || trimmed.starts_with("0X")) {
        return None;
    }
    // Split off the "0x0000" offset token.
    let rest = trimmed.split_once([' ', '\t', '\u{a0}'])?.1;
    Some(rest)
}

/// Extract up to 16 bytes from the hex region of a dump line, ignoring the
/// trailing ASCII gutter. Within the hex area, 2-byte words are separated by a
/// single space; the ASCII gutter is set off by a tab or a run of 2+ spaces.
/// Cutting at that boundary stops ASCII letters like "cafe" from being read as
/// bytes.
fn parse_hex_bytes(rest: &str) -> Vec<u8> {
    // Treat a non-breaking space (seen in some FGT locales) as a gutter marker.
    let rest = rest.trim_start().replace('\u{a0}', "\t");
    let hex_region = &rest[..gutter_start(&rest)];

    let digits: Vec<u8> = hex_region
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .map(|c| c as u8)
        .collect();

    let mut out = Vec::with_capacity(16);
    let mut idx = 0;
    while idx + 1 < digits.len() && out.len() < 16 {
        let hi = (digits[idx] as char).to_digit(16).unwrap() as u8;
        let lo = (digits[idx + 1] as char).to_digit(16).unwrap() as u8;
        out.push(hi << 4 | lo);
        idx += 2;
    }
    out
}

/// Byte index where the ASCII gutter starts: the first tab or run of 2+ spaces.
fn gutter_start(s: &str) -> usize {
    let chars: Vec<(usize, char)> = s.char_indices().collect();
    let mut k = 0;
    while k < chars.len() {
        let (bi, c) = chars[k];
        if c == '\t' {
            return bi;
        }
        if c == ' ' {
            let mut m = k;
            while m < chars.len() && chars[m].1 == ' ' {
                m += 1;
            }
            if m - k >= 2 {
                return bi;
            }
            k = m;
            continue;
        }
        k += 1;
    }
    s.len()
}

/// FortiGate-specific packet fixups, ported from fgt2eth.py adjustPacket.
/// Applied in order; each step sees the result of the previous.
fn adjust_packet(b: &mut Vec<u8>) {
    // 1. Collapse an extra 2-byte field when the ethertype at offset 14 is
    //    IPv4 (0800) or 8893: remove bytes 12-13.
    if b.len() >= 16 && (b[14] == 0x08 && b[15] == 0x00 || b[14] == 0x88 && b[15] == 0x93) {
        b.drain(12..14);
    }

    // 2. Prepend a dummy Ethernet header when the payload is raw IPv4
    //    (version/IHL 0x45, DSCP 0x00 or 0x10).
    if b.len() >= 2 && b[0] == 0x45 && (b[1] == 0x00 || b[1] == 0x10) {
        let mut header = vec![0u8; 12];
        header.push(0x08);
        header.push(0x00);
        header.extend_from_slice(b);
        *b = header;
    }

    // 3. Rewrite internal FGT ethertypes 8890/8891 to IPv4 (0800).
    if b.len() >= 14 && b[12] == 0x88 && (b[13] == 0x90 || b[13] == 0x91) {
        b[12] = 0x08;
        b[13] = 0x00;
    }
}

/// Resolve each packet to an absolute (seconds, microseconds) pair. Relative
/// timestamps are anchored so the first relative packet maps to `base_secs` and
/// later packets keep their exact deltas.
pub fn resolve_times(packets: &[Packet], base_secs: u64) -> Vec<(u64, u32)> {
    let first_rel = packets.iter().find_map(|p| match p.time {
        ParsedTime::Relative { secs, usec } => Some(secs as i128 * 1_000_000 + usec as i128),
        _ => None,
    });

    packets
        .iter()
        .map(|p| match p.time {
            ParsedTime::Absolute { secs, usec } => (secs, usec),
            ParsedTime::Relative { secs, usec } => {
                let rel = secs as i128 * 1_000_000 + usec as i128;
                let first = first_rel.unwrap_or(0);
                let total = (base_secs as i128 * 1_000_000 + (rel - first)).max(0);
                ((total / 1_000_000) as u64, (total % 1_000_000) as u32)
            }
        })
        .collect()
}

/// Serialize packets to classic pcap format (little-endian, Ethernet link
/// type).
pub fn to_pcap(packets: &[Packet], base_secs: u64) -> Vec<u8> {
    let times = resolve_times(packets, base_secs);
    let mut out = Vec::new();

    // Global header.
    out.extend_from_slice(&0xa1b2_c3d4u32.to_le_bytes()); // magic
    out.extend_from_slice(&2u16.to_le_bytes()); // version major
    out.extend_from_slice(&4u16.to_le_bytes()); // version minor
    out.extend_from_slice(&0i32.to_le_bytes()); // thiszone
    out.extend_from_slice(&0u32.to_le_bytes()); // sigfigs
    out.extend_from_slice(&65535u32.to_le_bytes()); // snaplen
    out.extend_from_slice(&1u32.to_le_bytes()); // network = LINKTYPE_ETHERNET

    for (p, (secs, usec)) in packets.iter().zip(times) {
        let incl = p.bytes.len() as u32;
        let orig = incl + p.orig_extra;
        out.extend_from_slice(&(secs as u32).to_le_bytes());
        out.extend_from_slice(&usec.to_le_bytes());
        out.extend_from_slice(&incl.to_le_bytes());
        out.extend_from_slice(&orig.to_le_bytes());
        out.extend_from_slice(&p.bytes);
    }

    out
}

/// Format a Unix epoch (UTC) for display, e.g. "2026-10-28 14:03:11.123456".
pub fn format_epoch(secs: u64, usec: u32) -> String {
    let days = (secs / 86400) as i64;
    let rem = secs % 86400;
    let (y, mo, d) = civil_from_days(days);
    let (h, mi, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    format!("{y:04}-{mo:02}-{d:02} {h:02}:{mi:02}:{s:02}.{usec:06}")
}

/// Days since Unix epoch for a civil date (Howard Hinnant's algorithm).
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = if m > 2 { m - 3 } else { m + 9 } as i64;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

/// Inverse of [`days_from_civil`]: civil date from days since Unix epoch.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts() -> Options {
        Options::default()
    }

    #[test]
    fn parses_absolute_packet() {
        let input = "2025-01-24 11:37:36.123456 port1 in 10.0.0.1 -> 10.0.0.2\n\
0x0000   0011 2233 4455 6677 8899 aabb 0800 4500   ..3DUfw.......E\n\
0x0010   0014 0000\n";
        let out = parse(input, &opts());
        assert_eq!(out.packets.len(), 1);
        let p = &out.packets[0];
        assert_eq!(p.interface.as_deref(), Some("port1"));
        assert_eq!(p.direction.as_deref(), Some("in"));
        // 14 header bytes + ethertype already present, then IPv4 payload.
        assert_eq!(&p.bytes[12..14], &[0x08, 0x00]);
        assert!(matches!(p.time, ParsedTime::Absolute { .. }));
    }

    #[test]
    fn absolute_epoch_is_correct() {
        let input = "2025-01-24 11:37:36.500000 port1 in x\n0x0000  4500 0014\n";
        let out = parse(input, &opts());
        match out.packets[0].time {
            ParsedTime::Absolute { secs, usec } => {
                // 2025-01-24 11:37:36 UTC = 1737718656.
                assert_eq!(secs, 1_737_718_656);
                assert_eq!(usec, 500_000);
            }
            _ => panic!("expected absolute"),
        }
    }

    #[test]
    fn hex_gutter_not_parsed_as_bytes() {
        // Short final line whose ASCII gutter contains "cafe" must not add bytes.
        let input = "1.000000 port1 in x\n\
0x0000   dead beef                                  cafe\n";
        let out = parse(input, &opts());
        // dead beef = 4 bytes; raw IP rule does not apply (not 0x45..).
        assert_eq!(out.packets[0].bytes, vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn caps_sixteen_bytes_per_line() {
        let input = "1.0 port1 in x\n\
0x0000   0001 0203 0405 0607 0809 0a0b 0c0d 0e0f 1011 1213\n";
        let out = parse(input, &opts());
        assert_eq!(out.packets[0].bytes.len(), 16);
        assert_eq!(out.packets[0].bytes[15], 0x0f);
    }

    #[test]
    fn adjust_raw_ip_gets_ethernet_header() {
        let mut b = vec![0x45, 0x00, 0xDE, 0xAD];
        adjust_packet(&mut b);
        assert_eq!(b.len(), 4 + 14);
        assert_eq!(&b[0..12], &[0u8; 12]);
        assert_eq!(&b[12..14], &[0x08, 0x00]);
        assert_eq!(&b[14..], &[0x45, 0x00, 0xDE, 0xAD]);
    }

    #[test]
    fn adjust_strips_two_bytes_when_ethertype_at_14() {
        // 12 header bytes, 2 extra (dead), then 0800 at offset 14.
        let mut b = vec![
            0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 0xde, 0xad, 0x08, 0x00, 0x45, 0x00,
        ];
        adjust_packet(&mut b);
        // bytes 12-13 removed, so 0800 is now at offset 12.
        assert_eq!(&b[12..14], &[0x08, 0x00]);
        assert_eq!(b.len(), 16);
    }

    #[test]
    fn adjust_rewrites_internal_ethertype() {
        let mut b = vec![0u8; 14];
        b[12] = 0x88;
        b[13] = 0x91;
        adjust_packet(&mut b);
        assert_eq!(&b[12..14], &[0x08, 0x00]);
    }

    #[test]
    fn skips_eth0_by_default() {
        let input = "1.0 eth0 out x\n0x0000  0011 2233 4455\n\
1.1 port1 in y\n0x0000  aabb ccdd eeff\n";
        let out = parse(input, &opts());
        assert_eq!(out.skipped_eth0, 1);
        assert_eq!(out.packets.len(), 1);
        assert_eq!(out.packets[0].interface.as_deref(), Some("port1"));
    }

    #[test]
    fn keeps_eth0_when_disabled() {
        let input = "1.0 eth0 out x\n0x0000  0011 2233 4455\n";
        let o = Options { skip_eth0: false };
        let out = parse(input, &o);
        assert_eq!(out.skipped_eth0, 0);
        assert_eq!(out.packets.len(), 1);
    }

    #[test]
    fn truncated_marker_sets_orig_len() {
        let input = "1.0 port1 in x truncated-ip - 100 bytes missing!\n0x0000  4500 0014\n";
        let out = parse(input, &opts());
        assert_eq!(out.packets[0].orig_extra, 100);
    }

    #[test]
    fn relative_times_anchor_to_base() {
        let input = "10.000000 port1 in x\n0x0000  4500 0014\n\
10.500000 port1 in y\n0x0000  4500 0014\n";
        let out = parse(input, &opts());
        let times = resolve_times(&out.packets, 1_000_000_000);
        // First packet anchored to base, second is +0.5s.
        assert_eq!(times[0], (1_000_000_000, 0));
        assert_eq!(times[1], (1_000_000_000, 500_000));
    }

    #[test]
    fn pcap_header_and_record() {
        let input = "1.000000 port1 in x\n0x0000  4500 0004\n";
        let out = parse(input, &opts());
        let pcap = to_pcap(&out.packets, 42);
        // Global header magic, little-endian.
        assert_eq!(&pcap[0..4], &0xa1b2_c3d4u32.to_le_bytes());
        // network = 1 at offset 20.
        assert_eq!(&pcap[20..24], &1u32.to_le_bytes());
        // One record: raw IP got a 14-byte Ethernet header + 4 payload = 18.
        let incl = u32::from_le_bytes(pcap[32..36].try_into().unwrap());
        assert_eq!(incl, 18);
        assert_eq!(pcap.len(), 24 + 16 + 18);
    }

    #[test]
    fn format_epoch_roundtrip() {
        // 1737718656 = 2025-01-24 11:37:36 UTC.
        assert_eq!(
            format_epoch(1_737_718_656, 500_000),
            "2025-01-24 11:37:36.500000"
        );
    }

    #[test]
    fn pcap_opens_in_tcpdump_when_available() {
        // A complete Ethernet + IPv4 + UDP frame (42 bytes), so no adjust rule
        // fires and the output is a clean capture.
        let input = "2.000000 port1 out 10.0.0.1.53 -> 10.0.0.2.53: udp 0\n\
0x0000   0011 2233 4455 6677 8899 aabb 0800 4500   ..\"3DUfw.......\n\
0x0010   001c 0001 0000 4011 0000 0a00 0001 0a00   ......@.........\n\
0x0020   0002 0035 0035 0008 0000                  ...5.5....\n";
        let out = parse(input, &Options::default());
        assert_eq!(out.packets.len(), 1);
        assert_eq!(out.packets[0].bytes.len(), 42);

        let pcap = to_pcap(&out.packets, 1_700_000_000);
        let path = std::env::temp_dir().join("omnipacket_fgt_roundtrip.pcap");
        std::fs::write(&path, &pcap).unwrap();

        // Validate the pcap container with tcpdump if it is installed.
        if let Ok(output) = std::process::Command::new("tcpdump")
            .args(["-r"])
            .arg(&path)
            .args(["-nn", "-c", "1"])
            .output()
        {
            assert!(
                output.status.success(),
                "tcpdump could not read the pcap: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn parses_any_verbose6_with_sll_descriptor() {
        // `diagnose sniffer packet any '...' 6` prints a "linux cooked capture"
        // descriptor line between the header and the hex. It must be skipped,
        // not treated as the end of the packet.
        let input = "interfaces=[any]\nfilters=[host 10.1.108.2]\n\
4.257341 Office-Wired out 10.1.105.1.4443 -> 10.1.108.2.50668: psh 4064655509 ack 3731294975\n\
linux cooked capture, packet type: 0x4, link layer address type: 0x1, protocol type: 0x800, link layer address: e0:23:ff:5d:a3:64\n\
0x0000   0000 0000 0000 e023 ff5d a364 0800 4502   .......#.].d..E.\n\
0x0010   03d3 cf84 0000 4006                        ......@.\n";
        let out = parse(input, &Options::default());
        assert_eq!(
            out.packets.len(),
            1,
            "descriptor line should not drop the packet"
        );
        let p = &out.packets[0];
        assert_eq!(p.interface.as_deref(), Some("Office-Wired"));
        assert_eq!(p.direction.as_deref(), Some("out"));
        // 16 bytes on the first line + 8 on the second, Ethernet frame intact.
        assert_eq!(p.bytes.len(), 24);
        assert_eq!(&p.bytes[0..6], &[0, 0, 0, 0, 0, 0]);
        assert_eq!(&p.bytes[6..12], &[0xe0, 0x23, 0xff, 0x5d, 0xa3, 0x64]);
        assert_eq!(&p.bytes[12..14], &[0x08, 0x00]);
        assert_eq!(&p.bytes[14..16], &[0x45, 0x02]);
    }

    #[test]
    fn ignores_preamble_lines() {
        let input = "interfaces=[port1]\nfilters=[none]\n\
1.000000 port1 in x\n0x0000  4500 0014\n";
        let out = parse(input, &opts());
        assert_eq!(out.packets.len(), 1);
    }
}
