//! NTP (SNTP client mode) packets and the offset/delay arithmetic from
//! RFC 5905. Pure: the socket work is in `commands`. Nothing here, or
//! anywhere in this tool, touches the system clock.

use serde::Serialize;

/// Seconds between 1900-01-01 (NTP era 0) and 1970-01-01.
const NTP_UNIX_DIFF: u64 = 2_208_988_800;

/// NTP 64-bit timestamp from Unix nanoseconds.
pub fn to_ntp(unix_ns: i128) -> u64 {
    let secs = (unix_ns.div_euclid(1_000_000_000)) as u64 + NTP_UNIX_DIFF;
    let frac = ((unix_ns.rem_euclid(1_000_000_000) as u128) << 32) / 1_000_000_000;
    (secs << 32) | (frac as u64 & 0xffff_ffff)
}

/// Unix nanoseconds from an NTP timestamp (era 0; valid until 2036, then
/// wrapped forward, as most clients do).
pub fn from_ntp(t: u64) -> i128 {
    let mut secs = (t >> 32) as i128;
    // Era 1 starts in 2036: small values are after the wrap.
    if secs < (NTP_UNIX_DIFF as i128 / 2) {
        secs += 1 << 32;
    }
    let frac = ((t & 0xffff_ffff) as i128 * 1_000_000_000) >> 32;
    (secs - NTP_UNIX_DIFF as i128) * 1_000_000_000 + frac
}

/// A client request carrying our transmit timestamp.
pub fn request(transmit: u64) -> [u8; 48] {
    let mut p = [0u8; 48];
    p[0] = (4 << 3) | 3; // LI 0, version 4, mode 3 (client)
    p[40..48].copy_from_slice(&transmit.to_be_bytes());
    p
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Reply {
    pub leap: u8,
    pub version: u8,
    pub mode: u8,
    pub stratum: u8,
    pub poll: i8,
    pub precision: i8,
    pub root_delay_ms: i64,
    pub root_dispersion_ms: i64,
    /// Reference ID: ASCII for stratum 0/1 ("GPS", "RATE"), an IPv4 for
    /// stratum 2+ over IPv4 (a hash over IPv6).
    pub ref_id: String,
    pub reference_ns: i128,
    pub origin: u64,
    pub receive: u64,
    pub transmit: u64,
}

fn short(b: &[u8]) -> i64 {
    // NTP short format: 16.16 seconds, as milliseconds.
    let v = u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as i64;
    (v * 1000) >> 16
}

/// Parse and sanity-check a server reply to our request.
pub fn parse(buf: &[u8], sent_transmit: u64) -> Result<Reply, String> {
    if buf.len() < 48 {
        return Err(format!("reply too short ({} bytes)", buf.len()));
    }
    let leap = buf[0] >> 6;
    let version = (buf[0] >> 3) & 7;
    let mode = buf[0] & 7;
    let stratum = buf[1];
    let ts = |i: usize| u64::from_be_bytes(buf[i..i + 8].try_into().unwrap_or([0; 8]));
    let id = &buf[12..16];
    let ref_id = if stratum <= 1 {
        String::from_utf8_lossy(id)
            .trim_end_matches('\0')
            .chars()
            .filter(|c| c.is_ascii_graphic())
            .collect()
    } else {
        format!("{}.{}.{}.{}", id[0], id[1], id[2], id[3])
    };
    let r = Reply {
        leap,
        version,
        mode,
        stratum,
        poll: buf[2] as i8,
        precision: buf[3] as i8,
        root_delay_ms: short(&buf[4..8]),
        root_dispersion_ms: short(&buf[8..12]),
        ref_id,
        reference_ns: from_ntp(ts(16)),
        origin: ts(24),
        receive: ts(32),
        transmit: ts(40),
    };
    if mode != 4 && mode != 5 {
        return Err(format!("not a server reply (mode {mode})"));
    }
    if r.origin != sent_transmit {
        return Err(
            "reply does not answer our request (origin timestamp mismatch); ignored".into(),
        );
    }
    if stratum == 0 {
        return Err(match r.ref_id.as_str() {
            "RATE" => "Kiss-o'-Death RATE: the server asks us to slow down".to_string(),
            "DENY" | "RSTR" => format!(
                "Kiss-o'-Death {}: the server refuses to serve this client",
                r.ref_id
            ),
            other => format!("Kiss-o'-Death {other} (stratum 0)"),
        });
    }
    if leap == 3 {
        return Err("server reports it is unsynchronized (leap indicator 3)".into());
    }
    if r.transmit == 0 {
        return Err("server transmit timestamp is zero".into());
    }
    Ok(r)
}

/// Offset and round-trip delay in nanoseconds (RFC 5905 section 8):
/// offset = ((T2 - T1) + (T3 - T4)) / 2, delay = (T4 - T1) - (T3 - T2).
pub fn offset_delay(t1: i128, t2: i128, t3: i128, t4: i128) -> (i128, i128) {
    (((t2 - t1) + (t3 - t4)) / 2, (t4 - t1) - (t3 - t2))
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Summary {
    pub samples: usize,
    pub answered: usize,
    /// Offset of the sample with the lowest delay (the most trustworthy).
    pub best_offset_ms: Option<f64>,
    pub min_offset_ms: Option<f64>,
    pub max_offset_ms: Option<f64>,
    pub mean_offset_ms: Option<f64>,
    /// Standard deviation of the offsets.
    pub jitter_ms: Option<f64>,
    pub min_delay_ms: Option<f64>,
}

/// Summarize (offset_ns, delay_ns) pairs from answered samples.
pub fn summarize(samples: usize, answered: &[(i128, i128)]) -> Summary {
    let ms = |ns: i128| ns as f64 / 1e6;
    if answered.is_empty() {
        return Summary {
            samples,
            answered: 0,
            best_offset_ms: None,
            min_offset_ms: None,
            max_offset_ms: None,
            mean_offset_ms: None,
            jitter_ms: None,
            min_delay_ms: None,
        };
    }
    let offs: Vec<f64> = answered.iter().map(|(o, _)| ms(*o)).collect();
    let mean = offs.iter().sum::<f64>() / offs.len() as f64;
    let var = offs.iter().map(|o| (o - mean).powi(2)).sum::<f64>() / offs.len() as f64;
    let best = answered.iter().min_by_key(|(_, d)| *d).map(|(o, _)| ms(*o));
    Summary {
        samples,
        answered: answered.len(),
        best_offset_ms: best,
        min_offset_ms: offs.iter().cloned().reduce(f64::min),
        max_offset_ms: offs.iter().cloned().reduce(f64::max),
        mean_offset_ms: Some(mean),
        jitter_ms: Some(var.sqrt()),
        min_delay_ms: answered.iter().map(|(_, d)| ms(*d)).reduce(f64::min),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamp_round_trip() {
        let ns: i128 = 1_794_614_400_123_456_789;
        let back = from_ntp(to_ntp(ns));
        assert!((back - ns).abs() < 2, "{back} vs {ns}");
        // After the 2036 era wrap.
        let later: i128 = 2_200_000_000_000_000_000;
        assert!((from_ntp(to_ntp(later)) - later).abs() < 2);
    }

    fn reply(stratum: u8, ref_id: &[u8; 4], origin: u64, leap: u8) -> Vec<u8> {
        let mut b = vec![0u8; 48];
        b[0] = (leap << 6) | (4 << 3) | 4;
        b[1] = stratum;
        b[2] = 6;
        b[3] = 0xe9;
        b[4..8].copy_from_slice(&(1u32 << 16).to_be_bytes()); // 1 s root delay
        b[12..16].copy_from_slice(ref_id);
        b[24..32].copy_from_slice(&origin.to_be_bytes());
        b[32..40].copy_from_slice(&to_ntp(1_794_614_400_000_000_000).to_be_bytes());
        b[40..48].copy_from_slice(&to_ntp(1_794_614_400_000_100_000).to_be_bytes());
        b
    }

    #[test]
    fn parses_and_validates() {
        let sent = to_ntp(1_794_614_399_990_000_000);
        let r = parse(&reply(1, b"GPS\0", sent, 0), sent).unwrap();
        assert_eq!(
            (r.stratum, r.ref_id.as_str(), r.version, r.mode),
            (1, "GPS", 4, 4)
        );
        assert_eq!(r.root_delay_ms, 1000);
        let r2 = parse(&reply(2, &[192, 0, 2, 1], sent, 0), sent).unwrap();
        assert_eq!(r2.ref_id, "192.0.2.1");
        assert!(
            parse(&reply(2, &[1, 2, 3, 4], sent + 1, 0), sent)
                .unwrap_err()
                .contains("mismatch")
        );
        assert!(
            parse(&reply(0, b"RATE", sent, 0), sent)
                .unwrap_err()
                .contains("RATE")
        );
        assert!(
            parse(&reply(0, b"DENY", sent, 0), sent)
                .unwrap_err()
                .contains("refuses")
        );
        assert!(
            parse(&reply(2, &[1, 2, 3, 4], sent, 3), sent)
                .unwrap_err()
                .contains("unsynchronized")
        );
        assert!(parse(&[0u8; 20], sent).is_err());
        let mut client = reply(2, &[1, 2, 3, 4], sent, 0);
        client[0] = (4 << 3) | 3;
        assert!(parse(&client, sent).unwrap_err().contains("mode 3"));
        let req = request(sent);
        assert_eq!(req[0], 0x23);
        assert_eq!(u64::from_be_bytes(req[40..48].try_into().unwrap()), sent);
    }

    #[test]
    fn offset_math() {
        // Client 50 ms behind, 20 ms each way, 1 ms server processing.
        let (t1, t2, t3, t4) = (
            1_000_000_000i128,
            1_070_000_000,
            1_071_000_000,
            1_041_000_000,
        );
        let (o, d) = offset_delay(t1, t2, t3, t4);
        assert_eq!(o, 50_000_000);
        assert_eq!(d, 40_000_000);
        let s = summarize(
            4,
            &[
                (50_000_000, 40_000_000),
                (52_000_000, 60_000_000),
                (48_000_000, 45_000_000),
            ],
        );
        assert_eq!(s.answered, 3);
        assert_eq!(s.best_offset_ms, Some(50.0));
        assert_eq!(s.min_offset_ms, Some(48.0));
        assert_eq!(s.max_offset_ms, Some(52.0));
        assert!((s.jitter_ms.unwrap() - 1.633).abs() < 0.01);
        assert_eq!(summarize(3, &[]).best_offset_ms, None);
    }
}
