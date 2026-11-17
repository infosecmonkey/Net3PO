//! Keyed, structure-keeping fake addresses for redaction.
//!
//! IPv4: private ranges stay private, public stays public, and two addresses
//! in the same /8, /16 or /24 stay together. The last octet is kept, and so
//! are 0 and 255 in the middle octets, so `10.1.1.0/24` and `10.1.0.0/16`
//! still read as networks. IPv6 works the same way per 16-bit group. MAC
//! addresses keep their vendor prefix (OUI).
//!
//! Each octet or group is passed through a small keyed Feistel permutation
//! (SHA-256 round function) whose input includes the original prefix, so the
//! mapping is one-to-one and cannot be reversed without the session key.
//! This is pseudonymization for sharing text, not encryption.

use std::net::{Ipv4Addr, Ipv6Addr};

use sha2::{Digest, Sha256};

/// A session key. The same key always gives the same fakes.
#[derive(Clone, PartialEq, Eq)]
pub struct FakeKey([u8; 32]);

impl std::fmt::Debug for FakeKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FakeKey(..)")
    }
}

impl FakeKey {
    /// A new random key.
    pub fn generate() -> Self {
        use ring::rand::{SecureRandom, SystemRandom};
        let mut k = [0u8; 32];
        if SystemRandom::new().fill(&mut k).is_err() {
            // Fall back to the std hasher's random seed; still unpredictable.
            use std::hash::BuildHasher;
            for (i, chunk) in k.chunks_mut(8).enumerate() {
                let v = std::collections::hash_map::RandomState::new().hash_one(i);
                chunk.copy_from_slice(&v.to_le_bytes());
            }
        }
        FakeKey(k)
    }

    /// Parse a 64-digit hex key.
    pub fn from_hex(s: &str) -> Option<Self> {
        let s = s.trim();
        if s.len() != 64 || !s.is_ascii() {
            return None;
        }
        let mut k = [0u8; 32];
        for (i, b) in k.iter_mut().enumerate() {
            *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
        }
        Some(FakeKey(k))
    }

    pub fn to_hex(&self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn prf(&self, ctx: &[u8], round: u8, bits: u32, half: u32) -> u32 {
        let mut h = Sha256::new();
        h.update(self.0);
        h.update([round, bits as u8, ctx.len() as u8]);
        h.update(ctx);
        h.update(half.to_be_bytes());
        let d = h.finalize();
        u32::from_be_bytes([d[0], d[1], d[2], d[3]])
    }

    /// A keyed permutation of `bits`-bit values (even, at most 32).
    fn feistel(&self, ctx: &[u8], x: u32, bits: u32) -> u32 {
        let h = bits / 2;
        let mask = (1u32 << h) - 1;
        let (mut l, mut r) = (x >> h & mask, x & mask);
        for round in 0..4u8 {
            let f = self.prf(ctx, round, bits, r) & mask;
            (l, r) = (r, l ^ f);
        }
        (l << h) | r
    }

    /// Permute `x` within the values where `allowed` is true (cycle walking).
    /// Values outside that set map to themselves.
    fn perm(&self, ctx: &[u8], x: u32, bits: u32, allowed: impl Fn(u32) -> bool) -> u32 {
        if !allowed(x) {
            return x;
        }
        let mut y = x;
        for _ in 0..=(1u32 << bits) {
            y = self.feistel(ctx, y, bits);
            if allowed(y) {
                return y;
            }
        }
        x
    }
}

/// IPv4 ranges kept as they are: protocol constants and documentation space.
fn keep_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    a == 0
        || a == 127
        || a >= 224
        || (a, b, c) == (192, 0, 2)
        || (a, b, c) == (198, 51, 100)
        || (a, b, c) == (203, 0, 113)
        || (a, b) == (198, 18)
        || (a, b) == (198, 19)
}

/// First octets a public address may map to. Octets that also hold a private
/// or special range are left out, so a public address never lands in one.
fn public_first(a: u32) -> bool {
    (1..=223).contains(&a) && ![10, 100, 127, 169, 172, 192].contains(&a)
}

/// Middle octets: 0 and 255 stay put so network and broadcast forms survive.
fn mid(x: u32) -> bool {
    (1..=254).contains(&x)
}

/// A fake for an IPv4 address.
pub fn fake_v4(key: &FakeKey, ip: Ipv4Addr) -> Ipv4Addr {
    if keep_v4(ip) {
        return ip;
    }
    let [a, b, c, d] = ip.octets().map(u32::from);
    let p = |ctx: &[u8], x: u32, allowed: &dyn Fn(u32) -> bool| -> u32 {
        let mut full = vec![b'4'];
        full.extend_from_slice(ctx);
        key.perm(&full, x, 8, allowed)
    };
    let (na, nb) = match (a, b) {
        (10, _) => (a, p(&[10], b, &mid)),
        (172, 16..=31) => (a, p(&[172], b, &|x| (16..=31).contains(&x))),
        (192, 168) | (169, 254) => (a, b),
        (100, 64..=127) => (a, p(&[100], b, &|x| (64..=127).contains(&x))),
        // Public addresses that share a first octet with a private range keep
        // it and stay out of that range.
        (172, _) => (a, p(&[172], b, &|x| mid(x) && !(16..=31).contains(&x))),
        (192, _) => (a, p(&[192], b, &|x| mid(x) && x != 168)),
        (169, _) => (a, p(&[169], b, &|x| mid(x) && x != 254)),
        (100, _) => (a, p(&[100], b, &|x| mid(x) && !(64..=127).contains(&x))),
        _ => (p(&[], a, &public_first), p(&[a as u8], b, &mid)),
    };
    let nc = p(&[a as u8, b as u8], c, &mid);
    Ipv4Addr::new(na as u8, nb as u8, nc as u8, d as u8)
}

/// A fake for an IPv6 address.
pub fn fake_v6(key: &FakeKey, ip: Ipv6Addr) -> Ipv6Addr {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return fake_v4(key, v4).to_ipv6_mapped();
    }
    let s = ip.segments();
    let keep = ip.is_unspecified()
        || ip.is_loopback()
        || s[0] >> 8 == 0xff
        || (s[0], s[1]) == (0x2001, 0x0db8);
    if keep {
        return ip;
    }
    // Groups 0 and 1 keep their meaning (`::`, `::1` style addresses).
    let group = |x: u32| x > 1;
    let mut out = s;
    let start = if s[0] & 0xffc0 == 0xfe80 {
        // Link-local: only the interface ID identifies anything.
        4
    } else if s[0] & 0xfe00 == 0xfc00 {
        // Unique local: keep fc/fd, permute the rest of the first group.
        let lo = key.perm(b"6u", u32::from(s[0] & 0xff), 8, |_| true);
        out[0] = (s[0] & 0xff00) | lo as u16;
        1
    } else if s[0] & 0xe000 == 0x2000 {
        out[0] = key.perm(b"6g", u32::from(s[0]), 16, |x| {
            x & 0xe000 == 0x2000 && x != 0x2001
        }) as u16;
        1
    } else {
        return ip;
    };
    for i in start..8 {
        let mut ctx = vec![b'6', i as u8];
        for g in &s[..i] {
            ctx.extend_from_slice(&g.to_be_bytes());
        }
        out[i] = key.perm(&ctx, u32::from(s[i]), 16, group) as u16;
    }
    Ipv6Addr::from(out)
}

/// A fake for a MAC address in any common notation, keeping the vendor
/// prefix, the notation and the letter case. None if `mac` is not a MAC.
pub fn fake_mac(key: &FakeKey, mac: &str) -> Option<String> {
    let hex: Vec<u8> = mac
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .map(|c| c.to_digit(16).unwrap_or(0) as u8)
        .collect();
    if hex.len() != 12 {
        return None;
    }
    let bytes: Vec<u8> = hex.chunks(2).map(|p| p[0] << 4 | p[1]).collect();
    // Broadcast, all-zero and multicast addresses are protocol constants.
    if bytes.iter().all(|b| *b == 0xff) || bytes.iter().all(|b| *b == 0) || bytes[0] & 1 == 1 {
        return Some(mac.to_string());
    }
    let mut ctx = vec![b'm'];
    ctx.extend_from_slice(&bytes[..3]);
    let nic = u32::from(bytes[3]) << 16 | u32::from(bytes[4]) << 8 | u32::from(bytes[5]);
    let n = key.perm(&ctx, nic, 24, |_| true);
    let new_hex = format!("{:02x}{:02x}{:02x}{:06x}", bytes[0], bytes[1], bytes[2], n);
    let upper = mac.chars().any(|c| c.is_ascii_uppercase());
    let mut digits = new_hex.chars();
    let out: String = mac
        .chars()
        .map(|c| {
            if c.is_ascii_hexdigit() {
                let d = digits.next().unwrap_or('0');
                if upper { d.to_ascii_uppercase() } else { d }
            } else {
                c
            }
        })
        .collect();
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn key(n: u8) -> FakeKey {
        FakeKey([n; 32])
    }

    fn v4(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    fn f4(k: &FakeKey, s: &str) -> Ipv4Addr {
        fake_v4(k, v4(s))
    }

    #[test]
    fn hex_round_trip_and_debug_hides_key() {
        let k = FakeKey::generate();
        assert_eq!(FakeKey::from_hex(&k.to_hex()), Some(k.clone()));
        assert!(FakeKey::from_hex("zz").is_none());
        assert!(FakeKey::from_hex(&"g".repeat(64)).is_none());
        assert_eq!(format!("{k:?}"), "FakeKey(..)");
        assert_ne!(FakeKey::generate(), FakeKey::generate());
    }

    #[test]
    fn v4_keeps_class_and_structure() {
        let k = key(1);
        let a = f4(&k, "10.20.30.5");
        let b = f4(&k, "10.20.30.9");
        let c = f4(&k, "10.20.31.9");
        assert_eq!(a.octets()[0], 10);
        assert_eq!(a.octets()[..3], b.octets()[..3]);
        assert_eq!(a.octets()[3], 5);
        assert_eq!(a.octets()[..2], c.octets()[..2]);
        assert_ne!(a.octets()[2], c.octets()[2]);
        // Network forms survive.
        let net = f4(&k, "10.20.0.0");
        assert_eq!(net.octets()[2..], [0, 0]);
        assert_eq!(f4(&k, "10.20.30.0").octets()[..3], a.octets()[..3]);
        let p = f4(&k, "172.20.1.1");
        assert!((16..=31).contains(&p.octets()[1]));
        assert_eq!(f4(&k, "192.168.7.1").octets()[..2], [192, 168]);
        assert_eq!(f4(&k, "100.70.1.1").octets()[0], 100);
        // Deterministic per key, different across keys.
        assert_eq!(a, f4(&key(1), "10.20.30.5"));
        assert_ne!(a, f4(&key(2), "10.20.30.5"));
    }

    #[test]
    fn v4_constants_and_documentation_kept() {
        let k = key(3);
        for s in [
            "127.0.0.1",
            "224.0.0.5",
            "255.255.255.255",
            "0.0.0.255",
            "192.0.2.7",
            "203.0.113.9",
        ] {
            assert_eq!(f4(&k, s), v4(s), "{s}");
        }
    }

    #[test]
    fn v4_public_stays_public() {
        let k = key(4);
        for a in 1..=223u8 {
            for b in [0u8, 1, 16, 64, 168, 200, 254] {
                let ip = Ipv4Addr::new(a, b, 9, 9);
                if keep_v4(ip)
                    || ip.is_private()
                    || ip.is_link_local()
                    || (a == 100 && (64..=127).contains(&b))
                {
                    continue;
                }
                let f = fake_v4(&k, ip);
                let [x, y, ..] = f.octets();
                let shared =
                    (x == 100 && (64..=127).contains(&y)) || x == 127 || x == 0 || x >= 224;
                assert!(
                    !f.is_private() && !f.is_link_local() && !shared,
                    "{ip} -> {f}"
                );
            }
        }
    }

    #[test]
    fn v4_is_one_to_one() {
        let k = key(5);
        let mut seen = HashSet::new();
        for b in 0..=255u8 {
            for c in 0..=255u8 {
                assert!(seen.insert(fake_v4(&k, Ipv4Addr::new(10, b, c, 1))));
            }
        }
        let mut seen = HashSet::new();
        for a in 1..=223u8 {
            assert!(seen.insert(fake_v4(&k, Ipv4Addr::new(a, 1, 1, 1))));
        }
    }

    #[test]
    fn v6_keeps_prefixes() {
        let k = key(6);
        let f = |s: &str| fake_v6(&k, s.parse().unwrap());
        let a = f("2600:1f18:aaaa:1::10");
        let b = f("2600:1f18:aaaa:1::11");
        assert_eq!(a.segments()[..4], b.segments()[..4]);
        assert_ne!(a, b);
        assert_eq!(a.segments()[0] & 0xe000, 0x2000);
        // Zero groups stay zero so the short form keeps its shape.
        assert_eq!(a.segments()[4..7], [0, 0, 0]);
        let ll = f("fe80::1c2b:3cff:fe4d:5e6f");
        assert_eq!(ll.segments()[..4], [0xfe80, 0, 0, 0]);
        assert_ne!(ll, "fe80::1c2b:3cff:fe4d:5e6f".parse::<Ipv6Addr>().unwrap());
        assert_eq!(f("fd12:3456:789a::1").segments()[0] >> 8, 0xfd);
        for s in ["ff02::1", "2001:db8::1", "::1"] {
            assert_eq!(f(s), s.parse::<Ipv6Addr>().unwrap());
        }
        assert_eq!(
            f("::ffff:10.1.2.3").to_ipv4_mapped().unwrap().octets()[0],
            10
        );
    }

    #[test]
    fn mac_keeps_vendor_and_notation() {
        let k = key(7);
        let m = fake_mac(&k, "00:09:0F:12:34:56").unwrap();
        assert!(m.starts_with("00:09:0F:"), "{m}");
        assert_ne!(m, "00:09:0F:12:34:56");
        assert_eq!(m, m.to_uppercase());
        let c = fake_mac(&k, "0009.0f12.3456").unwrap();
        assert!(c.starts_with("0009.0f") && c.len() == 14, "{c}");
        assert_eq!(c.replace('.', ""), m.replace(':', "").to_lowercase());
        assert_eq!(
            fake_mac(&k, "ff:ff:ff:ff:ff:ff").unwrap(),
            "ff:ff:ff:ff:ff:ff"
        );
        assert_eq!(
            fake_mac(&k, "01:00:5e:00:00:05").unwrap(),
            "01:00:5e:00:00:05"
        );
        assert!(fake_mac(&k, "00:11:22").is_none());
    }
}
