//! MTU, MSS and tunnel overhead. Layers are applied from the outside in to
//! the link's IP MTU; what is left is the inner IP MTU. ESP padding is
//! computed exactly for the largest inner packet, and shown as a range
//! because it varies with packet size. Pure arithmetic, no network.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum IpVer {
    #[default]
    V4,
    V6,
}

impl IpVer {
    fn header(self) -> u32 {
        match self {
            IpVer::V4 => 20,
            IpVer::V6 => 40,
        }
    }
    fn name(self) -> &'static str {
        match self {
            IpVer::V4 => "IPv4",
            IpVer::V6 => "IPv6",
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum Cipher {
    AesCbc,
    AesGcm,
    ChaCha20Poly1305,
    /// 3DES/DES-CBC: 8-byte blocks and IV.
    DesCbc,
    Null,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum Integrity {
    /// HMAC-SHA1-96 (12 bytes) and HMAC-MD5-96.
    Sha1,
    Sha256,
    Sha384,
    Sha512,
    /// AEAD ciphers carry their own 16-byte tag.
    None,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(
    tag = "type",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum Layer {
    Pppoe,
    Dot1q {
        tags: u8,
    },
    Mpls {
        labels: u8,
    },
    Gre {
        outer: IpVer,
        key: bool,
        seq: bool,
        checksum: bool,
    },
    IpInIp {
        outer: IpVer,
    },
    Vxlan {
        outer: IpVer,
        inner_vlan: bool,
    },
    WireGuard {
        outer: IpVer,
    },
    Esp {
        outer: IpVer,
        tunnel: bool,
        cipher: Cipher,
        integrity: Integrity,
        nat_t: bool,
    },
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Row {
    pub layer: String,
    pub part: String,
    /// Bytes as text: "20", or "2 to 17" for variable padding.
    pub bytes: String,
}

#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Result {
    pub link_mtu: u32,
    pub inner_mtu: i64,
    pub mss_v4: i64,
    pub mss_v6: i64,
    /// Fixed overhead plus padding for a maximum-size inner packet.
    pub overhead: i64,
    pub rows: Vec<Row>,
    pub notes: Vec<String>,
    pub errors: Vec<String>,
}

fn esp_params(
    cipher: Cipher,
    integ: Integrity,
) -> std::result::Result<(u32, u32, u32, &'static str), String> {
    // (IV bytes, padding alignment, ICV bytes, description)
    let aead = matches!(cipher, Cipher::AesGcm | Cipher::ChaCha20Poly1305);
    if aead && integ != Integrity::None {
        return Err("AES-GCM and ChaCha20-Poly1305 include their own integrity tag; choose no separate integrity".into());
    }
    if !aead && integ == Integrity::None && cipher != Cipher::Null {
        return Err("a CBC cipher needs an integrity algorithm (ESP without integrity is not recommended and rarely allowed)".into());
    }
    let icv = match integ {
        Integrity::Sha1 => 12,
        Integrity::Sha256 => 16,
        Integrity::Sha384 => 24,
        Integrity::Sha512 => 32,
        Integrity::None => {
            if aead {
                16
            } else {
                0
            }
        }
    };
    Ok(match cipher {
        Cipher::AesCbc => (16, 16, icv, "AES-CBC"),
        Cipher::DesCbc => (8, 8, icv, "3DES/DES-CBC"),
        Cipher::AesGcm => (8, 4, icv, "AES-GCM"),
        Cipher::ChaCha20Poly1305 => (8, 4, icv, "ChaCha20-Poly1305"),
        Cipher::Null => (0, 4, icv, "NULL encryption"),
    })
}

fn row(layer: &str, part: &str, bytes: impl ToString) -> Row {
    Row {
        layer: layer.into(),
        part: part.into(),
        bytes: bytes.to_string(),
    }
}

/// Outer IP header of a tunnel layer, if it has one.
fn outer_ip(l: &Layer) -> Option<IpVer> {
    match l {
        Layer::Gre { outer, .. }
        | Layer::IpInIp { outer }
        | Layer::Vxlan { outer, .. }
        | Layer::WireGuard { outer } => Some(*outer),
        Layer::Esp {
            outer,
            tunnel: true,
            ..
        } => Some(*outer),
        _ => None,
    }
}

pub fn calculate(link_mtu: u32, layers: &[Layer]) -> Result {
    let mut r = Result {
        link_mtu,
        ..Default::default()
    };
    if !(68..=65_535).contains(&link_mtu) {
        r.errors.push("link MTU must be 68 to 65535".into());
        return r;
    }
    if layers.len() > 12 {
        r.errors.push("at most 12 layers".into());
        return r;
    }
    let mut rem = link_mtu as i64;
    // Set when transport-mode ESP already counted the next layer's IP header.
    let mut skip_outer_ip = false;
    let mut link_layer_seen_tunnel = false;
    for (i, l) in layers.iter().enumerate() {
        let n = i + 1;
        let tag = |s: &str| format!("{n}. {s}");
        if let Some(v) = outer_ip(l) {
            link_layer_seen_tunnel = true;
            if !skip_outer_ip {
                let name = match l {
                    Layer::Esp { .. } => "ESP tunnel",
                    Layer::Gre { .. } => "GRE",
                    Layer::IpInIp { .. } => "IP-in-IP",
                    Layer::Vxlan { .. } => "VXLAN",
                    Layer::WireGuard { .. } => "WireGuard",
                    _ => "",
                };
                rem -= v.header() as i64;
                r.rows.push(row(
                    &tag(name),
                    &format!("outer {} header", v.name()),
                    v.header(),
                ));
            }
        }
        skip_outer_ip = false;
        match l {
            Layer::Pppoe => {
                if link_layer_seen_tunnel {
                    r.notes
                        .push("PPPoE is a link-layer header; put it before any tunnel".into());
                }
                rem -= 8;
                r.rows.push(row(&tag("PPPoE"), "PPPoE 6 + PPP 2", 8));
            }
            Layer::Dot1q { tags } => {
                let t = (*tags).clamp(1, 2) as u32;
                r.rows.push(row(
                    &tag("802.1Q"),
                    &format!("{t} tag(s), carried in the frame"),
                    0,
                ));
                r.notes.push(format!("802.1Q adds {} bytes to the Ethernet frame, not the IP packet; it only lowers the IP MTU on links that cannot carry larger frames", 4 * t));
            }
            Layer::Mpls { labels } => {
                let b = 4 * (*labels).clamp(1, 8) as i64;
                rem -= b;
                r.rows.push(row(
                    &tag("MPLS"),
                    &format!("{} label(s)", (*labels).clamp(1, 8)),
                    b,
                ));
            }
            Layer::Gre {
                key, seq, checksum, ..
            } => {
                rem -= 4;
                r.rows.push(row(&tag("GRE"), "GRE base header", 4));
                for (on, what) in [
                    (*checksum, "checksum"),
                    (*key, "key"),
                    (*seq, "sequence number"),
                ] {
                    if on {
                        rem -= 4;
                        r.rows.push(row(&tag("GRE"), &format!("GRE {what}"), 4));
                    }
                }
            }
            Layer::IpInIp { .. } => {}
            Layer::Vxlan { inner_vlan, .. } => {
                rem -= 8 + 8 + 14;
                r.rows.push(row(&tag("VXLAN"), "UDP header", 8));
                r.rows.push(row(&tag("VXLAN"), "VXLAN header", 8));
                r.rows.push(row(&tag("VXLAN"), "inner Ethernet header", 14));
                if *inner_vlan {
                    rem -= 4;
                    r.rows.push(row(&tag("VXLAN"), "inner 802.1Q tag", 4));
                }
            }
            Layer::WireGuard { .. } => {
                rem -= 8 + 16 + 16;
                r.rows.push(row(&tag("WireGuard"), "UDP header", 8));
                r.rows.push(row(
                    &tag("WireGuard"),
                    "message header (type, receiver, counter)",
                    16,
                ));
                r.rows.push(row(&tag("WireGuard"), "Poly1305 tag", 16));
                r.notes.push("WireGuard pads inner packets to 16 bytes only when the MTU allows; the usual 1420 assumes an IPv6 outer header".into());
            }
            Layer::Esp {
                tunnel,
                cipher,
                integrity,
                nat_t,
                ..
            } => {
                let (iv, align, icv, cname) = match esp_params(*cipher, *integrity) {
                    Ok(p) => p,
                    Err(e) => {
                        r.errors.push(format!("layer {n}: {e}"));
                        return r;
                    }
                };
                if !*tunnel {
                    // Transport mode sits between the next layer's IP header
                    // and its payload: that header stays outside ESP.
                    match layers.get(i + 1).and_then(outer_ip) {
                        Some(v) => {
                            rem -= v.header() as i64;
                            r.rows.push(row(
                                &tag("ESP transport"),
                                &format!(
                                    "{} header of the protected packet (layer {})",
                                    v.name(),
                                    n + 1
                                ),
                                v.header(),
                            ));
                            skip_outer_ip = true;
                        }
                        None => {
                            r.errors.push(format!("layer {n}: ESP transport mode protects a tunnel's packet (for example GRE); add the GRE or IP-in-IP layer after it, or use tunnel mode"));
                            return r;
                        }
                    }
                }
                let label = if *tunnel {
                    "ESP tunnel"
                } else {
                    "ESP transport"
                };
                if *nat_t {
                    rem -= 8;
                    r.rows.push(row(&tag(label), "NAT-T UDP header", 8));
                }
                rem -= 8 + iv as i64 + icv as i64;
                r.rows
                    .push(row(&tag(label), "ESP header (SPI, sequence)", 8));
                if iv > 0 {
                    r.rows.push(row(&tag(label), &format!("{cname} IV"), iv));
                }
                // Payload + 2-byte trailer must fill whole alignment units.
                let units = rem.div_euclid(align as i64) * align as i64;
                let payload = units - 2;
                let pad_full = rem - payload; // padding + trailer at max size, plus unusable remainder
                r.rows.push(row(
                    &tag(label),
                    &format!(
                        "padding and trailer (pad length, next header); {} alignment",
                        align
                    ),
                    format!("2 to {}", align + 1),
                ));
                r.rows.push(row(&tag(label), "integrity check value", icv));
                r.notes.push(format!("ESP padding varies with packet size (0 to {} bytes plus a 2-byte trailer); the inner MTU uses the largest packet that fits, which costs {} bytes here", align - 1, pad_full));
                rem = payload;
            }
        }
        if rem < 68 {
            r.errors.push(format!(
                "after layer {n} only {rem} bytes remain; that is below the 68-byte IPv4 minimum"
            ));
            return r;
        }
    }
    r.inner_mtu = rem;
    r.mss_v4 = rem - 40;
    r.mss_v6 = rem - 60;
    r.overhead = link_mtu as i64 - rem;
    if rem < 1280 {
        r.notes.push("The inner MTU is below 1280, the IPv6 minimum; IPv6 cannot run over this path without fragmentation".into());
    }
    r.notes.push("Assumes no IP options or IPv6 extension headers and TCP without options; TCP timestamps use 12 of the MSS bytes in practice".into());
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    fn esp(tunnel: bool, cipher: Cipher, integrity: Integrity, nat_t: bool) -> Layer {
        Layer::Esp {
            outer: IpVer::V4,
            tunnel,
            cipher,
            integrity,
            nat_t,
        }
    }

    #[test]
    fn simple_tunnels() {
        let r = calculate(
            1500,
            &[Layer::Gre {
                outer: IpVer::V4,
                key: false,
                seq: false,
                checksum: false,
            }],
        );
        assert_eq!((r.inner_mtu, r.mss_v4), (1476, 1436));
        let r = calculate(
            1500,
            &[Layer::Gre {
                outer: IpVer::V4,
                key: true,
                seq: false,
                checksum: false,
            }],
        );
        assert_eq!(r.inner_mtu, 1472);
        let r = calculate(
            1500,
            &[Layer::Vxlan {
                outer: IpVer::V4,
                inner_vlan: false,
            }],
        );
        assert_eq!(r.inner_mtu, 1450);
        let r = calculate(1500, &[Layer::Pppoe]);
        assert_eq!((r.inner_mtu, r.mss_v4), (1492, 1452));
        assert_eq!(
            calculate(1500, &[Layer::WireGuard { outer: IpVer::V6 }]).inner_mtu,
            1420
        );
        assert_eq!(
            calculate(1500, &[Layer::WireGuard { outer: IpVer::V4 }]).inner_mtu,
            1440
        );
        assert_eq!(
            calculate(1500, &[Layer::IpInIp { outer: IpVer::V4 }]).inner_mtu,
            1480
        );
        assert_eq!(
            calculate(1500, &[Layer::Mpls { labels: 2 }]).inner_mtu,
            1492
        );
        let r = calculate(1500, &[Layer::Dot1q { tags: 1 }]);
        assert_eq!(r.inner_mtu, 1500);
    }

    #[test]
    fn ipsec_exact() {
        // Widely cited: AES-CBC + SHA1 tunnel over 1500 carries 1438.
        assert_eq!(
            calculate(1500, &[esp(true, Cipher::AesCbc, Integrity::Sha1, false)]).inner_mtu,
            1438
        );
        assert_eq!(
            calculate(1500, &[esp(true, Cipher::AesCbc, Integrity::Sha1, true)]).inner_mtu,
            1422
        );
        assert_eq!(
            calculate(1500, &[esp(true, Cipher::AesCbc, Integrity::Sha256, false)]).inner_mtu,
            1438
        );
        assert_eq!(
            calculate(1500, &[esp(true, Cipher::AesGcm, Integrity::None, false)]).inner_mtu,
            1446
        );
        // GRE over IPsec transport: GRE delivery header outside ESP.
        let r = calculate(
            1500,
            &[
                esp(false, Cipher::AesCbc, Integrity::Sha1, false),
                Layer::Gre {
                    outer: IpVer::V4,
                    key: false,
                    seq: false,
                    checksum: false,
                },
            ],
        );
        assert_eq!(r.inner_mtu, 1434);
        assert!(r.errors.is_empty());
        // PPPoE then an IPsec tunnel.
        assert_eq!(
            calculate(
                1500,
                &[
                    Layer::Pppoe,
                    esp(true, Cipher::AesCbc, Integrity::Sha1, false)
                ]
            )
            .inner_mtu,
            1422
        );
    }

    #[test]
    fn invalid_combinations() {
        assert!(
            !calculate(1500, &[esp(true, Cipher::AesGcm, Integrity::Sha1, false)])
                .errors
                .is_empty()
        );
        assert!(
            !calculate(1500, &[esp(true, Cipher::AesCbc, Integrity::None, false)])
                .errors
                .is_empty()
        );
        assert!(
            !calculate(1500, &[esp(false, Cipher::AesCbc, Integrity::Sha1, false)])
                .errors
                .is_empty()
        );
        assert!(!calculate(40, &[]).errors.is_empty());
        let deep: Vec<Layer> = (0..13).map(|_| Layer::Pppoe).collect();
        assert!(!calculate(9000, &deep).errors.is_empty());
        let tiny = calculate(
            100,
            &[Layer::Vxlan {
                outer: IpVer::V6,
                inner_vlan: true,
            }],
        );
        assert!(tiny.errors[0].contains("68-byte"));
        assert!(
            calculate(1300, &[esp(true, Cipher::AesCbc, Integrity::Sha1, true)])
                .notes
                .iter()
                .any(|n| n.contains("1280"))
        );
    }

    #[test]
    fn breakdown_rows() {
        let r = calculate(1500, &[esp(true, Cipher::AesCbc, Integrity::Sha1, true)]);
        let parts: Vec<&str> = r.rows.iter().map(|x| x.part.as_str()).collect();
        assert_eq!(parts[0], "outer IPv4 header");
        assert!(parts.contains(&"NAT-T UDP header"));
        assert!(r.rows.iter().any(|x| x.bytes == "2 to 17"));
        assert_eq!(r.overhead, 78);
    }
}
