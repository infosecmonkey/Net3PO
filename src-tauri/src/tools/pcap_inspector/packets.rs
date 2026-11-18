//! Streaming PCAP/PCAPNG reader shared by the inspector, the sanitizer and
//! the extractor. One pass, bounded block size, timestamps normalized to
//! nanoseconds, damaged or truncated files reported as warnings.

use std::io::Read;

use pcap_parser::{PcapBlockOwned, PcapError, create_reader, pcapng::Block};

/// Largest single block accepted (a frame larger than this is malformed).
const MAX_BLOCK: usize = 16 * 1024 * 1024;
/// Most warnings kept.
const MAX_WARNINGS: usize = 20;

/// One packet as read from the capture.
pub struct Packet<'a> {
    pub link: i32,
    /// Nanoseconds since the Unix epoch; 0 when the format has none.
    pub ts_ns: i64,
    /// Length on the wire.
    pub orig: u32,
    pub data: &'a [u8],
    /// Where `data` starts in the stream.
    pub offset: u64,
}

/// What the reader learned about the file.
#[derive(Debug, Default)]
pub struct ReadInfo {
    pub format: String,
    pub warnings: Vec<String>,
    pub cancelled: bool,
    pub packets: u64,
}

struct Iface {
    link: i32,
    /// Timestamp units per second.
    resolution: u64,
    offset_s: i64,
}

fn ns(units: u128, resolution: u64, offset_s: i64) -> i64 {
    let r = resolution.max(1) as u128;
    let n = units / r * 1_000_000_000 + (units % r) * 1_000_000_000 / r;
    (n as i64).saturating_add(offset_s.saturating_mul(1_000_000_000))
}

fn warn(info: &mut ReadInfo, w: String) {
    if info.warnings.len() < MAX_WARNINGS {
        info.warnings.push(w);
    }
}

/// Read every packet. `on_packet` returns false to stop early;
/// `progress(bytes_read)` is called every 5000 packets and returns false to
/// cancel.
pub fn each_packet<R: Read + Send>(
    input: R,
    mut on_packet: impl FnMut(Packet<'_>) -> bool,
    mut progress: impl FnMut(u64) -> bool,
) -> Result<ReadInfo, String> {
    let mut reader = create_reader(1 << 20, input).map_err(|e| match e {
        PcapError::HeaderNotRecognized => "not a PCAP or PCAPNG file".to_string(),
        other => format!("could not read the capture: {other:?}"),
    })?;
    let mut info = ReadInfo {
        format: "PCAP".into(),
        ..Default::default()
    };
    let mut ifaces: Vec<Iface> = Vec::new();
    let mut legacy_link: i32 = 1;
    let mut legacy_ns = false;
    let mut base: u64 = 0;

    loop {
        match reader.next() {
            Ok((len, block)) => {
                let block_start = base;
                let pkt = match &block {
                    PcapBlockOwned::LegacyHeader(h) => {
                        legacy_link = h.network.0;
                        legacy_ns = h.is_nanosecond_precision();
                        None
                    }
                    PcapBlockOwned::Legacy(b) => {
                        let frac = b.ts_usec as i64;
                        let ts = b.ts_sec as i64 * 1_000_000_000
                            + if legacy_ns { frac } else { frac * 1000 };
                        Some(Packet {
                            link: legacy_link,
                            ts_ns: ts,
                            orig: b.origlen,
                            data: b.data,
                            offset: block_start + 16,
                        })
                    }
                    PcapBlockOwned::NG(Block::SectionHeader(_)) => {
                        info.format = "PCAPNG".into();
                        ifaces.clear();
                        None
                    }
                    PcapBlockOwned::NG(Block::InterfaceDescription(idb)) => {
                        ifaces.push(Iface {
                            link: idb.linktype.0,
                            resolution: idb.ts_resolution().unwrap_or(1_000_000),
                            offset_s: idb.if_tsoffset,
                        });
                        None
                    }
                    PcapBlockOwned::NG(Block::EnhancedPacket(epb)) => {
                        match ifaces.get(epb.if_id as usize) {
                            Some(i) => {
                                let units = ((epb.ts_high as u128) << 32) | epb.ts_low as u128;
                                Some(Packet {
                                    link: i.link,
                                    ts_ns: ns(units, i.resolution, i.offset_s),
                                    orig: epb.origlen,
                                    // `data` includes the block's padding.
                                    data: &epb.data[..(epb.caplen as usize).min(epb.data.len())],
                                    offset: block_start + 28,
                                })
                            }
                            None => {
                                warn(
                                    &mut info,
                                    format!("packet refers to unknown interface {}", epb.if_id),
                                );
                                None
                            }
                        }
                    }
                    PcapBlockOwned::NG(Block::SimplePacket(spb)) => {
                        ifaces.first().map(|i| Packet {
                            link: i.link,
                            ts_ns: 0,
                            orig: spb.origlen,
                            data: &spb.data[..(spb.origlen as usize).min(spb.data.len())],
                            offset: block_start + 12,
                        })
                    }
                    _ => None,
                };
                let mut stop = false;
                if let Some(p) = pkt {
                    info.packets += 1;
                    stop = !on_packet(p);
                }
                reader.consume(len);
                base += len as u64;
                if stop {
                    break;
                }
                if info.packets > 0 && info.packets.is_multiple_of(5000) && !progress(base) {
                    info.cancelled = true;
                    break;
                }
            }
            Err(PcapError::Eof) => break,
            Err(PcapError::Incomplete(_)) => {
                if let Err(e) = reader.refill() {
                    match e {
                        PcapError::Eof | PcapError::UnexpectedEof => {
                            warn(&mut info, "the file ends in the middle of a packet; the last record is incomplete".into());
                        }
                        other => warn(&mut info, format!("read stopped: {other:?}")),
                    }
                    break;
                }
            }
            Err(PcapError::BufferTooSmall) => {
                let cur = reader.data().len().max(1 << 20);
                if cur * 2 > MAX_BLOCK || !reader.grow(cur * 2) {
                    warn(&mut info, "a record larger than 16 MB was found; the file is damaged or not a capture. Stopped there.".into());
                    break;
                }
            }
            Err(PcapError::UnexpectedEof) => {
                warn(
                    &mut info,
                    "the file ends in the middle of a packet; the last record is incomplete".into(),
                );
                break;
            }
            Err(e) => {
                let n = info.packets;
                warn(
                    &mut info,
                    format!("damaged data after packet {n}: {e:?}. Stopped there."),
                );
                break;
            }
        }
    }
    Ok(info)
}
