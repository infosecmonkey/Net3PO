//! Pure traceroute logic: ICMP echo building and reply parsing (bounded,
//! hostile-input safe), per-hop statistics, path analysis, and the Path MTU
//! search. No sockets here; the OS probe backends are in `probe.rs`.

use std::collections::VecDeque;
use std::net::Ipv4Addr;

use serde::Serialize;

// The raw ICMP wire helpers below drive the macOS and Linux probes. Windows
// probes through IcmpSendEcho2, so there they are only used by tests.

#[cfg_attr(windows, allow(dead_code))]
pub const ECHO_REPLY: u8 = 0;
#[cfg_attr(windows, allow(dead_code))]
pub const DEST_UNREACHABLE: u8 = 3;
#[cfg_attr(windows, allow(dead_code))]
pub const ECHO_REQUEST: u8 = 8;
#[cfg_attr(windows, allow(dead_code))]
pub const TIME_EXCEEDED: u8 = 11;
/// Destination unreachable code: fragmentation needed and DF set.
#[cfg_attr(windows, allow(dead_code))]
pub const CODE_FRAG_NEEDED: u8 = 4;

/// IPv4 + ICMP header bytes added to an echo payload.
pub const IP_ICMP_OVERHEAD: u16 = 28;
/// RTT samples kept per hop for the per-hop charts.
pub const HISTORY_LEN: usize = 300;
/// Distinct responders tracked per hop (ECMP rarely exceeds a handful).
const MAX_RESPONDERS: usize = 16;

/// Internet checksum (RFC 1071).
#[cfg_attr(windows, allow(dead_code))]
pub fn checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    for chunk in data.chunks(2) {
        let word = u16::from_be_bytes([chunk[0], *chunk.get(1).unwrap_or(&0)]);
        sum = sum.wrapping_add(u32::from(word));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Build an ICMP echo request with `payload_len` bytes of payload.
#[cfg_attr(windows, allow(dead_code))]
pub fn build_echo(ident: u16, seq: u16, payload_len: usize) -> Vec<u8> {
    const PATTERN: &[u8] = b"Net3PO ";
    let mut p = Vec::with_capacity(8 + payload_len);
    p.extend_from_slice(&[ECHO_REQUEST, 0, 0, 0]);
    p.extend_from_slice(&ident.to_be_bytes());
    p.extend_from_slice(&seq.to_be_bytes());
    p.extend(PATTERN.iter().cycle().take(payload_len));
    let sum = checksum(&p);
    p[2..4].copy_from_slice(&sum.to_be_bytes());
    p
}

/// Skip an IPv4 header using its IHL field. The total-length field is never
/// used: BSD-derived stacks deliver it in host byte order.
#[cfg_attr(windows, allow(dead_code))]
pub fn strip_ipv4_header(buf: &[u8]) -> Option<&[u8]> {
    let first = *buf.first()?;
    if first >> 4 != 4 {
        return None;
    }
    let ihl = usize::from(first & 0x0f) * 4;
    if ihl < 20 || buf.len() < ihl {
        return None;
    }
    Some(&buf[ihl..])
}

/// What an ICMP message says about one of our probes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(windows, allow(dead_code))]
pub enum ReplyKind {
    EchoReply,
    TimeExceeded,
    /// Destination unreachable other than frag-needed.
    Unreachable(u8),
    /// Frag needed; carries the next-hop MTU when the router supplied one.
    FragNeeded(Option<u16>),
}

/// A parsed ICMP message, with the echo ident/seq it refers to (the quoted
/// original probe for error messages).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(windows, allow(dead_code))]
pub struct IcmpReply {
    pub kind: ReplyKind,
    pub ident: u16,
    pub seq: u16,
}

/// Parse an ICMP message that starts at the ICMP header (no IP header).
/// Error messages are matched through the quoted original echo request.
#[cfg_attr(windows, allow(dead_code))]
pub fn parse_icmp(buf: &[u8]) -> Option<IcmpReply> {
    if buf.len() < 8 {
        return None;
    }
    let (ty, code) = (buf[0], buf[1]);
    let be16 = |b: &[u8], at: usize| u16::from_be_bytes([b[at], b[at + 1]]);
    match ty {
        ECHO_REPLY => Some(IcmpReply {
            kind: ReplyKind::EchoReply,
            ident: be16(buf, 4),
            seq: be16(buf, 6),
        }),
        TIME_EXCEEDED | DEST_UNREACHABLE => {
            let inner_ip = &buf[8..];
            let inner = strip_ipv4_header(inner_ip)?;
            // Protocol field of the quoted header must be ICMP, and the quoted
            // message must be an echo request.
            if inner_ip.get(9) != Some(&1) || inner.len() < 8 || inner[0] != ECHO_REQUEST {
                return None;
            }
            let kind = match (ty, code) {
                (TIME_EXCEEDED, _) => ReplyKind::TimeExceeded,
                (_, CODE_FRAG_NEEDED) => {
                    let mtu = be16(buf, 6);
                    ReplyKind::FragNeeded((mtu >= 68).then_some(mtu))
                }
                (_, c) => ReplyKind::Unreachable(c),
            };
            Some(IcmpReply {
                kind,
                ident: be16(inner, 4),
                seq: be16(inner, 6),
            })
        }
        _ => None,
    }
}

/// Result of one TTL-limited probe.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Outcome {
    /// A router answered with Time Exceeded.
    Hop,
    /// The destination answered (echo reply, or port unreachable for UDP).
    Reached,
    /// A router or the destination reported unreachable (code).
    Unreachable(u8),
    /// Frag needed (MTU probing), with the reported next-hop MTU.
    TooBig(Option<u16>),
    Timeout,
}

/// One probe's result as produced by a probe backend.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ProbeResult {
    pub ttl: u8,
    pub responder: Option<Ipv4Addr>,
    pub outcome: Outcome,
    pub rtt_ms: Option<f64>,
}

/// A router seen answering at a hop.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Responder {
    pub ip: Ipv4Addr,
    pub count: u32,
    pub hostname: Option<String>,
}

/// Running statistics for one hop.
#[derive(Debug, Clone, Default)]
pub struct HopStats {
    pub ttl: u8,
    sent: u32,
    received: u32,
    last: Option<f64>,
    best: Option<f64>,
    worst: Option<f64>,
    mean: f64,
    m2: f64,
    jitter_sum: f64,
    jitter_n: u32,
    prev: Option<f64>,
    responders: Vec<Responder>,
    history: VecDeque<Option<f64>>,
    unreachable: Option<u8>,
}

/// Serializable view of a hop for the UI.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct HopView {
    pub ttl: u8,
    pub sent: u32,
    pub received: u32,
    pub loss_pct: f64,
    pub last_ms: Option<f64>,
    pub avg_ms: Option<f64>,
    pub best_ms: Option<f64>,
    pub worst_ms: Option<f64>,
    pub stdev_ms: Option<f64>,
    pub jitter_ms: Option<f64>,
    /// Most frequent responder, if any.
    pub ip: Option<Ipv4Addr>,
    pub hostname: Option<String>,
    pub responders: Vec<Responder>,
    /// RTT per cycle, oldest first; None is a lost probe.
    pub history: Vec<Option<f64>>,
    /// ICMP unreachable code last reported at this hop.
    pub unreachable: Option<u8>,
}

impl HopStats {
    pub fn new(ttl: u8) -> Self {
        HopStats {
            ttl,
            ..Default::default()
        }
    }

    /// Fold one probe result into the stats.
    pub fn record(&mut self, r: &ProbeResult) {
        self.sent += 1;
        let rtt = match r.outcome {
            Outcome::Timeout | Outcome::TooBig(_) => None,
            _ => r.rtt_ms,
        };
        if let Outcome::Unreachable(code) = r.outcome {
            self.unreachable = Some(code);
        }
        if let (Some(ip), Some(_)) = (r.responder, rtt) {
            if let Some(x) = self.responders.iter_mut().find(|x| x.ip == ip) {
                x.count += 1;
            } else if self.responders.len() < MAX_RESPONDERS {
                self.responders.push(Responder {
                    ip,
                    count: 1,
                    hostname: None,
                });
            }
        }
        if let Some(v) = rtt {
            self.received += 1;
            self.last = Some(v);
            self.best = Some(self.best.map_or(v, |b| b.min(v)));
            self.worst = Some(self.worst.map_or(v, |w| w.max(v)));
            // Welford's running mean and variance.
            let n = f64::from(self.received);
            let delta = v - self.mean;
            self.mean += delta / n;
            self.m2 += delta * (v - self.mean);
            if let Some(p) = self.prev {
                self.jitter_sum += (v - p).abs();
                self.jitter_n += 1;
            }
            self.prev = Some(v);
        }
        if self.history.len() == HISTORY_LEN {
            self.history.pop_front();
        }
        self.history.push_back(rtt);
    }

    /// Attach a reverse-DNS name to a responder.
    pub fn set_hostname(&mut self, ip: Ipv4Addr, name: String) {
        if let Some(r) = self.responders.iter_mut().find(|r| r.ip == ip) {
            r.hostname = Some(name);
        }
    }

    pub fn responder_ips(&self) -> impl Iterator<Item = Ipv4Addr> + '_ {
        self.responders.iter().map(|r| r.ip)
    }

    pub fn view(&self) -> HopView {
        let primary = self.responders.iter().max_by_key(|r| r.count);
        let has = self.received > 0;
        HopView {
            ttl: self.ttl,
            sent: self.sent,
            received: self.received,
            loss_pct: if self.sent == 0 {
                0.0
            } else {
                f64::from(self.sent - self.received) * 100.0 / f64::from(self.sent)
            },
            last_ms: self.last,
            avg_ms: has.then_some(self.mean),
            best_ms: self.best,
            worst_ms: self.worst,
            stdev_ms: (self.received > 1).then(|| (self.m2 / f64::from(self.received - 1)).sqrt()),
            jitter_ms: (self.jitter_n > 0).then(|| self.jitter_sum / f64::from(self.jitter_n)),
            ip: primary.map(|r| r.ip),
            hostname: primary.and_then(|r| r.hostname.clone()),
            responders: self.responders.clone(),
            history: self.history.iter().copied().collect(),
            unreachable: self.unreachable,
        }
    }
}

/// Loss at or above this is treated as real loss in path analysis.
const LOSS_THRESHOLD_PCT: f64 = 5.0;
/// A latency step at least this large (ms) and this fraction of the
/// destination latency is reported.
const JUMP_MIN_MS: f64 = 20.0;
const JUMP_MIN_FRACTION: f64 = 0.25;
/// Samples needed before loss is judged.
const MIN_SAMPLES: u32 = 5;

/// One finding from path analysis.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    /// "loss", "latency", "rateLimit", "unreachable", or "noReply".
    pub kind: String,
    pub ttl: Option<u8>,
    pub message: String,
}

/// Whole-path summary.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PathSummary {
    pub cycles: u32,
    pub hops: usize,
    pub reached: bool,
    pub dest_avg_ms: Option<f64>,
    pub dest_loss_pct: Option<f64>,
    pub findings: Vec<Finding>,
}

/// All hops of a trace.
#[derive(Debug, Clone)]
pub struct PathTracker {
    max_hops: u8,
    hops: Vec<HopStats>,
    dest_ttl: Option<u8>,
    cycles: u32,
}

impl PathTracker {
    pub fn new(max_hops: u8) -> Self {
        let max_hops = max_hops.clamp(1, 64);
        PathTracker {
            max_hops,
            hops: (1..=max_hops).map(HopStats::new).collect(),
            dest_ttl: None,
            cycles: 0,
        }
    }

    /// TTLs to probe this cycle: up to the destination once it is known.
    pub fn ttls(&self) -> std::ops::RangeInclusive<u8> {
        1..=self.dest_ttl.unwrap_or(self.max_hops)
    }

    /// Fold in one cycle of results. The lowest TTL that reached the
    /// destination fixes the path length; deeper hops are dropped.
    pub fn record_cycle(&mut self, results: &[ProbeResult]) {
        self.cycles += 1;
        if let Some(t) = results
            .iter()
            .filter(|r| r.outcome == Outcome::Reached)
            .map(|r| r.ttl)
            .min()
        {
            self.dest_ttl = Some(self.dest_ttl.map_or(t, |d| d.min(t)));
        }
        let limit = self.dest_ttl.unwrap_or(self.max_hops);
        for r in results.iter().filter(|r| r.ttl >= 1 && r.ttl <= limit) {
            self.hops[usize::from(r.ttl) - 1].record(r);
        }
    }

    pub fn hop_mut(&mut self, ttl: u8) -> Option<&mut HopStats> {
        self.hops.get_mut(usize::from(ttl).checked_sub(1)?)
    }

    /// Hops in the path so far.
    pub fn active(&self) -> &[HopStats] {
        let n = usize::from(self.dest_ttl.unwrap_or(self.last_answering().unwrap_or(1)));
        &self.hops[..n.min(self.hops.len())]
    }

    fn last_answering(&self) -> Option<u8> {
        self.hops
            .iter()
            .rev()
            .find(|h| h.received > 0)
            .map(|h| h.ttl)
    }

    pub fn views(&self) -> Vec<HopView> {
        self.active().iter().map(HopStats::view).collect()
    }

    pub fn summary(&self) -> PathSummary {
        let views = self.views();
        let dest = self.dest_ttl.and_then(|t| views.get(usize::from(t) - 1));
        PathSummary {
            cycles: self.cycles,
            hops: views.len(),
            reached: self.dest_ttl.is_some(),
            dest_avg_ms: dest.and_then(|d| d.avg_ms),
            dest_loss_pct: dest.map(|d| d.loss_pct),
            findings: analyze(&views, self.dest_ttl.is_some()),
        }
    }
}

/// Find where trouble starts. Loss or latency only counts when it carries
/// through to the destination; loss at a middle hop that clears later is a
/// router rate-limiting its ICMP replies, not forwarding loss.
pub fn analyze(hops: &[HopView], reached: bool) -> Vec<Finding> {
    let mut out = Vec::new();
    let judged = |h: &HopView| h.sent >= MIN_SAMPLES;

    if let Some(dest) = hops.last().filter(|_| reached) {
        // Loss onset: the first hop from which every later answering hop
        // (including the destination) keeps losing.
        if judged(dest) && dest.loss_pct >= LOSS_THRESHOLD_PCT {
            let onset = hops
                .iter()
                .enumerate()
                .filter(|(_, h)| judged(h) && h.received > 0)
                .find(|(i, h)| {
                    h.loss_pct >= LOSS_THRESHOLD_PCT
                        && hops[*i..]
                            .iter()
                            .filter(|x| x.received > 0)
                            .all(|x| x.loss_pct >= LOSS_THRESHOLD_PCT)
                })
                .map(|(_, h)| h.ttl);
            out.push(Finding {
                kind: "loss".into(),
                ttl: onset,
                message: match onset {
                    Some(t) => format!(
                        "{:.0}% loss to the destination, starting at hop {t}",
                        dest.loss_pct
                    ),
                    None => format!("{:.0}% loss to the destination", dest.loss_pct),
                },
            });
        }

        // Rate limiting: middle hops with loss that does not carry through.
        if dest.loss_pct < LOSS_THRESHOLD_PCT {
            for h in hops[..hops.len() - 1]
                .iter()
                .filter(|h| judged(h) && h.received > 0 && h.loss_pct >= LOSS_THRESHOLD_PCT)
            {
                out.push(Finding {
                    kind: "rateLimit".into(),
                    ttl: Some(h.ttl),
                    message: format!(
                        "hop {} drops {:.0}% of probes but the destination does not; likely ICMP rate limiting, not real loss",
                        h.ttl, h.loss_pct
                    ),
                });
            }
        }

        // Latency jump that persists to the destination.
        if let Some(dest_avg) = dest.avg_ms {
            let mut prev: Option<f64> = None;
            let mut best: Option<(u8, f64)> = None;
            for h in hops {
                let Some(avg) = h.avg_ms else { continue };
                if let Some(p) = prev {
                    let step = avg - p;
                    // The rise must still be there at the destination.
                    if step >= JUMP_MIN_MS
                        && step >= dest_avg * JUMP_MIN_FRACTION
                        && dest_avg >= avg - step / 2.0
                        && best.is_none_or(|(_, s)| step > s)
                    {
                        best = Some((h.ttl, step));
                    }
                }
                prev = Some(avg);
            }
            if let Some((ttl, step)) = best {
                out.push(Finding {
                    kind: "latency".into(),
                    ttl: Some(ttl),
                    message: format!("latency rises {step:.0} ms at hop {ttl} and stays high"),
                });
            }
        }
    } else if let Some(last) = hops.iter().rev().find(|h| h.received > 0) {
        out.push(Finding {
            kind: "noReply".into(),
            ttl: Some(last.ttl),
            message: format!("destination not reached; last reply from hop {}", last.ttl),
        });
    }

    if let Some(h) = hops.iter().find(|h| h.unreachable.is_some()) {
        out.push(Finding {
            kind: "unreachable".into(),
            ttl: Some(h.ttl),
            message: format!(
                "hop {} reports {}",
                h.ttl,
                unreachable_name(h.unreachable.unwrap_or(0))
            ),
        });
    }
    out
}

/// ICMP destination unreachable code names.
pub fn unreachable_name(code: u8) -> &'static str {
    match code {
        0 => "network unreachable",
        1 => "host unreachable",
        2 => "protocol unreachable",
        3 => "port unreachable",
        4 => "fragmentation needed",
        9 | 10 => "administratively prohibited",
        13 => "communication administratively filtered",
        _ => "destination unreachable",
    }
}

/// Outcome of one MTU probe of a given total packet size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MtuProbe {
    /// Echo reply received at this size.
    Fits,
    /// Too big: a router sent frag-needed (with optional MTU and source), or
    /// the local interface refused it (no source).
    TooBig {
        mtu: Option<u16>,
        from: Option<Ipv4Addr>,
    },
    /// No reply.
    Lost,
}

/// One step of the MTU search, for the UI.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MtuStep {
    pub size: u16,
    pub result: String,
}

/// Final Path MTU result.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MtuResult {
    pub mtu: Option<u16>,
    /// Router that reported the lower MTU, when one did.
    pub limited_by: Option<Ipv4Addr>,
    /// Large packets vanished without a frag-needed reply (PMTUD black hole).
    pub black_hole: bool,
    pub note: String,
    pub steps: Vec<MtuStep>,
}

/// Binary search for the largest DF packet that reaches the destination.
#[derive(Debug, Clone)]
pub struct MtuSearch {
    /// Largest size known to fit.
    lo: Option<u16>,
    /// Smallest size known not to fit.
    hi: u16,
    hint: Option<u16>,
    limited_by: Option<Ipv4Addr>,
    lost_large: bool,
    steps: Vec<MtuStep>,
    done: Option<MtuResult>,
}

/// Smallest MTU every IPv4 path must carry without fragmenting (RFC 791).
pub const MIN_MTU: u16 = 576;

impl MtuSearch {
    /// Search sizes up to `max` (the local interface MTU, typically 1500).
    pub fn new(max: u16) -> Self {
        MtuSearch {
            lo: None,
            hi: max.max(MIN_MTU) + 1,
            hint: None,
            limited_by: None,
            lost_large: false,
            steps: Vec::new(),
            done: None,
        }
    }

    /// Next size to probe, or None when finished.
    pub fn next_size(&self) -> Option<u16> {
        if self.done.is_some() {
            return None;
        }
        let Some(lo) = self.lo else {
            // First the largest size, then the guaranteed minimum.
            return Some(if self.steps.is_empty() {
                self.hi - 1
            } else {
                MIN_MTU
            });
        };
        if let Some(h) = self.hint.filter(|h| *h > lo && *h < self.hi) {
            return Some(h);
        }
        Some(lo + (self.hi - lo) / 2)
    }

    /// Record the result for `size`.
    pub fn feed(&mut self, size: u16, probe: MtuProbe) {
        let label = match probe {
            MtuProbe::Fits => "fits".to_string(),
            MtuProbe::TooBig {
                mtu: Some(m),
                from: Some(ip),
            } => format!("too big (frag-needed from {ip}, MTU {m})"),
            MtuProbe::TooBig {
                mtu: None,
                from: Some(ip),
            } => format!("too big (frag-needed from {ip})"),
            MtuProbe::TooBig { from: None, .. } => "too big for the local interface".to_string(),
            MtuProbe::Lost => "no reply".to_string(),
        };
        self.steps.push(MtuStep {
            size,
            result: label,
        });

        match probe {
            MtuProbe::Fits => self.lo = Some(self.lo.map_or(size, |l| l.max(size))),
            MtuProbe::TooBig { mtu, from } => {
                self.hi = self.hi.min(size);
                if let Some(m) = mtu.filter(|m| *m < size) {
                    self.hint = Some(m);
                }
                if from.is_some() {
                    self.limited_by = from;
                }
                if self.hint == Some(size) {
                    self.hint = None;
                }
            }
            MtuProbe::Lost => {
                if size == MIN_MTU && self.lo.is_none() {
                    self.finish(
                        None,
                        "the destination does not answer ICMP echo, so Path MTU cannot be measured",
                    );
                    return;
                }
                self.hi = self.hi.min(size);
                self.lost_large = true;
                if self.hint == Some(size) {
                    self.hint = None;
                }
            }
        }

        if let Some(lo) = self.lo
            && self.hi - lo <= 1
        {
            let note = if self.limited_by.is_some() {
                "a router on the path reported a smaller MTU"
            } else if self.lost_large && lo < self.hi_max() {
                "larger packets were dropped without a frag-needed reply (PMTUD black hole)"
            } else {
                "full-size packets reach the destination"
            };
            self.finish(Some(lo), note);
        }
    }

    fn hi_max(&self) -> u16 {
        self.steps.first().map_or(self.hi, |s| s.size)
    }

    fn finish(&mut self, mtu: Option<u16>, note: &str) {
        let black_hole = mtu.is_some() && self.limited_by.is_none() && self.lost_large;
        self.done = Some(MtuResult {
            mtu,
            limited_by: self.limited_by,
            black_hole,
            note: note.to_string(),
            steps: self.steps.clone(),
        });
    }

    pub fn result(&self) -> Option<&MtuResult> {
        self.done.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_known_vector() {
        // Echo request id 0x1234 seq 7 with an empty payload.
        let p = build_echo(0x1234, 7, 0);
        assert_eq!(checksum(&p), 0, "a correct checksum sums to zero");
        assert_eq!(&p[..2], &[ECHO_REQUEST, 0]);
        assert_eq!(&p[4..8], &[0x12, 0x34, 0, 7]);
    }

    #[test]
    fn echo_payload_length() {
        assert_eq!(build_echo(1, 1, 100).len(), 108);
        assert_eq!(checksum(&build_echo(9, 9, 33)), 0);
    }

    #[test]
    fn strip_header_uses_ihl_not_total_length() {
        // Real macOS capture: total length byte-swapped (0x2c00), IHL 5.
        let mut b = vec![0x45, 0x00, 0x2c, 0x00];
        b.extend_from_slice(&[0; 16]);
        b.extend_from_slice(&[0xaa, 0xbb]);
        assert_eq!(strip_ipv4_header(&b), Some(&[0xaa, 0xbb][..]));
        assert_eq!(strip_ipv4_header(&[0x46, 0, 0]), None);
        assert_eq!(strip_ipv4_header(&[0x60; 40]), None);
        assert_eq!(strip_ipv4_header(&[]), None);
    }

    fn quoted_echo(ident: u16, seq: u16) -> Vec<u8> {
        let mut ip = vec![0x45, 0, 0, 0x2c, 0, 0, 0, 0, 1, 1, 0, 0];
        ip.extend_from_slice(&[10, 0, 0, 2, 1, 1, 1, 1]);
        ip.extend_from_slice(&build_echo(ident, seq, 0));
        ip
    }

    fn error_msg(ty: u8, code: u8, word: [u8; 4], ident: u16, seq: u16) -> Vec<u8> {
        let mut m = vec![ty, code, 0, 0];
        m.extend_from_slice(&word);
        m.extend_from_slice(&quoted_echo(ident, seq));
        m
    }

    #[test]
    fn parse_echo_reply() {
        let mut r = build_echo(0x1234, 9, 4);
        r[0] = ECHO_REPLY;
        assert_eq!(
            parse_icmp(&r),
            Some(IcmpReply {
                kind: ReplyKind::EchoReply,
                ident: 0x1234,
                seq: 9
            })
        );
    }

    #[test]
    fn parse_time_exceeded_matches_quoted_probe() {
        let m = error_msg(TIME_EXCEEDED, 0, [0; 4], 0xbeef, 3);
        let r = parse_icmp(&m).unwrap();
        assert_eq!(r.kind, ReplyKind::TimeExceeded);
        assert_eq!((r.ident, r.seq), (0xbeef, 3));
    }

    #[test]
    fn parse_frag_needed_mtu() {
        let m = error_msg(DEST_UNREACHABLE, CODE_FRAG_NEEDED, [0, 0, 0x05, 0xdc], 1, 1);
        assert_eq!(
            parse_icmp(&m).unwrap().kind,
            ReplyKind::FragNeeded(Some(1500))
        );
        let m = error_msg(DEST_UNREACHABLE, CODE_FRAG_NEEDED, [0; 4], 1, 1);
        assert_eq!(parse_icmp(&m).unwrap().kind, ReplyKind::FragNeeded(None));
        let m = error_msg(DEST_UNREACHABLE, 13, [0; 4], 1, 1);
        assert_eq!(parse_icmp(&m).unwrap().kind, ReplyKind::Unreachable(13));
    }

    #[test]
    fn parse_ignores_foreign_and_malformed() {
        // Quoted packet is UDP, not our echo.
        let mut m = error_msg(TIME_EXCEEDED, 0, [0; 4], 1, 1);
        m[8 + 9] = 17;
        assert_eq!(parse_icmp(&m), None);
        // Echo request (someone pinging us).
        assert_eq!(parse_icmp(&build_echo(1, 1, 0)), None);
        // Truncated everywhere.
        let full = error_msg(TIME_EXCEEDED, 0, [0; 4], 1, 1);
        for cut in 0..full.len() {
            let _ = parse_icmp(&full[..cut]);
        }
        assert_eq!(parse_icmp(&full[..20]), None);
    }

    fn res(ttl: u8, ip: [u8; 4], outcome: Outcome, rtt: Option<f64>) -> ProbeResult {
        ProbeResult {
            ttl,
            responder: Some(Ipv4Addr::from(ip)),
            outcome,
            rtt_ms: rtt,
        }
    }

    fn timeout(ttl: u8) -> ProbeResult {
        ProbeResult {
            ttl,
            responder: None,
            outcome: Outcome::Timeout,
            rtt_ms: None,
        }
    }

    #[test]
    fn hop_stats_math() {
        let mut h = HopStats::new(1);
        for v in [10.0, 20.0, 30.0] {
            h.record(&res(1, [10, 0, 0, 1], Outcome::Hop, Some(v)));
        }
        h.record(&timeout(1));
        let v = h.view();
        assert_eq!((v.sent, v.received), (4, 3));
        assert_eq!(v.loss_pct, 25.0);
        assert_eq!(v.avg_ms, Some(20.0));
        assert_eq!(v.best_ms, Some(10.0));
        assert_eq!(v.worst_ms, Some(30.0));
        assert_eq!(v.stdev_ms, Some(10.0));
        assert_eq!(v.jitter_ms, Some(10.0));
        assert_eq!(v.last_ms, Some(30.0));
        assert_eq!(v.history, vec![Some(10.0), Some(20.0), Some(30.0), None]);
        assert_eq!(v.ip, Some(Ipv4Addr::new(10, 0, 0, 1)));
    }

    #[test]
    fn hop_tracks_ecmp_responders_and_history_cap() {
        let mut h = HopStats::new(3);
        h.record(&res(3, [10, 0, 0, 1], Outcome::Hop, Some(1.0)));
        h.record(&res(3, [10, 0, 0, 2], Outcome::Hop, Some(1.0)));
        h.record(&res(3, [10, 0, 0, 2], Outcome::Hop, Some(1.0)));
        let v = h.view();
        assert_eq!(v.responders.len(), 2);
        assert_eq!(v.ip, Some(Ipv4Addr::new(10, 0, 0, 2)));
        h.set_hostname(Ipv4Addr::new(10, 0, 0, 2), "core1".into());
        assert_eq!(h.view().hostname.as_deref(), Some("core1"));
        for _ in 0..HISTORY_LEN + 10 {
            h.record(&timeout(3));
        }
        assert_eq!(h.view().history.len(), HISTORY_LEN);
    }

    #[test]
    fn tracker_finds_destination_and_trims() {
        let mut t = PathTracker::new(30);
        assert_eq!(t.ttls(), 1..=30);
        let mut cycle = vec![
            res(1, [10, 0, 0, 1], Outcome::Hop, Some(1.0)),
            timeout(2),
            res(3, [1, 1, 1, 1], Outcome::Reached, Some(8.0)),
            res(4, [1, 1, 1, 1], Outcome::Reached, Some(8.0)),
        ];
        cycle.extend((5..=30).map(timeout));
        t.record_cycle(&cycle);
        assert_eq!(t.ttls(), 1..=3);
        let views = t.views();
        assert_eq!(views.len(), 3);
        assert_eq!(views[1].ip, None);
        let s = t.summary();
        assert!(s.reached);
        assert_eq!(s.dest_avg_ms, Some(8.0));
        assert_eq!(s.cycles, 1);
    }

    #[test]
    fn tracker_unreached_shows_up_to_last_answer() {
        let mut t = PathTracker::new(10);
        let mut cycle = vec![
            res(1, [10, 0, 0, 1], Outcome::Hop, Some(1.0)),
            res(2, [10, 0, 1, 1], Outcome::Hop, Some(2.0)),
        ];
        cycle.extend((3..=10).map(timeout));
        t.record_cycle(&cycle);
        assert_eq!(t.views().len(), 2);
        let s = t.summary();
        assert!(!s.reached);
        assert_eq!(s.findings[0].kind, "noReply");
    }

    /// Build hop views from (loss %, avg ms) per hop, 20 samples each.
    fn hops(spec: &[(f64, Option<f64>)]) -> Vec<HopView> {
        spec.iter()
            .enumerate()
            .map(|(i, (loss, avg))| {
                let sent = 20;
                let received = if avg.is_some() {
                    (f64::from(sent) * (100.0 - loss) / 100.0).round() as u32
                } else {
                    0
                };
                HopView {
                    ttl: i as u8 + 1,
                    sent,
                    received,
                    loss_pct: *loss,
                    last_ms: *avg,
                    avg_ms: *avg,
                    best_ms: *avg,
                    worst_ms: *avg,
                    stdev_ms: None,
                    jitter_ms: None,
                    ip: None,
                    hostname: None,
                    responders: vec![],
                    history: vec![],
                    unreachable: None,
                }
            })
            .collect()
    }

    #[test]
    fn analysis_finds_persistent_loss_onset() {
        let h = hops(&[
            (0.0, Some(1.0)),
            (0.0, Some(2.0)),
            (20.0, Some(10.0)),
            (25.0, Some(11.0)),
            (20.0, Some(12.0)),
        ]);
        let f = analyze(&h, true);
        let loss = f.iter().find(|f| f.kind == "loss").unwrap();
        assert_eq!(loss.ttl, Some(3));
    }

    #[test]
    fn analysis_flags_rate_limiting_not_loss() {
        let h = hops(&[(0.0, Some(1.0)), (60.0, Some(5.0)), (0.0, Some(6.0))]);
        let f = analyze(&h, true);
        assert!(f.iter().all(|f| f.kind != "loss"));
        let rl = f.iter().find(|f| f.kind == "rateLimit").unwrap();
        assert_eq!(rl.ttl, Some(2));
    }

    #[test]
    fn analysis_finds_persistent_latency_jump() {
        // Transatlantic-style step at hop 4 that holds to the destination.
        let h = hops(&[
            (0.0, Some(1.0)),
            (0.0, Some(5.0)),
            (0.0, Some(8.0)),
            (0.0, Some(85.0)),
            (0.0, Some(88.0)),
        ]);
        let lat = analyze(&h, true)
            .into_iter()
            .find(|f| f.kind == "latency")
            .unwrap();
        assert_eq!(lat.ttl, Some(4));
    }

    #[test]
    fn analysis_ignores_transient_hop_latency() {
        // Hop 3 is slow to answer (control plane) but forwarding is fast.
        let h = hops(&[
            (0.0, Some(1.0)),
            (0.0, Some(2.0)),
            (0.0, Some(150.0)),
            (0.0, Some(9.0)),
        ]);
        assert!(analyze(&h, true).iter().all(|f| f.kind != "latency"));
    }

    #[test]
    fn mtu_full_size_fits() {
        let mut s = MtuSearch::new(1500);
        assert_eq!(s.next_size(), Some(1500));
        s.feed(1500, MtuProbe::Fits);
        let r = s.result().unwrap();
        assert_eq!(r.mtu, Some(1500));
        assert!(!r.black_hole);
    }

    #[test]
    fn mtu_uses_router_hint() {
        let mut s = MtuSearch::new(1500);
        let router = Ipv4Addr::new(10, 9, 0, 1);
        s.feed(
            1500,
            MtuProbe::TooBig {
                mtu: Some(1400),
                from: Some(router),
            },
        );
        assert_eq!(s.next_size(), Some(MIN_MTU));
        s.feed(MIN_MTU, MtuProbe::Fits);
        assert_eq!(s.next_size(), Some(1400));
        s.feed(1400, MtuProbe::Fits);
        // Hint fits; binary search closes the gap to 1499 quickly.
        while let Some(n) = s.next_size() {
            s.feed(
                n,
                if n <= 1400 {
                    MtuProbe::Fits
                } else {
                    MtuProbe::Lost
                },
            );
        }
        let r = s.result().unwrap();
        assert_eq!(r.mtu, Some(1400));
        assert_eq!(r.limited_by, Some(router));
        assert!(!r.black_hole);
    }

    #[test]
    fn mtu_binary_search_black_hole() {
        let mut s = MtuSearch::new(1500);
        let mut guard = 0;
        while let Some(n) = s.next_size() {
            s.feed(
                n,
                if n <= 1420 {
                    MtuProbe::Fits
                } else {
                    MtuProbe::Lost
                },
            );
            guard += 1;
            assert!(guard < 20, "search must converge");
        }
        let r = s.result().unwrap();
        assert_eq!(r.mtu, Some(1420));
        assert!(r.black_hole);
    }

    #[test]
    fn mtu_unmeasurable_when_no_echo() {
        let mut s = MtuSearch::new(1500);
        s.feed(1500, MtuProbe::Lost);
        s.feed(MIN_MTU, MtuProbe::Lost);
        let r = s.result().unwrap();
        assert_eq!(r.mtu, None);
        assert_eq!(s.next_size(), None);
    }
}
