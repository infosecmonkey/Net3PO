//! FortiGate `diagnose sys session list` (and `session6 list`) parser.
//! Each `session info:` block becomes a session with its tuple, NAT,
//! counters, interfaces, policy, state flags and offload status, plus the
//! plain-language meaning of the flags and offload reasons that Fortinet
//! documents. Unknown lines are kept as raw text; nothing is guessed.

use std::sync::LazyLock;

use regex::Regex;
use serde::Serialize;

/// Largest input accepted.
pub const MAX_INPUT: usize = 20 * 1024 * 1024;
/// Most sessions kept.
const MAX_SESSIONS: usize = 100_000;
/// Most raw text kept per session.
const MAX_RAW: usize = 8 * 1024;
/// Most key/value fields kept per session.
const MAX_FIELDS: usize = 200;

fn re(p: &str) -> Regex {
    Regex::new(p).expect("valid built-in pattern")
}

static HOOK: LazyLock<Regex> =
    LazyLock::new(|| re(r"hook=(\S+)\s+dir=(\S+)\s+act=(\S+)\s+(\S+?)->(\S+?)\(([^)]*)\)"));
static STAT: LazyLock<Regex> = LazyLock::new(|| re(r"\b(org|reply)=(\d+)/(\d+)(?:/(\d+))?"));
static SPEED: LazyLock<Regex> = LazyLock::new(|| re(r"\b(tx|rx) speed\(Bps/kbps\):\s*(\d+)/(\d+)"));
static DEV: LazyLock<Regex> = LazyLock::new(|| re(r"\bdev=([^\s/]*)/(\S*)"));
static GWY: LazyLock<Regex> = LazyLock::new(|| re(r"\bgwy=([^\s/]*)/(\S*)"));
static TOTAL: LazyLock<Regex> = LazyLock::new(|| re(r"^total session:?\s*(\d+)"));

/// An address and port as printed (`10.0.0.1:443`, `2001:db8::1:443`).
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Endpoint {
    pub addr: String,
    pub port: u32,
}

/// One NAT/hook line: where in the path, which direction, what happened.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Hook {
    pub hook: String,
    pub dir: String,
    pub act: String,
    pub src: Endpoint,
    pub dst: Endpoint,
    /// The translated address and port, when not `0.0.0.0:0`.
    pub nat: Option<Endpoint>,
}

/// A flag or reason with Fortinet's documented meaning, when known.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Flag {
    pub name: String,
    pub meaning: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Field {
    pub key: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub struct Session {
    /// 1-based position in the output.
    pub index: usize,
    /// 1-based line of the `session info:` header.
    pub line: usize,
    pub ipv6: bool,
    pub proto: Option<u32>,
    pub proto_name: String,
    pub proto_state: String,
    /// Reading of `proto_state` for TCP, UDP, SCTP and ICMP.
    pub state_text: Option<String>,
    pub duration: Option<u64>,
    pub expire: Option<u64>,
    pub timeout: Option<u64>,
    pub flags: Vec<Flag>,
    pub org_bytes: Option<u64>,
    pub org_packets: Option<u64>,
    pub reply_bytes: Option<u64>,
    pub reply_packets: Option<u64>,
    /// Bytes per second, original and reply direction.
    pub tx_bps: Option<u64>,
    pub rx_bps: Option<u64>,
    /// Interface indexes, `in->out`, per direction.
    pub dev_org: Option<String>,
    pub dev_reply: Option<String>,
    pub gwy_org: Option<String>,
    pub gwy_reply: Option<String>,
    pub hooks: Vec<Hook>,
    pub src: Option<Endpoint>,
    pub dst: Option<Endpoint>,
    /// Source after SNAT.
    pub snat: Option<Endpoint>,
    /// Destination after DNAT (the real server behind a VIP).
    pub dnat: Option<Endpoint>,
    pub src_mac: Option<String>,
    pub dst_mac: Option<String>,
    pub policy_id: Option<String>,
    pub vd: Option<String>,
    pub serial: Option<String>,
    pub app: Option<String>,
    pub url_cat: Option<String>,
    pub tunnel: Option<String>,
    pub helper: Option<String>,
    pub user: Option<String>,
    pub shapers: Vec<Field>,
    pub npu_state: Option<String>,
    /// `npu_state` lists `ofld-O` / `ofld-R`.
    pub offload_org: bool,
    pub offload_reply: bool,
    pub no_offload: Vec<Flag>,
    /// Every `key=value` seen, in order.
    pub fields: Vec<Field>,
    pub notes: Vec<String>,
    pub raw: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub struct Parsed {
    pub sessions: Vec<Session>,
    /// The `total session:` count printed by the FortiGate.
    pub total_reported: Option<u64>,
    pub truncated: bool,
    pub error: Option<String>,
}

pub fn proto_name(p: u32) -> &'static str {
    match p {
        1 => "ICMP",
        2 => "IGMP",
        6 => "TCP",
        17 => "UDP",
        41 => "IPv6-in-IPv4",
        47 => "GRE",
        50 => "ESP",
        51 => "AH",
        58 => "ICMPv6",
        89 => "OSPF",
        103 => "PIM",
        112 => "VRRP",
        132 => "SCTP",
        _ => "",
    }
}

const TCP_STATES: [&str; 10] = [
    "NONE",
    "ESTABLISHED",
    "SYN_SENT",
    "SYN & SYN/ACK",
    "FIN_WAIT",
    "TIME_WAIT",
    "CLOSE",
    "CLOSE_WAIT",
    "LAST_ACK",
    "LISTEN",
];

const SCTP_STATES: [&str; 8] = [
    "NONE",
    "ESTABLISHED",
    "CLOSED",
    "COOKIE_WAIT",
    "COOKIE_ECHOED",
    "SHUTDOWN_SENT",
    "SHUTDOWN_RECD",
    "SHUTDOWN_ACK_SENT",
];

/// Reading of `proto_state`. For TCP and SCTP the second digit is the
/// client-side state and the first the server side (0 unless flow or proxy
/// inspection tracks it).
pub fn state_text(proto: u32, state: &str) -> Option<String> {
    let digits: Vec<u32> = state.chars().filter_map(|c| c.to_digit(10)).collect();
    let (first, second) = match digits.as_slice() {
        [a, b] => (*a, *b),
        [b] => (0, *b),
        _ => return None,
    };
    let side = |name: &str| {
        if first == 0 {
            name.to_string()
        } else {
            format!("{name} (server side state {first})")
        }
    };
    match proto {
        6 => TCP_STATES.get(second as usize).map(|s| side(s)),
        132 => SCTP_STATES.get(second as usize).map(|s| side(s)),
        17 => Some(
            if second == 0 {
                "reply not seen"
            } else {
                "reply seen"
            }
            .to_string(),
        ),
        1 | 58 => Some("no state for ICMP".to_string()),
        _ => None,
    }
}

/// Fortinet's description of a `state=` flag.
pub fn flag_meaning(f: &str) -> Option<&'static str> {
    Some(match f {
        "log" => "Session is logged",
        "log-start" | "log_start" => "Logged at start as well as at end",
        "local" => "To or from the FortiGate's own IP stack",
        "ext" => "Handled by a session helper (older releases)",
        "may_dirty" | "may-dirty" => {
            "Created by a policy; can be re-evaluated if the config changes"
        }
        "dirty" => "Changed since creation; re-checked against the config on the next packet",
        "npu" => "Hardware acceleration applies (see npu_state for what is offloaded)",
        "npd" => "Hardware acceleration denied",
        "npr" => "Eligible for hardware acceleration",
        "rem" => "Can be removed if memory runs short",
        "eph" => "Ephemeral session",
        "oe" => "Part of an IPsec tunnel, originator side",
        "re" => "Part of an IPsec tunnel, responder side",
        "br" => "Bridged (VDOM in transparent mode)",
        "redir" => "Redirected to an internal proxy (proxy-based inspection)",
        "wccp" => "Intercepted by WCCP",
        "nlb" => "From a load-balanced virtual server",
        "os" => "Shaped in the original direction",
        "rs" => "Shaped in the reply direction",
        "ndr" => "Inspected by IPS signatures",
        "nds" => "Inspected by IPS anomaly detection",
        "auth" => "Subject to user authentication",
        "authed" => "User authenticated",
        "block" => "Re-evaluated to block after a policy change",
        "app_ntf" => "Policy has block notification enabled",
        "f00" => "Traffic logging enabled in the policy",
        "pol_sniff" => "Packet capture enabled in the policy",
        "rst_tcp" => "Policy sends a TCP RST on timeout",
        "synced" => "Synced to the HA peer",
        "syn_ses" => "Synced to this unit from the HA primary",
        "need_sync" => "Waiting for the HA sync delay",
        "complex" => "Handled by a session helper",
        "app_valid" => "Application control identified the application",
        "intree" => "Child session (FTP, SIP, RPC); removed with its parent",
        "hlife" => "Closes when the policy schedule ends",
        "cap" => "Captive portal authentication requested",
        "dst-vis" | "src-vis" => "Device identification on this side",
        _ => return None,
    })
}

/// Fortinet's description of a `no_ofld_reason` value.
pub fn offload_reason(r: &str) -> Option<&'static str> {
    Some(match r {
        "dirty" => "Config changed; not offloaded until the session is revalidated",
        "local" => "Local-in or local-out session (management, SSL VPN portal, explicit proxy)",
        "disabled-by-policy" => {
            "Policy has auto-asic-offload disabled, or a software switch is in the path"
        }
        "non-npu-intf" => "An interface in the path is not NP accelerated, or fastpath is disabled",
        "npu-flag-off" => {
            "Hardware or software limit (for example EMAC VLAN or an unsupported protocol)"
        }
        "redir-to-ips" => "IPS did not hand the session back for offload",
        "denied-by-nturbo" => "nTurbo does not support this IPS session",
        "block-by-ips" => "Blocked by IPS",
        "redir-to-av" => "Flow-based antivirus prevents offload",
        "sflow" => "sFlow sampling on an interface in the path",
        "mac-host-check" => "Device identification not finished yet",
        "offload-denied" => "Usually a session helper whose sessions cannot be offloaded",
        "not-established" => "TCP session not established yet",
        _ => return None,
    })
}

fn endpoint(s: &str) -> Option<Endpoint> {
    let (addr, port) = s.rsplit_once(':')?;
    let addr = addr.trim_start_matches('[').trim_end_matches(']');
    Some(Endpoint {
        addr: addr.to_string(),
        port: port.parse().ok()?,
    })
}

fn nat_endpoint(s: &str) -> Option<Endpoint> {
    let e = endpoint(s)?;
    let empty = e.port == 0
        && e.addr
            .parse::<std::net::IpAddr>()
            .is_ok_and(|a| a.is_unspecified());
    (!empty).then_some(e)
}

fn kv(s: &str) -> impl Iterator<Item = (&str, &str)> {
    s.split_whitespace()
        .filter_map(|t| t.trim_end_matches(',').split_once('='))
}

fn flag(name: &str, meaning: Option<&str>) -> Flag {
    Flag {
        name: name.to_string(),
        meaning: meaning.map(str::to_string),
    }
}

impl Session {
    fn field(&self, key: &str) -> Option<String> {
        self.fields
            .iter()
            .find(|f| f.key == key)
            .map(|f| f.value.clone())
    }

    fn add_fields(&mut self, line: &str) {
        for (k, v) in kv(line) {
            if self.fields.len() < MAX_FIELDS && !self.fields.iter().any(|f| f.key == k) {
                self.fields.push(Field {
                    key: k.to_string(),
                    value: v.to_string(),
                });
            }
        }
    }

    fn line(&mut self, t: &str) {
        if let Some(rest) = t.strip_prefix("state=") {
            self.flags = rest
                .split_whitespace()
                .map(|f| flag(f, flag_meaning(f)))
                .collect();
        } else if t.starts_with("statistic(") {
            for c in STAT.captures_iter(t) {
                let n = |i: usize| c.get(i).and_then(|m| m.as_str().parse().ok());
                if &c[1] == "org" {
                    (self.org_bytes, self.org_packets) = (n(2), n(3));
                } else {
                    (self.reply_bytes, self.reply_packets) = (n(2), n(3));
                }
            }
        } else if t.starts_with("tx speed") {
            for c in SPEED.captures_iter(t) {
                let v = c[2].parse().ok();
                if &c[1] == "tx" {
                    self.tx_bps = v;
                } else {
                    self.rx_bps = v;
                }
            }
        } else if t.starts_with("orgin->sink") || t.starts_with("origin->sink") {
            if let Some(c) = DEV.captures(t) {
                self.dev_org = Some(c[1].to_string()).filter(|s| !s.is_empty());
                self.dev_reply = Some(c[2].to_string()).filter(|s| !s.is_empty());
            }
            if let Some(c) = GWY.captures(t) {
                self.gwy_org = Some(c[1].to_string()).filter(|s| !s.is_empty());
                self.gwy_reply = Some(c[2].to_string()).filter(|s| !s.is_empty());
            }
        } else if let Some(c) = HOOK.captures(t) {
            if let (Some(src), Some(dst)) = (endpoint(&c[4]), endpoint(&c[5])) {
                self.hooks.push(Hook {
                    hook: c[1].to_string(),
                    dir: c[2].to_string(),
                    act: c[3].to_string(),
                    src,
                    dst,
                    nat: nat_endpoint(&c[6]),
                });
            }
        } else if let Some(rest) = t.strip_prefix("npu_state=") {
            let mut parts = rest.split_whitespace();
            self.npu_state = parts.next().map(str::to_string);
            for p in parts {
                match p {
                    "ofld-O" => self.offload_org = true,
                    "ofld-R" => self.offload_reply = true,
                    _ => {}
                }
            }
        } else if let Some(rest) = t.strip_prefix("no_ofld_reason:") {
            self.no_offload = rest
                .split_whitespace()
                .map(|r| flag(r, offload_reason(r)))
                .collect();
        } else if let Some((k, v)) = t.split_once('=')
            && k.ends_with("shaper")
            && !k.contains(' ')
        {
            if !v.trim().is_empty() {
                self.shapers.push(Field {
                    key: k.to_string(),
                    value: v.trim().to_string(),
                });
            }
        } else if t.starts_with("npu info:")
            || t.starts_with("vlifid=")
            || t.starts_with("hrx info:")
        {
            // Offload internals; kept in the raw text only.
        } else {
            self.add_fields(t);
        }
    }

    fn finish(&mut self) {
        let get = |s: &Session, k: &str| s.field(k);
        self.proto = get(self, "proto").and_then(|p| p.parse().ok());
        self.proto_name = match self.proto {
            Some(p) => match proto_name(p) {
                "" => format!("proto {p}"),
                n => n.to_string(),
            },
            None => "?".to_string(),
        };
        self.proto_state = get(self, "proto_state").unwrap_or_default();
        self.state_text = self.proto.and_then(|p| state_text(p, &self.proto_state));
        let num = |s: &Session, k: &str| get(s, k).and_then(|v| v.parse().ok());
        self.duration = num(self, "duration");
        self.expire = num(self, "expire");
        self.timeout = num(self, "timeout");
        self.policy_id = get(self, "policy_id");
        self.vd = get(self, "vd");
        self.serial = get(self, "serial");
        self.app = get(self, "app").filter(|v| v != "0");
        self.url_cat = get(self, "url_cat").filter(|v| v != "0");
        self.tunnel = get(self, "tunnel").filter(|v| v != "/" && !v.is_empty());
        self.helper = get(self, "helper");
        self.user = get(self, "user");
        self.src_mac = get(self, "src_mac");
        self.dst_mac = get(self, "dst_mac");
        if let Some(h) = self
            .hooks
            .iter()
            .find(|h| h.dir == "org")
            .or(self.hooks.first())
        {
            self.src = Some(h.src.clone());
            self.dst = Some(h.dst.clone());
        }
        for h in self.hooks.iter().filter(|h| h.dir == "org") {
            match h.act.as_str() {
                "snat" => self.snat = h.nat.clone(),
                "dnat" => self.dnat = h.nat.clone(),
                _ => {}
            }
        }
        self.notes = self.make_notes();
    }

    fn make_notes(&self) -> Vec<String> {
        let mut n = Vec::new();
        let digit = self.proto_state.chars().last().and_then(|c| c.to_digit(10));
        match (self.proto, digit) {
            (Some(6), Some(2)) => n.push(
                "SYN sent, no SYN/ACK seen: the server or the path back is not answering.".into(),
            ),
            (Some(6), Some(3)) => {
                n.push("Handshake not finished: SYN/ACK seen, final ACK not seen yet.".into())
            }
            (Some(6), Some(4 | 7 | 8)) => n.push("TCP session is closing.".into()),
            (Some(17), Some(0)) => n.push(
                "No UDP reply seen: one-way traffic, or the reply takes another path.".into(),
            ),
            _ => {}
        }
        if self.proto != Some(17)
            && self.org_packets.is_some_and(|p| p > 0)
            && self.reply_packets == Some(0)
        {
            n.push("No packets counted in the reply direction.".into());
        }
        if let Some(s) = &self.snat {
            n.push(format!("Source NAT to {}:{}.", s.addr, s.port));
        }
        if let Some(d) = &self.dnat {
            n.push(format!("Destination NAT to {}:{} (VIP).", d.addr, d.port));
        }
        if self.flags.iter().any(|f| f.name == "local") {
            n.push("Local session: to or from the FortiGate itself.".into());
        }
        if !self.no_offload.is_empty() {
            let r: Vec<&str> = self.no_offload.iter().map(|f| f.name.as_str()).collect();
            n.push(format!("Not offloaded: {}.", r.join(", ")));
        }
        if let (Some(e), Some(t)) = (self.expire, self.timeout)
            && t > 0
            && e * 10 < t
        {
            n.push(format!(
                "Expires in {e} s (timeout {t} s): little recent traffic."
            ));
        }
        n
    }
}

/// Parse pasted `diagnose sys session list` or `session6 list` output.
pub fn parse(text: &str) -> Parsed {
    let mut out = Parsed::default();
    if text.len() > MAX_INPUT {
        out.error = Some("input larger than 20 MB".into());
        return out;
    }
    let mut cur: Option<Session> = None;
    let push = |out: &mut Parsed, s: Option<Session>| {
        if let Some(mut s) = s {
            s.finish();
            out.sessions.push(s);
        }
    };
    for (i, raw) in text.lines().enumerate() {
        let t = raw.trim();
        let header = t
            .strip_prefix("session info:")
            .map(|r| (r, false))
            .or_else(|| t.strip_prefix("session6 info:").map(|r| (r, true)));
        if let Some((rest, v6)) = header {
            push(&mut out, cur.take());
            if out.sessions.len() >= MAX_SESSIONS {
                out.truncated = true;
                break;
            }
            let mut s = Session {
                index: out.sessions.len() + 1,
                line: i + 1,
                ipv6: v6,
                ..Default::default()
            };
            s.add_fields(rest);
            s.raw.push_str(t);
            cur = Some(s);
            continue;
        }
        if let Some(c) = TOTAL.captures(t) {
            out.total_reported = c[1].parse().ok();
            continue;
        }
        if let Some(s) = cur.as_mut() {
            if t.is_empty() {
                continue;
            }
            if s.raw.len() + t.len() < MAX_RAW {
                s.raw.push('\n');
                s.raw.push_str(t);
            }
            s.line(t);
        }
    }
    push(&mut out, cur.take());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // Made-up output in the FortiOS 7.x layout.
    const SAMPLE: &str = "\
session info: proto=6 proto_state=01 duration=1200 expire=3590 timeout=3600 refresh_dir=both flags=00000000 socktype=0 sockport=0 av_idx=0 use=3
origin-shaper=
reply-shaper=
per_ip_shaper=
class_id=0 ha_id=0 policy_dir=0 tunnel=/ vlan_cos=0/255
state=log dirty may_dirty npu f00
statistic(bytes/packets/allow_err): org=5000/40/1 reply=90000/70/1 tuples=2
tx speed(Bps/kbps): 4/0 rx speed(Bps/kbps): 75/0
orgin->sink: org pre->post, reply pre->post dev=12->3/3->12 gwy=192.0.2.1/0.0.0.0
hook=post dir=org act=snat 10.1.1.10:51000->198.51.100.20:443(192.0.2.10:61000)
hook=pre dir=reply act=dnat 198.51.100.20:443->192.0.2.10:61000(10.1.1.10:51000)
pos/(before,after) 0/(0,0), 0/(0,0)
src_mac=02:00:00:00:00:01  dst_mac=02:00:00:00:00:02
misc=0 policy_id=12 pol_uuid_idx=500 auth_info=0 chk_client_info=0 vd=0
serial=0001a2b3 tos=ff/ff app_list=0 app=0 url_cat=0
route_policy_id=1
npu_state=0x000c00 ofld-O ofld-R
npu info: flag=0x81/0x81, offload=8/8, ips_offload=0/0, epid=1/2, ipid=2/1, vlan=0x0000/0x0000
no_ofld_reason:

session info: proto=17 proto_state=00 duration=30 expire=150 timeout=180 flags=00000000 use=3
state=log may_dirty
statistic(bytes/packets/allow_err): org=300/3/0 reply=0/0/0 tuples=2
orgin->sink: org pre->post, reply pre->post dev=5->12/12->5 gwy=10.1.1.10/0.0.0.0
hook=pre dir=org act=dnat 203.0.113.50:40000->192.0.2.10:5060(10.1.1.20:5060)
hook=post dir=reply act=snat 10.1.1.20:5060->203.0.113.50:40000(192.0.2.10:5060)
misc=0 policy_id=20 auth_info=0 vd=0
serial=0001a2b4
no_ofld_reason:  disabled-by-policy non-npu-intf

session info: proto=6 proto_state=02 duration=3 expire=7 timeout=10 use=3
state=log local may_dirty
statistic(bytes/packets/allow_err): org=60/1/0 reply=0/0/0 tuples=2
hook=pre dir=org act=noop 10.1.1.30:52000->10.1.1.1:443(0.0.0.0:0)
misc=0 policy_id=0 auth_info=0 vd=0
serial=0001a2b5
no_ofld_reason:  local

session6 info: proto=6 proto_state=11 duration=10 expire=3599 timeout=3600 use=3
state=log may_dirty redir
hook=pre dir=org act=noop 2001:db8:1::10:53990->2001:db8:2::20:22(:::0)
misc=0 policy_id=7 vd=0
serial=0001a2b6
total session: 4
";

    #[test]
    fn parses_tcp_snat_session() {
        let p = parse(SAMPLE);
        assert_eq!(p.sessions.len(), 4);
        assert_eq!(p.total_reported, Some(4));
        let s = &p.sessions[0];
        assert_eq!((s.index, s.line), (1, 1));
        assert_eq!(s.proto_name, "TCP");
        assert_eq!(s.state_text.as_deref(), Some("ESTABLISHED"));
        assert_eq!(
            (s.duration, s.expire, s.timeout),
            (Some(1200), Some(3590), Some(3600))
        );
        assert_eq!(
            s.src,
            Some(Endpoint {
                addr: "10.1.1.10".into(),
                port: 51000
            })
        );
        assert_eq!(s.dst.as_ref().unwrap().port, 443);
        assert_eq!(
            s.snat,
            Some(Endpoint {
                addr: "192.0.2.10".into(),
                port: 61000
            })
        );
        assert!(s.dnat.is_none());
        assert_eq!((s.org_bytes, s.org_packets), (Some(5000), Some(40)));
        assert_eq!((s.reply_bytes, s.reply_packets), (Some(90000), Some(70)));
        assert_eq!((s.tx_bps, s.rx_bps), (Some(4), Some(75)));
        assert_eq!(s.dev_org.as_deref(), Some("12->3"));
        assert_eq!(s.dev_reply.as_deref(), Some("3->12"));
        assert_eq!(s.gwy_org.as_deref(), Some("192.0.2.1"));
        assert_eq!(s.policy_id.as_deref(), Some("12"));
        assert_eq!(s.serial.as_deref(), Some("0001a2b3"));
        assert_eq!(s.src_mac.as_deref(), Some("02:00:00:00:00:01"));
        assert!(s.offload_org && s.offload_reply && s.no_offload.is_empty());
        assert!(s.tunnel.is_none() && s.app.is_none() && s.shapers.is_empty());
        let names: Vec<&str> = s.flags.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, ["log", "dirty", "may_dirty", "npu", "f00"]);
        assert!(s.flags.iter().all(|f| f.meaning.is_some()));
        assert!(
            s.notes
                .iter()
                .any(|n| n.contains("Source NAT to 192.0.2.10:61000"))
        );
    }

    #[test]
    fn parses_udp_dnat_and_offload_reasons() {
        let s = &parse(SAMPLE).sessions[1];
        assert_eq!(s.proto_name, "UDP");
        assert_eq!(s.state_text.as_deref(), Some("reply not seen"));
        assert_eq!(s.src.as_ref().unwrap().addr, "203.0.113.50");
        assert_eq!(
            s.dnat,
            Some(Endpoint {
                addr: "10.1.1.20".into(),
                port: 5060
            })
        );
        let r: Vec<&str> = s.no_offload.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(r, ["disabled-by-policy", "non-npu-intf"]);
        assert!(s.no_offload.iter().all(|f| f.meaning.is_some()));
        assert!(s.notes.iter().any(|n| n.contains("No UDP reply")));
        assert!(s.notes.iter().any(|n| n.contains("Destination NAT")));
    }

    #[test]
    fn local_half_open_and_ipv6() {
        let p = parse(SAMPLE);
        let s = &p.sessions[2];
        assert_eq!(s.state_text.as_deref(), Some("SYN_SENT"));
        assert!(s.notes.iter().any(|n| n.contains("SYN sent")));
        assert!(s.notes.iter().any(|n| n.contains("Local session")));
        assert!(s.notes.iter().any(|n| n.contains("No packets counted")));
        let v6 = &p.sessions[3];
        assert!(v6.ipv6);
        assert_eq!(
            v6.src,
            Some(Endpoint {
                addr: "2001:db8:1::10".into(),
                port: 53990
            })
        );
        assert_eq!(v6.dst.as_ref().unwrap().port, 22);
        assert!(v6.hooks[0].nat.is_none());
        assert_eq!(
            v6.state_text.as_deref(),
            Some("ESTABLISHED (server side state 1)")
        );
    }

    #[test]
    fn decoders() {
        assert_eq!(state_text(6, "05").as_deref(), Some("TIME_WAIT"));
        assert_eq!(state_text(132, "01").as_deref(), Some("ESTABLISHED"));
        assert_eq!(state_text(17, "01").as_deref(), Some("reply seen"));
        assert_eq!(state_text(1, "00").as_deref(), Some("no state for ICMP"));
        assert!(state_text(6, "x").is_none());
        assert!(state_text(47, "00").is_none());
        assert_eq!(proto_name(50), "ESP");
        assert!(flag_meaning("unknown_flag").is_none());
        assert!(offload_reason("sflow").is_some());
    }

    #[test]
    fn hostile_and_empty_input() {
        assert!(parse("").sessions.is_empty());
        assert!(parse("random text\nhook=pre dir=org").sessions.is_empty());
        let junk = "session info: proto=999999999999999 proto_state=zz\nhook=pre dir=org act=noop a->b(c)\nstate=\n";
        let p = parse(junk);
        assert_eq!(p.sessions.len(), 1);
        assert!(p.sessions[0].src.is_none());
        let big = "a".repeat(MAX_INPUT + 1);
        assert!(parse(&big).error.is_some());
        // Raw text per session is capped.
        let long = format!("session info: proto=6\n{}\n", "x=y ".repeat(10_000));
        let p = parse(&long);
        assert!(p.sessions[0].raw.len() <= MAX_RAW);
        assert!(p.sessions[0].fields.len() <= MAX_FIELDS);
    }
}
