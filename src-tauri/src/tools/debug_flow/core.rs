//! FortiGate `diagnose debug flow` parser. Lines are grouped by trace_id
//! into ordered events; packet, session, route, policy, NAT and IPsec facts
//! are pulled out of the messages. A verdict is reported only when the log
//! states one ("Allowed by Policy-5", "Denied by forward policy check",
//! "reverse path check fail, drop"); otherwise the trace says the log has
//! none. Every fact links back to the line it came from.

use std::collections::BTreeMap;
use std::sync::LazyLock;

use regex::Regex;
use serde::Serialize;

/// Largest input accepted.
pub const MAX_INPUT: usize = 20 * 1024 * 1024;
/// Most traces kept.
const MAX_TRACES: usize = 5000;
/// Most events kept per trace.
const MAX_EVENTS: usize = 500;

fn re(p: &str) -> Regex {
    Regex::new(p).expect("valid built-in pattern")
}

static LINE: LazyLock<Regex> = LazyLock::new(|| {
    re(r#"trace_id=(\d+)(?:.*?\bfunc=(\S+))?(?:.*?\bline=(\d+))?.*?\bmsg=(?:"(.*)"\s*$|(.*)$)"#)
});
static PKT: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"received a packet\(proto=(\d+), ([0-9a-fA-F:.\[\]]+?):(\d+)->([0-9a-fA-F:.\[\]]+?):(\d+)\)(?:.*?from (\S+?)\.)?(?:.*?flag \[([^\]]*)\])?",
    )
});
static PKT_ICMP: LazyLock<Regex> =
    LazyLock::new(|| re(r"received a packet\(proto=1, ([0-9.]+):(\d+)->([0-9.]+):(\d+)\)"));
static NEW_SESS: LazyLock<Regex> = LazyLock::new(|| re(r"allocate a new session-([0-9a-fA-F]+)"));
static OLD_SESS: LazyLock<Regex> =
    LazyLock::new(|| re(r"Find an existing session, id-([0-9a-fA-F]+), (\w+) direction"));
static ROUTE: LazyLock<Regex> = LazyLock::new(|| re(r"find a route: flag=\S+ gw-(\S+) via (\S+)"));
static PBR: LazyLock<Regex> = LazyLock::new(|| re(r"(?i)match policy routing id=(\d+)"));
static POLICY_CHECKED: LazyLock<Regex> =
    LazyLock::new(|| re(r"checked gnum-\S+ policy-(\d+), ret-(\S+?), act-(\w+)"));
static ALLOWED: LazyLock<Regex> = LazyLock::new(|| re(r"Allowed by Policy-(\d+)(?::\s*(.*))?"));
static DENIED_POLICY: LazyLock<Regex> =
    LazyLock::new(|| re(r"Denied by forward policy check \(policy (\d+)\)"));
static SNAT: LazyLock<Regex> =
    LazyLock::new(|| re(r"\bSNAT ([0-9a-fA-F:.]+)->([0-9a-fA-F:.]+(?::\d+)?)"));
static DNAT: LazyLock<Regex> =
    LazyLock::new(|| re(r"\bDNAT ([0-9a-fA-F:.]+(?::\d+)?)->([0-9a-fA-F:.]+(?::\d+)?)"));
static VIP: LazyLock<Regex> = LazyLock::new(|| re(r"find DNAT: IP-(\S+), port-(\d+)"));
static IPSEC_ENTER: LazyLock<Regex> = LazyLock::new(|| re(r"enter IPSec interface-(\S+)"));
static IPSEC_ENC: LazyLock<Regex> =
    LazyLock::new(|| re(r"encrypted, and send to (\S+) with source (\S+)"));
static IPSEC_DEC: LazyLock<Regex> = LazyLock::new(|| re(r"(?i)decrypted|enter IPsec tunnel-(\S+)"));
static IN_IFACE: LazyLock<Regex> = LazyLock::new(|| re(r"in-\[([^\]]*)\], out-\[([^\]]*)\]"));
static SDWAN: LazyLock<Regex> =
    LazyLock::new(|| re(r"(?i)(?:sdwan|sd-wan|vwl)[^,]*?(?:rule|service)[ -]?(?:id[=-])?(\d+)"));

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Event {
    pub line: usize,
    pub func: String,
    pub msg: String,
    /// Plain-language reading of a recognized message.
    pub note: Option<String>,
    pub kind: String,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum Verdict {
    Allowed,
    Denied,
    Dropped,
    /// Forwarded within an existing session (no new policy lookup).
    ExistingSession,
    /// The log does not say.
    Unknown,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub struct Fact {
    pub value: String,
    pub line: usize,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Trace {
    pub trace_id: u64,
    pub first_line: usize,
    pub proto: Option<String>,
    pub src: Option<String>,
    pub dst: Option<String>,
    pub in_iface: Option<Fact>,
    pub out_iface: Option<Fact>,
    pub tcp_flags: Option<String>,
    pub session: Option<Fact>,
    pub route: Option<Fact>,
    pub policy: Option<Fact>,
    pub nat: Vec<Fact>,
    pub ipsec: Vec<Fact>,
    pub verdict: Verdict,
    pub verdict_text: Option<Fact>,
    /// Conclusions that are inferred rather than stated, labelled as such.
    pub notes: Vec<String>,
    pub events: Vec<Event>,
    pub events_truncated: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub struct Parsed {
    pub traces: Vec<Trace>,
    /// Lines that look like debug flow but could not be read.
    pub unparsed: usize,
    pub other_lines: usize,
    pub truncated: bool,
    pub error: Option<String>,
}

fn proto_name(n: &str) -> String {
    match n {
        "1" => "ICMP".into(),
        "6" => "TCP".into(),
        "17" => "UDP".into(),
        "50" => "ESP".into(),
        "58" => "ICMPv6".into(),
        "47" => "GRE".into(),
        "89" => "OSPF".into(),
        other => format!("IP/{other}"),
    }
}

/// Plain-language meaning of the messages engineers most often ask about.
fn explain(msg: &str) -> Option<(&'static str, String)> {
    let m = msg.to_ascii_lowercase();
    let note = |k: &'static str, s: &str| Some((k, s.to_string()));
    if m.contains("reverse path check fail") {
        return note(
            "drop",
            "Reverse path check failed: the FortiGate has no route back to the source through the interface the packet arrived on (RPF). Check routing for the source subnet, or asymmetric paths.",
        );
    }
    if m.contains("denied by forward policy check (policy 0)") {
        return note(
            "deny",
            "No firewall policy matched, so the implicit deny (policy 0) dropped it. Check the policy's interfaces, addresses, services and schedule.",
        );
    }
    if m.contains("denied by forward policy check") {
        return note("deny", "A firewall policy with action deny matched.");
    }
    if m.contains("iprope_in_check() check failed") {
        return note(
            "drop",
            "Local-in traffic to the FortiGate itself was refused: the service is not allowed on this interface, or a local-in policy or trusted host blocks it.",
        );
    }
    if m.contains("no session matched") {
        return note(
            "drop",
            "The packet did not belong to any session and could not start one (for example a non-SYN TCP packet). Often seen with asymmetric routing or after a session timed out.",
        );
    }
    if m.contains("denied by quota check") {
        return note(
            "drop",
            "Traffic quota exceeded (traffic shaping or user quota).",
        );
    }
    if m.contains("denied by endpoint check") {
        return note(
            "deny",
            "Endpoint compliance (FortiClient/EMS) check failed.",
        );
    }
    if m.contains("exceeded shaper limit") || m.contains("shaper") && m.contains("drop") {
        return note("drop", "A traffic shaper dropped the packet.");
    }
    if m.contains("allocate a new session") {
        return note(
            "session",
            "First packet of a new session; the FortiGate does a policy lookup for it.",
        );
    }
    if m.contains("find an existing session") {
        return note(
            "session",
            "Matched an existing session; no new policy lookup is done for this packet.",
        );
    }
    if m.contains("find a route") {
        return note(
            "route",
            "Routing lookup result: next-hop gateway and egress interface.",
        );
    }
    if m.contains("match policy routing") {
        return note(
            "route",
            "A policy route (PBR) matched and overrides the routing table.",
        );
    }
    if m.contains("allowed by policy") {
        return note("allow", "Accepted by the firewall policy shown.");
    }
    if m.contains("enter ipsec interface") {
        return note("ipsec", "Routed into an IPsec tunnel interface.");
    }
    if m.contains("encrypted, and send to") {
        return note("ipsec", "Encrypted and sent to the IPsec peer.");
    }
    if m.contains("npu") && (m.contains("offload") || m.contains("hw")) {
        return note(
            "offload",
            "The session is offloaded to the NP; later packets will not show in debug flow.",
        );
    }
    if m.contains("snat") || m.contains("dnat") {
        return note("nat", "Address translation applied.");
    }
    if m.contains("checked gnum") && m.contains("ret-matched") {
        return note("policy", "This policy matched.");
    }
    if m.contains("checked gnum") {
        return note("policy", "This policy was checked and did not match.");
    }
    if m.contains("drop") || m.contains("denied") {
        return note(
            "drop",
            "The log reports a drop here; see the message for the reason.",
        );
    }
    None
}

fn fact(value: impl Into<String>, line: usize) -> Fact {
    Fact {
        value: value.into(),
        line,
    }
}

/// Parse pasted or imported debug flow output.
pub fn parse(text: &str) -> Parsed {
    let mut p = Parsed::default();
    if text.len() > MAX_INPUT {
        p.error = Some("input larger than 20 MB".into());
        return p;
    }
    let mut traces: BTreeMap<u64, Trace> = BTreeMap::new();
    for (i, raw) in text.lines().enumerate() {
        let n = i + 1;
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        let Some(c) = LINE.captures(line) else {
            if line.contains("trace_id=") {
                p.unparsed += 1;
            } else {
                p.other_lines += 1;
            }
            continue;
        };
        let Ok(tid) = c[1].parse::<u64>() else {
            p.unparsed += 1;
            continue;
        };
        let func = c.get(2).map(|m| m.as_str().to_string()).unwrap_or_default();
        let msg = c
            .get(4)
            .or(c.get(5))
            .map(|m| m.as_str().trim().trim_matches('"').to_string())
            .unwrap_or_default();
        if !traces.contains_key(&tid) && traces.len() >= MAX_TRACES {
            p.truncated = true;
            continue;
        }
        let t = traces.entry(tid).or_insert_with(|| Trace {
            trace_id: tid,
            first_line: n,
            proto: None,
            src: None,
            dst: None,
            in_iface: None,
            out_iface: None,
            tcp_flags: None,
            session: None,
            route: None,
            policy: None,
            nat: Vec::new(),
            ipsec: Vec::new(),
            verdict: Verdict::Unknown,
            verdict_text: None,
            notes: Vec::new(),
            events: Vec::new(),
            events_truncated: false,
        });

        if let Some(m) = PKT.captures(&msg) {
            t.proto = Some(proto_name(&m[1]));
            let (sp, dp) = (&m[3], &m[5]);
            if &m[1] == "1" {
                t.src = Some(m[2].to_string());
                t.dst = Some(m[4].to_string());
                if let Some(ic) = PKT_ICMP.captures(&msg) {
                    t.notes
                        .push(format!("ICMP id/type fields: {}:{}", &ic[2], &ic[4]));
                }
            } else {
                t.src = Some(format!("{}:{sp}", &m[2]));
                t.dst = Some(format!("{}:{dp}", &m[4]));
            }
            if let Some(iface) = m.get(6) {
                t.in_iface = Some(fact(iface.as_str(), n));
            }
            if let Some(fl) = m.get(7) {
                t.tcp_flags = Some(fl.as_str().to_string());
            }
        }
        if let Some(m) = NEW_SESS.captures(&msg) {
            t.session = Some(fact(format!("new session {}", &m[1]), n));
        }
        if let Some(m) = OLD_SESS.captures(&msg) {
            t.session = Some(fact(
                format!("existing session {}, {} direction", &m[1], &m[2]),
                n,
            ));
            if t.verdict == Verdict::Unknown {
                t.verdict = Verdict::ExistingSession;
            }
        }
        if let Some(m) = ROUTE.captures(&msg) {
            t.route = Some(fact(format!("gateway {} via {}", &m[1], &m[2]), n));
            t.out_iface.get_or_insert(fact(&m[2], n));
        }
        if let Some(m) = PBR.captures(&msg) {
            t.route = Some(fact(format!("policy route {} matched", &m[1]), n));
        }
        if let Some(m) = SDWAN.captures(&msg) {
            t.notes
                .push(format!("SD-WAN rule {} mentioned (line {n})", &m[1]));
        }
        if let Some(m) = IN_IFACE.captures(&msg) {
            if !m[1].is_empty() {
                t.in_iface.get_or_insert(fact(&m[1], n));
            }
            if !m[2].is_empty() {
                t.out_iface = Some(fact(&m[2], n));
            }
        }
        if let Some(m) = POLICY_CHECKED.captures(&msg)
            && &m[2] == "matched"
        {
            t.policy = Some(fact(
                format!("policy {} matched, action {}", &m[1], &m[3]),
                n,
            ));
        }
        if let Some(m) = ALLOWED.captures(&msg) {
            t.verdict = Verdict::Allowed;
            let extra = m
                .get(2)
                .map(|x| x.as_str().trim())
                .filter(|x| !x.is_empty());
            t.verdict_text = Some(fact(
                format!(
                    "Allowed by policy {}{}",
                    &m[1],
                    extra.map(|x| format!(" ({x})")).unwrap_or_default()
                ),
                n,
            ));
            t.policy.get_or_insert(fact(format!("policy {}", &m[1]), n));
        }
        if let Some(m) = DENIED_POLICY.captures(&msg) {
            t.verdict = Verdict::Denied;
            let id = &m[1];
            t.verdict_text = Some(fact(
                if id == "0" {
                    "Denied: no policy matched (implicit deny, policy 0)".to_string()
                } else {
                    format!("Denied by policy {id}")
                },
                n,
            ));
            t.policy = Some(fact(format!("policy {id}"), n));
        }
        let lower = msg.to_ascii_lowercase();
        if t.verdict != Verdict::Denied
            && (lower.contains(", drop")
                || lower.contains(" drop")
                    && (lower.contains("fail")
                        || lower.contains("denied")
                        || lower.contains("check"))
                || lower.contains("no session matched")
                || lower.contains("denied by"))
            && !lower.contains("allowed by")
        {
            t.verdict = Verdict::Dropped;
            t.verdict_text = Some(fact(msg.clone(), n));
        }
        for (r, label) in [(&*SNAT, "SNAT"), (&*DNAT, "DNAT")] {
            if let Some(m) = r.captures(&msg) {
                t.nat
                    .push(fact(format!("{label} {} to {}", &m[1], &m[2]), n));
            }
        }
        if let Some(m) = VIP.captures(&msg) {
            t.nat.push(fact(format!("VIP to {}:{}", &m[1], &m[2]), n));
        }
        if let Some(m) = IPSEC_ENTER.captures(&msg) {
            t.ipsec.push(fact(format!("into tunnel {}", &m[1]), n));
        }
        if let Some(m) = IPSEC_ENC.captures(&msg) {
            t.ipsec.push(fact(
                format!("encrypted to peer {} from {}", &m[1], &m[2]),
                n,
            ));
        }
        if IPSEC_DEC.is_match(&msg) && lower.contains("decrypt") {
            t.ipsec.push(fact("decrypted from a tunnel", n));
        }
        if t.events.len() < MAX_EVENTS {
            let (kind, note) = match explain(&msg) {
                Some((k, s)) => (k.to_string(), Some(s)),
                None => ("info".to_string(), None),
            };
            t.events.push(Event {
                line: n,
                func,
                msg,
                note,
                kind,
            });
        } else {
            t.events_truncated = true;
        }
    }
    for t in traces.values_mut() {
        if t.verdict == Verdict::Unknown {
            t.notes.push("The log contains no verdict for this trace. It may be cut off, offloaded to the NP after the first packet, or the debug flow ran out of its trace count.".into());
        }
        if t.verdict == Verdict::ExistingSession {
            t.notes.push("Forwarded within an existing session, so no policy decision appears for this packet; the session's first packet had it.".into());
        }
        if t.proto.is_none() {
            t.notes.push("The 'received a packet' line is missing, so the packet tuple is unknown (output may start mid-trace).".into());
        }
    }
    p.traces = traces.into_values().collect();
    p.traces.sort_by_key(|t| t.first_line);
    p
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALLOW: &str = r#"
id=65308 trace_id=1 func=print_pkt_detail line=5895 msg="vd-root:0 received a packet(proto=6, 10.1.1.10:51234->198.51.100.20:443) tun_id=0.0.0.0 from port2. flag [S], seq 1234, ack 0, win 64240"
id=65308 trace_id=1 func=init_ip_session_common line=6076 msg="allocate a new session-0001abcd, tun_id=0.0.0.0"
id=65308 trace_id=1 func=vf_ip_route_input_common line=2605 msg="find a route: flag=04000000 gw-192.0.2.1 via port1"
id=65308 trace_id=1 func=iprope_fwd_check line=815 msg="in-[port2], out-[port1], skb_flags-02000000, vid-0, app_id: 0, url_cat_id: 0"
id=65308 trace_id=1 func=__iprope_check_one_policy line=2033 msg="checked gnum-100004 policy-4, ret-no-match, act-accept"
id=65308 trace_id=1 func=__iprope_check_one_policy line=2033 msg="checked gnum-100004 policy-5, ret-matched, act-accept"
id=65308 trace_id=1 func=fw_forward_handler line=930 msg="Allowed by Policy-5: SNAT"
id=65308 trace_id=1 func=__ip_session_run_tuple line=3484 msg="SNAT 10.1.1.10->203.0.113.5:60123"
"#;

    #[test]
    fn allowed_trace() {
        let p = parse(ALLOW);
        assert_eq!(p.traces.len(), 1);
        let t = &p.traces[0];
        assert_eq!(t.proto.as_deref(), Some("TCP"));
        assert_eq!(t.src.as_deref(), Some("10.1.1.10:51234"));
        assert_eq!(t.dst.as_deref(), Some("198.51.100.20:443"));
        assert_eq!(t.in_iface.as_ref().unwrap().value, "port2");
        assert_eq!(t.out_iface.as_ref().unwrap().value, "port1");
        assert_eq!(t.tcp_flags.as_deref(), Some("S"));
        assert_eq!(t.session.as_ref().unwrap().value, "new session 0001abcd");
        assert_eq!(
            t.route.as_ref().unwrap().value,
            "gateway 192.0.2.1 via port1"
        );
        assert_eq!(t.verdict, Verdict::Allowed);
        assert_eq!(
            t.verdict_text.as_ref().unwrap().value,
            "Allowed by policy 5 (SNAT)"
        );
        assert_eq!(t.verdict_text.as_ref().unwrap().line, 8);
        assert_eq!(t.nat[0].value, "SNAT 10.1.1.10 to 203.0.113.5:60123");
        assert!(
            t.events
                .iter()
                .any(|e| e.kind == "policy" && e.msg.contains("policy-5"))
        );
        assert!(t.notes.is_empty(), "{:?}", t.notes);
    }

    #[test]
    fn denies_drops_and_unknown() {
        let text = r#"
2026-11-14 10:00:01 id=65308 trace_id=7 func=print_pkt_detail line=5895 msg="vd-root:0 received a packet(proto=17, 10.2.2.2:5353->10.9.9.9:53) tun_id=0.0.0.0 from internal."
2026-11-14 10:00:01 id=65308 trace_id=7 func=fw_forward_handler line=814 msg="Denied by forward policy check (policy 0)"
id=65308 trace_id=8 func=print_pkt_detail line=5895 msg="vd-root:0 received a packet(proto=6, 172.16.0.5:443->10.1.1.10:51234) tun_id=0.0.0.0 from wan1. flag [.], seq 1, ack 1, win 501"
id=65308 trace_id=8 func=ip_route_input_slowpath line=2205 msg="reverse path check fail, drop"
id=65308 trace_id=9 func=print_pkt_detail line=5895 msg="vd-root:0 received a packet(proto=1, 10.1.1.10:1->8.8.8.8:2048) tun_id=0.0.0.0 from port2. type=8, code=0, id=1, seq=1."
id=65308 trace_id=9 func=init_ip_session_common line=6076 msg="allocate a new session-00020000, tun_id=0.0.0.0"
"#;
        let p = parse(text);
        assert_eq!(p.traces.len(), 3);
        let deny = &p.traces[0];
        assert_eq!(deny.verdict, Verdict::Denied);
        assert!(
            deny.verdict_text
                .as_ref()
                .unwrap()
                .value
                .contains("implicit deny")
        );
        assert_eq!(deny.proto.as_deref(), Some("UDP"));
        assert!(deny.events.iter().any(|e| {
            e.note
                .as_deref()
                .unwrap_or("")
                .contains("No firewall policy matched")
        }));
        let rpf = &p.traces[1];
        assert_eq!(rpf.verdict, Verdict::Dropped);
        assert!(
            rpf.events
                .iter()
                .any(|e| e.note.as_deref().unwrap_or("").contains("Reverse path"))
        );
        let icmp = &p.traces[2];
        assert_eq!(icmp.proto.as_deref(), Some("ICMP"));
        assert_eq!(icmp.verdict, Verdict::Unknown);
        assert!(icmp.notes.iter().any(|n| n.contains("no verdict")));
    }

    #[test]
    fn interleaved_existing_sessions_and_ipsec() {
        let text = r#"
id=65308 trace_id=21 func=print_pkt_detail line=5895 msg="vd-root:0 received a packet(proto=6, 10.1.1.10:51000->10.50.0.5:22) tun_id=0.0.0.0 from port2. flag [S]"
id=65308 trace_id=22 func=print_pkt_detail line=5895 msg="vd-root:0 received a packet(proto=6, 10.1.1.10:51001->10.50.0.5:22) tun_id=0.0.0.0 from port2. flag [.]"
id=65308 trace_id=22 func=resolve_ip_tuple_fast line=5974 msg="Find an existing session, id-0003aaaa, original direction"
id=65308 trace_id=21 func=vf_ip_route_input_common line=2605 msg="find a route: flag=04000000 gw-169.254.0.2 via vpn-branch"
id=65308 trace_id=21 func=fw_forward_handler line=930 msg="Allowed by Policy-12:"
id=65308 trace_id=21 func=ipsecdev_hard_start_xmit line=669 msg="enter IPSec interface-vpn-branch"
id=65308 trace_id=21 func=esp_output4 line=844 msg="IPsec encrypt/auth"
id=65308 trace_id=21 func=ipsec_output_finish line=544 msg="encrypted, and send to 198.51.100.77 with source 203.0.113.5"
"#;
        let p = parse(text);
        assert_eq!(p.traces.len(), 2);
        let a = &p.traces[0];
        assert_eq!(a.trace_id, 21);
        assert_eq!(a.verdict, Verdict::Allowed);
        assert_eq!(
            a.verdict_text.as_ref().unwrap().value,
            "Allowed by policy 12"
        );
        assert_eq!(a.ipsec.len(), 2);
        assert!(a.ipsec[1].value.contains("198.51.100.77"));
        assert_eq!(a.events.len(), 6);
        let b = &p.traces[1];
        assert_eq!(b.verdict, Verdict::ExistingSession);
        assert!(b.session.as_ref().unwrap().value.contains("0003aaaa"));
    }

    #[test]
    fn local_in_dnat_and_junk() {
        let text = "id=65308 trace_id=30 func=print_pkt_detail line=5895 msg=\"vd-root:0 received a packet(proto=6, 198.51.100.9:40000->203.0.113.5:443) tun_id=0.0.0.0 from wan1. flag [S]\"\nid=65308 trace_id=30 func=get_new_addr line=1227 msg=\"find DNAT: IP-10.0.0.80, port-443\"\nid=65308 trace_id=30 func=__ip_session_run_tuple line=3497 msg=\"DNAT 203.0.113.5:443->10.0.0.80:443\"\nid=65308 trace_id=31 func=iprope_in_check line=1 msg=\"iprope_in_check() check failed on policy 0, drop\"\nFGT # diagnose debug enable\nid=65308 trace_id=xyz msg=\"bad\"\n";
        let p = parse(text);
        assert_eq!(p.traces.len(), 2);
        assert_eq!(p.traces[0].nat.len(), 2);
        assert!(
            p.traces[0].nat[1]
                .value
                .starts_with("DNAT 203.0.113.5:443 to 10.0.0.80:443")
        );
        assert_eq!(p.traces[1].verdict, Verdict::Dropped);
        assert!(p.traces[1].notes.iter().any(|n| n.contains("missing")));
        assert_eq!(p.other_lines, 1);
        assert_eq!(p.unparsed, 1);
        assert!(parse(&"x".repeat(MAX_INPUT + 1)).error.is_some());
        assert!(parse("").traces.is_empty());
    }
}
