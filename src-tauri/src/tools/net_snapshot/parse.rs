//! Parsers for the OS commands a snapshot runs. All are pure functions over
//! the command output, compiled on every platform so each OS's parser is
//! tested everywhere. Output is treated as untrusted text: unknown lines are
//! skipped and nothing here can panic on odd input.

// Each OS build calls only its own parsers; the others are kept so their
// tests run on every CI platform.
#![cfg_attr(not(test), allow(dead_code))]

use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::LazyLock;

use regex::Regex;
use serde::Deserialize;

use super::model::{DnsScope, Interface, Listener, Neighbor, Route};

fn re(p: &str) -> Regex {
    Regex::new(p).expect("valid built-in pattern")
}

/// `aa:bb:...` in lower case with two digits per octet. Accepts `-` or `:`
/// separators and the macOS habit of dropping leading zeros (`0:1c:...`).
/// Returns None for anything that is not six octets.
pub fn norm_mac(s: &str) -> Option<String> {
    let parts: Vec<&str> = s.trim().split([':', '-']).collect();
    if parts.len() != 6 {
        return None;
    }
    let mut out = Vec::with_capacity(6);
    for p in parts {
        if p.is_empty() || p.len() > 2 || !p.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        out.push(format!("{:0>2}", p.to_ascii_lowercase()));
    }
    Some(out.join(":"))
}

/// Drop an IPv6 zone (`fe80::1%en0` -> `fe80::1`).
fn strip_zone(s: &str) -> &str {
    s.split('%').next().unwrap_or(s)
}

fn family_of(addr: &str) -> &'static str {
    if addr.contains(':') { "IPv6" } else { "IPv4" }
}

/// A destination with a prefix length: hosts get /32 or /128.
fn with_prefix(dest: &str) -> String {
    if dest == "default" || dest.contains('/') {
        return dest.to_string();
    }
    let bits = if dest.contains(':') { 128 } else { 32 };
    format!("{dest}/{bits}")
}

// ---------------------------------------------------------------- macOS

static IFC_HEAD: LazyLock<Regex> =
    LazyLock::new(|| re(r"^([^\s:]+): flags=[0-9a-fA-F]+<([^>]*)>(?:.*\bmtu (\d+))?"));

/// `ifconfig -a` (macOS and BSD).
pub fn macos_ifconfig(text: &str) -> Vec<Interface> {
    let mut out: Vec<Interface> = Vec::new();
    let mut inactive = false;
    let finish = |out: &mut Vec<Interface>, inactive: bool| {
        if inactive && let Some(last) = out.last_mut() {
            last.up = Some(false);
        }
    };
    for line in text.lines() {
        if let Some(c) = IFC_HEAD.captures(line) {
            finish(&mut out, inactive);
            inactive = false;
            let flags = &c[2];
            out.push(Interface {
                name: c[1].to_string(),
                mtu: c.get(3).and_then(|m| m.as_str().parse().ok()),
                up: Some(flags.split(',').any(|f| f == "UP")),
                ..Default::default()
            });
            continue;
        }
        let Some(cur) = out.last_mut() else { continue };
        let t = line.trim();
        let mut w = t.split_whitespace();
        match w.next() {
            Some("ether") => cur.mac = w.next().and_then(norm_mac),
            Some("inet") => {
                let addr = w.next().unwrap_or("");
                let mut prefix = None;
                while let Some(k) = w.next() {
                    if k == "netmask" {
                        prefix = w.next().and_then(mask_bits);
                    }
                }
                if addr.parse::<Ipv4Addr>().is_ok() {
                    out_push_addr(cur, addr, prefix.unwrap_or(32));
                }
            }
            Some("inet6") => {
                let addr = strip_zone(w.next().unwrap_or(""));
                let mut prefix = 128;
                while let Some(k) = w.next() {
                    if k == "prefixlen" {
                        prefix = w.next().and_then(|p| p.parse().ok()).unwrap_or(128);
                    }
                }
                if addr.parse::<IpAddr>().is_ok() {
                    out_push_addr(cur, addr, prefix);
                }
            }
            Some("status:") => inactive = w.next() == Some("inactive"),
            _ => {}
        }
    }
    finish(&mut out, inactive);
    out
}

fn out_push_addr(i: &mut Interface, addr: &str, prefix: u32) {
    i.addrs.push(format!("{addr}/{prefix}"));
}

/// Prefix length from a netmask in `0xffffff00` or dotted form.
fn mask_bits(m: &str) -> Option<u32> {
    let v = if let Some(hex) = m.strip_prefix("0x") {
        u32::from_str_radix(hex, 16).ok()?
    } else {
        u32::from(m.parse::<Ipv4Addr>().ok()?)
    };
    // Only contiguous masks are meaningful as a prefix.
    (v.leading_ones() + v.trailing_zeros() == 32).then_some(v.leading_ones())
}

/// macOS writes networks short (`10.1/16`, `192.0.2/24`); pad to four octets.
fn pad_v4_net(dest: &str) -> String {
    let (net, len) = match dest.split_once('/') {
        Some((n, l)) => (n, Some(l)),
        None => (dest, None),
    };
    if net.contains(':') || net.split('.').count() >= 4 {
        return dest.to_string();
    }
    let mut octets: Vec<&str> = net.split('.').collect();
    while octets.len() < 4 {
        octets.push("0");
    }
    let net = octets.join(".");
    match len {
        Some(l) => format!("{net}/{l}"),
        // Without a length, macOS means the classful size of the octets given.
        None => format!("{net}/{}", 8 * dest.split('.').count()),
    }
}

/// `netstat -rn` (macOS), both the Internet and Internet6 tables.
pub fn macos_routes(text: &str) -> Vec<Route> {
    let mut out = Vec::new();
    let mut family = "";
    for line in text.lines() {
        let t = line.trim();
        match t {
            "Internet:" => {
                family = "IPv4";
                continue;
            }
            "Internet6:" => {
                family = "IPv6";
                continue;
            }
            _ => {}
        }
        if family.is_empty() || t.is_empty() || t.starts_with("Destination") {
            continue;
        }
        let w: Vec<&str> = t.split_whitespace().collect();
        if w.len() < 4 {
            continue;
        }
        let (dest, gw, flags, netif) = (w[0], w[1], w[2], w[3]);
        // Cloned host entries (W) and link-layer entries (a MAC as gateway)
        // are the ARP / ND cache, shown in Neighbors instead.
        if flags.contains('W') || norm_mac(gw).is_some() {
            continue;
        }
        let dest = strip_zone_keep_len(dest);
        let dest = if dest == "default" {
            dest
        } else if family == "IPv4" {
            if flags.contains('H') && !dest.contains('/') {
                with_prefix(&dest)
            } else {
                pad_v4_net(&dest)
            }
        } else {
            with_prefix(&dest)
        };
        let gateway = if gw.starts_with("link#") {
            String::new()
        } else {
            strip_zone(gw).to_string()
        };
        out.push(Route {
            family: family.into(),
            dest,
            gateway,
            iface: netif.into(),
            metric: None,
        });
    }
    out
}

/// `fe80::%lo0/64` -> `fe80::/64`.
fn strip_zone_keep_len(s: &str) -> String {
    match s.split_once('%') {
        Some((addr, rest)) => match rest.split_once('/') {
            Some((_, len)) => format!("{addr}/{len}"),
            None => addr.to_string(),
        },
        None => s.to_string(),
    }
}

static ARP_LINE: LazyLock<Regex> =
    LazyLock::new(|| re(r"\((\d+\.\d+\.\d+\.\d+)\) at (\S+) on (\S+)(.*)$"));

/// `arp -an` (macOS).
pub fn macos_arp(text: &str) -> Vec<Neighbor> {
    text.lines()
        .filter_map(|l| ARP_LINE.captures(l))
        .filter_map(|c| {
            let mac = norm_mac(&c[2]).unwrap_or_default();
            if is_group_mac(&mac) {
                return None;
            }
            let rest = &c[4];
            let state = if mac.is_empty() {
                "incomplete"
            } else if rest.contains("permanent") {
                "permanent"
            } else {
                "dynamic"
            };
            Some(Neighbor {
                ip: c[1].to_string(),
                mac,
                iface: c[3].to_string(),
                state: state.into(),
            })
        })
        .collect()
}

/// Multicast and broadcast MACs (group bit set) are not hosts.
fn is_group_mac(mac: &str) -> bool {
    u8::from_str_radix(mac.get(..2).unwrap_or("00"), 16).is_ok_and(|b| b & 1 == 1)
}

/// `ndp -an` (macOS IPv6 neighbors).
pub fn macos_ndp(text: &str) -> Vec<Neighbor> {
    let mut out = Vec::new();
    for line in text
        .lines()
        .skip_while(|l| !l.starts_with("Neighbor"))
        .skip(1)
    {
        let w: Vec<&str> = line.split_whitespace().collect();
        if w.len() < 5 {
            continue;
        }
        let ip = strip_zone(w[0]);
        if ip.parse::<IpAddr>().is_err() {
            continue;
        }
        let mac = norm_mac(w[1]).unwrap_or_default();
        let state = match w[4] {
            "R" => "reachable",
            "S" => "stale",
            "D" => "delay",
            "P" => "probe",
            "I" => "incomplete",
            "W" => "waitdelete",
            _ if w[3] == "permanent" => "permanent",
            _ => "unknown",
        };
        out.push(Neighbor {
            ip: ip.into(),
            mac,
            iface: w[2].into(),
            state: state.into(),
        });
    }
    out
}

/// `scutil --dns` (macOS). Reads the main configuration, not the duplicate
/// "for scoped queries" list. Resolvers without servers (mDNS) are skipped.
pub fn macos_dns(text: &str) -> Vec<DnsScope> {
    let main = text
        .split("DNS configuration (for scoped queries)")
        .next()
        .unwrap_or("");
    let mut out: Vec<DnsScope> = Vec::new();
    for block in main.split("\nresolver #").skip(1) {
        let mut servers = Vec::new();
        let mut search = Vec::new();
        let mut domain = None;
        let mut iface = None;
        for line in block.lines() {
            let Some((k, v)) = line.split_once(" : ") else {
                continue;
            };
            let (k, v) = (k.trim(), v.trim());
            if k.starts_with("nameserver[") {
                servers.push(strip_zone(v).to_string());
            } else if k.starts_with("search domain[") {
                search.push(v.to_string());
            } else if k == "domain" {
                domain = Some(v.to_string());
            } else if k == "if_index" {
                iface = v
                    .split_once('(')
                    .map(|(_, n)| n.trim_end_matches(')').to_string());
            }
        }
        if servers.is_empty() {
            continue;
        }
        let scope = match (domain, iface) {
            (Some(d), _) => format!("domain {d}"),
            (None, Some(i)) => format!("Default ({i})"),
            (None, None) => "Default".into(),
        };
        push_scope(&mut out, scope, servers, search);
    }
    out
}

/// Add a scope, numbering repeats so each key stays unique.
fn push_scope(out: &mut Vec<DnsScope>, scope: String, servers: Vec<String>, search: Vec<String>) {
    let mut name = scope.clone();
    let mut n = 2;
    while out.iter().any(|s| s.scope == name) {
        name = format!("{scope} #{n}");
        n += 1;
    }
    out.push(DnsScope {
        scope: name,
        servers,
        search,
    });
}

static MAC_LISTEN: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"^(tcp|udp)(4|6|46)\s+\d+\s+\d+\s+(\S+)\s+(\S+)\s+(?:([A-Z_]+)\s+)?\d+\s+\d+\s+\d+\s+\d+(?:\s+(.+?):(\d+)\s+[0-9a-f]{5}\s)?",
    )
});

/// `netstat -anv -p tcp` and `-p udp` (macOS). TCP sockets in LISTEN, and
/// UDP sockets bound with no remote peer.
pub fn macos_listeners(text: &str) -> Vec<Listener> {
    let mut out = Vec::new();
    for line in text.lines() {
        let Some(c) = MAC_LISTEN.captures(line) else {
            continue;
        };
        let tcp = &c[1] == "tcp";
        if tcp && c.get(5).map(|m| m.as_str()) != Some("LISTEN") {
            continue;
        }
        if !tcp && &c[4] != "*.*" {
            continue;
        }
        let Some((addr, port)) = c[3].rsplit_once('.') else {
            continue;
        };
        let Ok(port) = port.parse::<u16>() else {
            continue;
        };
        let addr = match (addr, &c[2]) {
            ("*", "4") => "0.0.0.0".to_string(),
            ("*", "6") => "::".to_string(),
            ("*", _) => "*".to_string(),
            (a, _) => strip_zone(a).to_string(),
        };
        out.push(Listener {
            proto: if tcp { "TCP" } else { "UDP" }.into(),
            addr,
            port,
            process: c.get(6).map(|m| m.as_str().trim().to_string()),
            pid: c.get(7).and_then(|m| m.as_str().parse().ok()),
        });
    }
    out
}

/// True when `netstat -an` output has any TCP or UDP row. Some launch
/// contexts get only the Unix-domain section back.
pub fn macos_has_inet(text: &str) -> bool {
    text.lines()
        .any(|l| l.starts_with("tcp") || l.starts_with("udp"))
}

/// `lsof +c 0 -nP -iTCP -sTCP:LISTEN -iUDP -FpcPn` (macOS fallback). Field
/// output: `p<pid>`, `c<command>`, `P<protocol>`, `n<address:port>`. Lists
/// only the user's own processes without root.
pub fn macos_lsof(text: &str) -> Vec<Listener> {
    let mut out: Vec<Listener> = Vec::new();
    let (mut pid, mut cmd, mut proto) = (None, None::<String>, String::new());
    for line in text.lines() {
        let (tag, val) = match line.chars().next() {
            Some(c) => (c, &line[c.len_utf8()..]),
            None => continue,
        };
        match tag {
            'p' => {
                pid = val.parse().ok();
                cmd = None;
            }
            'c' => cmd = Some(val.to_string()),
            'P' => proto = val.to_ascii_uppercase(),
            'n' => {
                // Connected UDP sockets show "local->remote"; not listeners.
                if val.contains("->") || !matches!(proto.as_str(), "TCP" | "UDP") {
                    continue;
                }
                let Some((addr, port)) = val.rsplit_once(':') else {
                    continue;
                };
                let Ok(port) = port.parse::<u16>() else {
                    continue;
                };
                let addr = strip_zone(addr.trim_start_matches('[').trim_end_matches(']'));
                let l = Listener {
                    proto: proto.clone(),
                    addr: addr.to_string(),
                    port,
                    process: cmd.clone(),
                    pid,
                };
                if !out.contains(&l) {
                    out.push(l);
                }
            }
            _ => {}
        }
    }
    out
}

// ---------------------------------------------------------------- Linux

#[derive(Deserialize, Default)]
#[serde(default)]
struct IpLink {
    ifname: String,
    flags: Vec<String>,
    mtu: Option<u32>,
    operstate: String,
    address: Option<String>,
    addr_info: Vec<IpAddrInfo>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct IpAddrInfo {
    local: Option<String>,
    prefixlen: Option<u32>,
}

/// `ip -j addr show` (Linux).
pub fn linux_addrs(json: &str) -> Result<Vec<Interface>, String> {
    let links: Vec<IpLink> =
        serde_json::from_str(json).map_err(|e| format!("unexpected ip output: {e}"))?;
    Ok(links
        .into_iter()
        .map(|l| {
            let up = match l.operstate.as_str() {
                "UP" => Some(true),
                "DOWN" | "LOWERLAYERDOWN" | "NOTPRESENT" => Some(false),
                // Loopback and tunnels report UNKNOWN; use the admin flag.
                _ => Some(l.flags.iter().any(|f| f == "UP")),
            };
            Interface {
                name: l.ifname,
                mac: l.address.as_deref().and_then(norm_mac),
                mtu: l.mtu,
                up,
                addrs: l
                    .addr_info
                    .into_iter()
                    .filter_map(|a| Some(format!("{}/{}", a.local?, a.prefixlen?)))
                    .collect(),
            }
        })
        .collect())
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct IpRoute {
    dst: String,
    gateway: Option<String>,
    dev: Option<String>,
    metric: Option<u32>,
    #[serde(rename = "type")]
    kind: Option<String>,
}

/// `ip -j route show` or `ip -j -6 route show` (Linux).
pub fn linux_routes(json: &str, family: &str) -> Result<Vec<Route>, String> {
    let routes: Vec<IpRoute> =
        serde_json::from_str(json).map_err(|e| format!("unexpected ip output: {e}"))?;
    Ok(routes
        .into_iter()
        .map(|r| {
            let dev = r.dev.unwrap_or_default();
            // unreachable, blackhole and prohibit routes have no device.
            let iface = match (dev.is_empty(), r.kind) {
                (true, Some(k)) => k,
                _ => dev,
            };
            Route {
                family: family.into(),
                dest: with_prefix(&r.dst),
                gateway: r.gateway.unwrap_or_default(),
                iface,
                metric: r.metric,
            }
        })
        .collect())
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct IpNeigh {
    dst: String,
    dev: String,
    lladdr: Option<String>,
    state: Vec<String>,
}

/// `ip -j neigh show` (Linux), IPv4 and IPv6.
pub fn linux_neighbors(json: &str) -> Result<Vec<Neighbor>, String> {
    let list: Vec<IpNeigh> =
        serde_json::from_str(json).map_err(|e| format!("unexpected ip output: {e}"))?;
    Ok(list
        .into_iter()
        .filter_map(|n| {
            let mac = n.lladdr.as_deref().and_then(norm_mac).unwrap_or_default();
            if is_group_mac(&mac) {
                return None;
            }
            Some(Neighbor {
                ip: n.dst,
                mac,
                iface: n.dev,
                state: n.state.join(",").to_lowercase(),
            })
        })
        .collect())
}

static SS_USER: LazyLock<Regex> = LazyLock::new(|| re(r#"\(\("([^"]+)",pid=(\d+)"#));

/// `ss -Hlntup` (Linux). Process names show only for the user's own sockets
/// unless run as root.
pub fn linux_listeners(text: &str) -> Vec<Listener> {
    let mut out = Vec::new();
    for line in text.lines() {
        let w: Vec<&str> = line.split_whitespace().collect();
        if w.len() < 5 {
            continue;
        }
        let proto = match w[0] {
            "tcp" => "TCP",
            "udp" => "UDP",
            _ => continue,
        };
        let Some((addr, port)) = w[4].rsplit_once(':') else {
            continue;
        };
        let Ok(port) = port.parse::<u16>() else {
            continue;
        };
        let addr = strip_zone(addr.trim_start_matches('[').trim_end_matches(']'));
        let user = SS_USER.captures(line);
        out.push(Listener {
            proto: proto.into(),
            addr: addr.to_string(),
            port,
            process: user.as_ref().map(|c| c[1].to_string()),
            pid: user.as_ref().and_then(|c| c[2].parse().ok()),
        });
    }
    out
}

/// `/etc/resolv.conf`.
pub fn resolv_conf(text: &str) -> Option<DnsScope> {
    let mut servers = Vec::new();
    let mut search = Vec::new();
    for line in text.lines() {
        let line = line.split(['#', ';']).next().unwrap_or("");
        let mut w = line.split_whitespace();
        match w.next() {
            Some("nameserver") => servers.extend(w.next().map(|s| strip_zone(s).to_string())),
            // The last search or domain line wins, as in the resolver.
            Some("search") | Some("domain") => search = w.map(str::to_string).collect(),
            _ => {}
        }
    }
    (!servers.is_empty()).then(|| DnsScope {
        scope: "resolv.conf".into(),
        servers,
        search,
    })
}

/// `resolvectl dns` plus `resolvectl domain` (systemd-resolved). Lines look
/// like `Global: 192.0.2.53` and `Link 2 (eth0): 192.0.2.1 2001:db8::1`.
pub fn resolvectl(dns: &str, domains: &str) -> Vec<DnsScope> {
    fn scopes(text: &str) -> BTreeMap<String, Vec<String>> {
        let mut m = BTreeMap::new();
        for line in text.lines() {
            let Some((head, vals)) = line.split_once(':') else {
                continue;
            };
            let head = head.trim();
            let scope = match head.split_once('(') {
                Some((_, rest)) => rest.trim_end_matches(')').to_string(),
                None => head.to_string(),
            };
            let vals: Vec<String> = vals
                .split_whitespace()
                .map(|v| strip_zone(v.split('#').next().unwrap_or(v)).to_string())
                .collect();
            m.insert(scope, vals);
        }
        m
    }
    let d = scopes(domains);
    let mut out = Vec::new();
    for (scope, servers) in scopes(dns) {
        if servers.is_empty() {
            continue;
        }
        let search = d.get(&scope).cloned().unwrap_or_default();
        push_scope(&mut out, scope, servers, search);
    }
    out
}

// ---------------------------------------------------------------- Windows

/// PowerShell's ConvertTo-Json writes a one-element array as a bare value.
#[derive(Deserialize)]
#[serde(untagged)]
enum Many<T> {
    List(Vec<T>),
    One(T),
}

impl<T> Default for Many<T> {
    fn default() -> Self {
        Many::List(Vec::new())
    }
}

impl<T> Many<T> {
    fn into_vec(self) -> Vec<T> {
        match self {
            Many::List(v) => v,
            Many::One(x) => vec![x],
        }
    }
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "PascalCase")]
struct WinAdapter {
    name: String,
    status: Option<String>,
    mac_address: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "PascalCase")]
struct WinAddr {
    interface_alias: String,
    #[serde(rename = "IPAddress")]
    ip_address: String,
    prefix_length: Option<u32>,
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "PascalCase")]
struct WinMtu {
    interface_alias: String,
    nl_mtu: Option<u32>,
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "PascalCase")]
struct WinRoute {
    destination_prefix: String,
    next_hop: String,
    interface_alias: String,
    route_metric: Option<u32>,
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "PascalCase")]
struct WinDns {
    interface_alias: String,
    server_addresses: Option<Many<String>>,
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "PascalCase")]
struct WinSuffix {
    interface_alias: String,
    connection_specific_suffix: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "PascalCase")]
struct WinNeighbor {
    #[serde(rename = "IPAddress")]
    ip_address: String,
    link_layer_address: Option<String>,
    interface_alias: String,
    state: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "PascalCase")]
struct WinSocket {
    local_address: String,
    local_port: u16,
    owning_process: Option<u32>,
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "PascalCase")]
struct WinProc {
    id: u32,
    process_name: String,
}

/// Everything the snapshot PowerShell script returns in one JSON object.
#[derive(Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct WinAll {
    adapters: Many<WinAdapter>,
    addresses: Many<WinAddr>,
    mtu: Many<WinMtu>,
    routes: Many<WinRoute>,
    dns: Many<WinDns>,
    suffixes: Many<WinSuffix>,
    search_list: Option<Many<String>>,
    neighbors: Many<WinNeighbor>,
    tcp: Many<WinSocket>,
    udp: Many<WinSocket>,
    procs: Many<WinProc>,
}

/// The PowerShell script run on Windows. Every cmdlet here works for a
/// normal user. Enums are turned into strings in the script, because Windows
/// PowerShell 5.1 writes them as numbers.
pub const WINDOWS_SCRIPT: &str = r#"
$ErrorActionPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$o = [ordered]@{}
$o.adapters = @(Get-NetAdapter | Select-Object Name, @{n='Status';e={"$($_.Status)"}}, MacAddress)
$o.addresses = @(Get-NetIPAddress | Select-Object InterfaceAlias, IPAddress, PrefixLength)
$o.mtu = @(Get-NetIPInterface -AddressFamily IPv4 | Select-Object InterfaceAlias, NlMtu)
$o.routes = @(Get-NetRoute | Select-Object DestinationPrefix, NextHop, InterfaceAlias, RouteMetric)
$o.dns = @(Get-DnsClientServerAddress | Select-Object InterfaceAlias, ServerAddresses)
$o.suffixes = @(Get-DnsClient | Select-Object InterfaceAlias, ConnectionSpecificSuffix)
$o.searchList = @((Get-DnsClientGlobalSetting).SuffixSearchList)
$o.neighbors = @(Get-NetNeighbor | Select-Object IPAddress, LinkLayerAddress, InterfaceAlias, @{n='State';e={"$($_.State)"}})
$o.tcp = @(Get-NetTCPConnection -State Listen | Select-Object LocalAddress, LocalPort, OwningProcess)
$o.udp = @(Get-NetUDPEndpoint | Select-Object LocalAddress, LocalPort, OwningProcess)
$o.procs = @(Get-Process | Select-Object Id, ProcessName)
$o | ConvertTo-Json -Depth 4 -Compress
"#;

/// Sections parsed from the Windows script output.
pub struct WindowsParts {
    pub interfaces: Vec<Interface>,
    pub routes: Vec<Route>,
    pub dns: Vec<DnsScope>,
    pub neighbors: Vec<Neighbor>,
    pub listeners: Vec<Listener>,
}

/// Parse the JSON written by [`WINDOWS_SCRIPT`].
pub fn windows_all(json: &str) -> Result<WindowsParts, String> {
    // PowerShell may prefix a UTF-8 byte order mark.
    let json = json.trim_start_matches('\u{feff}').trim();
    let all: WinAll =
        serde_json::from_str(json).map_err(|e| format!("unexpected PowerShell output: {e}"))?;

    // Interfaces: adapters first, then any alias that only has addresses
    // (such as the loopback pseudo-interface).
    let mtu: HashMap<String, u32> = all
        .mtu
        .into_vec()
        .into_iter()
        .filter_map(|m| Some((m.interface_alias, m.nl_mtu?)))
        .collect();
    let mut interfaces: Vec<Interface> = all
        .adapters
        .into_vec()
        .into_iter()
        .map(|a| Interface {
            mtu: mtu.get(&a.name).copied(),
            up: a.status.map(|s| s.eq_ignore_ascii_case("Up")),
            mac: a.mac_address.as_deref().and_then(norm_mac),
            name: a.name,
            addrs: Vec::new(),
        })
        .collect();
    for a in all.addresses.into_vec() {
        let ip = strip_zone(&a.ip_address).to_string();
        let cidr = format!(
            "{ip}/{}",
            a.prefix_length
                .unwrap_or(if ip.contains(':') { 128 } else { 32 })
        );
        match interfaces.iter_mut().find(|i| i.name == a.interface_alias) {
            Some(i) => i.addrs.push(cidr),
            None => interfaces.push(Interface {
                mtu: mtu.get(&a.interface_alias).copied(),
                name: a.interface_alias,
                addrs: vec![cidr],
                ..Default::default()
            }),
        }
    }

    let routes = all
        .routes
        .into_vec()
        .into_iter()
        .map(|r| {
            let on_link = matches!(r.next_hop.as_str(), "0.0.0.0" | "::" | "");
            let dest = match r.destination_prefix.as_str() {
                "0.0.0.0/0" | "::/0" => "default".to_string(),
                d => d.to_string(),
            };
            Route {
                family: family_of(&r.destination_prefix).into(),
                dest,
                gateway: if on_link { String::new() } else { r.next_hop },
                iface: r.interface_alias,
                metric: r.route_metric,
            }
        })
        .collect();

    // DNS: one scope per interface (IPv4 and IPv6 servers together).
    let suffix: HashMap<String, String> = all
        .suffixes
        .into_vec()
        .into_iter()
        .filter_map(|s| {
            let v = s.connection_specific_suffix?;
            (!v.is_empty()).then_some((s.interface_alias, v))
        })
        .collect();
    let mut per_if: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for d in all.dns.into_vec() {
        let servers = d.server_addresses.map(Many::into_vec).unwrap_or_default();
        let entry = per_if.entry(d.interface_alias).or_default();
        for s in servers {
            if !entry.contains(&s) {
                entry.push(s);
            }
        }
    }
    let mut dns = Vec::new();
    let global: Vec<String> = all.search_list.map(Many::into_vec).unwrap_or_default();
    if !global.is_empty() {
        dns.push(DnsScope {
            scope: "Global search list".into(),
            servers: Vec::new(),
            search: global,
        });
    }
    for (alias, servers) in per_if {
        if servers.is_empty() {
            continue;
        }
        let search = suffix
            .get(&alias)
            .map(|s| vec![s.clone()])
            .unwrap_or_default();
        push_scope(&mut dns, alias, servers, search);
    }

    let neighbors = all
        .neighbors
        .into_vec()
        .into_iter()
        .filter_map(|n| {
            let mac = n
                .link_layer_address
                .as_deref()
                .and_then(norm_mac)
                .unwrap_or_default();
            let state = n.state.unwrap_or_default().to_lowercase();
            // Group MACs, and the all-zero placeholder Windows keeps for
            // unreachable entries, are not hosts.
            if is_group_mac(&mac) || state == "unreachable" {
                return None;
            }
            let mac = if mac == "00:00:00:00:00:00" {
                String::new()
            } else {
                mac
            };
            Some(Neighbor {
                ip: strip_zone(&n.ip_address).to_string(),
                mac,
                iface: n.interface_alias,
                state,
            })
        })
        .collect();

    let names: HashMap<u32, String> = all
        .procs
        .into_vec()
        .into_iter()
        .map(|p| (p.id, p.process_name))
        .collect();
    let sock = |proto: &str, s: WinSocket| Listener {
        proto: proto.into(),
        addr: strip_zone(&s.local_address).to_string(),
        port: s.local_port,
        process: s.owning_process.and_then(|p| names.get(&p).cloned()),
        pid: s.owning_process,
    };
    let mut listeners: Vec<Listener> = all
        .tcp
        .into_vec()
        .into_iter()
        .map(|s| sock("TCP", s))
        .collect();
    listeners.extend(all.udp.into_vec().into_iter().map(|s| sock("UDP", s)));

    Ok(WindowsParts {
        interfaces,
        routes,
        dns,
        neighbors,
        listeners,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn macs_normalize() {
        assert_eq!(
            norm_mac("0:1c:42:a:b:ff").as_deref(),
            Some("00:1c:42:0a:0b:ff")
        );
        assert_eq!(
            norm_mac("AA-BB-CC-DD-EE-01").as_deref(),
            Some("aa:bb:cc:dd:ee:01")
        );
        assert_eq!(norm_mac("(incomplete)"), None);
        assert_eq!(norm_mac("aa:bb:cc:dd:ee"), None);
        assert_eq!(norm_mac("aa:bb:cc:dd:ee:fff"), None);
    }

    const IFCONFIG: &str = "lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
\toptions=1203<RXCSUM,TXCSUM,TXSTATUS,SW_TIMESTAMP>
\tinet 127.0.0.1 netmask 0xff000000
\tinet6 ::1 prefixlen 128
\tinet6 fe80::1%lo0 prefixlen 64 scopeid 0x1
gif0: flags=8010<POINTOPOINT,MULTICAST> mtu 1280
en1: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tether 2:0:0:0:0:a
\tmedia: none
\tstatus: inactive
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tether 02:00:00:00:00:01
\tinet 192.0.2.10 netmask 0xffffff00 broadcast 192.0.2.255
\tinet6 2001:db8::10 prefixlen 64 autoconf secured
\tstatus: active
";

    #[test]
    fn macos_interfaces() {
        let i = macos_ifconfig(IFCONFIG);
        assert_eq!(i.len(), 4);
        assert_eq!(i[0].name, "lo0");
        assert_eq!(i[0].addrs, vec!["127.0.0.1/8", "::1/128", "fe80::1/64"]);
        assert_eq!(i[1].up, Some(false));
        assert_eq!(i[2].mac.as_deref(), Some("02:00:00:00:00:0a"));
        assert_eq!(i[2].up, Some(false), "status: inactive means down");
        assert_eq!(i[3].up, Some(true));
        assert_eq!(i[3].mtu, Some(1500));
        assert_eq!(i[3].addrs, vec!["192.0.2.10/24", "2001:db8::10/64"]);
    }

    #[test]
    fn netmask_bits() {
        assert_eq!(mask_bits("0xffffff00"), Some(24));
        assert_eq!(mask_bits("255.255.252.0"), Some(22));
        assert_eq!(mask_bits("0x00000000"), Some(0));
        assert_eq!(mask_bits("0xff00ff00"), None);
        assert_eq!(mask_bits("junk"), None);
    }

    const NETSTAT_RN: &str = "Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
default            192.0.2.1          UGScg                 en0
127                127.0.0.1          UCS                   lo0
192.0.2/24         link#7             UCS                   en0      !
192.0.2.1/32       link#7             UCS                   en0      !
192.0.2.1          2:0:0:0:0:bb       UHLWIir               en0   1146
198.51.100.7       192.0.2.254        UGHS                  en0

Internet6:
Destination                             Gateway                                 Flags               Netif Expire
default                                 fe80::1%en0                             UGcg                en0
::1                                     ::1                                     UHL                 lo0
2001:db8::/64                           link#7                                  UC                  en0
fe80::%lo0/64                           fe80::1%lo0                             UcI                 lo0
";

    #[test]
    fn macos_route_table() {
        let r = macos_routes(NETSTAT_RN);
        let rows: Vec<String> = r
            .iter()
            .map(|r| format!("{} {} {} {}", r.family, r.dest, r.gateway, r.iface))
            .collect();
        assert_eq!(
            rows,
            vec![
                "IPv4 default 192.0.2.1 en0",
                "IPv4 127.0.0.0/8 127.0.0.1 lo0",
                "IPv4 192.0.2.0/24  en0",
                "IPv4 192.0.2.1/32  en0",
                "IPv4 198.51.100.7/32 192.0.2.254 en0",
                "IPv6 default fe80::1 en0",
                "IPv6 ::1/128 ::1 lo0",
                "IPv6 2001:db8::/64  en0",
                "IPv6 fe80::/64 fe80::1 lo0",
            ]
        );
    }

    #[test]
    fn macos_neighbors() {
        let arp = "? (192.0.2.1) at 2:0:0:0:0:bb on en0 ifscope [ethernet]
? (192.0.2.9) at (incomplete) on en0 ifscope [ethernet]
? (192.0.2.255) at ff:ff:ff:ff:ff:ff on en0 ifscope [ethernet]
? (224.0.0.251) at 1:0:5e:0:0:fb on en0 ifscope permanent [ethernet]
? (192.0.2.10) at 2:0:0:0:0:1 on en0 ifscope permanent [ethernet]
";
        let n = macos_arp(arp);
        let rows: Vec<_> = n
            .iter()
            .map(|n| format!("{} {} {}", n.ip, n.mac, n.state))
            .collect();
        assert_eq!(
            rows,
            vec![
                "192.0.2.1 02:00:00:00:00:bb dynamic",
                "192.0.2.9  incomplete",
                "192.0.2.10 02:00:00:00:00:01 permanent",
            ]
        );
        let ndp = "Neighbor                                Linklayer Address  Netif Expire    St Flgs Prbs
2001:db8::1                             2:0:0:0:0:bb          en0 23h59m58s S R
fe80::1%lo0                             (incomplete)          lo0 permanent R
";
        let n = macos_ndp(ndp);
        assert_eq!(n.len(), 2);
        assert_eq!(
            (n[0].ip.as_str(), n[0].state.as_str()),
            ("2001:db8::1", "stale")
        );
        assert_eq!((n[1].ip.as_str(), n[1].mac.as_str()), ("fe80::1", ""));
    }

    #[test]
    fn macos_resolvers() {
        let text = "DNS configuration

resolver #1
  search domain[0] : corp.example.com
  nameserver[0] : 192.0.2.53
  nameserver[1] : 2001:db8::53
  if_index : 7 (en0)
  flags    : Request A records, Request AAAA records
  reach    : 0x00000002 (Reachable)

resolver #2
  domain   : local
  options  : mdns
  timeout  : 5

resolver #3
  domain   : example.net
  nameserver[0] : 198.51.100.53

DNS configuration (for scoped queries)

resolver #1
  nameserver[0] : 192.0.2.53
  if_index : 7 (en0)
";
        let d = macos_dns(text);
        assert_eq!(d.len(), 2);
        assert_eq!(d[0].scope, "Default (en0)");
        assert_eq!(d[0].servers, vec!["192.0.2.53", "2001:db8::53"]);
        assert_eq!(d[0].search, vec!["corp.example.com"]);
        assert_eq!(d[1].scope, "domain example.net");
    }

    #[test]
    fn macos_listening() {
        let text = "Active Internet connections (including servers)
Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)          rxbytes      txbytes  rhiwat  shiwat          process:pid    state  options           gencnt    flags   flags1 usecnt rtncnt fltrs
tcp4       0      0  192.0.2.10.56870       203.0.113.5.443        ESTABLISHED        21122         2414  131072  131768          2.1.325:17844  00102 00000008 0000000000331ee7 00000081 04000900      2      0 000000
tcp4       0      0  127.0.0.1.631          *.*                    LISTEN                 0            0  131072  131072            cupsd:25512  00080 00000006 000000000032f8ae 00000001 00000800      1      0 000000
tcp46      0      0  *.28198                *.*                    LISTEN                 0            0  131072  131072      Stream Deck:1970   00100 00000106 000000000032e8ae 00000000 00000800      1      0 000000
tcp6       0      0  *.22                   *.*                    LISTEN                 0            0  131072  131072        launchd:1   00100 00000106 000000000032e8ae 00000000 00000800      1      0 000000
udp4       0      0  *.3283                 *.*                                           0            0  225000    9216         ARDAgent:56420  00000 00000024 00000000002a548c 00000000 00000800      1      0 000000
udp4       0      0  192.0.2.10.5353        203.0.113.9.5353                              0            0  225000    9216      mDNSResponder:300  00000 00000024 00000000002a548c 00000000 00000800      1      0 000000
";
        let l = macos_listeners(text);
        let rows: Vec<String> = l
            .iter()
            .map(|l| {
                format!(
                    "{} {} {} {:?} {:?}",
                    l.proto, l.addr, l.port, l.process, l.pid
                )
            })
            .collect();
        assert_eq!(
            rows,
            vec![
                "TCP 127.0.0.1 631 Some(\"cupsd\") Some(25512)",
                "TCP * 28198 Some(\"Stream Deck\") Some(1970)",
                "TCP :: 22 Some(\"launchd\") Some(1)",
                "UDP 0.0.0.0 3283 Some(\"ARDAgent\") Some(56420)",
            ]
        );
        // Older netstat without the process column still parses.
        let old = "tcp4       0      0  *.22                   *.*                    LISTEN                 0            0  131072  131072\n";
        let l = macos_listeners(old);
        assert_eq!((l[0].port, l[0].process.clone()), (22, None));
    }

    #[test]
    fn linux_ip_json() {
        let addrs = r#"[{"ifindex":1,"ifname":"lo","flags":["LOOPBACK","UP","LOWER_UP"],"mtu":65536,"operstate":"UNKNOWN","address":"00:00:00:00:00:00","addr_info":[{"family":"inet","local":"127.0.0.1","prefixlen":8},{"family":"inet6","local":"::1","prefixlen":128}]},
            {"ifindex":2,"ifname":"eth0","flags":["BROADCAST","MULTICAST","UP","LOWER_UP"],"mtu":1500,"operstate":"UP","address":"02:00:00:00:00:01","addr_info":[{"family":"inet","local":"192.0.2.10","prefixlen":24}]},
            {"ifindex":3,"ifname":"wg0","flags":["POINTOPOINT","NOARP"],"mtu":1420,"operstate":"DOWN","addr_info":[]}]"#;
        let i = linux_addrs(addrs).unwrap();
        assert_eq!(i[0].up, Some(true));
        assert_eq!(i[0].addrs, vec!["127.0.0.1/8", "::1/128"]);
        assert_eq!(i[1].mac.as_deref(), Some("02:00:00:00:00:01"));
        assert_eq!((i[2].up, i[2].mac.clone()), (Some(false), None));
        assert!(linux_addrs("not json").is_err());

        let routes = r#"[{"dst":"default","gateway":"192.0.2.1","dev":"eth0","protocol":"dhcp","metric":100,"flags":[]},
            {"dst":"192.0.2.0/24","dev":"eth0","protocol":"kernel","scope":"link","prefsrc":"192.0.2.10","metric":100,"flags":[]},
            {"type":"blackhole","dst":"203.0.113.0/24","flags":[]},
            {"dst":"198.51.100.7","gateway":"192.0.2.254","dev":"eth0","flags":[]}]"#;
        let r = linux_routes(routes, "IPv4").unwrap();
        assert_eq!(r[0].dest, "default");
        assert_eq!(r[0].metric, Some(100));
        assert_eq!(r[1].gateway, "");
        assert_eq!(r[2].iface, "blackhole");
        assert_eq!(r[3].dest, "198.51.100.7/32");

        let neigh = r#"[{"dst":"192.0.2.1","dev":"eth0","lladdr":"02:00:00:00:00:bb","state":["REACHABLE"]},
            {"dst":"192.0.2.9","dev":"eth0","state":["FAILED"]},
            {"dst":"ff02::1","dev":"eth0","lladdr":"33:33:00:00:00:01","state":["NOARP"]}]"#;
        let n = linux_neighbors(neigh).unwrap();
        assert_eq!(n.len(), 2);
        assert_eq!(n[0].state, "reachable");
        assert_eq!(n[1].mac, "");
    }

    #[test]
    fn linux_ss() {
        let text = r#"tcp   LISTEN 0      4096   127.0.0.53%lo:53        0.0.0.0:*
tcp   LISTEN 0      128          0.0.0.0:22        0.0.0.0:*    users:(("sshd",pid=812,fd=3))
tcp   LISTEN 0      128             [::]:22           [::]:*
udp   UNCONN 0      0            0.0.0.0:5353      0.0.0.0:*    users:(("avahi-daemon",pid=700,fd=12))
udp   UNCONN 0      0     [fe80::1%eth0]:546          [::]:*
"#;
        let l = linux_listeners(text);
        let rows: Vec<String> = l
            .iter()
            .map(|l| format!("{} {} {} {:?}", l.proto, l.addr, l.port, l.process))
            .collect();
        assert_eq!(
            rows,
            vec![
                "TCP 127.0.0.53 53 None",
                "TCP 0.0.0.0 22 Some(\"sshd\")",
                "TCP :: 22 None",
                "UDP 0.0.0.0 5353 Some(\"avahi-daemon\")",
                "UDP fe80::1 546 None",
            ]
        );
    }

    #[test]
    fn linux_dns_sources() {
        let rc = "# generated\nnameserver 127.0.0.53\noptions edns0\nsearch example.com corp.example.com\n";
        let d = resolv_conf(rc).unwrap();
        assert_eq!(d.servers, vec!["127.0.0.53"]);
        assert_eq!(d.search, vec!["example.com", "corp.example.com"]);
        assert!(resolv_conf("# empty\n").is_none());

        let dns = "Global:\nLink 2 (eth0): 192.0.2.53 2001:db8::53\nLink 3 (wg0): 198.51.100.53#dns.example.net\n";
        let dom = "Global:\nLink 2 (eth0): corp.example.com\nLink 3 (wg0):\n";
        let s = resolvectl(dns, dom);
        assert_eq!(s.len(), 2);
        assert_eq!(s[0].scope, "eth0");
        assert_eq!(s[0].search, vec!["corp.example.com"]);
        assert_eq!(s[1].servers, vec!["198.51.100.53"]);
    }

    #[test]
    fn windows_json() {
        // Shapes as Windows PowerShell 5.1 writes them, including bare
        // objects where a list has one element.
        let json = "\u{feff}".to_string()
            + r#"{"adapters":{"Name":"Ethernet","Status":"Up","MacAddress":"02-00-00-00-00-01"},
            "addresses":[{"InterfaceAlias":"Ethernet","IPAddress":"192.0.2.10","PrefixLength":24},
                         {"InterfaceAlias":"Ethernet","IPAddress":"fe80::10%12","PrefixLength":64},
                         {"InterfaceAlias":"Loopback Pseudo-Interface 1","IPAddress":"127.0.0.1","PrefixLength":8}],
            "mtu":[{"InterfaceAlias":"Ethernet","NlMtu":1500},{"InterfaceAlias":"Loopback Pseudo-Interface 1","NlMtu":4294967295}],
            "routes":[{"DestinationPrefix":"0.0.0.0/0","NextHop":"192.0.2.1","InterfaceAlias":"Ethernet","RouteMetric":0},
                      {"DestinationPrefix":"192.0.2.0/24","NextHop":"0.0.0.0","InterfaceAlias":"Ethernet","RouteMetric":256},
                      {"DestinationPrefix":"::/0","NextHop":"fe80::1","InterfaceAlias":"Ethernet","RouteMetric":0}],
            "dns":[{"InterfaceAlias":"Ethernet","ServerAddresses":["192.0.2.53"]},
                   {"InterfaceAlias":"Ethernet","ServerAddresses":"2001:db8::53"},
                   {"InterfaceAlias":"Loopback Pseudo-Interface 1","ServerAddresses":[]}],
            "suffixes":[{"InterfaceAlias":"Ethernet","ConnectionSpecificSuffix":"corp.example.com"}],
            "searchList":["example.com"],
            "neighbors":[{"IPAddress":"192.0.2.1","LinkLayerAddress":"02-00-00-00-00-BB","InterfaceAlias":"Ethernet","State":"Reachable"},
                         {"IPAddress":"224.0.0.22","LinkLayerAddress":"01-00-5E-00-00-16","InterfaceAlias":"Ethernet","State":"Permanent"},
                         {"IPAddress":"192.0.2.77","LinkLayerAddress":"00-00-00-00-00-00","InterfaceAlias":"Ethernet","State":"Unreachable"}],
            "tcp":{"LocalAddress":"0.0.0.0","LocalPort":3389,"OwningProcess":1200},
            "udp":[],
            "procs":[{"Id":1200,"ProcessName":"svchost"}]}"#;
        let w = windows_all(&json).unwrap();
        assert_eq!(w.interfaces.len(), 2);
        assert_eq!(w.interfaces[0].mac.as_deref(), Some("02:00:00:00:00:01"));
        assert_eq!(w.interfaces[0].mtu, Some(1500));
        assert_eq!(w.interfaces[0].addrs, vec!["192.0.2.10/24", "fe80::10/64"]);
        assert_eq!(w.interfaces[1].name, "Loopback Pseudo-Interface 1");
        assert_eq!(w.routes[0].dest, "default");
        assert_eq!(w.routes[1].gateway, "");
        assert_eq!(w.routes[2].family, "IPv6");
        assert_eq!(w.dns.len(), 2);
        assert_eq!(w.dns[0].search, vec!["example.com"]);
        assert_eq!(w.dns[1].servers, vec!["192.0.2.53", "2001:db8::53"]);
        assert_eq!(w.dns[1].search, vec!["corp.example.com"]);
        assert_eq!(w.neighbors.len(), 1);
        assert_eq!(w.neighbors[0].state, "reachable");
        assert_eq!(w.listeners.len(), 1);
        assert_eq!(w.listeners[0].process.as_deref(), Some("svchost"));
        assert!(windows_all("garbage").is_err());
    }
    #[test]
    fn macos_lsof_fallback() {
        let text = "p1021\ncrapportd\nf11\nPTCP\nn*:49152\nf12\nPTCP\nn*:49152\nf31\nPUDP\nn*:3722\np1034\ncStream Deck\nf9\nPTCP\nn[::1]:28198\nf10\nPUDP\nn192.0.2.10:5353->203.0.113.9:5353\n";
        let l = macos_lsof(text);
        let rows: Vec<String> = l
            .iter()
            .map(|l| {
                format!(
                    "{} {} {} {:?} {:?}",
                    l.proto, l.addr, l.port, l.process, l.pid
                )
            })
            .collect();
        assert_eq!(
            rows,
            vec![
                "TCP * 49152 Some(\"rapportd\") Some(1021)",
                "UDP * 3722 Some(\"rapportd\") Some(1021)",
                "TCP ::1 28198 Some(\"Stream Deck\") Some(1034)",
            ]
        );
        assert!(!macos_has_inet(
            "Active LOCAL (UNIX) domain sockets\nAddress Type\n"
        ));
        assert!(macos_has_inet("tcp4 0 0 *.22 *.* LISTEN\n"));
    }
    #[test]
    fn windows_script_matches_parser() {
        // Every top-level key and per-row property the parser reads must be
        // produced by the script.
        for key in [
            "$o.adapters",
            "$o.addresses",
            "$o.mtu",
            "$o.routes",
            "$o.dns",
            "$o.suffixes",
            "$o.searchList",
            "$o.neighbors",
            "$o.tcp",
            "$o.udp",
            "$o.procs",
            "MacAddress",
            "PrefixLength",
            "NlMtu",
            "DestinationPrefix",
            "NextHop",
            "RouteMetric",
            "ServerAddresses",
            "ConnectionSpecificSuffix",
            "LinkLayerAddress",
            "LocalPort",
            "OwningProcess",
            "ProcessName",
            "-Compress",
        ] {
            assert!(WINDOWS_SCRIPT.contains(key), "script is missing {key}");
        }
        // Enums must be stringified (Windows PowerShell 5.1 writes numbers).
        assert!(WINDOWS_SCRIPT.contains("@{n='State';e={\"$($_.State)\"}}"));
        assert!(WINDOWS_SCRIPT.contains("@{n='Status';e={\"$($_.Status)\"}}"));
    }
}
