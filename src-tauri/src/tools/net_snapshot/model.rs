//! Snapshot data model and the snapshot diff. Pure: no OS calls, so the
//! comparison logic is unit tested on every platform.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// One network interface.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", default)]
pub struct Interface {
    pub name: String,
    /// Hardware address, lower case with colons, when the OS reports one.
    pub mac: Option<String>,
    pub mtu: Option<u32>,
    /// Administrative or link state as the OS reports it.
    pub up: Option<bool>,
    /// Addresses in CIDR form (`192.0.2.10/24`, `2001:db8::10/64`).
    pub addrs: Vec<String>,
}

/// One routing table entry.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", default)]
pub struct Route {
    /// "IPv4" or "IPv6".
    pub family: String,
    /// Destination in CIDR form, or "default".
    pub dest: String,
    /// Next hop, or empty for on-link routes.
    pub gateway: String,
    pub iface: String,
    pub metric: Option<u32>,
}

/// DNS servers that apply to one scope (global, an interface or a domain).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", default)]
pub struct DnsScope {
    /// "Global", an interface name, or "domain example.com".
    pub scope: String,
    pub servers: Vec<String>,
    pub search: Vec<String>,
}

/// One ARP (IPv4) or neighbor discovery (IPv6) entry.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", default)]
pub struct Neighbor {
    pub ip: String,
    /// Empty when the entry is incomplete.
    pub mac: String,
    pub iface: String,
    pub state: String,
}

/// One listening TCP socket or bound UDP socket.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", default)]
pub struct Listener {
    /// "TCP" or "UDP".
    pub proto: String,
    /// Local address, `*` for all addresses.
    pub addr: String,
    pub port: u16,
    /// Process name, when the OS shows it to a normal user.
    pub process: Option<String>,
    pub pid: Option<u32>,
}

/// Where one section came from, and whether collecting it worked.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", default)]
pub struct Source {
    pub section: String,
    pub command: String,
    pub ok: bool,
    /// Why it failed, or a limitation worth knowing.
    pub note: String,
}

/// A point-in-time view of this computer's network configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", default)]
pub struct Snapshot {
    /// Stable id (also the file name in the snapshot store).
    pub id: String,
    /// User label, empty by default.
    pub label: String,
    /// When it was taken, RFC 3339 with offset.
    pub taken: String,
    pub host: String,
    /// "macOS", "Linux" or "Windows".
    pub os: String,
    pub interfaces: Vec<Interface>,
    pub routes: Vec<Route>,
    pub dns: Vec<DnsScope>,
    pub neighbors: Vec<Neighbor>,
    pub listeners: Vec<Listener>,
    pub sources: Vec<Source>,
}

/// One row that differs between two snapshots.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Change {
    /// "added", "removed" or "changed".
    pub kind: String,
    /// What identifies the row, such as the interface name or route.
    pub key: String,
    /// The row in snapshot A (empty when added).
    pub before: String,
    /// The row in snapshot B (empty when removed).
    pub after: String,
    /// For "changed": which fields differ.
    pub fields: Vec<String>,
}

/// Differences in one section.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SectionDiff {
    pub section: String,
    pub changes: Vec<Change>,
    /// Rows present and identical in both.
    pub unchanged: usize,
}

/// A row type that can be compared across snapshots.
trait Row {
    /// What identifies the row across snapshots.
    fn key(&self) -> String;
    /// One-line rendering for the diff view.
    fn line(&self) -> String;
    /// Names of the fields that differ from `other` (same key).
    fn fields(&self, other: &Self) -> Vec<String>;
}

fn opt<T: ToString>(v: &Option<T>) -> String {
    v.as_ref()
        .map(|x| x.to_string())
        .unwrap_or_else(|| "-".into())
}

fn diff_field<T: PartialEq>(out: &mut Vec<String>, name: &str, a: &T, b: &T) {
    if a != b {
        out.push(name.to_string());
    }
}

fn sorted(v: &[String]) -> Vec<String> {
    let mut v = v.to_vec();
    v.sort();
    v
}

impl Row for Interface {
    fn key(&self) -> String {
        self.name.clone()
    }
    fn line(&self) -> String {
        let state = match self.up {
            Some(true) => "up",
            Some(false) => "down",
            None => "-",
        };
        format!(
            "{}  {}  mtu {}  mac {}  {}",
            self.name,
            state,
            opt(&self.mtu),
            self.mac.as_deref().unwrap_or("-"),
            if self.addrs.is_empty() {
                "no addresses".to_string()
            } else {
                sorted(&self.addrs).join(", ")
            }
        )
    }
    fn fields(&self, o: &Self) -> Vec<String> {
        let mut f = Vec::new();
        diff_field(&mut f, "state", &self.up, &o.up);
        diff_field(&mut f, "MTU", &self.mtu, &o.mtu);
        diff_field(&mut f, "MAC", &self.mac, &o.mac);
        diff_field(&mut f, "addresses", &sorted(&self.addrs), &sorted(&o.addrs));
        f
    }
}

impl Row for Route {
    fn key(&self) -> String {
        let via = if self.gateway.is_empty() {
            "on-link".to_string()
        } else {
            format!("via {}", self.gateway)
        };
        format!("{} {} {} dev {}", self.family, self.dest, via, self.iface)
    }
    fn line(&self) -> String {
        format!("{}  metric {}", self.key(), opt(&self.metric))
    }
    fn fields(&self, o: &Self) -> Vec<String> {
        let mut f = Vec::new();
        diff_field(&mut f, "metric", &self.metric, &o.metric);
        f
    }
}

impl Row for DnsScope {
    fn key(&self) -> String {
        self.scope.clone()
    }
    fn line(&self) -> String {
        let mut s = format!("{}: {}", self.scope, self.servers.join(", "));
        if !self.search.is_empty() {
            s.push_str(&format!("  search {}", self.search.join(" ")));
        }
        s
    }
    fn fields(&self, o: &Self) -> Vec<String> {
        let mut f = Vec::new();
        diff_field(&mut f, "servers", &self.servers, &o.servers);
        diff_field(&mut f, "search domains", &self.search, &o.search);
        f
    }
}

impl Row for Neighbor {
    fn key(&self) -> String {
        format!("{} on {}", self.ip, self.iface)
    }
    fn line(&self) -> String {
        let mac = if self.mac.is_empty() {
            "(incomplete)"
        } else {
            &self.mac
        };
        format!("{} on {}  {}  {}", self.ip, self.iface, mac, self.state)
    }
    fn fields(&self, o: &Self) -> Vec<String> {
        // State changes (reachable, stale, ...) are routine churn; a MAC
        // change for the same IP is what matters.
        let mut f = Vec::new();
        diff_field(&mut f, "MAC", &self.mac, &o.mac);
        f
    }
}

impl Row for Listener {
    fn key(&self) -> String {
        format!("{} {}:{}", self.proto, self.addr, self.port)
    }
    fn line(&self) -> String {
        let who = match (&self.process, self.pid) {
            (Some(p), Some(pid)) => format!("{p} (pid {pid})"),
            (Some(p), None) => p.clone(),
            (None, Some(pid)) => format!("pid {pid}"),
            (None, None) => "process not visible".into(),
        };
        format!("{}  {}", self.key(), who)
    }
    fn fields(&self, o: &Self) -> Vec<String> {
        // A restarted service gets a new pid; only a different program counts.
        let mut f = Vec::new();
        if self.process.is_some() && o.process.is_some() {
            diff_field(&mut f, "process", &self.process, &o.process);
        }
        f
    }
}

fn diff_rows<T: Row>(section: &str, a: &[T], b: &[T]) -> SectionDiff {
    // Several rows can share a key (ECMP routes, duplicate listeners); keep
    // the first of each, which is what the panel shows.
    let index = |v: &[T]| {
        let mut m: BTreeMap<String, usize> = BTreeMap::new();
        for (i, r) in v.iter().enumerate() {
            m.entry(r.key()).or_insert(i);
        }
        m
    };
    let (ia, ib) = (index(a), index(b));
    let mut changes = Vec::new();
    let mut unchanged = 0;
    for (k, &i) in &ia {
        match ib.get(k) {
            None => changes.push(Change {
                kind: "removed".into(),
                key: k.clone(),
                before: a[i].line(),
                after: String::new(),
                fields: Vec::new(),
            }),
            Some(&j) => {
                let fields = a[i].fields(&b[j]);
                if fields.is_empty() {
                    unchanged += 1;
                } else {
                    changes.push(Change {
                        kind: "changed".into(),
                        key: k.clone(),
                        before: a[i].line(),
                        after: b[j].line(),
                        fields,
                    });
                }
            }
        }
    }
    for (k, &j) in &ib {
        if !ia.contains_key(k) {
            changes.push(Change {
                kind: "added".into(),
                key: k.clone(),
                before: String::new(),
                after: b[j].line(),
                fields: Vec::new(),
            });
        }
    }
    changes.sort_by(|x, y| x.key.cmp(&y.key).then(x.kind.cmp(&y.kind)));
    SectionDiff {
        section: section.into(),
        changes,
        unchanged,
    }
}

/// Section names, in display order.
pub const SECTIONS: [&str; 5] = [
    "Interfaces",
    "Routes",
    "DNS",
    "Neighbors",
    "Listening ports",
];

/// Compare snapshot `a` (before) with `b` (after), section by section.
pub fn compare(a: &Snapshot, b: &Snapshot) -> Vec<SectionDiff> {
    vec![
        diff_rows(SECTIONS[0], &a.interfaces, &b.interfaces),
        diff_rows(SECTIONS[1], &a.routes, &b.routes),
        diff_rows(SECTIONS[2], &a.dns, &b.dns),
        diff_rows(SECTIONS[3], &a.neighbors, &b.neighbors),
        diff_rows(SECTIONS[4], &a.listeners, &b.listeners),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn iface(name: &str, addrs: &[&str], mtu: u32) -> Interface {
        Interface {
            name: name.into(),
            mac: Some("02:00:00:00:00:01".into()),
            mtu: Some(mtu),
            up: Some(true),
            addrs: addrs.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn interface_changes_added_and_removed() {
        let a = Snapshot {
            interfaces: vec![
                iface("eth0", &["192.0.2.10/24"], 1500),
                iface("wg0", &[], 1420),
            ],
            ..Default::default()
        };
        let b = Snapshot {
            interfaces: vec![
                iface("eth0", &["192.0.2.11/24"], 1400),
                iface("tun0", &["198.51.100.2/32"], 1400),
            ],
            ..Default::default()
        };
        let d = &compare(&a, &b)[0];
        assert_eq!(d.unchanged, 0);
        let kinds: Vec<_> = d
            .changes
            .iter()
            .map(|c| (c.kind.as_str(), c.key.as_str()))
            .collect();
        assert_eq!(
            kinds,
            vec![("changed", "eth0"), ("added", "tun0"), ("removed", "wg0")]
        );
        assert_eq!(d.changes[0].fields, vec!["MTU", "addresses"]);
    }

    #[test]
    fn address_order_does_not_matter() {
        let a = Snapshot {
            interfaces: vec![iface("en0", &["192.0.2.1/24", "2001:db8::1/64"], 1500)],
            ..Default::default()
        };
        let b = Snapshot {
            interfaces: vec![iface("en0", &["2001:db8::1/64", "192.0.2.1/24"], 1500)],
            ..Default::default()
        };
        let d = &compare(&a, &b)[0];
        assert!(d.changes.is_empty());
        assert_eq!(d.unchanged, 1);
    }

    #[test]
    fn neighbor_mac_change_is_flagged_state_is_not() {
        let n = |mac: &str, state: &str| Neighbor {
            ip: "192.0.2.1".into(),
            mac: mac.into(),
            iface: "en0".into(),
            state: state.into(),
        };
        let a = Snapshot {
            neighbors: vec![n("02:00:00:00:00:aa", "reachable")],
            ..Default::default()
        };
        let b = Snapshot {
            neighbors: vec![n("02:00:00:00:00:aa", "stale")],
            ..Default::default()
        };
        assert!(compare(&a, &b)[3].changes.is_empty());
        let b = Snapshot {
            neighbors: vec![n("02:00:00:00:00:bb", "reachable")],
            ..Default::default()
        };
        let d = &compare(&a, &b)[3];
        assert_eq!(d.changes.len(), 1);
        assert_eq!(d.changes[0].fields, vec!["MAC"]);
    }

    #[test]
    fn route_metric_change_and_new_default() {
        let r = |dest: &str, gw: &str, metric: u32| Route {
            family: "IPv4".into(),
            dest: dest.into(),
            gateway: gw.into(),
            iface: "eth0".into(),
            metric: Some(metric),
        };
        let a = Snapshot {
            routes: vec![r("default", "192.0.2.1", 100), r("192.0.2.0/24", "", 0)],
            ..Default::default()
        };
        let b = Snapshot {
            routes: vec![
                r("default", "192.0.2.1", 600),
                r("default", "192.0.2.254", 50),
                r("192.0.2.0/24", "", 0),
            ],
            ..Default::default()
        };
        let d = &compare(&a, &b)[1];
        assert_eq!(d.unchanged, 1);
        let kinds: Vec<_> = d.changes.iter().map(|c| c.kind.as_str()).collect();
        assert_eq!(kinds, vec!["changed", "added"]);
        assert_eq!(d.changes[0].fields, vec!["metric"]);
    }

    #[test]
    fn listener_pid_change_is_not_a_change() {
        let l = |pid: u32, proc_: &str| Listener {
            proto: "TCP".into(),
            addr: "*".into(),
            port: 22,
            process: Some(proc_.into()),
            pid: Some(pid),
        };
        let a = Snapshot {
            listeners: vec![l(100, "sshd")],
            ..Default::default()
        };
        let b = Snapshot {
            listeners: vec![l(200, "sshd")],
            ..Default::default()
        };
        assert!(compare(&a, &b)[4].changes.is_empty());
        let b = Snapshot {
            listeners: vec![l(200, "nc")],
            ..Default::default()
        };
        assert_eq!(compare(&a, &b)[4].changes[0].fields, vec!["process"]);
    }
}
