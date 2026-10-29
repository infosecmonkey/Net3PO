//! Routing builder in three modes, as in FortiDebug Builder: OSPF, BGP, and
//! routing table / policy routes. Options were checked against FortiOS 7.6.7;
//! the live debugs can enable `all` or chosen areas, and the stop block always
//! disables all of them.

use serde::Deserialize;

use super::{BuildResult, err, opt_cidr, opt_ipv4};

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum Mode {
    #[default]
    Ospf,
    Bgp,
    Table,
}

/// `diagnose ip router ospf` debug areas.
pub const OSPF_AREAS: &[&str] = &["lsa", "packet", "events", "ifsm", "nfsm", "nsm", "route"];
/// `diagnose ip router bgp` debug areas.
pub const BGP_AREAS: &[&str] = &[
    "events",
    "fsm",
    "keepalives",
    "updates",
    "filters",
    "dampening",
    "nsm",
];
/// `get router info routing-table` views (details is a separate field).
pub const TABLE_VIEWS: &[&str] = &[
    "all",
    "static",
    "connected",
    "ospf",
    "bgp",
    "rip",
    "isis",
    "database",
];

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct RoutingInput {
    pub mode: Mode,
    // OSPF.
    pub ospf_status: bool,
    pub ospf_neighbor: bool,
    pub ospf_interface: bool,
    pub ospf_database: bool,
    pub ospf_route: bool,
    pub ospf_rib: bool,
    pub ospf_border_routers: bool,
    pub ospf_virtual_links: bool,
    pub ospf_debug: bool,
    /// Empty enables `all`.
    pub ospf_areas: Vec<String>,
    // BGP.
    pub bgp_summary: bool,
    pub bgp_peer: String,
    pub bgp_routes: bool,
    pub bgp_advertised: bool,
    pub bgp_received: bool,
    pub bgp_network: bool,
    /// Optional prefix for `bgp network`.
    pub bgp_prefix: String,
    pub bgp_debug: bool,
    pub bgp_areas: Vec<String>,
    // Routing table and policy routes.
    pub table_views: Vec<String>,
    pub details_ip: String,
    pub proute_list: bool,
    pub proute6_list: bool,
    pub proute_stats: bool,
    // Shared debug options.
    pub reset_first: bool,
    pub timestamps: bool,
    pub stop_block: bool,
}

impl Default for RoutingInput {
    fn default() -> Self {
        RoutingInput {
            mode: Mode::Ospf,
            ospf_status: true,
            ospf_neighbor: true,
            ospf_interface: false,
            ospf_database: false,
            ospf_route: false,
            ospf_rib: false,
            ospf_border_routers: false,
            ospf_virtual_links: false,
            ospf_debug: false,
            ospf_areas: Vec::new(),
            bgp_summary: true,
            bgp_peer: String::new(),
            bgp_routes: false,
            bgp_advertised: false,
            bgp_received: false,
            bgp_network: false,
            bgp_prefix: String::new(),
            bgp_debug: false,
            bgp_areas: Vec::new(),
            table_views: vec!["all".to_string()],
            details_ip: String::new(),
            proute_list: false,
            proute6_list: false,
            proute_stats: false,
            reset_first: true,
            timestamps: true,
            stop_block: true,
        }
    }
}

/// Validate chosen debug areas against an allowlist, in allowlist order.
fn areas<'a>(field: &str, chosen: &[String], allowed: &[&'a str]) -> BuildResult<Vec<&'a str>> {
    if let Some(bad) = chosen.iter().find(|c| !allowed.contains(&c.as_str())) {
        return err(field, format!("unknown debug area '{bad}'"));
    }
    Ok(allowed
        .iter()
        .copied()
        .filter(|a| chosen.iter().any(|c| c == a))
        .collect())
}

/// Live routing-protocol debug block for `proto` (`ospf` or `bgp`).
fn debug_block(
    lines: &mut Vec<String>,
    i: &RoutingInput,
    proto: &str,
    label: &str,
    chosen: &[&str],
) {
    let d = format!("diagnose ip router {proto}");
    if !lines.is_empty() {
        lines.push(String::new());
    }
    lines.push(format!("# Live {label} debug:"));
    if i.reset_first {
        lines.push("diagnose debug disable".into());
        lines.push("diagnose debug reset".into());
    }
    if i.timestamps {
        lines.push("diagnose debug console timestamp enable".into());
    }
    if chosen.is_empty() {
        lines.push(format!("{d} all enable"));
    } else {
        for a in chosen {
            lines.push(format!("{d} {a} enable"));
        }
    }
    lines.push(format!("{d} level info"));
    lines.push("diagnose debug enable".into());
    if i.stop_block {
        lines.push(String::new());
        lines.push("# When finished, stop the debug:".into());
        lines.push(format!("{d} all disable"));
        lines.push("diagnose debug disable".into());
        lines.push("diagnose debug reset".into());
    }
}

fn ospf(i: &RoutingInput) -> BuildResult<Vec<String>> {
    const G: &str = "get router info ospf";
    let mut lines = Vec::new();
    for (on, sub) in [
        (i.ospf_status, "status"),
        (i.ospf_neighbor, "neighbor"),
        (i.ospf_interface, "interface"),
        (i.ospf_database, "database"),
        (i.ospf_route, "route"),
        (i.ospf_border_routers, "border-routers"),
        (i.ospf_virtual_links, "virtual-links"),
    ] {
        if on {
            lines.push(format!("{G} {sub}"));
        }
    }
    if i.ospf_rib {
        lines.push("get router info routing-table ospf".into());
    }
    if i.ospf_debug {
        let chosen = areas("ospfAreas", &i.ospf_areas, OSPF_AREAS)?;
        debug_block(&mut lines, i, "ospf", "OSPF", &chosen);
    }
    Ok(lines)
}

fn bgp(i: &RoutingInput) -> BuildResult<Vec<String>> {
    const G: &str = "get router info bgp";
    let mut lines = Vec::new();
    if i.bgp_summary {
        lines.push(format!("{G} summary"));
    }
    match opt_ipv4("bgpPeer", &i.bgp_peer)? {
        Some(peer) => {
            lines.push(format!("{G} neighbors {peer}"));
            for (on, sub) in [
                (i.bgp_routes, "routes"),
                (i.bgp_advertised, "advertised-routes"),
                (i.bgp_received, "received-routes"),
            ] {
                if on {
                    lines.push(format!("{G} neighbors {peer} {sub}"));
                }
            }
        }
        None if i.bgp_routes || i.bgp_advertised || i.bgp_received => {
            return err("bgpPeer", "enter the neighbor IP for its routes");
        }
        None => {}
    }
    if i.bgp_network {
        match opt_cidr("bgpPrefix", &i.bgp_prefix)? {
            Some(p) => lines.push(format!("{G} network {p}")),
            None => lines.push(format!("{G} network")),
        }
    }
    if i.bgp_debug {
        let chosen = areas("bgpAreas", &i.bgp_areas, BGP_AREAS)?;
        debug_block(&mut lines, i, "bgp", "BGP", &chosen);
    }
    Ok(lines)
}

fn table(i: &RoutingInput) -> BuildResult<Vec<String>> {
    let mut lines = Vec::new();
    for v in areas("tableViews", &i.table_views, TABLE_VIEWS)? {
        lines.push(format!("get router info routing-table {v}"));
    }
    if let Some(ip) = opt_ipv4("detailsIp", &i.details_ip)? {
        lines.push(format!("get router info routing-table details {ip}"));
    }
    if i.proute_list {
        lines.push("diagnose firewall proute list".into());
    }
    if i.proute6_list {
        lines.push("diagnose firewall proute6 list".into());
    }
    if i.proute_stats {
        lines.push("diagnose firewall proute show".into());
    }
    Ok(lines)
}

/// Build the routing commands for the selected mode.
pub fn build(i: &RoutingInput) -> BuildResult<String> {
    let lines = match i.mode {
        Mode::Ospf => ospf(i)?,
        Mode::Bgp => bgp(i)?,
        Mode::Table => table(i)?,
    };
    if lines.is_empty() {
        return err("mode", "choose at least one command");
    }
    Ok(lines.join("\n"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ospf_reads_and_all_debug_match_swift() {
        let i = RoutingInput {
            ospf_interface: true,
            ospf_database: true,
            ospf_rib: true,
            ospf_debug: true,
            reset_first: false,
            ..Default::default()
        };
        assert_eq!(
            build(&i).unwrap(),
            "get router info ospf status\n\
             get router info ospf neighbor\n\
             get router info ospf interface\n\
             get router info ospf database\n\
             get router info routing-table ospf\n\
             \n\
             # Live OSPF debug:\n\
             diagnose debug console timestamp enable\n\
             diagnose ip router ospf all enable\n\
             diagnose ip router ospf level info\n\
             diagnose debug enable\n\
             \n\
             # When finished, stop the debug:\n\
             diagnose ip router ospf all disable\n\
             diagnose debug disable\n\
             diagnose debug reset"
        );
    }

    #[test]
    fn ospf_selected_areas() {
        let i = RoutingInput {
            ospf_status: false,
            ospf_neighbor: false,
            ospf_debug: true,
            ospf_areas: vec!["nfsm".into(), "lsa".into()],
            reset_first: false,
            timestamps: false,
            stop_block: false,
            ..Default::default()
        };
        assert_eq!(
            build(&i).unwrap(),
            "# Live OSPF debug:\n\
             diagnose ip router ospf lsa enable\n\
             diagnose ip router ospf nfsm enable\n\
             diagnose ip router ospf level info\n\
             diagnose debug enable"
        );
    }

    #[test]
    fn bgp_neighbor_views() {
        let i = RoutingInput {
            mode: Mode::Bgp,
            bgp_peer: "169.254.0.1".into(),
            bgp_routes: true,
            bgp_advertised: true,
            bgp_received: true,
            bgp_network: true,
            bgp_prefix: "10.0.0.0/8".into(),
            ..Default::default()
        };
        assert_eq!(
            build(&i).unwrap(),
            "get router info bgp summary\n\
             get router info bgp neighbors 169.254.0.1\n\
             get router info bgp neighbors 169.254.0.1 routes\n\
             get router info bgp neighbors 169.254.0.1 advertised-routes\n\
             get router info bgp neighbors 169.254.0.1 received-routes\n\
             get router info bgp network 10.0.0.0/8"
        );
    }

    #[test]
    fn bgp_debug_areas() {
        let i = RoutingInput {
            mode: Mode::Bgp,
            bgp_summary: false,
            bgp_debug: true,
            bgp_areas: vec!["fsm".into(), "events".into()],
            stop_block: false,
            ..Default::default()
        };
        assert_eq!(
            build(&i).unwrap(),
            "# Live BGP debug:\n\
             diagnose debug disable\n\
             diagnose debug reset\n\
             diagnose debug console timestamp enable\n\
             diagnose ip router bgp events enable\n\
             diagnose ip router bgp fsm enable\n\
             diagnose ip router bgp level info\n\
             diagnose debug enable"
        );
    }

    #[test]
    fn table_and_policy_routes() {
        let i = RoutingInput {
            mode: Mode::Table,
            table_views: vec!["static".into(), "connected".into()],
            details_ip: "8.8.8.8".into(),
            proute_list: true,
            proute6_list: true,
            proute_stats: true,
            ..Default::default()
        };
        assert_eq!(
            build(&i).unwrap(),
            "get router info routing-table static\n\
             get router info routing-table connected\n\
             get router info routing-table details 8.8.8.8\n\
             diagnose firewall proute list\n\
             diagnose firewall proute6 list\n\
             diagnose firewall proute show"
        );
    }

    #[test]
    fn validation() {
        let cases = [
            (
                RoutingInput {
                    mode: Mode::Bgp,
                    bgp_routes: true,
                    ..Default::default()
                },
                "bgpPeer",
            ),
            (
                RoutingInput {
                    mode: Mode::Bgp,
                    bgp_peer: "peer1".into(),
                    ..Default::default()
                },
                "bgpPeer",
            ),
            (
                RoutingInput {
                    mode: Mode::Bgp,
                    bgp_network: true,
                    bgp_prefix: "10.0.0.0/40".into(),
                    ..Default::default()
                },
                "bgpPrefix",
            ),
            (
                RoutingInput {
                    ospf_debug: true,
                    ospf_areas: vec!["all; x".into()],
                    ..Default::default()
                },
                "ospfAreas",
            ),
            (
                RoutingInput {
                    mode: Mode::Table,
                    table_views: vec!["eigrp".into()],
                    ..Default::default()
                },
                "tableViews",
            ),
            (
                RoutingInput {
                    mode: Mode::Table,
                    details_ip: "host".into(),
                    ..Default::default()
                },
                "detailsIp",
            ),
            (
                RoutingInput {
                    mode: Mode::Table,
                    table_views: vec![],
                    ..Default::default()
                },
                "mode",
            ),
        ];
        for (i, field) in cases {
            assert_eq!(build(&i).unwrap_err().field, field);
        }
    }
}
