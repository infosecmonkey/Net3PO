//! IPsec VPN builder: gateway and tunnel status, then a filtered live IKE
//! debug. Filter options match FortiOS 7.6 (`diagnose vpn ike log filter`):
//! the peer is `rem-addr4`; FortiDebug Builder's `dst-addr4` is not accepted.

use std::net::Ipv6Addr;

use serde::Deserialize;

use super::{BuildResult, err, interface_name, opt_int, opt_ipv4, opt_port, present};

/// `diagnose vpn tunnel list name` takes up to this many names.
pub const MAX_TUNNEL_NAMES: usize = 8;

/// How to select tunnels for `diagnose vpn tunnel list`.
#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum TunnelBy {
    #[default]
    Name,
    Number,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct VpnInput {
    /// Gateway and tunnel lists before the debug.
    pub show_status: bool,
    /// Phase 1 name: filters the gateway list and the IKE log.
    pub gateway: String,
    pub tunnel_by: TunnelBy,
    /// Up to 8 tunnel names, comma or space separated.
    pub tunnels: String,
    pub tunnel_number: String,
    pub reset_first: bool,
    /// VDOM index; -1 matches all.
    pub vdom: String,
    pub rem_addr4: String,
    pub loc_addr4: String,
    pub rem_addr6: String,
    pub dst_port: String,
    /// Show the active filter before enabling the debug.
    pub list_filter: bool,
    pub timestamps: bool,
    /// `diagnose debug application ike` level; blank is -1.
    pub level: String,
    pub stop_block: bool,
}

impl Default for VpnInput {
    fn default() -> Self {
        VpnInput {
            show_status: true,
            gateway: String::new(),
            tunnel_by: TunnelBy::Name,
            tunnels: String::new(),
            tunnel_number: String::new(),
            reset_first: true,
            vdom: String::new(),
            rem_addr4: String::new(),
            loc_addr4: String::new(),
            rem_addr6: String::new(),
            dst_port: String::new(),
            list_filter: false,
            timestamps: true,
            level: String::new(),
            stop_block: true,
        }
    }
}

/// Optional phase 1 / tunnel name.
fn opt_name(field: &str, s: &str) -> BuildResult<Option<String>> {
    match present(s) {
        None => Ok(None),
        Some(_) => interface_name(field, s).map(Some),
    }
}

/// Integer that may be negative, within `[min, max]`.
fn opt_signed(field: &str, s: &str, min: i64, max: i64) -> BuildResult<Option<i64>> {
    match present(s) {
        None => Ok(None),
        Some(t) => match t.parse::<i64>() {
            Ok(n) if (min..=max).contains(&n) => Ok(Some(n)),
            _ => err(
                field,
                format!("'{t}' must be a whole number from {min} to {max}"),
            ),
        },
    }
}

/// Build the VPN status and IKE debug commands.
pub fn build(i: &VpnInput) -> BuildResult<String> {
    const F: &str = "diagnose vpn ike log filter";
    let gateway = opt_name("gateway", &i.gateway)?;
    let mut lines = Vec::new();

    if i.show_status {
        match &gateway {
            Some(g) => lines.push(format!("diagnose vpn ike gateway list name {g}")),
            None => lines.push("diagnose vpn ike gateway list".to_string()),
        }
        match i.tunnel_by {
            TunnelBy::Name => {
                let names: Vec<&str> = i
                    .tunnels
                    .split([',', ' '])
                    .filter(|n| !n.is_empty())
                    .collect();
                if names.len() > MAX_TUNNEL_NAMES {
                    return err(
                        "tunnels",
                        format!("at most {MAX_TUNNEL_NAMES} tunnel names"),
                    );
                }
                let checked = names
                    .iter()
                    .map(|n| interface_name("tunnels", n))
                    .collect::<BuildResult<Vec<_>>>()?;
                if checked.is_empty() {
                    lines.push("diagnose vpn tunnel list".to_string());
                } else {
                    lines.push(format!(
                        "diagnose vpn tunnel list name {}",
                        checked.join(" ")
                    ));
                }
            }
            TunnelBy::Number => match opt_int("tunnelNumber", &i.tunnel_number, 0, 1_000_000)? {
                Some(n) => lines.push(format!("diagnose vpn tunnel list number {n}")),
                None => return err("tunnelNumber", "enter a tunnel number"),
            },
        }
        lines.push(String::new());
    }

    lines.push("# Live IKE debug:".to_string());
    if i.reset_first {
        lines.push("diagnose debug disable".to_string());
        lines.push("diagnose debug reset".to_string());
    }
    lines.push(format!("{F} clear"));
    if let Some(v) = opt_signed("vdom", &i.vdom, -1, 65_535)? {
        lines.push(format!("{F} vd {v}"));
    }
    if let Some(g) = &gateway {
        lines.push(format!("{F} name {g}"));
    }
    if let Some(ip) = opt_ipv4("remAddr4", &i.rem_addr4)? {
        lines.push(format!("{F} rem-addr4 {ip}"));
    }
    if let Some(ip) = opt_ipv4("locAddr4", &i.loc_addr4)? {
        lines.push(format!("{F} loc-addr4 {ip}"));
    }
    if let Some(t) = present(&i.rem_addr6) {
        match t.parse::<Ipv6Addr>() {
            Ok(ip) => lines.push(format!("{F} rem-addr6 {ip}")),
            Err(_) => return err("remAddr6", format!("'{t}' is not an IPv6 address")),
        }
    }
    if let Some(p) = opt_port("dstPort", &i.dst_port)? {
        lines.push(format!("{F} dst-port {p}"));
    }
    if i.list_filter {
        lines.push(format!("{F} list"));
    }
    if i.timestamps {
        lines.push("diagnose debug console timestamp enable".to_string());
    }
    let level = opt_signed("level", &i.level, -1, 65_535)?.unwrap_or(-1);
    lines.push(format!("diagnose debug application ike {level}"));
    lines.push("diagnose debug enable".to_string());

    if i.stop_block {
        lines.push(String::new());
        lines.push("# When finished, stop the debug:".to_string());
        lines.push("diagnose debug disable".to_string());
        lines.push("diagnose debug reset".to_string());
    }
    Ok(lines.join("\n"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults() {
        assert_eq!(
            build(&VpnInput::default()).unwrap(),
            "diagnose vpn ike gateway list\n\
             diagnose vpn tunnel list\n\
             \n\
             # Live IKE debug:\n\
             diagnose debug disable\n\
             diagnose debug reset\n\
             diagnose vpn ike log filter clear\n\
             diagnose debug console timestamp enable\n\
             diagnose debug application ike -1\n\
             diagnose debug enable\n\
             \n\
             # When finished, stop the debug:\n\
             diagnose debug disable\n\
             diagnose debug reset"
        );
    }

    #[test]
    fn filters_use_76_syntax() {
        let i = VpnInput {
            show_status: false,
            gateway: "to-branch1".into(),
            reset_first: false,
            vdom: "-1".into(),
            rem_addr4: "203.0.113.10".into(),
            loc_addr4: "198.51.100.1".into(),
            rem_addr6: "2001:DB8::1".into(),
            dst_port: "4500".into(),
            list_filter: true,
            timestamps: false,
            level: "63".into(),
            stop_block: false,
            ..Default::default()
        };
        assert_eq!(
            build(&i).unwrap(),
            "# Live IKE debug:\n\
             diagnose vpn ike log filter clear\n\
             diagnose vpn ike log filter vd -1\n\
             diagnose vpn ike log filter name to-branch1\n\
             diagnose vpn ike log filter rem-addr4 203.0.113.10\n\
             diagnose vpn ike log filter loc-addr4 198.51.100.1\n\
             diagnose vpn ike log filter rem-addr6 2001:db8::1\n\
             diagnose vpn ike log filter dst-port 4500\n\
             diagnose vpn ike log filter list\n\
             diagnose debug application ike 63\n\
             diagnose debug enable"
        );
        assert!(!build(&i).unwrap().contains("dst-addr4"));
    }

    #[test]
    fn tunnel_selection() {
        let names = VpnInput {
            gateway: "hub".into(),
            tunnels: "spoke1, spoke2 spoke3".into(),
            ..Default::default()
        };
        let out = build(&names).unwrap();
        assert!(out.starts_with(
            "diagnose vpn ike gateway list name hub\ndiagnose vpn tunnel list name spoke1 spoke2 spoke3\n"
        ));
        let number = VpnInput {
            tunnel_by: TunnelBy::Number,
            tunnel_number: "4".into(),
            ..Default::default()
        };
        assert!(
            build(&number)
                .unwrap()
                .contains("diagnose vpn tunnel list number 4\n")
        );
    }

    #[test]
    fn validation() {
        let cases = [
            (
                VpnInput {
                    tunnels: "a b c d e f g h i".into(),
                    ..Default::default()
                },
                "tunnels",
            ),
            (
                VpnInput {
                    tunnels: "bad;name".into(),
                    ..Default::default()
                },
                "tunnels",
            ),
            (
                VpnInput {
                    tunnel_by: TunnelBy::Number,
                    ..Default::default()
                },
                "tunnelNumber",
            ),
            (
                VpnInput {
                    gateway: "my vpn".into(),
                    ..Default::default()
                },
                "gateway",
            ),
            (
                VpnInput {
                    vdom: "-2".into(),
                    ..Default::default()
                },
                "vdom",
            ),
            (
                VpnInput {
                    rem_addr4: "peer".into(),
                    ..Default::default()
                },
                "remAddr4",
            ),
            (
                VpnInput {
                    rem_addr6: "10.0.0.1".into(),
                    ..Default::default()
                },
                "remAddr6",
            ),
            (
                VpnInput {
                    level: "-5".into(),
                    ..Default::default()
                },
                "level",
            ),
        ];
        for (i, field) in cases {
            assert_eq!(build(&i).unwrap_err().field, field);
        }
    }
}
