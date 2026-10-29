//! `diagnose debug flow` trace builder: how the FortiGate handles a packet
//! (route lookup, policy, NAT, session). Narrow filters matter: an unfiltered
//! trace on a busy unit floods the console.

use serde::Deserialize;

use super::{BuildResult, opt_int, opt_ipv4, opt_port, opt_vdom_index};

/// Trace count used when the field is blank.
pub const DEFAULT_TRACE_COUNT: u64 = 1000;
/// Largest trace count accepted.
pub const MAX_TRACE_COUNT: u64 = 100_000;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct FlowInput {
    pub reset_first: bool,
    pub vdom: String,
    pub addr: String,
    pub saddr: String,
    pub daddr: String,
    pub port: String,
    pub sport: String,
    pub dport: String,
    pub proto: Option<u8>,
    pub show_function_name: bool,
    pub show_iprope: bool,
    pub timestamps: bool,
    pub trace_count: String,
    pub stop_block: bool,
}

impl Default for FlowInput {
    fn default() -> Self {
        FlowInput {
            reset_first: true,
            vdom: String::new(),
            addr: String::new(),
            saddr: String::new(),
            daddr: String::new(),
            port: String::new(),
            sport: String::new(),
            dport: String::new(),
            proto: None,
            show_function_name: true,
            show_iprope: false,
            timestamps: true,
            trace_count: String::new(),
            stop_block: true,
        }
    }
}

/// Build the flow trace commands.
pub fn build(i: &FlowInput) -> BuildResult<String> {
    const F: &str = "diagnose debug flow filter";
    let mut lines = Vec::new();
    if i.reset_first {
        lines.push("diagnose debug disable".to_string());
        lines.push("diagnose debug reset".to_string());
    }
    lines.push(format!("{F} clear"));
    if let Some(v) = opt_vdom_index("vdom", &i.vdom)? {
        lines.push(format!("{F} vd {v}"));
    }
    for (field, value) in [("addr", &i.addr), ("saddr", &i.saddr), ("daddr", &i.daddr)] {
        if let Some(ip) = opt_ipv4(field, value)? {
            lines.push(format!("{F} {field} {ip}"));
        }
    }
    for (field, value) in [("port", &i.port), ("sport", &i.sport), ("dport", &i.dport)] {
        if let Some(p) = opt_port(field, value)? {
            lines.push(format!("{F} {field} {p}"));
        }
    }
    if let Some(p) = i.proto {
        lines.push(format!("{F} proto {p}"));
    }
    if i.show_function_name {
        lines.push("diagnose debug flow show function-name enable".to_string());
    }
    if i.show_iprope {
        lines.push("diagnose debug flow show iprope enable".to_string());
    }
    if i.timestamps {
        lines.push("diagnose debug console timestamp enable".to_string());
    }
    let count =
        opt_int("traceCount", &i.trace_count, 1, MAX_TRACE_COUNT)?.unwrap_or(DEFAULT_TRACE_COUNT);
    lines.push(format!("diagnose debug flow trace start {count}"));
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
            build(&FlowInput::default()).unwrap(),
            "diagnose debug disable\n\
             diagnose debug reset\n\
             diagnose debug flow filter clear\n\
             diagnose debug flow show function-name enable\n\
             diagnose debug console timestamp enable\n\
             diagnose debug flow trace start 1000\n\
             diagnose debug enable\n\
             \n\
             # When finished, stop the debug:\n\
             diagnose debug disable\n\
             diagnose debug reset"
        );
    }

    #[test]
    fn filters_in_swift_order() {
        let i = FlowInput {
            reset_first: false,
            vdom: "2".into(),
            addr: "10.0.0.5".into(),
            daddr: "1.1.1.1".into(),
            dport: "443".into(),
            proto: Some(6),
            show_function_name: false,
            show_iprope: true,
            timestamps: false,
            trace_count: "50".into(),
            stop_block: false,
            ..Default::default()
        };
        assert_eq!(
            build(&i).unwrap(),
            "diagnose debug flow filter clear\n\
             diagnose debug flow filter vd 2\n\
             diagnose debug flow filter addr 10.0.0.5\n\
             diagnose debug flow filter daddr 1.1.1.1\n\
             diagnose debug flow filter dport 443\n\
             diagnose debug flow filter proto 6\n\
             diagnose debug flow show iprope enable\n\
             diagnose debug flow trace start 50\n\
             diagnose debug enable"
        );
    }

    #[test]
    fn rejects_bad_count_and_address() {
        let i = FlowInput {
            trace_count: "0".into(),
            ..Default::default()
        };
        assert_eq!(build(&i).unwrap_err().field, "traceCount");
        let i = FlowInput {
            saddr: "host1".into(),
            ..Default::default()
        };
        assert_eq!(build(&i).unwrap_err().field, "saddr");
    }
}
