//! `diagnose sys session` filter builder: find live sessions by address, port,
//! protocol, and VDOM. All filters combine with AND on the FortiGate.

use serde::Deserialize;

use super::{BuildResult, opt_ipv4, opt_port, opt_vdom_index};

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SessionInput {
    pub clear_first: bool,
    pub vdom: String,
    pub src: String,
    pub dst: String,
    pub sport: String,
    pub dport: String,
    /// IP protocol number; None is any.
    pub proto: Option<u8>,
    pub negate: bool,
    pub stats: bool,
    pub list: bool,
}

impl Default for SessionInput {
    fn default() -> Self {
        SessionInput {
            clear_first: true,
            vdom: String::new(),
            src: String::new(),
            dst: String::new(),
            sport: String::new(),
            dport: String::new(),
            proto: None,
            negate: false,
            stats: false,
            list: true,
        }
    }
}

/// Build the session filter commands.
pub fn build(i: &SessionInput) -> BuildResult<String> {
    const F: &str = "diagnose sys session filter";
    let mut lines = Vec::new();
    if i.clear_first {
        lines.push(format!("{F} clear"));
    }
    if let Some(v) = opt_vdom_index("vdom", &i.vdom)? {
        lines.push(format!("{F} vd {v}"));
    }
    if let Some(ip) = opt_ipv4("src", &i.src)? {
        lines.push(format!("{F} src {ip}"));
    }
    if let Some(ip) = opt_ipv4("dst", &i.dst)? {
        lines.push(format!("{F} dst {ip}"));
    }
    if let Some(p) = opt_port("sport", &i.sport)? {
        lines.push(format!("{F} sport {p}"));
    }
    if let Some(p) = opt_port("dport", &i.dport)? {
        lines.push(format!("{F} dport {p}"));
    }
    if let Some(p) = i.proto {
        lines.push(format!("{F} proto {p}"));
    }
    if i.negate {
        lines.push(format!("{F} negate"));
    }
    if i.stats {
        lines.push("diagnose sys session stat".to_string());
    }
    if i.list {
        lines.push("diagnose sys session list".to_string());
    }
    Ok(lines.join("\n"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_clear_and_list() {
        assert_eq!(
            build(&SessionInput::default()).unwrap(),
            "diagnose sys session filter clear\ndiagnose sys session list"
        );
    }

    #[test]
    fn full_filter_matches_swift_order() {
        let i = SessionInput {
            vdom: "1".into(),
            src: "10.1.1.10".into(),
            dst: "8.8.8.8".into(),
            sport: "51000".into(),
            dport: "53".into(),
            proto: Some(17),
            negate: true,
            stats: true,
            ..Default::default()
        };
        assert_eq!(
            build(&i).unwrap(),
            "diagnose sys session filter clear\n\
             diagnose sys session filter vd 1\n\
             diagnose sys session filter src 10.1.1.10\n\
             diagnose sys session filter dst 8.8.8.8\n\
             diagnose sys session filter sport 51000\n\
             diagnose sys session filter dport 53\n\
             diagnose sys session filter proto 17\n\
             diagnose sys session filter negate\n\
             diagnose sys session stat\n\
             diagnose sys session list"
        );
    }

    #[test]
    fn rejects_bad_fields() {
        let bad_src = SessionInput {
            src: "10.0.0.1\ndiagnose sys reboot".into(),
            ..Default::default()
        };
        assert_eq!(build(&bad_src).unwrap_err().field, "src");
        let bad_port = SessionInput {
            dport: "99999".into(),
            ..Default::default()
        };
        assert_eq!(build(&bad_port).unwrap_err().field, "dport");
        let bad_vdom = SessionInput {
            vdom: "root".into(),
            ..Default::default()
        };
        assert_eq!(build(&bad_vdom).unwrap_err().field, "vdom");
    }
}
