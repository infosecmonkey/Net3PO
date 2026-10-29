//! `execute traceroute-options` + `execute traceroute` builder. Options match
//! a live FortiGate's list: device, queries, reset, source, use-sdwan,
//! view-settings, vrf. (FortiDebug Builder also emitted min-ttl, max-ttl and
//! wait, which FortiOS does not accept.) Options persist for the admin
//! session, so resetting first avoids inheriting stale settings.

use serde::Deserialize;

use super::{BuildResult, opt_int, opt_interface, opt_source, target_host};

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct TracerouteInput {
    pub target: String,
    pub reset_first: bool,
    pub source: String,
    /// Interface name or `auto`.
    pub device: String,
    pub queries: String,
    /// VRF ID.
    pub vrf: String,
    /// Pick the egress interface from SD-WAN rules.
    pub use_sdwan: bool,
    pub view_settings: bool,
}

impl Default for TracerouteInput {
    fn default() -> Self {
        TracerouteInput {
            target: String::new(),
            reset_first: true,
            source: String::new(),
            device: String::new(),
            queries: String::new(),
            vrf: String::new(),
            use_sdwan: false,
            view_settings: true,
        }
    }
}

/// Build the traceroute commands.
pub fn build(i: &TracerouteInput) -> BuildResult<String> {
    const O: &str = "exec traceroute-options";
    let target = target_host("target", &i.target)?;
    let mut lines = Vec::new();
    if i.reset_first {
        lines.push(format!("{O} reset"));
    }
    if let Some(s) = opt_source("source", &i.source)? {
        lines.push(format!("{O} source {s}"));
    }
    if let Some(d) = opt_interface("device", &i.device)? {
        lines.push(format!("{O} device {d}"));
    }
    if let Some(q) = opt_int("queries", &i.queries, 1, 10)? {
        lines.push(format!("{O} queries {q}"));
    }
    if let Some(n) = opt_int("vrf", &i.vrf, 0, 511)? {
        lines.push(format!("{O} vrf {n}"));
    }
    if i.use_sdwan {
        lines.push(format!("{O} use-sdwan yes"));
    }
    if i.view_settings {
        lines.push(format!("{O} view-settings"));
    }
    lines.push(format!("exec traceroute {target}"));
    Ok(lines.join("\n"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimal() {
        let i = TracerouteInput {
            target: "1.1.1.1".into(),
            ..Default::default()
        };
        assert_eq!(
            build(&i).unwrap(),
            "exec traceroute-options reset\n\
             exec traceroute-options view-settings\n\
             exec traceroute 1.1.1.1"
        );
    }

    #[test]
    fn all_options() {
        let i = TracerouteInput {
            target: "fortinet.com".into(),
            reset_first: false,
            source: "auto".into(),
            device: "wan1".into(),
            queries: "3".into(),
            vrf: "2".into(),
            use_sdwan: true,
            view_settings: true,
        };
        assert_eq!(
            build(&i).unwrap(),
            "exec traceroute-options source auto\n\
             exec traceroute-options device wan1\n\
             exec traceroute-options queries 3\n\
             exec traceroute-options vrf 2\n\
             exec traceroute-options use-sdwan yes\n\
             exec traceroute-options view-settings\n\
             exec traceroute fortinet.com"
        );
    }

    #[test]
    fn device_accepts_auto() {
        let i = TracerouteInput {
            target: "1.1.1.1".into(),
            reset_first: false,
            device: "auto".into(),
            view_settings: false,
            ..Default::default()
        };
        assert_eq!(
            build(&i).unwrap(),
            "exec traceroute-options device auto\nexec traceroute 1.1.1.1"
        );
    }

    #[test]
    fn validation() {
        let base = TracerouteInput {
            target: "1.1.1.1".into(),
            ..Default::default()
        };
        let cases = [
            (
                TracerouteInput {
                    target: "x;y".into(),
                    ..base.clone()
                },
                "target",
            ),
            (
                TracerouteInput {
                    queries: "11".into(),
                    ..base.clone()
                },
                "queries",
            ),
            (
                TracerouteInput {
                    vrf: "-1".into(),
                    ..base.clone()
                },
                "vrf",
            ),
            (
                TracerouteInput {
                    device: "wan 1".into(),
                    ..base
                },
                "device",
            ),
        ];
        for (i, field) in cases {
            assert_eq!(build(&i).unwrap_err().field, field);
        }
    }
}
