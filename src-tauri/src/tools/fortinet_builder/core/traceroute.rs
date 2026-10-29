//! `execute traceroute-options` + `execute traceroute` builder.

use serde::Deserialize;

use super::{BuildResult, err, opt_int, opt_interface, opt_source, target_host};

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct TracerouteInput {
    pub target: String,
    pub source: String,
    pub device: String,
    pub queries: String,
    pub min_ttl: String,
    pub max_ttl: String,
    pub wait: String,
    pub view_settings: bool,
}

impl Default for TracerouteInput {
    fn default() -> Self {
        TracerouteInput {
            target: String::new(),
            source: String::new(),
            device: String::new(),
            queries: String::new(),
            min_ttl: String::new(),
            max_ttl: String::new(),
            wait: String::new(),
            view_settings: true,
        }
    }
}

/// Build the traceroute commands.
pub fn build(i: &TracerouteInput) -> BuildResult<String> {
    const O: &str = "exec traceroute-options";
    let target = target_host("target", &i.target)?;
    let min = opt_int("minTtl", &i.min_ttl, 1, 255)?;
    let max = opt_int("maxTtl", &i.max_ttl, 1, 255)?;
    if let (Some(lo), Some(hi)) = (min, max)
        && hi < lo
    {
        return err("maxTtl", "max TTL must be at least the min TTL");
    }

    let mut lines = Vec::new();
    if let Some(s) = opt_source("source", &i.source)? {
        lines.push(format!("{O} source {s}"));
    }
    if let Some(d) = opt_interface("device", &i.device)? {
        lines.push(format!("{O} device {d}"));
    }
    if let Some(q) = opt_int("queries", &i.queries, 1, 10)? {
        lines.push(format!("{O} queries {q}"));
    }
    if let Some(n) = min {
        lines.push(format!("{O} min-ttl {n}"));
    }
    if let Some(n) = max {
        lines.push(format!("{O} max-ttl {n}"));
    }
    if let Some(w) = opt_int("wait", &i.wait, 1, 60)? {
        lines.push(format!("{O} wait {w}"));
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
    fn all_options_in_swift_order() {
        let i = TracerouteInput {
            target: "1.1.1.1".into(),
            source: "auto".into(),
            device: "wan1".into(),
            queries: "3".into(),
            min_ttl: "2".into(),
            max_ttl: "20".into(),
            wait: "2".into(),
            view_settings: true,
        };
        assert_eq!(
            build(&i).unwrap(),
            "exec traceroute-options source auto\n\
             exec traceroute-options device wan1\n\
             exec traceroute-options queries 3\n\
             exec traceroute-options min-ttl 2\n\
             exec traceroute-options max-ttl 20\n\
             exec traceroute-options wait 2\n\
             exec traceroute-options view-settings\n\
             exec traceroute 1.1.1.1"
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
                    min_ttl: "10".into(),
                    max_ttl: "5".into(),
                    ..base.clone()
                },
                "maxTtl",
            ),
            (
                TracerouteInput {
                    wait: "0".into(),
                    ..base
                },
                "wait",
            ),
        ];
        for (i, field) in cases {
            assert_eq!(build(&i).unwrap_err().field, field);
        }
    }
}
