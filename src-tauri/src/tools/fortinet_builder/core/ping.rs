//! `execute ping-options` + `execute ping` builder. Ping options persist for
//! the admin session, so resetting first avoids inheriting stale settings.

use serde::Deserialize;

use super::{BuildResult, err, opt_int, opt_interface, opt_source, present, target_host};

/// `ping-options tos` keywords.
pub const TOS: &[&str] = &[
    "default",
    "lowcost",
    "lowdelay",
    "throughput",
    "reliability",
];

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct PingInput {
    pub target: String,
    pub reset_first: bool,
    pub source: String,
    pub interface: String,
    pub repeat_count: String,
    pub timeout: String,
    pub data_size: String,
    /// TOS keyword, or empty to omit.
    pub tos: String,
    pub pattern: String,
    /// Seconds between pings.
    pub interval: String,
    pub ttl: String,
    /// VRF ID.
    pub vrf: String,
    /// Pick the egress interface from SD-WAN rules.
    pub use_sdwan: bool,
    pub df_bit: bool,
    pub adaptive: bool,
    pub validate_reply: bool,
    pub view_settings: bool,
}

impl Default for PingInput {
    fn default() -> Self {
        PingInput {
            target: String::new(),
            reset_first: true,
            source: String::new(),
            interface: String::new(),
            repeat_count: String::new(),
            timeout: String::new(),
            data_size: String::new(),
            tos: String::new(),
            pattern: String::new(),
            interval: String::new(),
            ttl: String::new(),
            vrf: String::new(),
            use_sdwan: false,
            df_bit: false,
            adaptive: false,
            validate_reply: false,
            view_settings: true,
        }
    }
}

/// Hex payload pattern, up to 16 bytes.
fn opt_pattern(field: &str, s: &str) -> BuildResult<Option<String>> {
    match present(s) {
        None => Ok(None),
        Some(t) if t.len() <= 32 && t.chars().all(|c| c.is_ascii_hexdigit()) => {
            Ok(Some(t.to_ascii_lowercase()))
        }
        Some(_) => err(
            field,
            "pattern is hex digits only, up to 32 (16 bytes), e.g. ff",
        ),
    }
}

/// Build the ping commands.
pub fn build(i: &PingInput) -> BuildResult<String> {
    const O: &str = "exec ping-options";
    let target = target_host("target", &i.target)?;
    let mut lines = Vec::new();
    if i.reset_first {
        lines.push(format!("{O} reset"));
    }
    if let Some(s) = opt_source("source", &i.source)? {
        lines.push(format!("{O} source {s}"));
    }
    if let Some(n) = opt_interface("interface", &i.interface)? {
        lines.push(format!("{O} interface {n}"));
    }
    if let Some(n) = opt_int("repeatCount", &i.repeat_count, 1, 2_147_483_647)? {
        lines.push(format!("{O} repeat-count {n}"));
    }
    if let Some(n) = opt_int("timeout", &i.timeout, 1, 3600)? {
        lines.push(format!("{O} timeout {n}"));
    }
    if let Some(n) = opt_int("dataSize", &i.data_size, 0, 65_507)? {
        lines.push(format!("{O} data-size {n}"));
    }
    if let Some(t) = present(&i.tos) {
        match TOS.iter().find(|k| k.eq_ignore_ascii_case(t)) {
            Some(k) => lines.push(format!("{O} tos {k}")),
            None => return err("tos", format!("unknown TOS keyword '{t}'")),
        }
    }
    if let Some(p) = opt_pattern("pattern", &i.pattern)? {
        lines.push(format!("{O} pattern {p}"));
    }
    if let Some(n) = opt_int("interval", &i.interval, 1, 3600)? {
        lines.push(format!("{O} interval {n}"));
    }
    if let Some(n) = opt_int("ttl", &i.ttl, 1, 255)? {
        lines.push(format!("{O} ttl {n}"));
    }
    if let Some(n) = opt_int("vrf", &i.vrf, 0, 511)? {
        lines.push(format!("{O} vrf {n}"));
    }
    if i.use_sdwan {
        lines.push(format!("{O} use-sdwan yes"));
    }
    if i.df_bit {
        lines.push(format!("{O} df-bit yes"));
    }
    // adaptive-ping takes enable/disable, unlike the yes/no options.
    if i.adaptive {
        lines.push(format!("{O} adaptive-ping enable"));
    }
    if i.validate_reply {
        lines.push(format!("{O} validate-reply yes"));
    }
    if i.view_settings {
        lines.push(format!("{O} view-settings"));
    }
    lines.push(format!("exec ping {target}"));
    Ok(lines.join("\n"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimal() {
        let i = PingInput {
            target: "8.8.8.8".into(),
            ..Default::default()
        };
        assert_eq!(
            build(&i).unwrap(),
            "exec ping-options reset\nexec ping-options view-settings\nexec ping 8.8.8.8"
        );
    }

    #[test]
    fn all_options_in_swift_order() {
        let i = PingInput {
            target: "fortinet.com".into(),
            reset_first: false,
            source: "10.10.10.1".into(),
            interface: "port2".into(),
            repeat_count: "10".into(),
            timeout: "2".into(),
            data_size: "1472".into(),
            tos: "lowdelay".into(),
            pattern: "FF".into(),
            interval: "2".into(),
            ttl: "64".into(),
            vrf: "3".into(),
            use_sdwan: true,
            df_bit: true,
            adaptive: true,
            validate_reply: true,
            view_settings: false,
        };
        assert_eq!(
            build(&i).unwrap(),
            "exec ping-options source 10.10.10.1\n\
             exec ping-options interface port2\n\
             exec ping-options repeat-count 10\n\
             exec ping-options timeout 2\n\
             exec ping-options data-size 1472\n\
             exec ping-options tos lowdelay\n\
             exec ping-options pattern ff\n\
             exec ping-options interval 2\n\
             exec ping-options ttl 64\n\
             exec ping-options vrf 3\n\
             exec ping-options use-sdwan yes\n\
             exec ping-options df-bit yes\n\
             exec ping-options adaptive-ping enable\n\
             exec ping-options validate-reply yes\n\
             exec ping fortinet.com"
        );
    }

    #[test]
    fn validation() {
        let base = PingInput {
            target: "8.8.8.8".into(),
            ..Default::default()
        };
        let cases = [
            (
                PingInput {
                    target: "".into(),
                    ..base.clone()
                },
                "target",
            ),
            (
                PingInput {
                    source: "wan1".into(),
                    ..base.clone()
                },
                "source",
            ),
            (
                PingInput {
                    interface: "port 1".into(),
                    ..base.clone()
                },
                "interface",
            ),
            (
                PingInput {
                    data_size: "70000".into(),
                    ..base.clone()
                },
                "dataSize",
            ),
            (
                PingInput {
                    tos: "ef".into(),
                    ..base.clone()
                },
                "tos",
            ),
            (
                PingInput {
                    pattern: "zz".into(),
                    ..base.clone()
                },
                "pattern",
            ),
            (
                PingInput {
                    ttl: "256".into(),
                    ..base.clone()
                },
                "ttl",
            ),
            (
                PingInput {
                    interval: "0".into(),
                    ..base.clone()
                },
                "interval",
            ),
            (
                PingInput {
                    vrf: "x".into(),
                    ..base.clone()
                },
                "vrf",
            ),
            (
                PingInput {
                    repeat_count: "0".into(),
                    ..base
                },
                "repeatCount",
            ),
        ];
        for (i, field) in cases {
            assert_eq!(build(&i).unwrap_err().field, field);
        }
    }
}
