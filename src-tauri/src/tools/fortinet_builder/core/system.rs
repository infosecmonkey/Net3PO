//! System top / performance builder. The `diagnose sys top` family matches a
//! FortiOS 7.6.7 listing: top, top-all, top-fd, top-mem, top-sockmem.
//! (FortiDebug Builder's top-summary and top-io do not exist there.) `top`
//! and `top-all` take positional `[delay] [max-lines] [iterations]`; the
//! others take a process count. `hardware sysinfo` offers memory, cpu,
//! interrupts, slab and conserve (FortiDebug Builder's `shm` does not exist).

use serde::Deserialize;

use super::{BuildResult, opt_int};

const DEFAULT_DELAY: u64 = 5;
const DEFAULT_LINES: u64 = 20;

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum Variant {
    #[default]
    Top,
    TopAll,
    TopMem,
    TopFd,
    TopSockmem,
}

impl Variant {
    fn command(self) -> &'static str {
        match self {
            Variant::Top => "diagnose sys top",
            Variant::TopAll => "diagnose sys top-all",
            Variant::TopMem => "diagnose sys top-mem",
            Variant::TopFd => "diagnose sys top-fd",
            Variant::TopSockmem => "diagnose sys top-sockmem",
        }
    }

    /// Takes delay / lines / iterations rather than a process count.
    fn is_interactive(self) -> bool {
        matches!(self, Variant::Top | Variant::TopAll)
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SystemInput {
    pub variant: Variant,
    pub delay: String,
    pub lines: String,
    pub iterations: String,
    /// Process count for top-mem / top-fd / top-sockmem.
    pub count: String,
    pub perf_status: bool,
    pub perf_top: bool,
    pub sysinfo_memory: bool,
    pub sysinfo_cpu: bool,
    pub sysinfo_interrupts: bool,
    pub sysinfo_slab: bool,
    pub sysinfo_conserve: bool,
}

impl Default for SystemInput {
    fn default() -> Self {
        SystemInput {
            variant: Variant::Top,
            delay: String::new(),
            lines: String::new(),
            iterations: String::new(),
            count: String::new(),
            perf_status: true,
            perf_top: false,
            sysinfo_memory: false,
            sysinfo_cpu: false,
            sysinfo_interrupts: false,
            sysinfo_slab: false,
            sysinfo_conserve: false,
        }
    }
}

fn main_command(i: &SystemInput) -> BuildResult<String> {
    let mut parts = vec![i.variant.command().to_string()];
    if i.variant.is_interactive() {
        let delay = opt_int("delay", &i.delay, 1, 3600)?;
        let lines = opt_int("lines", &i.lines, 1, 1000)?;
        let iterations = opt_int("iterations", &i.iterations, 1, 100_000)?;
        // Positional: a later argument needs the earlier ones filled in.
        let delay = delay.or((lines.is_some() || iterations.is_some()).then_some(DEFAULT_DELAY));
        let lines = lines.or(iterations.is_some().then_some(DEFAULT_LINES));
        parts.extend(
            [delay, lines, iterations]
                .into_iter()
                .flatten()
                .map(|n| n.to_string()),
        );
    } else if let Some(n) = opt_int("count", &i.count, 1, 1000)? {
        parts.push(n.to_string());
    }
    Ok(parts.join(" "))
}

/// Build the companion checks, then the top command.
pub fn build(i: &SystemInput) -> BuildResult<String> {
    let mut lines: Vec<String> = Vec::new();
    if i.perf_status {
        lines.push("get system performance status".into());
    }
    if i.perf_top {
        lines.push("get system performance top".into());
    }
    for (on, sub) in [
        (i.sysinfo_memory, "memory"),
        (i.sysinfo_cpu, "cpu"),
        (i.sysinfo_interrupts, "interrupts"),
        (i.sysinfo_slab, "slab"),
        (i.sysinfo_conserve, "conserve"),
    ] {
        if on {
            lines.push(format!("diagnose hardware sysinfo {sub}"));
        }
    }
    if !lines.is_empty() {
        lines.push(String::new());
    }
    lines.push(main_command(i)?);
    Ok(lines.join("\n"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_matches_swift() {
        assert_eq!(
            build(&SystemInput::default()).unwrap(),
            "get system performance status\n\ndiagnose sys top"
        );
    }

    #[test]
    fn positional_defaults_fill_in() {
        let top = |delay: &str, lines: &str, iterations: &str| SystemInput {
            perf_status: false,
            delay: delay.into(),
            lines: lines.into(),
            iterations: iterations.into(),
            ..Default::default()
        };
        assert_eq!(build(&top("2", "", "")).unwrap(), "diagnose sys top 2");
        assert_eq!(build(&top("", "30", "")).unwrap(), "diagnose sys top 5 30");
        assert_eq!(build(&top("", "", "3")).unwrap(), "diagnose sys top 5 20 3");
        assert_eq!(
            build(&top("1", "50", "10")).unwrap(),
            "diagnose sys top 1 50 10"
        );
    }

    #[test]
    fn count_variants_and_companions() {
        let i = SystemInput {
            variant: Variant::TopFd,
            count: "20".into(),
            perf_top: true,
            sysinfo_memory: true,
            sysinfo_conserve: true,
            ..Default::default()
        };
        assert_eq!(
            build(&i).unwrap(),
            "get system performance status\n\
             get system performance top\n\
             diagnose hardware sysinfo memory\n\
             diagnose hardware sysinfo conserve\n\
             \n\
             diagnose sys top-fd 20"
        );
        let mem = SystemInput {
            variant: Variant::TopSockmem,
            perf_status: false,
            // Interactive fields are ignored for count variants.
            delay: "9".into(),
            ..Default::default()
        };
        assert_eq!(build(&mem).unwrap(), "diagnose sys top-sockmem");
    }

    #[test]
    fn validation() {
        let cases = [
            (
                SystemInput {
                    delay: "0".into(),
                    ..Default::default()
                },
                "delay",
            ),
            (
                SystemInput {
                    lines: "x".into(),
                    ..Default::default()
                },
                "lines",
            ),
            (
                SystemInput {
                    iterations: "-1".into(),
                    ..Default::default()
                },
                "iterations",
            ),
            (
                SystemInput {
                    variant: Variant::TopMem,
                    count: "0".into(),
                    ..Default::default()
                },
                "count",
            ),
        ];
        for (i, field) in cases {
            assert_eq!(build(&i).unwrap_err().field, field);
        }
    }
}
