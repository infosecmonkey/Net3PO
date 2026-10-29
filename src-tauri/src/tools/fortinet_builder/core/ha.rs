//! HA cluster builder: status and health reads, checksums, dumps, a live
//! hatalk/hasync debug, and (kept separate and labeled) commands that change
//! cluster state. Every option was checked against a FortiOS 7.6.7 cluster;
//! FortiDebug Builder's `dump-by all-vcluster` and `synchronize all` do not
//! exist there, and `ha manage` needs an admin name (the password is
//! prompted, never part of the command).

use serde::Deserialize;

use super::{BuildResult, err, interface_name, opt_int, present};

/// `diagnose sys ha dump-by` targets on FortiOS 7.6.
pub const DUMP_BY: &[&str] = &[
    "group",
    "vcluster",
    "vdom",
    "device",
    "kernel",
    "rcache",
    "debug-zone",
];

/// Serial numbers `checksum cluster` accepts at most.
pub const MAX_SERIALS: usize = 16;

/// Which HA uptime reset to emit.
#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum ResetUptime {
    #[default]
    None,
    All,
    PrimaryOnly,
}

/// `execute ha synchronize` action.
#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum Synchronize {
    #[default]
    None,
    Start,
    Stop,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct HaInput {
    // Status and health (read only).
    pub get_status: bool,
    pub diag_status: bool,
    pub history: bool,
    pub stats: bool,
    pub heartbeat: bool,
    pub mac: bool,
    pub sync_stats: bool,
    pub hasync_stats: bool,
    // Checksums.
    pub checksum_cluster: bool,
    /// Optional serial numbers for `checksum cluster`, up to 16.
    pub serials: String,
    pub checksum_show: bool,
    /// Blank for the system checksum, `global`, or a VDOM name.
    pub checksum_scope: String,
    pub show_nonsync: bool,
    pub recalculate: bool,
    /// `dump-by` target, or empty for none.
    pub dump_by: String,
    // Live debug.
    pub debug_hatalk: bool,
    pub debug_hasync: bool,
    pub reset_first: bool,
    pub timestamps: bool,
    pub level: String,
    pub stop_block: bool,
    // Changes cluster state.
    pub reset_uptime: ResetUptime,
    pub synchronize: Synchronize,
    pub manage: bool,
    pub manage_index: String,
    pub manage_admin: String,
}

impl Default for HaInput {
    fn default() -> Self {
        HaInput {
            get_status: true,
            diag_status: false,
            history: false,
            stats: false,
            heartbeat: false,
            mac: false,
            sync_stats: false,
            hasync_stats: false,
            checksum_cluster: false,
            serials: String::new(),
            checksum_show: false,
            checksum_scope: String::new(),
            show_nonsync: false,
            recalculate: false,
            dump_by: String::new(),
            debug_hatalk: false,
            debug_hasync: false,
            reset_first: true,
            timestamps: true,
            level: String::new(),
            stop_block: true,
            reset_uptime: ResetUptime::None,
            synchronize: Synchronize::None,
            manage: false,
            manage_index: String::new(),
            manage_admin: String::new(),
        }
    }
}

/// A FortiGate serial number: letters and digits, 8 to 20 characters.
fn serial(field: &str, s: &str) -> BuildResult<String> {
    let ok = (8..=20).contains(&s.len()) && s.chars().all(|c| c.is_ascii_alphanumeric());
    if ok {
        Ok(s.to_ascii_uppercase())
    } else {
        err(field, format!("'{s}' is not a FortiGate serial number"))
    }
}

/// An admin login name: letters, digits, and `. _ - @`, at most 64.
fn admin_name(field: &str, s: &str) -> BuildResult<String> {
    let t = s.trim();
    if t.is_empty() {
        return err(field, "enter the admin name to log in to the peer with");
    }
    if t.len() > 64
        || !t
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '@'))
    {
        return err(field, format!("'{t}' is not a valid admin name"));
    }
    Ok(t.to_string())
}

/// Debug level that may be -1.
fn level(field: &str, s: &str) -> BuildResult<i64> {
    match present(s) {
        None => Ok(-1),
        Some(t) => match t.parse::<i64>() {
            Ok(n) if (-1..=65_535).contains(&n) => Ok(n),
            _ => err(
                field,
                format!("'{t}' must be a whole number from -1 to 65535"),
            ),
        },
    }
}

/// Build the HA commands.
pub fn build(i: &HaInput) -> BuildResult<String> {
    const D: &str = "diagnose sys ha";
    let mut lines: Vec<String> = Vec::new();

    if i.get_status {
        lines.push("get system ha status".into());
    }
    for (on, sub) in [
        (i.diag_status, "status"),
        (i.history, "history"),
        (i.stats, "stats"),
        (i.heartbeat, "heartbeat"),
        (i.mac, "mac"),
        (i.sync_stats, "sync-stats"),
        (i.hasync_stats, "hasync-stats"),
    ] {
        if on {
            lines.push(format!("{D} {sub}"));
        }
    }

    if i.checksum_cluster {
        let serials: Vec<&str> = i
            .serials
            .split([',', ' '])
            .filter(|s| !s.is_empty())
            .collect();
        if serials.len() > MAX_SERIALS {
            return err("serials", format!("at most {MAX_SERIALS} serial numbers"));
        }
        let checked = serials
            .iter()
            .map(|s| serial("serials", s))
            .collect::<BuildResult<Vec<_>>>()?;
        if checked.is_empty() {
            lines.push(format!("{D} checksum cluster"));
        } else {
            lines.push(format!("{D} checksum cluster {}", checked.join(" ")));
        }
    }
    if i.checksum_show {
        match present(&i.checksum_scope) {
            None => lines.push(format!("{D} checksum show")),
            Some(_) => {
                let scope = interface_name("checksumScope", &i.checksum_scope)?;
                lines.push(format!("{D} checksum show {scope}"));
            }
        }
    }
    if i.show_nonsync {
        lines.push(format!("{D} checksum show-nonsync"));
    }
    if i.recalculate {
        lines.push(format!("{D} checksum recalculate"));
    }
    if let Some(t) = present(&i.dump_by) {
        match DUMP_BY.iter().find(|d| **d == t) {
            Some(d) => lines.push(format!("{D} dump-by {d}")),
            None => return err("dumpBy", format!("unknown dump-by target '{t}'")),
        }
    }

    if i.debug_hatalk || i.debug_hasync {
        let lvl = level("level", &i.level)?;
        if !lines.is_empty() {
            lines.push(String::new());
        }
        lines.push("# Live HA debug:".into());
        if i.reset_first {
            lines.push("diagnose debug disable".into());
            lines.push("diagnose debug reset".into());
        }
        if i.timestamps {
            lines.push("diagnose debug console timestamp enable".into());
        }
        if i.debug_hatalk {
            lines.push(format!("diagnose debug application hatalk {lvl}"));
        }
        if i.debug_hasync {
            lines.push(format!("diagnose debug application hasync {lvl}"));
        }
        lines.push("diagnose debug enable".into());
        if i.stop_block {
            lines.push(String::new());
            lines.push("# When finished, stop the debug:".into());
            lines.push("diagnose debug disable".into());
            lines.push("diagnose debug reset".into());
        }
    }

    let mut changes: Vec<String> = Vec::new();
    match i.reset_uptime {
        ResetUptime::None => {}
        ResetUptime::All => changes.push(format!("{D} reset-uptime")),
        ResetUptime::PrimaryOnly => changes.push(format!("{D} reset-uptime-primary-only")),
    }
    match i.synchronize {
        Synchronize::None => {}
        Synchronize::Start => changes.push("execute ha synchronize start".into()),
        Synchronize::Stop => changes.push("execute ha synchronize stop".into()),
    }
    // Last: manage switches the CLI to the peer unit.
    if i.manage {
        let idx = match opt_int("manageIndex", &i.manage_index, 0, 255)? {
            Some(n) => n,
            None => return err("manageIndex", "enter the peer unit index"),
        };
        let admin = admin_name("manageAdmin", &i.manage_admin)?;
        changes.push(format!("execute ha manage {idx} {admin}"));
    }
    if !changes.is_empty() {
        if !lines.is_empty() {
            lines.push(String::new());
        }
        lines.push("# Changes cluster state: review before running".into());
        lines.extend(changes);
    }

    Ok(lines.join("\n"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_status_only() {
        assert_eq!(build(&HaInput::default()).unwrap(), "get system ha status");
    }

    #[test]
    fn reads_and_checksums() {
        let i = HaInput {
            diag_status: true,
            history: true,
            sync_stats: true,
            checksum_cluster: true,
            serials: "fgvm08tm24000123, FGVM08TM24000124".into(),
            checksum_show: true,
            checksum_scope: "global".into(),
            show_nonsync: true,
            recalculate: true,
            dump_by: "vcluster".into(),
            ..Default::default()
        };
        assert_eq!(
            build(&i).unwrap(),
            "get system ha status\n\
             diagnose sys ha status\n\
             diagnose sys ha history\n\
             diagnose sys ha sync-stats\n\
             diagnose sys ha checksum cluster FGVM08TM24000123 FGVM08TM24000124\n\
             diagnose sys ha checksum show global\n\
             diagnose sys ha checksum show-nonsync\n\
             diagnose sys ha checksum recalculate\n\
             diagnose sys ha dump-by vcluster"
        );
    }

    #[test]
    fn checksum_show_system_and_vdom() {
        let sys = HaInput {
            get_status: false,
            checksum_show: true,
            ..Default::default()
        };
        assert_eq!(build(&sys).unwrap(), "diagnose sys ha checksum show");
        let vdom = HaInput {
            get_status: false,
            checksum_show: true,
            checksum_scope: "root".into(),
            ..Default::default()
        };
        assert_eq!(build(&vdom).unwrap(), "diagnose sys ha checksum show root");
    }

    #[test]
    fn debug_block() {
        let i = HaInput {
            get_status: false,
            debug_hatalk: true,
            debug_hasync: true,
            stop_block: false,
            ..Default::default()
        };
        assert_eq!(
            build(&i).unwrap(),
            "# Live HA debug:\n\
             diagnose debug disable\n\
             diagnose debug reset\n\
             diagnose debug console timestamp enable\n\
             diagnose debug application hatalk -1\n\
             diagnose debug application hasync -1\n\
             diagnose debug enable"
        );
    }

    #[test]
    fn cluster_changes_are_labeled_and_last() {
        let i = HaInput {
            reset_uptime: ResetUptime::PrimaryOnly,
            synchronize: Synchronize::Start,
            manage: true,
            manage_index: "0".into(),
            manage_admin: "admin".into(),
            ..Default::default()
        };
        assert_eq!(
            build(&i).unwrap(),
            "get system ha status\n\
             \n\
             # Changes cluster state: review before running\n\
             diagnose sys ha reset-uptime-primary-only\n\
             execute ha synchronize start\n\
             execute ha manage 0 admin"
        );
    }

    #[test]
    fn never_emits_removed_swift_syntax() {
        let i = HaInput {
            dump_by: "all-vcluster".into(),
            ..Default::default()
        };
        assert_eq!(build(&i).unwrap_err().field, "dumpBy");
    }

    #[test]
    fn validation() {
        let cases = [
            (
                HaInput {
                    checksum_cluster: true,
                    serials: "FG-1".into(),
                    ..Default::default()
                },
                "serials",
            ),
            (
                HaInput {
                    checksum_cluster: true,
                    serials: vec!["FGVM08TM24000123"; 17].join(" "),
                    ..Default::default()
                },
                "serials",
            ),
            (
                HaInput {
                    checksum_show: true,
                    checksum_scope: "root;x".into(),
                    ..Default::default()
                },
                "checksumScope",
            ),
            (
                HaInput {
                    debug_hatalk: true,
                    level: "-2".into(),
                    ..Default::default()
                },
                "level",
            ),
            (
                HaInput {
                    manage: true,
                    manage_admin: "admin".into(),
                    ..Default::default()
                },
                "manageIndex",
            ),
            (
                HaInput {
                    manage: true,
                    manage_index: "0".into(),
                    ..Default::default()
                },
                "manageAdmin",
            ),
            (
                HaInput {
                    manage: true,
                    manage_index: "0".into(),
                    manage_admin: "admin pass".into(),
                    ..Default::default()
                },
                "manageAdmin",
            ),
        ];
        for (i, field) in cases {
            assert_eq!(build(&i).unwrap_err().field, field);
        }
    }
}
