//! Provider-specific explanations for common event IDs, plus decoders for
//! coded fields (logon types, NTSTATUS failure reasons). An ID means
//! different things under different providers, so lookups are keyed on
//! both. Explanations say what to look at; none of them, alone, shows a
//! compromise.

use serde::Serialize;

use super::model::EventRecord;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Explanation {
    pub title: &'static str,
    pub meaning: &'static str,
    /// Fields worth reading for this event.
    pub look_at: &'static [&'static str],
    pub caution: &'static str,
}

const SEC: &str = "microsoft-windows-security-auditing";
const SYSMON: &str = "microsoft-windows-sysmon";

/// Normal events that are not suspicious on their own.
const ROUTINE: &str =
    "Routine on its own; context (who, from where, when, how often) decides whether it matters.";

macro_rules! ex {
    ($title:expr, $meaning:expr, [$($f:expr),*], $caution:expr) => {
        Explanation { title: $title, meaning: $meaning, look_at: &[$($f),*], caution: $caution }
    };
}

fn table(provider: &str, id: u32) -> Option<Explanation> {
    let p = provider.to_ascii_lowercase();
    let p = p.as_str();
    Some(match (p, id) {
        (SEC, 4624) => ex!(
            "An account logged on",
            "A logon session was created. LogonType tells how (2 console, 3 network, 10 RDP, and so on).",
            [
                "LogonType",
                "TargetUserName",
                "TargetDomainName",
                "IpAddress",
                "WorkstationName",
                "LogonProcessName",
                "AuthenticationPackageName",
                "ElevatedToken"
            ],
            ROUTINE
        ),
        (SEC, 4625) => ex!(
            "An account failed to log on",
            "A logon attempt failed. Status and SubStatus give the reason.",
            [
                "TargetUserName",
                "LogonType",
                "IpAddress",
                "WorkstationName",
                "Status",
                "SubStatus",
                "FailureReason"
            ],
            "One failure is ordinary. Many failures against many accounts from one source suggests password spraying; many against one account suggests guessing."
        ),
        (SEC, 4634) | (SEC, 4647) => ex!(
            "An account logged off",
            "A logon session ended (4647 is a user-initiated logoff).",
            ["TargetUserName", "LogonType", "TargetLogonId"],
            ROUTINE
        ),
        (SEC, 4648) => ex!(
            "Logon with explicit credentials",
            "A process used different credentials than the logged-on user (runas, mapped drives, some admin tools).",
            [
                "SubjectUserName",
                "TargetUserName",
                "TargetServerName",
                "ProcessName",
                "IpAddress"
            ],
            "Common with administration; also used in lateral movement. Check the process and the target."
        ),
        (SEC, 4672) => ex!(
            "Special privileges assigned to a new logon",
            "An administrator-equivalent logon: sensitive privileges were granted.",
            ["SubjectUserName", "PrivilegeList"],
            ROUTINE
        ),
        (SEC, 4688) => ex!(
            "A new process was created",
            "Process creation auditing. Command lines appear only if that policy is enabled.",
            [
                "NewProcessName",
                "CommandLine",
                "ParentProcessName",
                "SubjectUserName",
                "TokenElevationType"
            ],
            "Judge by the command line and parent process, not the event itself."
        ),
        (SEC, 4697) => ex!(
            "A service was installed",
            "A new service was registered with the Service Control Manager.",
            [
                "ServiceName",
                "ServiceFileName",
                "ServiceType",
                "ServiceStartType",
                "SubjectUserName"
            ],
            "Software installs do this; so do attackers for persistence and remote execution (PsExec-style). Check the binary path."
        ),
        (SEC, 4698) | (SEC, 4702) => ex!(
            "A scheduled task was created or updated",
            "The task XML is in TaskContent.",
            ["TaskName", "TaskContent", "SubjectUserName"],
            "Check what the task runs and when; scheduled tasks are a common persistence method."
        ),
        (SEC, 4699) | (SEC, 4700) | (SEC, 4701) => ex!(
            "A scheduled task was deleted, enabled or disabled",
            "A change to an existing scheduled task.",
            ["TaskName", "SubjectUserName"],
            ROUTINE
        ),
        (SEC, 4719) => ex!(
            "System audit policy was changed",
            "Which events Windows records was changed.",
            [
                "SubjectUserName",
                "CategoryId",
                "SubcategoryGuid",
                "AuditPolicyChanges"
            ],
            "Disabling auditing can hide later activity; confirm the change was planned."
        ),
        (SEC, 4720) => ex!(
            "A user account was created",
            "A new local or domain account.",
            ["TargetUserName", "TargetDomainName", "SubjectUserName"],
            "Confirm the account was expected and who created it."
        ),
        (SEC, 4722) | (SEC, 4725) => ex!(
            "A user account was enabled or disabled",
            "Account status changed (4722 enabled, 4725 disabled).",
            ["TargetUserName", "SubjectUserName"],
            ROUTINE
        ),
        (SEC, 4723) | (SEC, 4724) => ex!(
            "Password change or reset",
            "4723: the user changed their own password; 4724: someone reset it.",
            ["TargetUserName", "SubjectUserName"],
            "A reset by an unexpected account deserves a look."
        ),
        (SEC, 4726) => ex!(
            "A user account was deleted",
            "An account was removed.",
            ["TargetUserName", "SubjectUserName"],
            ROUTINE
        ),
        (SEC, 4728) | (SEC, 4732) | (SEC, 4756) => ex!(
            "A member was added to a security group",
            "4728 global, 4732 local, 4756 universal group.",
            [
                "MemberName",
                "MemberSid",
                "TargetUserName",
                "SubjectUserName"
            ],
            "Additions to admin groups (Domain Admins, Administrators) should match a change request."
        ),
        (SEC, 4738) => ex!(
            "A user account was changed",
            "Account attributes changed; changed fields show new values, '-' means unchanged.",
            [
                "TargetUserName",
                "SubjectUserName",
                "UserAccountControl",
                "PasswordLastSet"
            ],
            ROUTINE
        ),
        (SEC, 4740) => ex!(
            "A user account was locked out",
            "Too many failed logons; the caller computer is the source.",
            ["TargetUserName", "TargetDomainName"],
            "Find the source in matching 4625/4771 events; stale saved passwords are a common cause."
        ),
        (SEC, 4767) => ex!(
            "A user account was unlocked",
            "An administrator or the user unlocked the account.",
            ["TargetUserName", "SubjectUserName"],
            ROUTINE
        ),
        (SEC, 4768) => ex!(
            "Kerberos TGT requested",
            "Domain controller: an authentication ticket was requested.",
            [
                "TargetUserName",
                "IpAddress",
                "Status",
                "TicketEncryptionType",
                "PreAuthType"
            ],
            ROUTINE
        ),
        (SEC, 4769) => ex!(
            "Kerberos service ticket requested",
            "Domain controller: a ticket for a service was requested.",
            [
                "TargetUserName",
                "ServiceName",
                "IpAddress",
                "TicketEncryptionType",
                "Status"
            ],
            "Many RC4 (0x17) service tickets for many services from one account can indicate Kerberoasting."
        ),
        (SEC, 4771) => ex!(
            "Kerberos pre-authentication failed",
            "Usually a wrong password on a domain account.",
            ["TargetUserName", "IpAddress", "Status"],
            "Bursts across many accounts suggest password spraying."
        ),
        (SEC, 4776) => ex!(
            "NTLM credential validation",
            "A domain controller or local SAM checked NTLM credentials.",
            ["TargetUserName", "Workstation", "Status"],
            ROUTINE
        ),
        (SEC, 4798) | (SEC, 4799) => ex!(
            "Group or user membership enumerated",
            "A process read a user's local groups (4798) or a group's members (4799).",
            ["TargetUserName", "SubjectUserName", "CallerProcessName"],
            "Very noisy from normal tools; interesting when the caller process is unusual."
        ),
        (SEC, 5140) | (SEC, 5145) => ex!(
            "Network share accessed",
            "5140 share opened; 5145 detailed file access check.",
            [
                "ShareName",
                "RelativeTargetName",
                "IpAddress",
                "SubjectUserName",
                "AccessMask"
            ],
            ROUTINE
        ),
        (SEC, 1102) | ("microsoft-windows-eventlog", 1102) => ex!(
            "The Security log was cleared",
            "Someone cleared the Security event log.",
            ["SubjectUserName", "SubjectDomainName"],
            "Clearing logs destroys evidence. Confirm it was authorized; check what happened just before."
        ),
        ("microsoft-windows-eventlog", 104) => ex!(
            "An event log was cleared",
            "A log other than Security (System, Application, ...) was cleared.",
            ["Channel", "SubjectUserName", "BackupPath"],
            "Confirm it was authorized."
        ),
        ("service control manager", 7045) => ex!(
            "A service was installed",
            "The Service Control Manager registered a new service.",
            [
                "ServiceName",
                "ImagePath",
                "ServiceType",
                "StartType",
                "AccountName"
            ],
            "Legitimate installers do this; so does remote execution tooling. An ImagePath in a temp folder, or with encoded PowerShell, is a red flag."
        ),
        ("service control manager", 7036) => ex!(
            "A service changed state",
            "Started or stopped.",
            ["param1", "param2"],
            ROUTINE
        ),
        ("service control manager", 7034) | ("service control manager", 7031) => ex!(
            "A service stopped unexpectedly",
            "The service crashed or was killed.",
            ["param1"],
            ROUTINE
        ),
        ("service control manager", 7040) => ex!(
            "A service start type changed",
            "For example from disabled to automatic.",
            ["param1", "param2", "param3"],
            "Re-enabling a disabled service, or disabling security software, deserves a look."
        ),
        ("eventlog", 6005) => ex!("Event log service started", "Logged at boot.", [], ROUTINE),
        ("eventlog", 6006) => ex!(
            "Event log service stopped",
            "Logged at clean shutdown.",
            [],
            ROUTINE
        ),
        ("eventlog", 6008) => ex!(
            "Previous shutdown was unexpected",
            "The system went down without a clean shutdown.",
            [],
            ROUTINE
        ),
        ("microsoft-windows-kernel-power", 41) => ex!(
            "System rebooted without a clean shutdown",
            "Power loss, crash or forced reset.",
            ["BugcheckCode", "PowerButtonTimestamp"],
            ROUTINE
        ),
        ("user32", 1074) => ex!(
            "Shutdown or restart initiated",
            "A process or user requested shutdown.",
            ["param1", "param3", "param5", "param7"],
            ROUTINE
        ),
        ("microsoft-windows-taskscheduler", 106) => ex!(
            "Scheduled task registered",
            "Task Scheduler operational log.",
            ["TaskName", "UserContext"],
            "Check what the task runs."
        ),
        ("microsoft-windows-taskscheduler", 200) | ("microsoft-windows-taskscheduler", 201) => ex!(
            "Scheduled task action started or completed",
            "",
            ["TaskName", "ActionName", "ResultCode"],
            ROUTINE
        ),
        ("microsoft-windows-powershell", 4104) => ex!(
            "PowerShell script block logged",
            "The text of a script block that ran (script block logging).",
            ["ScriptBlockText", "Path", "ScriptBlockId"],
            "Read the script. Encoded commands, download cradles and AMSI bypass strings are worth investigating; the Script Decoder can unwrap obfuscation."
        ),
        ("microsoft-windows-powershell", 4103) => ex!(
            "PowerShell module logging",
            "Pipeline execution details.",
            ["Payload", "ContextInfo"],
            ROUTINE
        ),
        ("microsoft-windows-windows defender", 1116) => ex!(
            "Defender detected malware or unwanted software",
            "A detection, before any action.",
            ["Threat Name", "Path", "Detection User", "Process Name"],
            "Check whether 1117 (action taken) followed."
        ),
        ("microsoft-windows-windows defender", 1117) => ex!(
            "Defender took action",
            "Quarantine, removal or block.",
            ["Threat Name", "Action Name", "Path"],
            ROUTINE
        ),
        ("microsoft-windows-windows defender", 5001) => ex!(
            "Defender real-time protection disabled",
            "",
            [],
            "Confirm it was intentional."
        ),
        ("microsoft-windows-terminalservices-localsessionmanager", 21) => ex!(
            "RDP session logon",
            "Remote Desktop session logon succeeded.",
            ["User", "Address", "SessionID"],
            ROUTINE
        ),
        ("microsoft-windows-terminalservices-localsessionmanager", 24) => {
            ex!("RDP session disconnected", "", ["User", "Address"], ROUTINE)
        }
        ("microsoft-windows-terminalservices-localsessionmanager", 25) => {
            ex!("RDP session reconnected", "", ["User", "Address"], ROUTINE)
        }
        ("microsoft-windows-terminalservices-remoteconnectionmanager", 1149) => ex!(
            "RDP network authentication succeeded",
            "A user authenticated to Remote Desktop (before the session starts).",
            ["Param1", "Param2", "Param3"],
            "Param3 is the source address."
        ),
        (SYSMON, 1) => ex!(
            "Sysmon: process created",
            "Full command line, hashes and parent process.",
            [
                "Image",
                "CommandLine",
                "ParentImage",
                "ParentCommandLine",
                "User",
                "Hashes"
            ],
            "Judge by the command line and parent."
        ),
        (SYSMON, 3) => ex!(
            "Sysmon: network connection",
            "A process opened a TCP or UDP connection.",
            [
                "Image",
                "DestinationIp",
                "DestinationPort",
                "DestinationHostname",
                "User"
            ],
            ROUTINE
        ),
        (SYSMON, 5) => ex!(
            "Sysmon: process terminated",
            "",
            ["Image", "ProcessId"],
            ROUTINE
        ),
        (SYSMON, 6) => ex!(
            "Sysmon: driver loaded",
            "",
            ["ImageLoaded", "Signed", "Signature"],
            "Unsigned or unexpected drivers deserve a look."
        ),
        (SYSMON, 7) => ex!(
            "Sysmon: image (DLL) loaded",
            "",
            ["Image", "ImageLoaded", "Signed"],
            ROUTINE
        ),
        (SYSMON, 8) => ex!(
            "Sysmon: CreateRemoteThread",
            "A process created a thread in another process.",
            ["SourceImage", "TargetImage", "StartFunction"],
            "A classic injection technique; some legitimate software does it too."
        ),
        (SYSMON, 10) => ex!(
            "Sysmon: process access",
            "A process opened another process.",
            ["SourceImage", "TargetImage", "GrantedAccess"],
            "Access to lsass.exe by unusual processes may indicate credential dumping."
        ),
        (SYSMON, 11) => ex!(
            "Sysmon: file created",
            "",
            ["Image", "TargetFilename"],
            ROUTINE
        ),
        (SYSMON, 12) | (SYSMON, 13) | (SYSMON, 14) => ex!(
            "Sysmon: registry event",
            "Key or value created, deleted, set or renamed.",
            ["Image", "TargetObject", "Details"],
            "Run keys and services keys are common persistence locations."
        ),
        (SYSMON, 15) => ex!(
            "Sysmon: alternate data stream created",
            "",
            ["Image", "TargetFilename", "Hash"],
            ROUTINE
        ),
        (SYSMON, 17) | (SYSMON, 18) => ex!(
            "Sysmon: named pipe created or connected",
            "",
            ["Image", "PipeName"],
            ROUTINE
        ),
        (SYSMON, 22) => ex!(
            "Sysmon: DNS query",
            "A process looked up a name.",
            ["Image", "QueryName", "QueryResults"],
            ROUTINE
        ),
        (SYSMON, 23) | (SYSMON, 26) => ex!(
            "Sysmon: file deleted",
            "",
            ["Image", "TargetFilename"],
            ROUTINE
        ),
        (SYSMON, 25) => ex!(
            "Sysmon: process tampering",
            "Process image changed in memory (hollowing or herpaderping).",
            ["Image", "Type"],
            "Investigate; legitimate software rarely triggers this."
        ),
        _ => return None,
    })
}

/// Explanation for a record, keyed on provider and event ID.
pub fn explain(r: &EventRecord) -> Option<Explanation> {
    table(&r.provider, r.event_id)
}

fn logon_type(t: &str) -> Option<&'static str> {
    Some(match t.trim() {
        "2" => "Interactive (console)",
        "3" => "Network (file shares, many services)",
        "4" => "Batch (scheduled task)",
        "5" => "Service",
        "7" => "Unlock",
        "8" => "NetworkCleartext (password sent in clear, e.g. IIS basic auth)",
        "9" => "NewCredentials (runas /netonly)",
        "10" => "RemoteInteractive (Remote Desktop)",
        "11" => "CachedInteractive (cached domain credentials)",
        "12" => "CachedRemoteInteractive",
        "13" => "CachedUnlock",
        _ => return None,
    })
}

fn ntstatus(code: &str) -> Option<&'static str> {
    Some(match code.trim().to_ascii_lowercase().as_str() {
        "0xc000006a" => "wrong password",
        "0xc0000064" => "user name does not exist",
        "0xc000006d" => "bad user name or authentication information",
        "0xc000006e" => "account restriction",
        "0xc000006f" => "logon outside allowed hours",
        "0xc0000070" => "logon from a workstation that is not allowed",
        "0xc0000071" => "password expired",
        "0xc0000072" => "account disabled",
        "0xc0000133" => "clock skew between client and domain controller",
        "0xc000015b" => "logon type not granted to this account",
        "0xc0000193" => "account expired",
        "0xc0000224" => "user must change password at next logon",
        "0xc0000234" => "account locked out",
        "0xc0000413" => "authentication firewall blocked the logon",
        _ => return None,
    })
}

/// Plain-language readings of coded fields in a record.
pub fn decode(r: &EventRecord) -> Vec<(String, String)> {
    let mut out = Vec::new();
    if let Some(t) = r.field("LogonType").and_then(logon_type) {
        out.push(("LogonType".into(), t.into()));
    }
    for name in ["Status", "SubStatus", "FailureReason"] {
        if let Some(v) = r.field(name)
            && let Some(m) = ntstatus(v)
        {
            out.push((name.into(), m.into()));
        }
    }
    if let Some(e) = r.field("TicketEncryptionType") {
        let m = match e.trim().to_ascii_lowercase().as_str() {
            "0x17" => Some("RC4-HMAC (weak; common in Kerberoasting)"),
            "0x12" => Some("AES256"),
            "0x11" => Some("AES128"),
            _ => None,
        };
        if let Some(m) = m {
            out.push(("TicketEncryptionType".into(), m.into()));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(provider: &str, id: u32, fields: &[(&str, &str)]) -> EventRecord {
        EventRecord {
            index: 0,
            record_id: None,
            time_raw: String::new(),
            time_utc_ms: None,
            zone_unknown: false,
            sort_ms: 0,
            provider: provider.into(),
            channel: String::new(),
            event_id: id,
            level: 0,
            outcome: String::new(),
            computer: String::new(),
            user_sid: String::new(),
            fields: fields
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            message: String::new(),
            raw: String::new(),
        }
    }

    #[test]
    fn provider_specific() {
        let logon = explain(&rec("Microsoft-Windows-Security-Auditing", 4624, &[])).unwrap();
        assert_eq!(logon.title, "An account logged on");
        // Same ID, different provider: Sysmon 1 is not Security 1.
        assert!(
            explain(&rec("Microsoft-Windows-Sysmon", 1, &[]))
                .unwrap()
                .title
                .starts_with("Sysmon")
        );
        assert!(explain(&rec("Microsoft-Windows-Security-Auditing", 1, &[])).is_none());
        assert!(explain(&rec("Some App", 4624, &[])).is_none());
        let cleared = explain(&rec("Microsoft-Windows-Eventlog", 1102, &[])).unwrap();
        assert!(cleared.caution.contains("evidence"));
        assert!(explain(&rec("Service Control Manager", 7045, &[])).is_some());
    }

    #[test]
    fn decoders() {
        let r = rec(
            "x",
            4625,
            &[
                ("LogonType", "10"),
                ("Status", "0xC000006D"),
                ("SubStatus", "0xc000006a"),
                ("TicketEncryptionType", "0x17"),
            ],
        );
        let d = decode(&r);
        assert!(d.contains(&(
            "LogonType".into(),
            "RemoteInteractive (Remote Desktop)".into()
        )));
        assert!(d.contains(&("SubStatus".into(), "wrong password".into())));
        assert!(
            d.iter()
                .any(|(k, v)| k == "TicketEncryptionType" && v.contains("RC4"))
        );
        assert!(decode(&rec("x", 1, &[("LogonType", "99")])).is_empty());
    }
}
