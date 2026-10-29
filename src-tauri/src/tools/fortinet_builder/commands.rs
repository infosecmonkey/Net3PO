//! Tauri commands for the Fortinet command builder. All command text is
//! produced by the validated builders in `core`; these are thin wrappers.

use serde::Deserialize;

use super::core::{BuildError, flow, ping, session, sniffer, traceroute};

/// Which builder to run, with its form input.
#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum BuildInput {
    Session(session::SessionInput),
    Flow(flow::FlowInput),
    Sniffer(sniffer::SnifferInput),
    Ping(ping::PingInput),
    Traceroute(traceroute::TracerouteInput),
}

/// Build FortiOS CLI text from a builder's form input.
#[tauri::command]
pub fn fortinet_build(input: BuildInput) -> Result<String, BuildError> {
    match input {
        BuildInput::Session(i) => session::build(&i),
        BuildInput::Flow(i) => flow::build(&i),
        BuildInput::Sniffer(i) => sniffer::build(&i),
        BuildInput::Ping(i) => ping::build(&i),
        BuildInput::Traceroute(i) => traceroute::build(&i),
    }
}

/// Render a BPF snippet and append it to `existing` with `and` / `or`.
#[tauri::command]
pub fn fortinet_bpf_add(
    existing: String,
    snippet: sniffer::Snippet,
    negate: bool,
    wrap: bool,
    or: bool,
) -> Result<String, BuildError> {
    let piece = sniffer::decorate(&sniffer::render_snippet(&snippet)?, negate, wrap);
    Ok(sniffer::append(&existing, &piece, or))
}

/// Append a ready-made BPF expression (a preset) in parentheses.
#[tauri::command]
pub fn fortinet_bpf_preset(existing: String, expr: String, or: bool) -> Result<String, BuildError> {
    let expr = sniffer::custom_filter("preset", &expr)?;
    Ok(sniffer::append(&existing, &format!("({expr})"), or))
}

/// The policy snippet that disables ASIC/NPU offload for sniffing.
#[tauri::command]
pub fn fortinet_offload_snippet() -> &'static str {
    sniffer::OFFLOAD_DISABLE
}

/// Write command text to a path chosen via the save dialog.
#[tauri::command]
pub fn fortinet_save_text(path: String, contents: String) -> Result<(), String> {
    std::fs::write(&path, contents).map_err(|e| format!("could not write {path}: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// The exact shapes the Svelte forms send.
    #[test]
    fn ui_payloads_deserialize() {
        let session: BuildInput = serde_json::from_value(json!({
            "kind": "session", "src": "10.1.1.10", "dst": "", "sport": "", "dport": "443",
            "proto": 6, "vdom": "", "negate": false, "clearFirst": true, "list": true, "stats": false
        }))
        .unwrap();
        assert!(
            fortinet_build(session)
                .unwrap()
                .contains("filter dport 443")
        );

        let flow: BuildInput = serde_json::from_value(json!({
            "kind": "flow", "addr": "10.0.0.5", "saddr": "", "daddr": "", "port": "", "sport": "",
            "dport": "", "proto": null, "vdom": "", "traceCount": "1000", "resetFirst": true,
            "showFunctionName": true, "showIprope": false, "timestamps": true, "stopBlock": true
        }))
        .unwrap();
        assert!(
            fortinet_build(flow)
                .unwrap()
                .contains("filter addr 10.0.0.5")
        );

        let sniffer: BuildInput = serde_json::from_value(json!({
            "kind": "sniffer", "interface": "port1", "useCustomFilter": false, "customFilter": "",
            "host": "10.0.0.1", "hostDir": "src", "net": "", "netDir": "any", "ports": "443",
            "portDir": "any", "proto": "tcp", "verbose": 6, "count": "", "timestamp": "local"
        }))
        .unwrap();
        assert_eq!(
            fortinet_build(sniffer).unwrap(),
            "diagnose sniffer packet port1 'tcp and src host 10.0.0.1 and port 443' 6 0 l"
        );
    }

    #[test]
    fn ping_and_traceroute_payloads_deserialize() {
        let ping: BuildInput = serde_json::from_value(json!({
            "kind": "ping", "target": "8.8.8.8", "resetFirst": true, "source": "10.0.0.1",
            "interface": "wan1", "repeatCount": "5", "timeout": "", "dataSize": "1472", "tos": "",
            "pattern": "", "interval": "", "ttl": "", "vrf": "", "useSdwan": false, "dfBit": true, "adaptive": false, "validateReply": false, "viewSettings": false
        }))
        .unwrap();
        assert_eq!(
            fortinet_build(ping).unwrap(),
            "exec ping-options reset\n\
             exec ping-options source 10.0.0.1\n\
             exec ping-options interface wan1\n\
             exec ping-options repeat-count 5\n\
             exec ping-options data-size 1472\n\
             exec ping-options df-bit yes\n\
             exec ping 8.8.8.8"
        );
        let tr: BuildInput = serde_json::from_value(json!({
            "kind": "traceroute", "target": "1.1.1.1", "resetFirst": false, "source": "", "device": "wan1",
            "queries": "", "vrf": "", "useSdwan": true, "viewSettings": false
        }))
        .unwrap();
        assert_eq!(
            fortinet_build(tr).unwrap(),
            "exec traceroute-options device wan1\nexec traceroute-options use-sdwan yes\nexec traceroute 1.1.1.1"
        );
    }

    #[test]
    fn bpf_payloads_deserialize() {
        let flags: sniffer::Snippet =
            serde_json::from_value(json!({"type": "tcpFlags", "flags": ["syn"], "exact": false}))
                .unwrap();
        assert_eq!(
            fortinet_bpf_add("arp".into(), flags, false, true, true).unwrap(),
            "arp or (tcp[tcpflags] & tcp-syn != 0)"
        );
        let mac: sniffer::Snippet = serde_json::from_value(
            json!({"type": "etherHost", "mac": "00:1b:44:11:3a:b7", "dir": "dst"}),
        )
        .unwrap();
        assert_eq!(
            fortinet_bpf_add(String::new(), mac, true, false, false).unwrap(),
            "not (ether dst 00:1b:44:11:3a:b7)"
        );
        let bcast: sniffer::Snippet =
            serde_json::from_value(json!({"type": "etherBroadcast"})).unwrap();
        assert_eq!(
            fortinet_bpf_add(String::new(), bcast, false, false, false).unwrap(),
            "ether broadcast"
        );
        assert!(fortinet_bpf_preset(String::new(), "arp' ; x".into(), false).is_err());
    }
}
