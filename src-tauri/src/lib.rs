mod projects;
mod report;
mod store;
mod tools;

use projects::commands::{
    ProjectsLock, project_add, project_create, project_delete, project_export, project_get,
    project_list, project_note_delete, project_note_save, project_redact_preview, project_update,
};
use report::commands::{report_export, report_redact_preview};
use store::commands::{StoreLock, store_load, store_save};
use tools::cert_convert::commands::{cert_export, cert_inspect, cert_read_file};
use tools::config_diff::commands::{diff_compare, diff_read_file, diff_save};
use tools::conn_monitor::commands::{MonitorRegistry, mon_save, mon_start, mon_stop};
use tools::debug_flow::commands::{flow_parse, flow_read_file};
use tools::dhcp_monitor::commands::{DhcpRegistry, dhcp_interfaces, dhcp_monitor, dhcp_stop};
use tools::dig::commands::dig_query;
use tools::dns_analyzer::commands::dns_analyze;
use tools::dns_bench::commands::{
    BenchRegistry, dns_bench_cancel, dns_bench_defaults, dns_bench_run,
};
use tools::email_analyzer::commands::{
    email_analyze, email_blocklist_check, email_blocklists, email_ip_owner, email_open,
};
use tools::encoder::commands::codec_run;
use tools::event_log::commands::{
    EventLogRegistry, evtlog_cancel, evtlog_close, evtlog_export_rows, evtlog_load, evtlog_query,
    evtlog_record,
};
use tools::fgt_session::commands::session_parse;
use tools::fgt_sniffer::commands::{fgt_parse, fgt_read_file, fgt_save};
use tools::filter_builder::commands::filter_build;
use tools::fortinet_builder::commands::{
    fortinet_bpf_add, fortinet_bpf_preset, fortinet_build, fortinet_offload_snippet,
    fortinet_save_text,
};
use tools::grep_builder::commands::{grep_build, grep_preview};
use tools::hashes::commands::{HashRegistry, hash_compare, hash_file, hash_stop, hash_text};
use tools::http_client::commands::http_send;
use tools::ioc::commands::{ioc_extract, ioc_transform};
use tools::iperf::commands::{IperfRegistry, iperf_client, iperf_detect, iperf_server, iperf_stop};
use tools::jwt_saml::commands::{jwt_inspect, saml_inspect, saml_read_file, saml_scan};
use tools::lldp::commands::{LldpRegistry, lldp_listen, lldp_read_file, lldp_status, lldp_stop};
use tools::mac_vendor::commands::{mac_db_info, mac_lookup};
use tools::mtu_calc::commands::mtu_calculate;
use tools::net_snapshot::commands::{
    snap_compare, snap_delete, snap_export_file, snap_get, snap_import_file, snap_label, snap_list,
    snap_take,
};
use tools::ntp_check::commands::ntp_check;
use tools::obfuscator::commands::{obfuscate_restore, obfuscate_text};
use tools::pcap_inspector::commands::{
    PcapRegistry, pcap_cancel, pcap_close, pcap_extract, pcap_extract_save, pcap_open,
    pcap_open_external, pcap_packet, pcap_query, pcap_sanitize,
};
use tools::port_mapper::commands::{PortMapRegistry, port_map, port_map_cancel, port_map_save};
use tools::port_scanner::commands::{ScanRegistry, port_scan, port_scan_cancel};
use tools::regex_builder::commands::{regex_recipes, regex_replace, regex_test};
use tools::remote_launch::commands::{remote_clients, remote_launch, vnc_check};
use tools::script_decoder::commands::{script_decode, script_read_file};
use tools::sftp::commands::{
    SftpRegistry, sftp_cancel, sftp_close, sftp_connect, sftp_download, sftp_list, sftp_mkdir,
    sftp_remove, sftp_rename, sftp_upload,
};
use tools::shell_explain::commands::shell_explain;
use tools::snmp_sweep::commands::{SweepRegistry, snmp_sweep, snmp_sweep_cancel};
use tools::snmp_walk::commands::{
    MibState, SnmpRegistry, snmp_load_mib, snmp_mib_info, snmp_walk, snmp_walk_cancel,
};
use tools::socket_tools::commands::{
    SocketRegistry, sock_listen, sock_send, sock_stop, sock_timing,
};
use tools::ssh::commands::{
    SshRegistry, ssh_close, ssh_connect, ssh_forget_host, ssh_resize, ssh_secret_delete,
    ssh_secret_has, ssh_secret_set, ssh_write,
};
use tools::subnet_calculator::commands::{
    cidr_aggregate, cidr_compare, subnet_calculate, subnet_split,
};
use tools::syslog_server::commands::{
    SyslogRegistry, syslog_save, syslog_send, syslog_start, syslog_stop,
};
use tools::tftp_server::commands::{TftpRegistry, tftp_start, tftp_stop};
use tools::timestamp::commands::{ts_convert, ts_now};
use tools::tls_inspector::commands::{tls_decode, tls_decode_file, tls_inspect, tls_test_suites};
use tools::traceroute::commands::{TraceRegistry, trace_method, trace_run, trace_stop};
use tools::wake_on_lan::commands::{WolRegistry, wol_check, wol_interfaces, wol_send, wol_stop};

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .manage(ScanRegistry::default())
        .manage(BenchRegistry::default())
        .manage(PcapRegistry::default())
        .manage(HashRegistry::default())
        .manage(MonitorRegistry::default())
        .manage(IperfRegistry::default())
        .manage(LldpRegistry::default())
        .manage(SocketRegistry::default())
        .manage(SyslogRegistry::default())
        .manage(TftpRegistry::default())
        .manage(SnmpRegistry::default())
        .manage(MibState::default())
        .manage(SweepRegistry::default())
        .manage(PortMapRegistry::default())
        .manage(DhcpRegistry::default())
        .manage(EventLogRegistry::default())
        .manage(WolRegistry::default())
        .manage(TraceRegistry::default())
        .manage(StoreLock::default())
        .manage(SshRegistry::default())
        .manage(SftpRegistry::default())
        .manage(ProjectsLock::default())
        .invoke_handler(tauri::generate_handler![
            cidr_aggregate,
            cidr_compare,
            subnet_calculate,
            subnet_split,
            regex_test,
            regex_replace,
            regex_recipes,
            grep_build,
            grep_preview,
            mac_lookup,
            mtu_calculate,
            ntp_check,
            pcap_open,
            pcap_cancel,
            pcap_close,
            pcap_query,
            pcap_packet,
            pcap_open_external,
            pcap_sanitize,
            pcap_extract,
            pcap_extract_save,
            mac_db_info,
            fgt_parse,
            filter_build,
            fgt_save,
            fgt_read_file,
            diff_compare,
            diff_read_file,
            diff_save,
            report_export,
            report_redact_preview,
            ssh_connect,
            ssh_write,
            ssh_resize,
            ssh_close,
            ssh_secret_set,
            ssh_secret_has,
            ssh_secret_delete,
            ssh_forget_host,
            sftp_connect,
            sftp_close,
            sftp_list,
            sftp_mkdir,
            sftp_rename,
            sftp_remove,
            sftp_cancel,
            sftp_download,
            sftp_upload,
            remote_clients,
            remote_launch,
            vnc_check,
            script_decode,
            shell_explain,
            obfuscate_text,
            obfuscate_restore,
            script_read_file,
            project_list,
            project_create,
            project_get,
            project_update,
            project_delete,
            project_add,
            project_export,
            project_redact_preview,
            project_note_save,
            project_note_delete,
            dig_query,
            dns_analyze,
            port_scan,
            port_scan_cancel,
            cert_read_file,
            cert_inspect,
            cert_export,
            dns_bench_defaults,
            dns_bench_run,
            dns_bench_cancel,
            syslog_start,
            syslog_stop,
            syslog_save,
            syslog_send,
            tftp_start,
            tftp_stop,
            snmp_walk,
            snmp_walk_cancel,
            snmp_load_mib,
            snmp_mib_info,
            snmp_sweep,
            snmp_sweep_cancel,
            port_map,
            port_map_cancel,
            port_map_save,
            dhcp_interfaces,
            dhcp_monitor,
            flow_parse,
            flow_read_file,
            session_parse,
            dhcp_stop,
            hash_text,
            hash_file,
            hash_stop,
            hash_compare,
            http_send,
            ioc_extract,
            jwt_inspect,
            saml_inspect,
            saml_scan,
            saml_read_file,
            ioc_transform,
            mon_start,
            mon_stop,
            mon_save,
            iperf_detect,
            iperf_client,
            iperf_server,
            iperf_stop,
            lldp_status,
            lldp_listen,
            lldp_stop,
            lldp_read_file,
            snap_take,
            snap_list,
            snap_get,
            snap_label,
            snap_delete,
            snap_compare,
            snap_export_file,
            snap_import_file,
            ts_convert,
            ts_now,
            tls_decode,
            tls_decode_file,
            tls_inspect,
            tls_test_suites,
            sock_send,
            sock_listen,
            sock_timing,
            sock_stop,
            evtlog_load,
            evtlog_cancel,
            evtlog_query,
            evtlog_record,
            evtlog_export_rows,
            evtlog_close,
            codec_run,
            email_analyze,
            email_open,
            email_blocklists,
            email_ip_owner,
            email_blocklist_check,
            wol_interfaces,
            wol_send,
            wol_check,
            wol_stop,
            trace_method,
            trace_run,
            trace_stop,
            store_load,
            store_save,
            fortinet_build,
            fortinet_bpf_add,
            fortinet_bpf_preset,
            fortinet_offload_snippet,
            fortinet_save_text
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
