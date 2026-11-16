# Getting started

Net3PO is a desktop toolkit for network and security engineers: one app, many tools, each in
its own panel. It runs on macOS, Windows and Linux, needs no account, and sends no telemetry.

## The window

- **Sidebar (left):** tools grouped by job. Click a group name to collapse or expand it;
  **Expand all / Collapse all** sits at the top. The app remembers which groups you closed.
- **Main area:** the selected tool.
- **Notes (right, optional):** a pop-out for project notes, toggled with
  **Cmd+Shift+N** (macOS) or **Ctrl+Shift+N** (Windows, Linux). See
  [Projects and notes](projects-and-notes.md).
- **Help (right, optional):** this manual, built into the app and readable offline. Press
  **F1** or click the **?** next to the logo to open the page for the tool you are using;
  **Contents** lists every page. Help and Notes share the right edge, so opening one hides
  the other (an unsaved note is kept). **Esc** closes it.
- **SSH session bar:** when SSH sessions are open, a bar above other tools lets you switch to
  a session or dock a terminal under the current tool. See [SSH](tools/ssh.md).

## Tool groups

| Group | Tools |
|---|---|
| Workspace | [Projects](tools/projects.md) |
| Analysis | [DNS Analyzer](tools/dns-analyzer.md), [Email Header Analyzer](tools/email-analyzer.md), [TLS Inspector](tools/tls-inspector.md), [JWT / SAML Inspector](tools/jwt-saml.md), [Windows Event Log](tools/event-log.md), [PCAP Inspector](tools/pcap-inspector.md), [IOC Extractor](tools/ioc-extractor.md), [Config Diff](tools/config-diff.md), [Script Decoder](tools/script-decoder.md), [Encoder Workbench](tools/encoder-workbench.md) |
| Troubleshooting | [Dig](tools/dig.md), [NTP Checker](tools/ntp-checker.md), [Port Scanner](tools/port-scanner.md), [Visual Traceroute](tools/traceroute.md), [HTTP Troubleshooter](tools/http-troubleshooter.md), [Socket Tools](tools/socket-tools.md), [Connectivity Monitor](tools/conn-monitor.md), [Throughput Tester](tools/iperf.md), [Network Snapshot](tools/net-snapshot.md), [Wake-on-LAN](tools/wake-on-lan.md) |
| Discovery and SNMP | [LLDP / CDP Neighbors](tools/lldp.md), [SNMP Walk](tools/snmp-walk.md), [SNMP Sweep](tools/snmp-sweep.md), [Switch Port Mapper](tools/port-mapper.md), [DHCP Monitor](tools/dhcp-monitor.md) |
| Servers | [Syslog Server](tools/syslog-server.md), [TFTP Server](tools/tftp-server.md) |
| Remote | [SSH](tools/ssh.md), [SFTP](tools/sftp.md), [RDP](tools/rdp.md) and [VNC](tools/vnc.md) (shown when a client is installed; see [Settings](tools/settings.md)) |
| Utilities | [Subnet Calculator](tools/subnet-calculator.md), [Timestamp Converter](tools/timestamp-converter.md), [Hash Calculator](tools/hash-calculator.md), [MTU Calculator](tools/mtu-calculator.md), [Regex Builder](tools/regex-builder.md), [Grep Builder](tools/grep-builder.md), [Packet Filter Builder](tools/filter-builder.md), [MAC Vendor Lookup](tools/mac-vendor.md) |
| Fortinet | [Fortinet Command Builder](tools/forti-builder.md), [FortiGate Sniffer to PCAP](tools/forti-sniffer.md), [Debug Flow Parser](tools/debug-flow.md) |

## A typical workflow

1. Net3PO opens on **Workspace > Projects**. Create a project for the job there (for example "Branch 12 VPN outage").
2. Run tools. When a result matters, open the tool's **Export** menu and pick the project under
   **Add to project**.
3. Keep notes as you go in the Notes pop-out; each note is tied to the project and the tool.
4. At the end, export the whole project as one HTML, PDF, Markdown or text report, redacted if
   it leaves your organization. See [Export and redaction](export-and-redaction.md).

## Conventions used in every tool

- **Nothing runs on its own.** Network traffic and online lookups happen only when you click a
  button. Offline tools never touch the network.
- **Long jobs can be stopped.** Scans, sweeps, monitors and servers stream results as they run
  and have a **Stop** button.
- **Results say what they cannot prove.** For example, a silent UDP port is reported as
  "open or filtered", not "open".
- **Hostile input is bounded.** Pasted text and opened files have size limits, and parsers
  reject malformed data with a message instead of crashing.

## Next

- [Installing](installing.md)
- [Privacy and data](privacy.md)
- [Troubleshooting and FAQ](troubleshooting.md)
