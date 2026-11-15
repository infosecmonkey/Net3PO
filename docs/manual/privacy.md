# Privacy and data

Net3PO has no accounts, no telemetry, no analytics and no automatic update checks. It sends
nothing anywhere unless you click a button that does a network job.

## What goes on the network, and when

- **Offline tools never use the network:** Subnet Calculator, Timestamp Converter, Hash
  Calculator, MTU Calculator, Regex Builder, Grep Builder, Filter Builder, MAC Vendor Lookup
  (the vendor database is bundled), Config Diff, Script Decoder, Encoder Workbench, IOC
  Extractor, PCAP Inspector, Windows Event Log, JWT / SAML Inspector, Debug Flow Parser,
  FortiGate Sniffer to PCAP, the Fortinet Command Builder and Network Snapshot (which reads
  local configuration with the OS's own commands).
- **Network tools send traffic only to the target you enter, only when you click:** Dig, DNS
  Analyzer, NTP Checker, Port Scanner, Visual Traceroute, HTTP Troubleshooter, Socket Tools,
  Connectivity Monitor, Throughput Tester (client mode), Wake-on-LAN, SNMP Walk and Sweep, Switch Port Mapper, TLS Inspector,
  SSH and SFTP. RDP and VNC send nothing themselves: they open your installed
  client, which connects to the host you pick.
- **Listeners accept traffic only while running:** Syslog Server, TFTP Server, DHCP Monitor and
  the Throughput Tester in server mode
  listen on a port from **Start** until **Stop**.
- **Optional online lookups** are separate buttons and say what they contact. For example the
  Email Header Analyzer can look up a sending IP in the regional internet registry (RDAP);
  without the click, header analysis stays offline.
- **Links in tokens are never followed.** For example the JWT inspector shows `jku` and `x5u`
  URLs but never fetches them.

## What is stored on this computer

| Data | Where |
|---|---|
| Projects, saved results and notes | App data folder, `projects/` |
| Saved SSH hosts and known host keys | App data folder |
| Saved RDP and VNC hosts, and app settings (which remote clients to open) | App data folder (`rdp_hosts`, `vnc_hosts`, `settings`) |
| SSH passwords and key passphrases | OS keychain (macOS Keychain, Windows Credential Manager, Linux Secret Service), only if you choose to save them |
| Network snapshots | App data folder, `snapshots/` |
| Tool history and settings (for example recent targets) | App data folder |
| Unsaved note draft, sidebar layout, redaction settings | App's local web storage |

App data folder:

- **macOS:** `~/Library/Application Support/com.infosecops.omnipacket/`
- **Windows:** `%APPDATA%\com.infosecops.omnipacket\`
- **Linux:** `~/.local/share/com.infosecops.omnipacket/`

(The folder keeps the project's original internal name so data carries over between versions.)

To remove everything, uninstall the app, delete that folder, and remove any "OmniPacket SSH"
entries from your OS keychain.

## Files you open

Captures, logs and configs you open are read locally and stay where they are. Net3PO does not
copy them anywhere. A result is written to disk only when you export it or add it to a project.

## Reports

Reports never include passwords, SNMP communities, SNMPv3 keys or private keys. Use
[redacted export](export-and-redaction.md#redacted-export) to replace addresses, names and other
identifying values before sharing.
