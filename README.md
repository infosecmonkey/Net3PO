# Net3PO

A free, open-source desktop toolkit for network and security engineers. One
app, many tools, each in its own panel. Runs on macOS, Windows and Linux,
needs no admin rights for the app itself, and sends no telemetry.

## Tools

The sidebar groups tools the way troubleshooting usually goes. Every tool has
a page in the [user manual](docs/manual/README.md), also available inside the
app from the help button.

| Group | Tools |
| --- | --- |
| Workspace | Projects: collect results and notes from several tools and export one report (HTML, PDF, Markdown, text), redacted if needed |
| Analysis | DNS Analyzer (SPF, DMARC, DKIM, MX, DNSSEC, NS), Email Header Analyzer, TLS Inspector, Certificate Converter (PEM, DER, P7B, PFX; chain and key matching), JWT / SAML Inspector, Windows Event Log, PCAP Inspector (with clean copies for sharing and extraction of HTTP, FTP and TFTP files and G.711 calls), IOC Extractor, Config Diff, Script Decoder (unwraps obfuscated Python, JavaScript, Bash and PowerShell statically), Encoder Workbench (with a shell command explainer) |
| Troubleshooting | Dig, DNS Benchmark (UDP, TCP, DoT, DoH), NTP Checker, Port Scanner (TCP connect), Visual Traceroute with Path MTU, HTTP Troubleshooter, Socket Tools, Connectivity Monitor, Throughput Tester (iperf3 compatible), Network Snapshot, Wake-on-LAN |
| Discovery and SNMP | LLDP / CDP Neighbors, SNMP Walk (v1, v2c, v3), SNMP Sweep, Switch Port Mapper, DHCP Monitor (rogue server detection) |
| Servers | Syslog Server, TFTP Server |
| Remote | SSH (OS keychain secrets, host key pinning, tabs), SFTP, and RDP and VNC launchers for the installed clients, all sharing one set of connection groups |
| Utilities | Subnet Calculator (IPv4/IPv6, splitting), Timestamp Converter, Hash Calculator, MTU Calculator, Regex Builder, Grep Builder, Packet Filter Builder, MAC Vendor Lookup, Obfuscator (remove IPs, names, accounts, secrets, MACs and serials before pasting into an AI assistant or a ticket, then restore the reply) |
| Fortinet | Fortinet Command Builder, FortiGate Sniffer to PCAP, Debug Flow Parser, Session List Parser (`diagnose sys session list` with decoded flags and offload reasons) |

## Build from source

Requirements: Rust stable, Node.js 22+, pnpm, and the
[Tauri 2 prerequisites](https://v2.tauri.app/start/prerequisites/) for your OS.

```sh
pnpm install
pnpm tauri dev      # run with hot reload
pnpm tauri build    # installer for the current OS
```

Checks run in CI on macOS, Windows and Ubuntu:

```sh
cargo fmt --manifest-path src-tauri/Cargo.toml --check
cargo clippy --manifest-path src-tauri/Cargo.toml --all-targets -- -D warnings
cargo test --manifest-path src-tauri/Cargo.toml
pnpm check
```

The MAC vendor database is built from the IEEE registry at compile time. Set
`OUI_OFFLINE=1` to build offline with the bundled seed set.

## Feedback and support

No email needed; everything goes through GitHub (a free account is enough):

- **Found a bug?** [Open a bug report](https://github.com/infosecmonkey/Net3PO/issues/new?template=bug_report.yml). The form asks for the tool, your OS and the version from About.
- **Have an idea?** [Request a feature](https://github.com/infosecmonkey/Net3PO/issues/new?template=feature_request.yml).
- **Questions or general feedback?** Start a thread in [Discussions](https://github.com/infosecmonkey/Net3PO/discussions).
- **Security problem?** Report it [privately](https://github.com/infosecmonkey/Net3PO/security/advisories/new), never in a public issue.

Please leave out passwords, keys and real customer data when you post.

## Download

Installers for macOS, Windows and Linux are on the
[Releases page](https://github.com/infosecmonkey/Net3PO/releases/latest),
with install notes and SHA-256 checksums.

## Contributing

Issues and pull requests are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md).
Report security problems privately as described in [SECURITY.md](SECURITY.md).

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE). Third-party
licenses are listed in `static/third-party-notices.txt` and in the app under
About.
