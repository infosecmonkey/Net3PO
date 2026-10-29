# Net3PO

A free, open-source desktop toolkit for network and security engineers. One
app, many tools, each in its own panel. Runs on macOS, Windows and Linux,
needs no admin rights for the app itself, and sends no telemetry.

## Tools

| Category | Tools |
| --- | --- |
| Offline | Subnet Calculator (IPv4/IPv6, splitting), Regex Builder with networking recipes, Grep Builder (multi-pattern pipelines, GNU/BSD), MAC Vendor Lookup, Config Diff |
| Network | Dig, DNS Analyzer (SPF, DMARC, DKIM, MX, DNSSEC, NS), Port Scanner (TCP connect), Syslog Server, TFTP Server |
| SNMP | SNMP Walk (v1, v2c, v3), SNMP Sweep, Switch Port Mapper |
| Advanced | DHCP Monitor (rogue server detection), Visual Traceroute with Path MTU |
| Fortinet | Fortinet Command Builder, FortiGate Sniffer to PCAP |
| Decoders | Script Decoder (Python, JavaScript, Bash, PowerShell): unwraps obfuscation layers statically, never executes input |
| Remote | SSH with grouped saved connections, OS keychain secrets, host key pinning, tabs and a docked terminal |
| Workspace | Projects: collect results from several tools and export one report (HTML, PDF, Markdown, text) |

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

## Contributing

Issues and pull requests are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md).
Report security problems privately as described in [SECURITY.md](SECURITY.md).

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE). Third-party
licenses are listed in `static/third-party-notices.txt` and in the app under
About.
