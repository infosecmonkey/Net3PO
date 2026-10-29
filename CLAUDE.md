# CLAUDE.md

Project context for Claude Code. Read this at the start of every session.

## Product

A free, open-source, cross-platform desktop toolkit for network and security
engineers. One app, many tools, each in its own panel. Owner: Manny (InfoSecOps, Inc.).
Product name: **Net3PO** (repo `infosecmonkey/Net3PO`). Internal names stay
`omnipacket` (crate, bundle identifier `com.infosecops.omnipacket`, keychain
service "OmniPacket SSH") so existing app data and saved secrets keep working.
Licensed under Apache-2.0 (`LICENSE`, `NOTICE`). The source is public, so code
quality, signed builds and clean dependency licensing matter.

Targets: macOS (Apple Silicon and Intel, universal build), Windows 10/11 (x64), Linux (Ubuntu, Debian, RHEL family).

## Stack

- Tauri 2 (Rust backend, web front end)
- Front end: Svelte + TypeScript, built with Vite, package manager pnpm
- Backend: Rust stable, async with tokio
- Packaging: Tauri bundler (.dmg, .msi/NSIS, .deb, .rpm, AppImage)
- CI: GitHub Actions matrix (macOS, Windows, Ubuntu)

## Commands

- `pnpm install` install front-end deps
- `pnpm tauri dev` run the app with hot reload
- `pnpm tauri build` production build for the current OS
- `cargo test --manifest-path src-tauri/Cargo.toml` run Rust tests
- `cargo clippy --manifest-path src-tauri/Cargo.toml -- -D warnings` lint
- `cargo fmt --manifest-path src-tauri/Cargo.toml` format
- `pnpm check` Svelte/TypeScript type check
- `cargo deny check` (from `src-tauri`) Rust licenses, advisories, banned crates; policy in `src-tauri/deny.toml`
- `pnpm licenses:check` npm license allowlist

Run fmt, clippy, tests and `pnpm check` before calling a task done.

## Architecture

- Each tool is a Rust module under `src-tauri/src/tools/<tool_name>/` with:
  - pure logic in `mod.rs` or `core.rs` (no Tauri types, fully unit tested)
  - Tauri commands in `commands.rs` that call the core and return serializable results
- Register commands in `src-tauri/src/lib.rs`.
- Each tool has a Svelte panel under `src/lib/tools/<ToolName>/`.
- The app shell has a left sidebar listing tools, grouped by category; the main area shows the selected tool.
- Long-running tools (scans, sweeps, servers like syslog and TFTP) stream progress to the UI with Tauri events and must be cancellable.
- Errors: use `thiserror` in Rust, return clear messages to the UI. Never panic on bad user input.
- Settings and history: store locally in the OS app data dir. No telemetry.

## Feature roadmap

Build in this order. Finish, test and commit each tool before starting the next.

Phase 1, offline tools (no privileges, no network):
1. Subnet calculator, sipcalc style, including splitting (e.g. 10.1.1.0/24 into /28s). IPv4 and IPv6.
2. Regex builder: paste sample data, build and test expressions live.
3. Grep builder: build grep commands, integrated with the regex builder.
4. MAC address vendor lookup from a bundled OUI database built from the IEEE registry.
5. FortiGate sniffer output to PCAP converter (from `diagnose sniffer packet` text output).

Phase 2, basic network tools:
6. Dig with selectable record-type buttons (A, AAAA, MX, TXT, NS, CNAME, SOA, PTR, SRV, CAA).
7. DNS analyzer with audit (SPF, DMARC, DKIM, DNSSEC, NS consistency).
8. Port scanner, nmap-like TCP connect scan first.
9. Syslog server for temporary log collection (UDP/TCP 514, configurable port).
10. TFTP server (UDP 69, configurable port, chosen root folder).

Phase 3, SNMP:
11. SNMP walk, v1, v2c and v3 (auth and priv), with MIB testing.
12. SNMP sweep across a subnet.
13. Switch port mapper via SNMP (MAC to port mapping, visual layout).

Phase 4, advanced:
14. DHCP monitor (detect who is offering DHCP, rogue server detection).
15. Visual traceroute, HopMatrix style.

Phase 5:
16. Fortinet command builder, ported from Manny's existing Swift/Xcode app.

## Hard rules

- Cross-platform: every tool must work on macOS, Windows and Linux, or clearly show why it can't on that OS.
- Privileges: never require running the whole app as admin/root. Detect missing privileges and explain what is needed for that tool only.
- Never bundle Npcap: its license forbids redistribution, free or paid. Prefer normal sockets wherever possible; any capture feature must use a user-installed Npcap/libpcap and degrade cleanly without it.
- Licenses: MIT, Apache-2.0, BSD, ISC, Zlib, MPL-2.0 dependencies only (plus the documented exceptions in `src-tauri/deny.toml`). No GPL, LGPL or AGPL. Enforce with `cargo-deny`.
- Third-party notices: after adding or updating a dependency, run `pnpm notices` and commit `static/third-party-notices.txt` (shown in the About dialog).
- Security: this is a security tool, so treat all network input as hostile. Bound buffer sizes, validate parsers, add timeouts on every socket.
- Secrets: never commit keys, certificates, `.env` files or signing credentials. They live in GitHub Actions secrets only. The repo is public: no customer names, device IPs or configs from real networks in code, tests or fixtures.

## Style

- Rust: idiomatic, small functions, doc comments on public items, unit tests for all core logic.
- UI text: short, technical, practitioner tone. No marketing fluff.
- No em dashes in UI text, docs or comments.
- Prefer well-maintained crates over hand-rolled protocol code, but check their licenses first.

## Workflow

- Work one tool at a time.
- Explain the plan briefly before large changes.
- After a tool works, summarize what changed so Manny can test and commit.
- Ask before adding a new dependency that is large or has native build requirements.

## Branching

- Cut a new branch from `main` for each tool, named `feat/<tool>`.
- Finish, test and commit the tool on its branch, then open a PR into `main`.
- Merge into `main` only after Manny confirms the tool works in `pnpm tauri dev`.
- Start the next tool from a fresh branch off the updated `main`.
