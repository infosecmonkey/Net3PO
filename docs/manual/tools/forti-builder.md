# Fortinet Command Builder

> Build FortiOS CLI diagnostic command sets from validated form inputs, then copy them, save them, or send them to an open SSH session.

**Sidebar group:** Fortinet · **Works offline:** yes (nothing is sent unless you click Send to SSH) · **Needs admin rights:** no

## When to use it

- You need a correct `diagnose debug flow` or `diagnose sniffer packet` command quickly, with filters, and without typos in the middle of an outage.
- You want a repeatable set of HA, VPN or routing checks to run the same way on every unit.
- You want the stop-debug commands appended so a live debug is not left running on the firewall.
- You keep a personal library of commands you run often.

The builder generates text only. Always confirm the options against your FortiOS version (for example with `?` on the CLI) before running them on a production unit. Several tabs state that their options follow FortiOS 7.6.

## Quick start

1. Pick a tab: Session, Debug Flow, Sniffer, Ping, Traceroute, VPN, HA, Routing, System or Saved.
2. Fill in the fields you need. Blank fields are left out of the command.
3. Watch the **Command** box update as you type. A field with an invalid value is highlighted and the error message replaces the command.
4. Click **Copy** and paste into the FortiGate CLI, or click **Send to SSH** to type it into an open [SSH](ssh.md) session.
5. Click **Save .txt** to write it to a file, or **Save for later** to keep it in the **Saved** tab with a title and notes.

Input in every tab is kept when you switch tabs.

## Inputs and options

### Shared command box

Every builder tab ends with the same **Command** box:

| Button | What it does |
|---|---|
| Copy | Copies the command text to the clipboard. |
| Send to SSH | Types the command into an open SSH session, one line at a time, each followed by Enter, and makes that session active. `#` note lines and blank lines are skipped. The stop-debug block is held back (see below). With several sessions open, a menu lets you pick one (the active session is listed first). Disabled when no session is open. |
| Send stop | Appears after **Send to SSH** when the command has a stop-debug block. Click it when you are finished to type `diagnose debug disable` and `diagnose debug reset` into the same session. |
| Save .txt | Saves the command to a text file (default name `fortigate-<tab>.txt`). |
| Save for later | Asks for a **Title** (pre-filled from your inputs) and optional **Notes**, then adds the command to the Saved tab. |

All buttons are disabled while the inputs have an error.

**Send to SSH** skips `#` note lines and does not type the stop-debug block, so a live debug keeps running. When you have the output you need, click **Send stop** (or type the stop commands yourself). Commands under `# Changes cluster state` in the HA tab are sent like any other line, so review them before sending.

### Session

Builds `diagnose sys session filter ...` lines, then optionally `diagnose sys session stat` and `diagnose sys session list`. All filters combine with AND.

| Field | What it means |
|---|---|
| Source IP, Destination IP | IPv4 addresses. |
| Source port, Destination port | 1 to 65535. |
| Protocol | Any, TCP (6), UDP (17), ICMP (1), GRE (47), ESP (50). |
| VDOM index | The numeric index from `diagnose sys vd list`, not the VDOM name. |
| Clear filter first | Adds `filter clear` before the filters. On by default. |
| Negate filter | Adds `filter negate`. |
| Include session stats | Adds `diagnose sys session stat`. |
| List matching sessions | Adds `diagnose sys session list`. On by default. |

### Debug Flow

Builds a `diagnose debug flow` trace: filter, options, `trace start <count>`, `diagnose debug enable`.

| Field | What it means |
|---|---|
| Address (either), Source address, Destination address | IPv4 filters (`addr`, `saddr`, `daddr`). |
| Port (either), Source port, Destination port | Port filters (`port`, `sport`, `dport`). |
| Protocol | As in Session. |
| VDOM index | Numeric VDOM index. |
| Trace count | Packets to trace, 1 to 100,000. Default 1000. |
| Reset debug state first | Adds `diagnose debug disable` and `diagnose debug reset` first. On. |
| Show function names | `diagnose debug flow show function-name enable`. On. |
| Show iprope (policy lookup) | `diagnose debug flow show iprope enable`. Off. |
| Console timestamps | `diagnose debug console timestamp enable`. On. |
| Append stop-debug block | Adds a commented block with `diagnose debug disable` and `diagnose debug reset` to run when finished. On. |

With no address, port or protocol filter, the tab warns that an unfiltered trace floods the console on a busy unit. Parse the output with the [Debug Flow Parser](debug-flow.md).

### Sniffer

Builds one `diagnose sniffer packet <interface> '<filter>' <verbosity> <count> <timestamp>` command.

| Field | What it means | Default |
|---|---|---|
| Interface | Interface name (letters, digits, `. _ - :`, up to 35 characters), with suggestions such as `any`, `port1`, `wan1`. | any |
| Save interface name | Adds the current name to your suggestion list (shared with Ping and Traceroute). Remove a saved name with its **x**. | |
| Verbosity | 1 headers only, 2 headers and IP data, 3 headers and Ethernet data, 4 headers and interface names, 5 IP data and interface names, 6 Ethernet data and interface names. | 4 |
| Count (blank = until stopped) | Packets to capture, 0 to 10,000,000. | Blank |
| Timestamps | Relative, Absolute UTC (`a`), Absolute local (`l`). | Absolute local |
| Host, Network, Ports, Protocol | Simple filter fields, each with a direction (Either, Source, Destination). Ports are comma separated. Protocols: tcp, udp, icmp, icmp6, arp, ip, ip6, esp, gre. | |
| Custom BPF filter | Replaces the simple fields with a free BPF expression (up to 1,024 characters). | Off |

With **Custom BPF filter** on, a snippet builder helps compose the expression:

- **Presets**: TCP SYN, TCP RST, New TCP, ICMP ping, ARP, VLAN any, IPv6, Broadcast, Multicast. Click to add.
- **Snippet type**: Host (IP), Network (CIDR), Port(s), Protocol, Ethernet host (MAC), VLAN, TCP flags (with Exact match), ICMP type, Ether broadcast, Ether multicast, IP version, Ether protocol number, IP protocol number (decimal or `0x` hex). Host, Network, Ports and MAC take a direction.
- **Negate (NOT)**, **Wrap in parentheses**, **Combine with** AND or OR, then **Add to filter**. **Clear filter** empties it.

The tab also shows a policy snippet that disables ASIC/NPU offload (`set auto-asic-offload disable` on a firewall policy), with **Copy offload-disable snippet**. Offloaded sessions bypass the CPU sniffer after the first packets; re-enable offload when done. Verbosity 6 output can be converted with [FortiGate Sniffer to PCAP](forti-sniffer.md).

### Ping

Builds `exec ping-options ...` lines then `exec ping <destination>`. Blank fields are left out. No command is shown until a destination is entered.

| Field | What it means |
|---|---|
| Destination | IPv4 address or DNS host name. |
| Source IP (or auto) | IPv4 source or `auto`. Disabled when an egress interface is set. |
| Egress interface (or auto) | Interface name. Disabled when a source IP is set. |
| Repeat count, Timeout (s), Data size (bytes), Interval (s), TTL, VRF ID | Numeric ping options. |
| TOS | default, lowcost, lowdelay, throughput, reliability, or omitted. |
| Payload pattern (hex) | Hex pattern for the payload. |
| Reset ping options first | `exec ping-options reset`. On. Ping options persist for your admin session, so this avoids inheriting an earlier source or size. |
| Use SD-WAN rules for egress, Set DF bit, Adaptive ping, Validate reply | Toggle options. |
| Show settings before ping | `exec ping-options view-settings`. On. |

For an MTU test, set DF and a data size: 1472 bytes of data makes a 1500-byte packet. See the [MTU Calculator](mtu-calculator.md).

### Traceroute

Builds `exec traceroute-options ...` then `exec traceroute <destination>`: Destination, Source IP (or auto), Device (interface), Queries per hop, VRF ID, Reset traceroute options first (on), Use SD-WAN rules for egress, Show settings before trace (on).

### VPN

Shows IPsec gateway and tunnel state, then a filtered live IKE debug with `diagnose vpn ike log filter` and `diagnose debug application ike <level>`.

| Field | What it means |
|---|---|
| Phase 1 name | Filters the IKE log by gateway name, and narrows the gateway list. |
| Remote gateway (rem-addr4), Local gateway (loc-addr4), Remote gateway IPv6 (rem-addr6) | IKE log filters. |
| Destination port | For example 500 or 4500. |
| VDOM index (-1 = all) | Numeric VDOM index. |
| IKE debug level | Default -1. |
| Show gateway and tunnel status first | `diagnose vpn ike gateway list` and `diagnose vpn tunnel list`, by tunnel **Name** (up to 8, blank = all) or **Number**. On. |
| Reset debug state first, Show the active filter, Console timestamps, Append stop-debug block | As in Debug Flow. |

With no filter set, the tab warns that the debug mixes every negotiation together.

### HA

Health checks for a FortiGate HA cluster:

- **Status and health**: `get system ha status` (on by default), HA status (diagnose), failover history, HA statistics, heartbeat stats, virtual MAC info, sync statistics, hasync daemon stats.
- **Checksums and dumps**: cluster checksum (optional serial numbers, up to 16), show checksum (optional scope, such as `global` or a VDOM), show non-sync checksum, recalculate checksum, and **Dump HA data by** group, vcluster, vdom, device, kernel, rcache or debug-zone.
- **Live debug**: hatalk (heartbeat, election) and hasync (config sync), with level and the reset, timestamp and stop-debug options.
- **Changes cluster state** (placed last, under a `# Changes cluster state: review before running` comment): reset HA uptime (primary only, or all), `execute ha synchronize start` or `stop`, and `execute ha manage <index> <admin>` to log in to a peer. Resetting uptime can trigger a failover. The peer password is never part of the command; the FortiGate prompts for it.

### Routing

Pick one mode:

- **OSPF**: `get router info ospf` views (status and neighbors on by default; interfaces, database, routes, routes in RIB, border routers, virtual links) and an optional live OSPF debug with areas lsa, packet, events, ifsm, nfsm, nsm, route (none ticked means all).
- **BGP**: summary, network table (optional prefix), neighbor routes, advertised routes and received routes for a **Neighbor IP**, and an optional live BGP debug with areas events, fsm, keepalives, updates, filters, dampening, nsm. Received routes need soft-reconfiguration inbound on the neighbor.
- **Routing table / policy routes**: `get router info routing-table` views (all, static, connected, ospf, bgp, rip, isis, database), route details for an IP, and `diagnose firewall proute list`, `proute6 list` and policy route stats.

### System

CPU, memory and process checks:

- **Command**: `diagnose sys top`, `top-all`, `top-mem`, `top-fd` or `top-sockmem`. For top and top-all: Delay (default 5 s), Max lines (default 20), Iterations (default unlimited). The arguments are positional, so setting a later one fills in the defaults before it. For the others: Processes (default 5).
- **Run first**: performance status (on by default), performance top, and `diagnose hardware sysinfo` memory, CPU, interrupts, slab and conserve mode.

### Saved

Lists commands saved with **Save for later**, newest first, with title, category tag, date, notes and the command.

| Control | What it does |
|---|---|
| Search | Matches title, notes, command and category. |
| Export shown | Saves the listed commands to one text file, each under `#` comment lines with its title, category and notes. |
| Delete all | Click twice within 3 seconds to confirm. |
| Copy, Export, Edit, Delete (per item) | Edit changes the title and notes only. |

## Reading the results

The command box shows plain FortiOS CLI, one command per line. Lines starting with `#` are notes for you (for example `# When finished, stop the debug:`). Leave them out when pasting if your CLI complains about them.

Worked example. Debug Flow with Source address `192.0.2.10`, Destination port `443`, Protocol TCP and the defaults produces:

```
diagnose debug disable
diagnose debug reset
diagnose debug flow filter clear
diagnose debug flow filter saddr 192.0.2.10
diagnose debug flow filter dport 443
diagnose debug flow filter proto 6
diagnose debug flow show function-name enable
diagnose debug console timestamp enable
diagnose debug flow trace start 1000
diagnose debug enable

# When finished, stop the debug:
diagnose debug disable
diagnose debug reset
```

A Sniffer with interface `port1`, host `198.51.100.7`, port 53, verbosity 6 and count 100 produces:

```
diagnose sniffer packet port1 'host 198.51.100.7 and port 53' 6 100 l
```

## What the results do and do not tell you

- The builder checks syntax (addresses, ports, ranges, names, keywords). It does not know which options your FortiOS version, model or license supports. Confirm against your FortiOS version before running.
- Live debugs (flow, IKE, HA, OSPF, BGP) consume CPU and console output on the firewall. Filter them and keep the stop-debug block.
- HA "Changes cluster state" commands act on the cluster. Review them before running.
- VDOM fields take the numeric index, not the name.

## Online activity and privacy

The builder runs locally and sends nothing by itself. **Send to SSH** types the command into a session you opened yourself in the [SSH](ssh.md) tool.

Saved commands and saved interface names are stored on this computer in the app data folder (`fortinet_saved_commands` and `fortinet_interfaces`). Do not save commands containing secrets. The HA peer login never includes a password. See [Privacy](../privacy.md).

## Export and projects

**Save .txt** saves the current command. **Export shown** and per-item **Export** in the Saved tab write plain text with comment headers. There is no report export or "Add to project" for this tool; paste commands into a [project note](../projects-and-notes.md) if needed.

## Platform notes

No differences between macOS, Windows and Linux.

## Troubleshooting

**The command box shows an error instead of a command.** A field is invalid; it is highlighted. Typical messages: an address that is not IPv4, a port outside 1 to 65535, a number outside its range ("must be a whole number from ... to ..."), "verbosity must be 1 to 6", "filter is longer than 1024 characters", "at most 8 tunnel names", "unknown TCP flag", "unknown ICMP type".

**Ping or Traceroute shows "Enter a destination to build the command."** Enter a destination.

**Source IP or Egress interface is greyed out.** They are either/or. Clear one to use the other.

**Send to SSH is disabled.** No SSH session is open. Open one in the [SSH](ssh.md) tool.

**"That session is closed."** The session ended between opening the menu and sending. Reconnect.

**"The saved commands file was unreadable and was moved aside as ..."** The saved commands file was damaged. A new empty list was started and the old file was kept under the name shown.

**The sniffer only shows the first packets of a session.** The session is offloaded to the NPU. Use the offload-disable snippet on the policy, then clear the session.

## Related tools

- [SSH](ssh.md)
- [Debug Flow Parser](debug-flow.md)
- [FortiGate Sniffer to PCAP](forti-sniffer.md)
- [Packet Filter Builder](filter-builder.md)
- [MTU Calculator](mtu-calculator.md)
