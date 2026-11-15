# Network Snapshot

> Record this computer's interfaces, routes, DNS, neighbor table and listening ports, and compare two snapshots.

**Sidebar group:** Troubleshooting · **Works offline:** yes (it reads local configuration only and sends nothing) · **Needs admin rights:** no

## When to use it

- Before and after a change: a firewall policy push, a VPN client upgrade, a driver update. Compare the two snapshots to see exactly what moved.
- Connect and disconnect a VPN, and see which routes, DNS servers and interfaces it adds.
- "It worked yesterday": compare today's snapshot with one saved earlier.
- Compare two computers that should be configured the same, using **Save file...** on one and **Open file...** on the other.
- Spot a gateway MAC address that changed for the same IP, a possible sign of ARP spoofing.

## Quick start

1. Click **Take snapshot**. It takes a few seconds and is saved automatically.
2. Optionally type a **Label** (for example `before VPN`) and click **Save label**.
3. Make your change, then click **Take snapshot** again.
4. Switch to **Compare**. The newest snapshot is already selected as **After (B)** and the previous one as **Before (A)**.
5. Click **Compare** and read the **Notable changes** list, then each section tab.
6. Use **Export** to save the snapshot or the comparison as a report, or add it to a project.

## Inputs and options

| Field | What it means | Default / accepted values |
|---|---|---|
| Take snapshot | Reads the current configuration and saves it. | |
| Open file... | Adds a snapshot file saved with **Save file...** (for example from another computer) to the list. If its id clashes with a saved one, it gets a new id. | `.json` snapshot files up to 16 MB |
| View / Compare | Switches between viewing one snapshot and comparing two. Compare needs at least two saved snapshots. | View |
| Saved list | Every saved snapshot, newest first: label or host and time, OS, and counts. A **failed** tag means a section could not be read. | |
| Label | A name for the selected snapshot. Press Enter or click **Save label**. | Empty; up to 200 characters |
| Section tabs | Interfaces, Routes, DNS, Neighbors, Listening ports, each with its row count. | Interfaces |
| Filter rows | Shows only rows containing the text, in any column. | Empty |
| Save file... | Writes the selected snapshot to a JSON file. | |
| Delete | Removes the selected snapshot after confirmation. | |
| Before (A) / After (B) | The two snapshots to compare. **Swap** exchanges them. | Previous and newest after a new snapshot |

## Reading the results

**View** shows the time, host name and OS, then one table per section:

- **Interfaces:** name, state (up or down), MTU, MAC address and every address in CIDR form, including IPv6 link-local.
- **Routes:** IPv4 and IPv6 routes with destination, gateway (`on-link` when there is none), interface and metric. On Linux the main table is read; on macOS the ARP/ND host entries that `netstat -rn` mixes into the table are left out (they appear under Neighbors).
- **DNS:** servers and search domains per scope. macOS shows the default resolver and any per-domain resolvers; Linux shows `/etc/resolv.conf` and, with systemd-resolved, each link; Windows shows each interface and the global suffix search list.
- **Neighbors:** ARP (IPv4) and neighbor discovery (IPv6) entries: IP, MAC, interface and state. Multicast and broadcast entries are left out.
- **Listening ports:** TCP sockets in LISTEN and bound UDP sockets, with process name and PID where the OS shows them.

A yellow box lists any source that failed and why. A grey box shows limits that applied (for example "your own processes only"). **Sources** at the bottom lists the exact command behind every section.

**Compare** shows:

- **Notable changes:** a MAC address that changed for the same neighbor IP, a default route that was added, removed or changed, DNS servers or search domains that changed, and new listening ports.
- One tab per section with the number of differences. Each row is **added** (only in B), **removed** (only in A) or **changed** (in both, with the differing fields named).

Worked example. Snapshot A is taken on a laptop, then a VPN client connects and snapshot B is taken. The comparison shows:

- Interfaces: `utun4` added with `198.51.100.23/32`.
- Routes: `IPv4 default via 198.51.100.1 dev utun4` added, and `IPv4 203.0.113.0/24 via 198.51.100.1 dev utun4` added.
- DNS: `Default (utun4)` added with `198.51.100.53`, search `corp.example.com`.

The notable list repeats the new default route and DNS scope at the top.

## What the results do and do not tell you

- A snapshot is a point in time. Neighbor entries age out and idle listeners come and go, so an entry missing from one snapshot is not proof that something was removed.
- Neighbor state changes (reachable, stale, delay) are not counted as changes; only a different MAC for the same IP is. A changed MAC is expected after a device or NIC swap, a failover, or a VRRP/HSRP move.
- A listener whose process restarted with a new PID is not a change; a different program on the same port is.
- Rows are matched by a key: interface name, route (family, destination, gateway, interface), DNS scope, neighbor IP and interface, listener protocol, address and port. If several rows share a key (equal-cost routes, for example), the first is compared.
- Comparing snapshots from two different computers is allowed, and the panel warns about it; expect most rows to differ.
- Route metrics are not shown on macOS (`netstat -rn` has no metric column). Windows shows the route metric only, not the interface metric added to it.

## Online activity and privacy

Nothing is sent on the network. The tool runs local, read-only commands:

- **macOS:** `ifconfig -a`, `netstat -rn`, `arp -an`, `ndp -an`, `scutil --dns`, `netstat -anv`, and `lsof` as a fallback.
- **Linux:** `ip -j addr`, `ip -j route` (IPv4 and IPv6), `ip -j neigh`, `ss -Hlntup`, `/etc/resolv.conf` and `resolvectl`.
- **Windows:** one PowerShell call using `Get-NetAdapter`, `Get-NetIPAddress`, `Get-NetIPInterface`, `Get-NetRoute`, `Get-DnsClientServerAddress`, `Get-DnsClient`, `Get-NetNeighbor`, `Get-NetTCPConnection`, `Get-NetUDPEndpoint` and `Get-Process`.

Each command has a 30 second timeout and a 16 MB output limit. Snapshots are saved as JSON files in the app data folder, under `snapshots/` (see [Privacy and data](../privacy.md)). They contain your host name, addresses and process names; use a redacted export before sharing.

## Export and projects

**Export** on a snapshot writes a report with a summary, the sources and every section as a table. **Export** in Compare writes the summary counts, the notable changes and a table of differences per section. Both can be added to a project. See [Export and redaction](../export-and-redaction.md). **Save file...** writes the raw snapshot for use in another copy of Net3PO; it is not a report.

## Platform notes

- **macOS:** process names come from `netstat -anv`. When the app is started in a way that macOS hides other processes' sockets from (seen with unsigned builds), the tool falls back to `lsof`, which lists only your own processes, and says so in the grey box.
- **Linux:** needs `iproute2` (`ip` with JSON output, `-j`) and `ss`, which current distributions include. Without root, `ss` names only your own processes; other sockets show "process not visible". The DNS section adds systemd-resolved scopes when `resolvectl` is present.
- **Windows:** Windows PowerShell 5.1 (built in) is used. All cmdlets work for a normal user and show process names for every listener.

## Troubleshooting

**A section shows "failed" with "ip is not installed or not on PATH".** Install `iproute2`. Very old distributions without `ip -j` JSON output are not supported.

**"unexpected ip output" or "unexpected PowerShell output".** The command printed something the parser did not recognize. Note the OS version and report it.

**Listening ports shows "your own processes only" on macOS.** See Platform notes. Ports held by system services may be missing from that snapshot.

**"not a Net3PO snapshot file".** The file opened with **Open file...** is not a snapshot saved by this tool.

**Compare is greyed out.** Take or open at least two snapshots.

## Related tools

- [Config Diff](config-diff.md) to compare device configurations.
- [Port Scanner](port-scanner.md) to check listening ports from another host.
- [MAC Vendor Lookup](mac-vendor.md) to identify a neighbor's MAC address.
- [Visual Traceroute](traceroute.md) to see where routed traffic goes.
