# Switch Port Mapper

> Map the MAC addresses a switch has learned to its ports over SNMP, with vendor names, VLANs, port status and optional IP addresses from a router's ARP table.

**Sidebar group:** Discovery and SNMP · **Works offline:** no (queries the switch, and the ARP source if set, only when you click Map ports) · **Needs admin rights:** no

## When to use it

- Find which switch port a device is plugged into, starting from its MAC or IP address.
- Document an access switch: port names, descriptions, status, speed, access VLAN and what is connected.
- Find unused ports (admin down or oper down with no MACs) before a move or a cleanup.
- Spot unexpected devices on a port, or a port with many MACs that should be an access port.

## Quick start

1. Enter the switch in **Switch host or IP**, for example `192.0.2.20`.
2. Pick the **Version** and enter the **Community** (v1, v2c) or the v3 user and keys.
3. Optional: enter a router or Layer 3 switch in **ARP source** (for example `192.0.2.1`) to add IP addresses. It uses the same credentials.
4. Click **Map ports**. The status line shows each stage. Click **Cancel** to stop.
5. Look at the faceplate. Click a port tile to list the MACs on it.
6. Type a MAC, vendor, IP, VLAN or port into the filter on the **MACs** tab to find a device.
7. Switch to the **Ports** tab for a per-port table.
8. Use **Copy CSV** or **Save CSV** for the current tab, or **Export** for a full report.

## Inputs and options

| Field | What it means | Default / accepted values |
|---|---|---|
| Switch host or IP | The switch to query. | Required |
| Port | UDP port of the SNMP agent. | 161; 1 to 65535 |
| Version | SNMP version. v1 uses GETNEXT; v2c and v3 use GETBULK (25 repetitions per request). | v1, v2c, v3; default v2c |
| Community | v1 and v2c community string. | `public` (selected on focus) |
| Username | SNMPv3 user (v3 only). | Empty |
| Auth | SNMPv3 auth protocol. | none, md5, sha1, sha224, sha256, sha384, sha512; default sha1 |
| Auth password | SNMPv3 auth key. Disabled when Auth is none. | Empty |
| Privacy | SNMPv3 privacy cipher. Disabled when Auth is none. | none, des, aes128, aes192, aes256; default aes128 |
| Privacy password | SNMPv3 privacy key. Disabled when Privacy or Auth is none. | Empty |
| ARP source (router or L3 switch, optional, same credentials) | A second device whose ARP table (ipNetToMediaPhysAddress) is merged in to add IPs to MACs. | Empty |
| all interfaces (checkbox under the faceplate) | Also show non-Ethernet interfaces (VLAN SVIs, loopbacks, tunnels, port-channels) on the faceplate and in the Ports tab. | Off |
| Filter (MACs tab) | Matches MAC (any separator: `:`, `.`, `-` or none), vendor, port, VLAN or IP. | Empty |
| hide MACs on uplinks (MACs tab) | Hides MACs learned on ports flagged as likely uplinks. Not shown while a port is selected. | On |
| show MACs (Ports tab) | Lists each port's MACs, vendors and IPs in the MACs column. | Off |

The SNMP timeout is 3 seconds per request, with no retries. The v3 security level follows what you fill in, as in [SNMP Walk](snmp-walk.md).

## Reading the results

**How the forwarding table is read.** The mapper reads the system group, the interface tables (IF-MIB, including ifName, ifAlias and ifHighSpeed), the bridge port to ifIndex table and dot1qPvid. It then picks one forwarding table source:

1. **Q-BRIDGE-MIB** (dot1qTpFdbTable), which carries the VLAN with each MAC, if the switch has it.
2. Otherwise, on Cisco switches that report VTP VLANs, **BRIDGE-MIB per VLAN (Cisco)**: one walk per operational VLAN, using community indexing (`your-community@10`) for v1 and v2c, or the context `vlan-10` for v3. VLANs 1002 to 1005 are skipped and at most 1,024 VLANs are read.
3. Otherwise plain **BRIDGE-MIB** (dot1dTpFdbTable), which has no VLAN.

Entries with status invalid or self, and entries on bridge port 0, are dropped. The switch's own ARP table is always read; the ARP source, if set, is merged in.

**Device line.** sysName (or the host), the data source, the number of interfaces and MACs, and "(capped)" if the MAC list hit the limit. sysDescr appears below.

**Warnings.** Shown below the device line, for example a VLAN whose table could not be read, a failed ARP source, or no learned MACs.

**Faceplate.** Ethernet ports grouped by name prefix (for example `Gi1/0/`) and sorted naturally, so port 10 follows port 9. Each tile shows the port number and, if any, the MAC count. Hover for name, description, admin and oper status, speed, PVID and MAC count. Colors, as in the legend: **up**, **down**, **admin down**, and **likely uplink** (a port with 10 or more learned MACs). Click a tile to filter the MACs tab to that port; click again or use the x on the chip to clear it.

**MACs tab.** Columns MAC (uppercase, colon form), Vendor (from the bundled IEEE OUI database), VLAN, Port (click to select that port; an "uplink" tag marks uplink ports) and IP. The table shows the first 5,000 matches; the count line gives the total.

**Ports tab.** Columns Port, Description (ifAlias), Status (admin down, or the oper status), Speed (from ifHighSpeed, else ifSpeed, as M or G), PVID, VLANs, and MACs (count plus an uplink tag).

Worked example. On `sw1.example.com` (Q-BRIDGE-MIB), with ARP source `192.0.2.1`:

| MAC | Vendor | VLAN | Port | IP |
|---|---|---|---|---|
| 00:00:5E:00:53:0A | ICANN, IANA Department | 20 | Gi1/0/7 | 192.0.2.57 |
| 00:00:5E:00:53:2B | ICANN, IANA Department | 20 | Gi1/0/48 `uplink` | |

Port Gi1/0/48 has 10 or more MACs, so it is marked as a likely uplink and its MACs are hidden by default.

## What the results do and do not tell you

- A MAC appears only while it is in the switch's forwarding table. Idle devices age out (often after 5 minutes) and will be missing.
- "Likely uplink" is a count threshold (10 MACs), not LLDP or CDP data. A port with a small unmanaged switch or a hypervisor behind it can be flagged too, and a quiet uplink may not be.
- The **VLANs** column lists VLANs seen in learned MACs on that port, not the port's configured VLANs. **PVID** is the access or native VLAN from Q-BRIDGE-MIB, where the switch reports it.
- IPs come only from ARP tables you can read. Devices in other subnets, or whose gateway is not the ARP source, have no IP.
- If the bridge port table is empty, the mapper assumes bridge port numbers equal ifIndex and says so in a warning. That assumption is wrong on some switches.
- Limits: 100,000 rows per walked table and 50,000 MACs per result.
- "Physical" means an Ethernet ifType (6, 62, 69 or 117) and not a Null or stack port by name. Other port types need **all interfaces**.

## Online activity and privacy

When you click **Map ports**, the app sends SNMP requests over UDP to the switch, and to the ARP source if you entered one. Vendor names come from a database bundled with the app, so no lookup goes online. Nothing is sent at other times.

Communities and v3 keys stay in the panel for the current session only. They are not saved and are not written to CSV files or reports.

## Export and projects

- **Copy CSV** and **Save CSV** export the current tab. MACs tab: `mac,vendor,vlan,port,description,ips` for the MACs currently shown (filter applied). Ports tab: `port,description,status,speed,pvid,vlans,mac,vendor,mac_vlan,ips`, one row per MAC, and one row for each port without MACs. The default file name is the switch name plus the tab.
- **Export** offers HTML, PDF, Markdown and plain text, **Redacted...**, and **Add to project**. The report includes host, sysName, sysDescr, data source, warnings, a truncation note if the MAC list was capped, the full MAC table and the full port table (all interfaces, not just physical). It states that SNMP credentials are not included. See [Export and redaction](../export-and-redaction.md).

## Platform notes

Same behavior on macOS, Windows and Linux. Normal UDP sockets, no elevated privileges.

## Troubleshooting

**Error "Enter the switch host or IP."** The host field is empty.

**Error "the agent answered but returned no system group; check the view/ACL for this community or user".** The community or user works but its view excludes the system group. Widen the SNMP view on the switch.

**Warning "no learned MACs found; the device may not expose its forwarding table over SNMP, or the view excludes BRIDGE-MIB".** Check that BRIDGE-MIB and Q-BRIDGE-MIB are in the view. Some devices do not expose these tables.

**Warning "could not read the forwarding table for VLAN ...".** On Cisco, the per-VLAN community (`your-community@VLAN`) or v3 context `vlan-N` was refused. For v3, the user's group needs access to those contexts.

**Warning "ARP from ... failed: ...".** The ARP source did not answer with the same credentials. The map is still built without those IPs.

**Error "no response from the agent within the timeout", "authentication failed", "v3 engine discovery failed".** Same causes as in [SNMP Walk](snmp-walk.md#troubleshooting).

**Message "No physical interfaces reported."** The switch reports no Ethernet-type ports. Enable **all interfaces**.

**Error "could not write <path>: ...".** The CSV could not be saved there. Pick another folder.

## Related tools

- [SNMP Walk](snmp-walk.md)
- [SNMP Sweep](snmp-sweep.md)
- [MAC Vendor Lookup](mac-vendor.md)
- [DHCP Monitor](dhcp-monitor.md)
