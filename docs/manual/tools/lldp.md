# LLDP / CDP Neighbors

> See which switch and port this computer is plugged into, from the LLDP or CDP announcements the switch sends: port, VLANs, voice VLAN, PoE and management address. Listen live or read a capture file.

**Sidebar group:** Discovery and SNMP · **Works offline:** yes (it only listens; nothing is sent) · **Needs admin rights:** no, but live capture needs a capture library and, on macOS and Linux, capture permission (see Platform notes). Reading a file needs neither.

## When to use it

- Find out which switch and port a desk jack, a server NIC or a lab cable lands on, without tracing cables.
- Check the untagged VLAN, voice VLAN, PoE budget and link speed a switch port gives you.
- Confirm that a port change (new VLAN, PoE, description) actually took effect.
- Read neighbors out of a capture someone else took, such as a Wireshark file from a remote site.

## Quick start

1. Open **LLDP / CDP Neighbors** from the Discovery and SNMP group in the sidebar.
2. Pick the wired **Interface** that goes to the switch.
3. Leave **Listen for** at **65 s (LLDP and CDP)** and click **Listen**.
4. Each neighbor appears as a card as soon as it announces itself. The headline reads the switch name and the port, for example `access-sw1.example.net port GigabitEthernet1/0/12`.
5. To read a file instead, click **Open capture file...** and choose a `.pcap` or `.pcapng`.

## Inputs and options

| Field | What it does | Default and limits |
|---|---|---|
| Interface | The interface to listen on, as the capture library names it. On Windows the readable adapter name is shown. Interfaces that are down are marked. | The first interface that is up. Loopback is not listed. |
| Listen for | How long to listen. Switches send LLDP every 30 seconds and CDP every 60 seconds by default, so 35 s catches one LLDP announcement and 65 s catches both. | 65 s. **Until stopped** listens for up to an hour. |
| Open capture file... | Reads LLDP and CDP frames from a PCAP or PCAPNG file. Works without a capture library. | Files up to 2 GB. Ethernet and Linux cooked captures. |

## Reading the results

The status line shows what is happening (`Listening on en0... 41 s left`) and, at the end, the number of discovery frames and neighbors. The capture library's version is on the right.

Each neighbor card shows the fields the device sent; empty fields are left out:

- **Port** and **Port description**: the switch port you are on, and its configured description.
- **System name**, **Chassis ID** and **Management address**: which device it is and where to manage it.
- **Port VLAN (untagged)**: the access or native VLAN (LLDP 802.1 port VLAN ID, or CDP native VLAN).
- **Voice VLAN**: from LLDP-MED network policy or CDP, with tagging, 802.1p priority and DSCP when given.
- **VLAN names**, **Link** (speed, duplex and autonegotiation), **Power (PoE)** (class and requested and allocated power), **Max frame size**.
- **Capabilities**: what the device can do. For LLDP, capabilities it has but has not enabled are marked "(not enabled)".
- **Platform**, **System description** and inventory fields such as Model, Serial number or Software.
- **Hold time**, **Source MAC**, **Announcements** (how many were received) and when it was first and last seen.
- **Decoder notes** appear only when a frame was malformed or cut short.

If nothing arrives, a note explains the usual causes.

## What the results do and do not tell you

- LLDP and CDP are what the neighbor says about itself. They are not authenticated: any device on the segment can send them. Treat them as a strong hint, not proof.
- A switch only announces on ports where discovery is enabled. No result does not mean there is no switch.
- An unmanaged switch, hub or media converter in between passes the announcements of the switch behind it, or none at all, so the port shown can be one hop further away than you think.
- Some fields are optional, and each vendor sends a different set. A missing VLAN or PoE field means it was not announced, not that it is off.
- Link speed is shown as the MAU type the switch reports. Uncommon types are shown by number.

## Online activity and privacy

Nothing is sent. The tool only listens on the interface you pick, or reads the file you open. A kernel filter passes only LLDP (EtherType 0x88CC) and CDP (multicast 01:00:0C:CC:CC:CC) frames to the app; other traffic is never seen. Results stay in memory unless you export them or add them to a project.

## Export and projects

The **Export** menu (shown once a neighbor is found) offers HTML, PDF, Markdown and plain text, **Redacted...**, and **Add to project**. The report lists the source (interface or file), the capture library version, and every field of every neighbor, with a note on how far to trust the data. See [Export and redaction](../export-and-redaction.md).

## Platform notes

Live capture uses a capture library you install yourself; Net3PO loads it when you open this tool and never bundles one. Reading a capture file works everywhere without it.

- **macOS:** libpcap is part of macOS. Capturing needs read access to `/dev/bpf*`. Install Wireshark and its **ChmodBPF** package, which adds your user to the `access_bpf` group, then log out and back in. Net3PO does not need to run as root.
- **Windows:** install **Npcap** from npcap.com (the free edition is fine). Leave **Restrict Npcap driver's access to Administrators only** unticked so capture works without running as admin. Net3PO loads Npcap only from its own folder under `System32`.
- **Linux:** install libpcap (`sudo apt install libpcap0.8` on Debian and Ubuntu, `sudo dnf install libpcap` on RHEL and Fedora). Capturing needs CAP_NET_RAW. Grant only that capability to the app binary with `sudo setcap cap_net_raw,cap_net_admin=eip <path to app>`; the error message shows the exact path.
- Wi-Fi interfaces rarely see LLDP or CDP, because access points do not forward them. Use a wired interface.

## Troubleshooting

**"Live capture is not available" with "packet capture library not found".** Install libpcap or Npcap as described in Platform notes, then click **Check again**.

**Permission denied, or "Operation not permitted", when you click Listen.** The OS refused capture access. Follow the macOS, Windows or Linux steps in Platform notes; the error message includes the fix for your OS.

**"... is not an Ethernet interface".** The interface uses another link type (for example a VPN tunnel). Pick the wired Ethernet interface.

**No neighbors after 65 s.** Check that the cable goes straight to a managed switch, that LLDP or CDP is enabled on that port, and that you picked the right interface. Some switches send LLDP only every 60 or 120 seconds; choose **Until stopped** and wait.

**A capture file shows no neighbors.** The capture may have been taken with a filter that dropped LLDP and CDP, or on Wi-Fi. Packets with link types other than Ethernet or Linux cooked are skipped, with a warning.

## Related tools

- [Switch Port Mapper](port-mapper.md): map MAC addresses to switch ports over SNMP, from the switch's side.
- [SNMP Walk](snmp-walk.md): read the LLDP-MIB on the switch for every neighbor it sees.
- [PCAP Inspector](pcap-inspector.md): browse the rest of a capture file.
- [DHCP Monitor](dhcp-monitor.md): check which DHCP servers answer on the VLAN you landed on.
