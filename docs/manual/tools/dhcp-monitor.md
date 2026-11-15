# DHCP Monitor

> Broadcast a DHCPDISCOVER on the local segment and list every DHCP server that answers, flagging any that are not on your authorized list.

**Sidebar group:** Discovery and SNMP · **Works offline:** no (broadcasts on the local network, only when you click Probe or Monitor) · **Needs admin rights:** on Linux, permission to bind UDP 68 (see Platform notes); no on macOS and Windows in normal setups

## When to use it

- Users are getting wrong addresses or gateways and you suspect a rogue DHCP server (a home router, a misconfigured VM, a test lab box).
- Confirm which DHCP servers or relays actually answer on a VLAN after a change.
- Check what a server hands out (address, mask, router, DNS, domain, lease, next-server) without touching your own lease.
- Watch a segment over time for a server that appears intermittently.

## Quick start

1. Pick the **Interface** on the segment you want to test, or leave **Default route**.
2. Enter your known servers in **Authorized servers**, for example `192.0.2.1, 192.0.2.2`. Leave it empty if you only want to see who answers.
3. Click **Probe**. The tool sends one DISCOVER and listens for the number of seconds in **Probe: listen (s)**.
4. Read the verdict banner and the **Servers** table.
5. For ongoing checks, click **Monitor** instead. It sends a new DISCOVER every **Monitor: every (s)** seconds until you click **Stop**.
6. Use **Export** next to the Servers heading to save the result or add it to a project.

## Inputs and options

| Field | What it means | Default / accepted values |
|---|---|---|
| Interface | The interface to send and listen on. The list shows non-loopback IPv4 interfaces as `name (address/prefix)`. | Default route |
| Authorized servers (optional) | IPv4 addresses of legitimate DHCP servers, separated by commas, spaces or new lines. A server is authorized if its server identifier or the packet's source address is on the list. | Empty (every server shows as unverified) |
| Probe: listen (s) | How long Probe listens after its single DISCOVER. | 5; 1 to 60 |
| Monitor: every (s) | Seconds between DISCOVERs in Monitor mode. | 30; 5 to 3600 |
| Probe | Send one DISCOVER, listen, then stop. | |
| Monitor | Send a DISCOVER now and then on the interval, until Stop. | |

Each DISCOVER uses a new random transaction id and a random, locally administered unicast client MAC, and sets the broadcast flag so servers broadcast their offers back. The tool never sends a REQUEST, so no lease is taken and your own lease is untouched. A server may still hold the offered address briefly, as it would for any DISCOVER.

## Reading the results

**Status line.** `Listening on UDP 68 (interface)`, then `DISCOVER #n sent as <client MAC>, xid <id>`, and at the end `Stopped after N DISCOVERs, M servers seen.`

**Warnings.** Non-fatal problems, such as an interface that could not be bound, or rate-limited replies.

**Verdict banner.**

- Red: `Rogue DHCP server(s) detected:` followed by the addresses, when an authorized list is set and a server is not on it.
- Amber: `N DHCP servers are answering on this segment. Add the authorized ones above to classify them.` when more than one server answered and no list is set.
- Green: `All answering servers are authorized.`
- Amber: `No DHCP server answered...` after a probe with no replies.

**Servers table**, one row per server identity (option 54, or the source address if absent):

- **Status** badge: `authorized`, `rogue`, or `unverified` (no list given). Rogue rows are highlighted.
- **Server**: the server identifier. Below it, `via <address>` if the packet came from a different source, `relay <address>` if giaddr is set, and `next-server <address>` if siaddr is set (typically a PXE or TFTP boot server).
- **Offered**, **Mask**, **Router**, **DNS**, **Domain**: from the last reply.
- **Lease**: shown as days, hours, minutes or seconds, or `infinite`.
- **Replies** and **Last seen**.

**Replies log**, newest first, last 300 replies: time, message type (OFFER, ACK or NAK), source address, server, client MAC, transaction id, and **For**: `our probe` if the reply matches one of the tool's recent transaction ids, or `other client` for broadcast replies to other hosts on the segment.

Worked example. With authorized servers `192.0.2.1`, a probe on `en0` returns:

| Status | Server | Offered | Mask | Router | DNS | Lease |
|---|---|---|---|---|---|---|
| authorized | 192.0.2.1 | 192.0.2.150 | 255.255.255.0 | 192.0.2.1 | 192.0.2.53 | 1d |
| rogue | 192.0.2.254 | 203.0.113.100 | 255.255.255.0 | 192.0.2.254 | 192.0.2.254 | 12h |

The red banner reads `Rogue DHCP server detected: 192.0.2.254`.

## What the results do and do not tell you

- Only servers that answer are listed. A server that ignores unknown clients (MAC filtering, reservations only) or sits behind DHCP snooping or a filter will not appear. The report says so too.
- Replies to other clients are included only when they are broadcast; unicast replies to other hosts are not visible without packet capture, which this tool does not use.
- "Rogue" means "not on your list". It is a comparison, not proof of malice.
- If a relay forwards a server's reply, the source is the relay; matching either the server identifier or the source counts as authorized.
- Limits: replies larger than 1,500 bytes are ignored; malformed packets are dropped; at most 256 distinct servers are tracked (a warning reports a possible spoofing flood beyond that); at most 50 replies per second are shown, with a warning counting the rest.
- IPv4 DHCP only. DHCPv6 is not covered.

## Online activity and privacy

The tool sends DHCPDISCOVER broadcasts to 255.255.255.255:67 on the local segment, and only when you click Probe or Monitor. It listens on UDP 68 only while running and closes the socket on Stop or at the end of a probe. Nothing leaves the local segment unless a DHCP relay forwards the DISCOVER, which is normal relay behavior. Results are not saved unless you export them.

## Export and projects

The **Export** menu (shown once a server answered) offers HTML, PDF, Markdown and plain text, **Redacted...**, and **Add to project**. The report lists the interface, authorized servers, probes sent, and for each server: status, replies, offered address, mask, router, DNS, domain, lease (seconds), relay, first and last seen, plus any warnings. The replies log is not included. See [Export and redaction](../export-and-redaction.md).

## Platform notes

- **Linux:** binding UDP 68 needs permission for ports below 1024. Grant only that capability to the app binary with `sudo setcap cap_net_bind_service=+ep <path to app>`, or allow low ports system-wide with `sudo sysctl net.ipv4.ip_unprivileged_port_start=67`. The error message shows the exact path. Pinning to a chosen interface needs CAP_NET_RAW; without it the tool warns and uses the default route.
- **macOS:** interface selection works. Binding UDP 68 normally works without admin rights.
- **Windows:** interface selection works by binding the interface's own IPv4 address, so the DISCOVER leaves through that interface and broadcast replies arriving on it are heard. An interface with only a link-local (169.254.x.x) address still works. Windows can report ICMP errors as receive errors; the tool skips them.
- On all systems, the OS DHCP client or a local DHCP server may hold UDP 68 exclusively. The tool uses address reuse to share the port where the OS allows it.

## Troubleshooting

**Error "binding UDP 68 needs permission to use ports below 1024..."** (Linux). Use one of the two commands in the message.

**Error "permission denied binding UDP 68: ...".** The OS refused the port. Check local security policy or endpoint software.

**Error "UDP 68 is held exclusively by another program, usually the OS DHCP client or a local DHCP server."** Close that program, or run the probe from another host.

**Error "could not send the DHCPDISCOVER broadcast: ... Check that the interface is up and has an IPv4 address."** The interface is down or has no IPv4 address.

**Warning "could not bind to <if>: ...; using the default route".** The interface pin failed. On Linux this needs CAP_NET_RAW.

**Warning "interface <if> not found; using the default route".** The interface disappeared since the list was loaded.

**Error "invalid IPv4 address '...'".** An entry in Authorized servers is not an IPv4 address.

**Banner "No DHCP server answered."** Check the interface, that the segment has a server or relay, and that a host firewall is not blocking inbound UDP 68.

**Error "receive failed repeatedly: ...".** 100 receive errors in a row. Check the interface and try again.

## Related tools

- [Switch Port Mapper](port-mapper.md)
- [MAC Vendor Lookup](mac-vendor.md)
- [PCAP Inspector](pcap-inspector.md)
- [TFTP Server](tftp-server.md)
