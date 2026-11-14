# PCAP Inspector

> Summarize a PCAP or PCAPNG capture, or FortiGate sniffer text: packets with L2 to L4 fields and hex, conversations, top talkers, protocols and DNS.

**Sidebar group:** Analysis · **Works offline:** yes · **Needs admin rights:** no (it reads capture files; it does not capture)

## When to use it

- A customer sent a capture and you want a quick overview (who talked to whom, which protocols, any resets or DNS errors) before opening Wireshark.
- You are on a machine without Wireshark and need to look at a few packets and their headers.
- You have `diagnose sniffer packet` text from a FortiGate and want to browse it as packets without converting it by hand first.
- You need a short, shareable summary of a capture for a ticket.

## Quick start

1. Open **PCAP Inspector** from the Analysis group.
2. Click **Open capture...** and choose a `.pcap`, `.pcapng`, `.cap` or `.dmp` file, or a FortiGate sniffer `.txt` / `.log`. A progress bar shows bytes read; **Stop** ends the read early.
3. Read the summary cards at the top.
4. On the **Packets** tab, filter by text, protocol, IP or port. Click a packet to see its decoded fields and hex.
5. Switch to **Conversations**, **Top talkers**, **Protocols** or **DNS** for aggregate views. The **packets** links jump back to a filtered packet list.
6. Click **Open in Wireshark** when you need full protocol analysis.
7. Use **Export** to save a summary report or add it to a project.

## Inputs and options

| Field | What it means | Default / accepted values |
|---|---|---|
| Open capture... | Loads a file. Captures are detected by their magic number; anything else is tried as FortiGate sniffer text. | PCAP or PCAPNG of any size (streamed). Sniffer text up to 64 MB, verbose level 3, 4 or 6 with hex. |
| Stop | Cancels reading. Figures then cover only the part read. | Shown while loading. |
| Open in Wireshark | Opens the file in the system's default app for captures. Converted sniffer text is first written as a `.pcap` to the app cache folder. | |
| Search box (Packets tab) | Case-insensitive substring match on source, destination, protocol and info. | Free text. |
| Protocol | Show one protocol only. | "any protocol" or any label found in the file. |
| IP address | Packets where either address equals this IP. | Exact address. |
| port | Packets where either L4 port equals this number. | 1 to 65535. |
| truncated or malformed | Show only packets cut by the snap length or that failed to decode. | Off. |
| Previous / Next | Page through matches. | 500 rows per page. |

## Reading the results

**Summary cards.** Packets, bytes on the wire, duration, TCP SYN count, TCP resets, encrypted payloads, truncated packets and malformed or undecoded packets. The last two turn amber when non-zero. Below them: file name, format, link types (for example "Ethernet (1)") and the start time in UTC. Warnings follow, such as a file that ends mid-packet, damaged data, an unknown link type, or that only the first packets are listed.

**Packets tab.** A match count with the current range, then a table: number, time (UTC), source, destination (with ports, IPv6 as `[addr]:port`), protocol, length and info. An **enc** tag marks encrypted payloads; a **cut** tag marks packets captured shorter than their original length (hover for the byte counts). Malformed packets are highlighted. Clicking a row opens the detail view: the link type, any decode problem, fields grouped by layer (Ethernet, VLAN, IPv4/IPv6, TCP/UDP/ICMP and so on) and a hex dump.

**Conversations tab.** Protocol, endpoint A, endpoint B, packets, bytes and duration. The top 1,000 by bytes. If more than 50,000 distinct conversations or addresses were seen, a note says tracking stopped adding new entries.

**Top talkers tab.** Each address with packets and bytes (up to 500), and a **packets** link that filters the packet list to it.

**Protocols tab.** Each protocol label with packets, bytes and share of packets, and a **packets** link. Labels include Ethernet-level protocols (ARP, LLDP, LACP, EAPOL, VLAN, MPLS, PPPoE), IP protocols (ICMP, ICMPv6, IGMP, GRE, ESP, AH, OSPF, SCTP, VRRP) and application labels by port or payload (DNS, mDNS, DHCP, DHCPv6, NTP, SNMP, Syslog, TFTP, RADIUS, IKE, Kerberos, LDAP, LDAPS, SMB, NetBIOS, HTTP, HTTPS, TLS, QUIC, SSH, Telnet, FTP, SMTP, POP3, IMAP, RDP, SIP, SSDP, BGP, DNS over TLS).

**DNS tab.** Each queried name and type with query count, response count, and error codes with counts (for example `NXDOMAIN x3`). Up to 2,000 names.

Example: a capture of a failing web request shows Top talkers `192.0.2.10` and `198.51.100.80`, a TCP conversation between `192.0.2.10:51544` and `198.51.100.80:443` with 3 packets, TCP resets 1, and in DNS `www.example.com A 1 query, 1 response`.

## What the results do and do not tell you

- "Facts derived from the capture file only. Encrypted payloads are counted, not decrypted, and protocols the inspector does not decode are labelled as such."
- "Labels come from ports and payload checks; a protocol on a non-standard port shows as plain TCP or UDP."
- Decoding covers L2 to L4 fields. Use Wireshark for application-layer dissection, stream reassembly and expert analysis.
- Decoded link types: Ethernet, Raw IP, Raw IPv4, Raw IPv6, BSD and OpenBSD loopback, Linux cooked (SLL and SLL2). Other link types are counted but not dissected.
- Limits: the first 200,000 packets are listed (statistics cover all packets); records over 16 MB stop the read as damaged; conversation and address tracking stops adding new entries after 50,000. The three most recently opened captures are kept in memory.
- For FortiGate sniffer text: "Converted from FortiGate sniffer output with the Sniffer to PCAP converter. Relative timestamps are placed on today's date."

## Online activity and privacy

Nothing goes online. Captures are read locally. **Open in Wireshark** hands the file to another local application; for converted sniffer text, a `.pcap` copy is written to the app's cache folder for that purpose. Nothing else is saved unless you export or add to a project.

## Export and projects

The **Export** menu offers HTML, PDF, Markdown, Plain text, **Redacted...** and **Add to project**. See [Export and redaction](../export-and-redaction.md) and [Projects and notes](../projects-and-notes.md).

The report contains the capture facts (file, format, link types, packet and byte counts, first packet time, duration, truncated, malformed, encrypted, TCP SYN, TCP resets, ICMP unreachable) and warnings, the protocol table, the top 25 talkers, the top 50 conversations, up to 200 DNS names, and a note on what the summary covers. It does not include individual packets or payloads. Addresses and DNS names are included, so consider **Redacted...** before sharing.

## Platform notes

The same on macOS, Windows and Linux. **Open in Wireshark** uses the operating system's default handler for `.pcap` files, so Wireshark (or another capture viewer) must be installed and associated with the file type.

## Troubleshooting

**"not a PCAP/PCAPNG file or FortiGate sniffer output (verbose 3, 4 or 6 with hex)".** The file is neither. For sniffer text, capture with a verbose level that prints hex.

**"not a PCAP/PCAPNG file, and too large to be FortiGate sniffer text".** Non-capture files over 64 MB are not parsed.

**"the file ends in the middle of a packet; the last record is incomplete".** The capture was copied while still being written, or cut short. The packets before it are fine.

**"link type N is not decoded; packets are counted but not dissected".** The capture uses an encapsulation the inspector does not decode. Open it in Wireshark.

**"could not open the capture: ... Is Wireshark installed and set to open .pcap files?"** Install Wireshark or associate `.pcap` files with it.

**"this capture is no longer loaded".** Only three captures stay in memory. Open the file again.

## Related tools

- [FortiGate Sniffer to PCAP](forti-sniffer.md) to convert sniffer text and save the `.pcap`.
- [Filter Builder](filter-builder.md) to build capture and display filters.
- [IOC Extractor](ioc-extractor.md) for indicators in text exports.
- [MAC Vendor Lookup](mac-vendor.md) for vendor names behind MAC addresses.
