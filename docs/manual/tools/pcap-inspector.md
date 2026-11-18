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
| Clean copy... | Opens the clean copy options: see [Clean copy for sharing](#clean-copy-for-sharing). | |
| Extract files... | Opens the extraction options: see [Extract files and calls](#extract-files-and-calls). | |
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

## Clean copy for sharing

**Clean copy...** writes a new PCAPNG file for sending to a vendor TAC, a forum or an AI assistant. The original file is not changed, and the copy cannot overwrite it.

| Option | What it does | Default |
|---|---|---|
| Remove payloads | Keeps the link, IP and TCP/UDP headers (8 bytes of ICMP) and removes everything after them: application data, DNS names, TLS server names, logins. Each packet keeps its original length on the wire, so Wireshark shows it as "Packet size limited during capture". | On |
| Replace IP addresses | IPv4 and IPv6 source and destination addresses, ARP addresses, addresses quoted inside ICMP errors, and neighbor discovery targets. Uses the Obfuscator's fake addresses: private stays private, public stays public, hosts in the same /8, /16 or /24 stay together. Loopback, multicast and documentation addresses are kept. IP, TCP, UDP and ICMPv6 checksums are corrected. | On |
| Replace MAC addresses | Ethernet and Linux cooked capture addresses, ARP, and neighbor discovery link-layer options. The vendor prefix (OUI) is kept; broadcast and multicast MACs are kept. | On |
| Match the Obfuscator session | Uses the Obfuscator's session key, so addresses get the same fakes as text you obfuscate there. If no session exists yet, this starts one. | Off |

Click **Save clean copy...** and choose a file name. The result lists packets written, payloads removed, addresses and MACs replaced, and any packets left out. **Replaced addresses** lists original and fake values; it is shown in the app only and is not written anywhere.

So that nothing passes through unexamined:

- Frames that are not IP or ARP (LLDP, CDP, STP, LACP and others) are cut to their link header, because their contents (device names, management addresses) cannot be cleaned.
- Packets with a link type that cannot be parsed (anything other than Ethernet, raw IP, loopback and Linux cooked capture) are left out, with a warning.

Limits:

- Without **Remove payloads**, names and addresses inside application data (DNS, DHCP, HTTP, TLS server names) are not changed.
- Only the outer headers of tunnels (GRE, IPsec, VXLAN) are changed; with **Remove payloads** the inner packets are removed.
- Checksums that were already wrong in the original (common with checksum offload on the capturing host) stay wrong.

## Extract files and calls

**Extract files...** finds files and voice calls carried in clear text and saves the ones you pick.

| Option | What it finds | Default |
|---|---|---|
| HTTP objects and uploads | Every HTTP/1.x response body (pages, images, scripts, downloads) and request body (uploads) on any TCP port. TCP streams are reassembled in sequence order; retransmissions and out-of-order segments are handled. Pipelined requests are paired with their responses. | On |
| FTP transfers | Files and listings on FTP data connections, matched to the control connection's `PORT`, `EPRT`, `227` or `229` and named from `RETR`, `STOR`, `STOU` or `APPE`. | On |
| TFTP transfers | Read and write requests and their data blocks, including the `blksize` option and block number wrap. | On |
| Voice calls (RTP G.711) | RTP streams in G.711 mu-law (PCMU) or A-law (PCMA), decoded to 16-bit 8 kHz WAV, one file per direction. Lost packets become silence. | On |
| Decode gzip and deflate bodies | Saves HTTP bodies decoded, as the browser saw them. Off saves them as sent. | On |

Click **Find**. The table lists each object with its type, a safe file name, size, sender and receiver, details (request and status, FTP command, codec and packet loss) and the packet number where it starts. Hover a name for its SHA-256. **incomplete** means bytes are missing: lost or uncaptured packets, a capture that ends mid-transfer, or a size limit. Filter the list, tick the objects you want (or **Select shown**), and click **Save to folder...**.

Saving never replaces an existing file: a second `logo.png` is saved as `logo (2).png`. File names are cleaned so they cannot point outside the folder or use names the OS reserves.

The files come from network traffic and may be malicious. The app saves them and never opens them; scan them before you open them.

Limits:

- Encrypted traffic (HTTPS, FTPS, SFTP, SRTP, VPN tunnels) cannot be extracted. HTTP/2 and HTTP/3 are always encrypted in practice and are not decoded.
- A connection whose start is not in the capture is found only if its first captured bytes begin an HTTP message.
- Voice: G.711 only (the common default on SIP trunks and phones). Other codecs (G.722, G.729, Opus) are not decoded. Streams with fewer than 20 packets are ignored to avoid false matches.
- Memory limits: 64 MB per stream or transfer, 512 MB buffered in total, 512 MB and 5,000 objects kept. Objects over a limit are marked incomplete or left out, with a warning.
- Found objects are kept in memory until you save them, close the capture or search again.

## What the results do and do not tell you

- "Facts derived from the capture file only. Encrypted payloads are counted, not decrypted, and protocols the inspector does not decode are labelled as such."
- "Labels come from ports and payload checks; a protocol on a non-standard port shows as plain TCP or UDP."
- Decoding covers L2 to L4 fields. Use Wireshark for application-layer dissection, stream reassembly and expert analysis.
- Decoded link types: Ethernet, Raw IP, Raw IPv4, Raw IPv6, BSD and OpenBSD loopback, Linux cooked (SLL and SLL2). Other link types are counted but not dissected.
- Limits: the first 200,000 packets are listed (statistics cover all packets); records over 16 MB stop the read as damaged; conversation and address tracking stops adding new entries after 50,000. The three most recently opened captures are kept in memory.
- For FortiGate sniffer text: "Converted from FortiGate sniffer output with the Sniffer to PCAP converter. Relative timestamps are placed on today's date."

## Online activity and privacy

Nothing goes online. Captures are read locally. **Clean copy** writes only the file you choose, and **Extract files** writes only the files you pick, into the folder you choose. **Open in Wireshark** hands the file to another local application; for converted sniffer text, a `.pcap` copy is written to the app's cache folder for that purpose. Nothing else is saved unless you export or add to a project.

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
- [Packet Filter Builder](filter-builder.md) to build capture and display filters.
- [IOC Extractor](ioc-extractor.md) for indicators in text exports.
- [MAC Vendor Lookup](mac-vendor.md) for vendor names behind MAC addresses.
