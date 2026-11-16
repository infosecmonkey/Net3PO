# Packet Filter Builder

> Describe the traffic once and get a tcpdump capture filter (BPF), a Wireshark display filter and a FortiGate `diagnose sniffer packet` command, each in its own syntax.

**Sidebar group:** Utilities · **Works offline:** yes · **Needs admin rights:** no

## When to use it

- Write a capture filter for a FortiGate sniffer or tcpdump session without looking up BPF syntax for port ranges, negation or TCP flags.
- Turn the same conditions into a Wireshark display filter to apply after the capture.
- Start from a common case (DNS, DHCP, IPsec, BGP, SYN only, TCP resets) and adjust it.
- Find out early that a condition, such as TCP retransmissions, cannot be expressed as a capture filter.

## Quick start

1. Open **Packet Filter Builder**. It starts with one group holding one empty **Host** condition.
2. Optionally pick a case from **Start from a scenario...** to replace the conditions.
3. Fill in each condition, choose its direction, and tick **not** to exclude matching traffic.
4. Add conditions to the group with **+ add condition...** (all must match), or add alternatives with **+ Add an OR group**.
5. For the FortiGate command, set **FortiGate interface** (default `any`).
6. Read the plain-language explanation to confirm the logic.
7. Pick the **tcpdump**, **Wireshark** or **FortiGate** tab and click **Copy**.

## Inputs and options

| Field | What it means | Default / accepted values |
|---|---|---|
| Start from | Loads a scenario: DNS, DHCP, HTTPS / TLS, New TCP connections (SYN only), TCP resets, ICMP and ICMPv6, ARP, IPsec (IKE, NAT-T, ESP), BGP, SNMP and traps, Syslog, NTP, RADIUS, and three display-only ones: TCP retransmissions, TCP zero window, DNS errors. | |
| FortiGate interface | Interface name placed in the FortiGate command. | `any`. Letters, digits, `-`, `_` and `.`, up to 32 characters. |
| Host | One IPv4 or IPv6 address. | Empty |
| Network | `address/prefix`, IPv4 or IPv6. | Empty |
| Port | Ports and ranges separated by commas or spaces, such as `80,443,8000-8100`. Transport: **TCP or UDP**, **TCP**, **UDP**. | Empty, TCP or UDP. Up to 50 entries. |
| Protocol | tcp, udp, icmp, icmp6, arp, ip, ip6, esp, gre, sctp. | tcp |
| TCP flags | SYN, ACK, FIN, RST, PSH, URG check boxes. **only these** means the chosen flags are set and the other four are clear. Without it, the chosen flags must be set and the rest are ignored. | SYN, not exact |
| VLAN | 802.1Q VLAN ID, or empty for any tagged frame. | Empty (any). 1 to 4094. |
| MAC address | Colon, dash or dot separated, any case. Output is lowercase with colons. | Empty |
| Direction | For Host, Network, Port and MAC: **either way**, **source**, **destination**. | either way |
| not | Excludes traffic that matches this condition. | Off |
| x | Removes the condition. Removing the last condition in a group removes the group. | |
| + add condition... | Adds a condition to this group. All conditions in a group must match (AND). | |
| + Add an OR group | Adds a new group. Any group may match (OR). | |

Limits: 20 groups, 20 conditions per group.

## Reading the results

1. **Explanation**: a plain-language reading, such as "Matches traffic to or from 192.0.2.10 and TCP port 443."
2. **Target tabs**:
   - **tcpdump**: the BPF filter wrapped as `tcpdump -nn '<filter>'`, with a note to add `-i <interface>` (`tcpdump -D` lists them) and `-w file.pcap` to save for Wireshark.
   - **Wireshark** (default tab): the **Display filter** for the display filter bar, and the **Capture filter** for Capture > Options before starting a capture.
   - **FortiGate**: `diagnose sniffer packet <interface> '<filter>' 4 0 l`. Verbose 4 shows interface names, count 0 runs until Ctrl+C, `l` prints local time.
3. **Notes** under each output, including any warnings about the syntax used.

If a capture filter cannot express a condition, the tcpdump, Capture filter and FortiGate boxes show "A capture filter cannot express: ... Capture more broadly and use the display filter." The display filter is still produced.

### Worked example

Group 1: **Host** `192.0.2.10` either way, and **Port** `443` TCP.
Group 2 (OR): **Network** `198.51.100.0/24` source, and **Port** `22` TCP or UDP with **not** ticked.

Explanation: "Matches any of: (traffic to or from 192.0.2.10 and TCP port 443) or (traffic from 198.51.100.0/24 and not TCP or UDP port 22)."

tcpdump:

```
tcpdump -nn '(host 192.0.2.10 and tcp port 443) or (src net 198.51.100.0/24 and not (port 22))'
```

Wireshark display filter:

```
(ip.addr == 192.0.2.10 && tcp.port == 443) || (ip.src == 198.51.100.0/24 && !(tcp.port == 22 || udp.port == 22))
```

FortiGate, with interface `port1`:

```
diagnose sniffer packet port1 '(host 192.0.2.10 and tcp port 443) or (src net 198.51.100.0/24 and not (port 22))' 4 0 l
```

The **New TCP connections (SYN only)** scenario gives `tcp[tcpflags] & 0x3f == 0x02` for capture and `tcp.flags & 0x3f == 0x002` for display. Without **only these**, SYN gives `tcp[tcpflags] & (tcp-syn) == (tcp-syn)` and `tcp.flags.syn == 1`.

A multi-port term such as `80,443,8000-8100` on TCP becomes `(tcp port 80 or tcp port 443 or tcp portrange 8000-8100)` and `tcp.port in {80 443 8000..8100}`.

## What the results do and do not tell you

- Nothing is compiled or validated by a real filter engine. No libpcap or Wireshark is bundled. Check a BPF filter with `tcpdump -d '<filter>'`; the Wireshark display filter bar turns green when the syntax is valid.
- `tcp[tcpflags]` reads the TCP header at a fixed IPv4 offset. It does not match TCP over IPv6.
- In BPF, `vlan` shifts the offsets of everything after it. Keep a VLAN condition first in its group.
- Display-only conditions (retransmissions, zero window, DNS errors) come only from scenarios and have no capture filter form.
- Networks are passed through as typed. If you enter host bits (for example `192.0.2.5/24`), tcpdump may reject the filter; enter the network address.
- The FortiGate command is refused if the filter is longer than 1,024 characters or contains a single quote.

## Online activity and privacy

None. Filters are built locally, and nothing is captured by this tool. See [Privacy](../privacy.md).

## Export and projects

**Export** appears next to the explanation when there are no input errors. Formats: HTML, PDF, Markdown, Plain text and **Redacted...** (see [Export and redaction](../export-and-redaction.md)), plus **Add to project**. The report has the explanation and three sections: capture filter (BPF), Wireshark display filter and FortiGate sniffer command, each with its notes or the reason it could not be built. The tcpdump wrapper command is not included, only the bare BPF filter. See [Projects and notes](../projects-and-notes.md).

## Platform notes

Same on macOS, Windows and Linux. The tcpdump command uses single quotes for a POSIX shell. On Windows, Wireshark and its command-line tools take the same capture filter syntax, but quoting in `cmd.exe` or PowerShell differs.

## Troubleshooting

Errors are listed as "group N, condition M: ..." and no filter is produced until they are fixed.

**"... is not an IP address".** The Host field is empty or invalid. A new Host condition starts empty, so this shows until you type an address.

**"...: use address/prefix, e.g. 10.0.0.0/8" or "bad prefix length /N".** Network needs a prefix within range (32 for IPv4, 128 for IPv6).

**"bad port X", "bad port range X", "port range X is reversed", "enter at least one port", "more than 50 ports in one term".** Fix the Port field.

**"choose at least one TCP flag".** Tick at least one flag.

**"VLAN ID must be 1 to 4094".** Enter a valid VLAN or leave it empty.

**"... is not a MAC address".** The MAC needs 12 hex digits with only `:`, `-` or `.` separators.

**"interface name may use letters, digits, - _ and .".** Fix the FortiGate interface name.

**"filter too long or contains a quote for the FortiGate CLI".** Shorten the filter or split it into separate captures.

## Related tools

- [Fortinet Sniffer to PCAP](forti-sniffer.md)
- [Fortinet Command Builder](forti-builder.md)
- [PCAP Inspector](pcap-inspector.md)
- [Grep Builder](grep-builder.md)
- [Regex Builder](regex-builder.md)
