# FortiGate Sniffer to PCAP

> Convert FortiGate `diagnose sniffer packet` text output with hex dumps into a .pcap file you can open in Wireshark.

**Sidebar group:** Fortinet · **Works offline:** yes · **Needs admin rights:** no

## When to use it

- You captured on a FortiGate CLI over SSH or the console and need the packets in Wireshark for protocol detail.
- You only have CLI access to the firewall (no GUI packet capture, no file download).
- A customer or colleague sent sniffer output as a text file and you want to inspect it properly.
- You want a quick count of the captured packets per interface and direction before digging in.

## Quick start

1. On the FortiGate, run the sniffer at a verbosity that prints hex: 3 or 6, for example `diagnose sniffer packet port1 'host 192.0.2.10' 6 200 a`. The [Fortinet Command Builder](forti-builder.md) Sniffer tab builds this command.
2. Log the session output to a file in your terminal client, or copy it from the screen.
3. Paste the text into the box, or click **Load .txt file**.
4. Check the packet count and the preview table.
5. Leave **Skip eth0 (internal)** ticked unless you need those packets.
6. Click **Save .pcap** and choose where to save it.
7. Open the file in Wireshark or the [PCAP Inspector](pcap-inspector.md).

## Inputs and options

| Field | What it means | Default / accepted values |
|---|---|---|
| Text box | The sniffer output. Parsing runs automatically as you type or paste. Header lines such as `interfaces=[port1]` and `filters=[...]` are ignored. | Empty |
| Load .txt file | Opens a `.txt`, `.log` or any text file and puts its contents in the box. | |
| Skip eth0 (internal) | Drops packets captured on the internal `eth0` interface, which are usually management noise. | On |
| Save .pcap | Writes the converted file. Disabled until at least one packet is recognized. Default name `capture.pcap`. | |

## Reading the results

**Stats line.** Total packets, total bytes, and how many eth0 packets were skipped.

**Preview table**, one row per packet:

- **#**: packet number.
- **Time (UTC)**: the packet time as it will be written to the pcap.
- **Interface** and **Dir**: taken from the header line (the word before `in` or `out`). A dash means the header did not include them; lower verbosity levels do not print interface names.
- **Bytes**: the captured length after the fixups below.

The table shows the first 500 packets. A note says so when there are more; the saved file includes all of them.

After saving, a message reads `Wrote N packets (M bytes).`

**How packets are recognized.** A packet starts at a line beginning with a timestamp, either relative (`2.123456 ...`) or absolute (`2026-11-14 09:12:01.123456 ...`). Hex lines that start with an offset (`0x0000`, `0x0010`, ...) up to the next blank line or the next timestamp are its bytes. The ASCII column on the right is ignored. Non-hex lines inside a block, such as the `linux cooked capture` line that `any` captures print at verbosity 6, are skipped.

**Fixups applied to each packet** (ported from the fgt2eth script):

1. If the bytes at offset 14 are an IPv4 (0x0800) or 0x8893 ethertype, the two extra bytes at offset 12 are removed.
2. If the packet starts with raw IPv4 (0x45, with DSCP byte 0x00 or 0x10), a dummy Ethernet header with zero MAC addresses is added.
3. Internal FortiGate ethertypes 0x8890 and 0x8891 are rewritten to IPv4.

**Timestamps.** Absolute timestamps are written as they appear and treated as UTC. Relative timestamps are anchored so the first packet gets the current time on this computer, and later packets keep their exact offsets. A packet header marked `truncated-ip - N bytes missing!` is written with its original length increased by N, so Wireshark shows it as truncated.

Worked example. Input:

```
interfaces=[port1]
filters=[host 192.0.2.10]
2026-11-14 09:12:01.104512 port1 in 192.0.2.10.51514 -> 198.51.100.20.443: syn 1234567
0x0000   0000 5e00 5301 0000 5e00 5302 0800 4500   ..^.S...^.S...E.
0x0010   003c 1c46 4000 4006 0000 c000 020a c633   .<.F@.@......Z.3
...
```

The preview shows packet 1 at `2026-11-14 09:12:01.104512`, interface `port1`, direction `in`, and its byte count.

## What the results do and do not tell you

- Output must include hex dumps. Verbosity 1 (headers only) has no packet bytes, so nothing is converted. Verbosity 3 and 6 include Ethernet headers and convert best. Verbosity 2 and 5 contain IP data only; an Ethernet header is added only for IPv4 packets with DSCP 0x00 or 0x10, so other packets may not decode correctly.
- The pcap uses the Ethernet link type. MAC addresses in packets that got a dummy header are all zeros.
- Local timestamps (sniffer option `l`) are also treated as UTC, so they are shifted by your FortiGate's UTC offset. Use `a` (absolute UTC) for correct times.
- Relative timestamps (no option) get today's date and time; only the spacing between packets is real.
- Each hex line contributes at most 16 bytes. Lines wrapped or damaged by a terminal client can lose bytes; check that payload lengths look right in Wireshark.
- Offloaded sessions are not seen by the sniffer after the first packets. See the offload note in the [Fortinet Command Builder](forti-builder.md#sniffer).

## Online activity and privacy

Nothing leaves this computer. The text is parsed locally and the pcap is written only where you save it. The pasted text is not stored by the app. Captures can contain sensitive payloads; see [Privacy](../privacy.md).

## Export and projects

**Save .pcap** writes a classic pcap file (microsecond timestamps, snap length 65535). There is no report export or "Add to project" for this tool. To add findings to a project, open the pcap in the [PCAP Inspector](pcap-inspector.md).

## Platform notes

No differences between macOS, Windows and Linux. Wireshark is not needed to create the file.

## Troubleshooting

**"No packets recognized."** The text has no `0x0000 ...` hex lines under the packet headers. Re-run the sniffer at verbosity 3 or 6.

**Error "no packets found in the input".** Same cause, shown when saving.

**Fewer packets than expected.** eth0 packets are skipped (see the stats line), a header line lost its timestamp when copied, or blank lines were inserted inside hex blocks. Turn off **Skip eth0** or log the session to a file instead of copying from the screen.

**Wireshark shows malformed packets.** The capture was at verbosity 2 or 5 (no Ethernet header) or lines were wrapped by the terminal. Capture again at verbosity 6 with a wide terminal or session logging.

**Times are off by some hours.** The capture used local timestamps (`l`). Use `a` for UTC.

**Error "could not read <path>: ..." or "could not write <path>: ...".** The file could not be opened as text, or the save location is not writable.

## Related tools

- [Fortinet Command Builder](forti-builder.md)
- [PCAP Inspector](pcap-inspector.md)
- [Debug Flow Parser](debug-flow.md)
- [Packet Filter Builder](filter-builder.md)
- [SSH](ssh.md)
