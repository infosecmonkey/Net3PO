# Session List Parser

> Turn FortiGate `diagnose sys session list` and `diagnose sys session6 list` output into a filterable table, with the tuple, NAT, policy, counters, state flags and offload status of every session explained.

**Sidebar group:** Fortinet · **Works offline:** yes · **Needs admin rights:** no

## When to use it

- A user reports a slow or broken application and you want to see the FortiGate's sessions for that host: which policy matched, whether NAT applied, and whether traffic flows in both directions.
- You need to know why sessions are not offloaded to the NPU (`no_ofld_reason`).
- You want the top talkers, busiest destinations and most-used policies in a session dump.
- You see half-open TCP or one-way UDP sessions and want to find them quickly.

## Quick start

1. On the FortiGate, narrow the output first on a busy unit:
   ```text
   diagnose sys session filter clear
   diagnose sys session filter src 192.0.2.10
   diagnose sys session list
   ```
2. Copy the output (or save it to a file).
3. Open **Session List Parser** from the Fortinet group.
4. Paste the output and click **Parse**, or click **Open file...**.
5. Use the summary cards, search box and filters to narrow the table.
6. Click a session to open its details on the right.
7. Click **Copy** under **Show it on the FortiGate** to get the filter commands for that session.

## Inputs and options

| Field | What it means | Default / accepted values |
|---|---|---|
| Text box | `diagnose sys session list` or `session6 list` output. Other lines are ignored. | Up to 20 MB, 100,000 sessions |
| Search | Matches addresses, ports, `policy N`, NAT addresses, interface indexes, state flags, offload reasons, MACs, tunnel and user names. | Empty |
| Protocol | Show one protocol only. | All |
| Offload | Offloaded both ways, one direction, not offloaded (a `no_ofld_reason` is listed), or no offload information. | Any |
| Sort | Output order, most bytes, oldest, or expiring soonest. | Output order |

## Reading the results

**Summary.** The number of sessions parsed, and the `total session` count the FortiGate printed. A higher total means a filter was set or not everything was pasted. The cards show protocols, top sources by bytes, top destinations, policies and offload status. Click an entry to filter on it.

**Table.** One row per session: protocol and state, source and destination (before NAT), NAT, policy, bytes in the original and reply directions, age, time left before it expires, and offload status. Rows with an amber edge have a warning, such as a half-open TCP session or no reply traffic.

**Details.** For the selected session:

- **Notes** in plain language, for example `SYN sent, no SYN/ACK seen`, `No UDP reply seen`, `Source NAT to 192.0.2.10:61000`, `Not offloaded: non-npu-intf`, or a session that is close to expiring.
- **Facts:** state with the raw `proto_state`, interface indexes (`dev=`), gateway, counters and rates, MACs, tunnel, helper, user, shapers, application and URL category IDs, session serial and `npu_state`.
- **State flags** with Fortinet's documented meaning, for example `may_dirty`, `dirty`, `npu`, `local`, `redir`, `ndr`, `synced`, `f00`.
- **Why it is not offloaded:** each `no_ofld_reason` with its meaning.
- **NAT hooks:** the raw hook lines. SNAT shows as `post org snat` with the new source in brackets. DNAT (a VIP) shows as `pre org dnat` with the real server in brackets.
- **Show it on the FortiGate:** `diagnose sys session filter` commands for this session. IPv6 sessions use `session6`.
- **Raw output** of the session block.

### proto_state

For TCP and SCTP the second digit is the state: `1` ESTABLISHED, `2` SYN_SENT, `3` SYN and SYN/ACK, `4` FIN_WAIT, `5` TIME_WAIT, `6` CLOSE, `7` CLOSE_WAIT, `8` LAST_ACK, `9` LISTEN. A non-zero first digit is the server-side state, used when flow or proxy inspection tracks it. For UDP, `0` means no reply seen and `1` reply seen. ICMP has no state.

## What the results do and do not tell you

- `dev=` values are interface indexes, not names. Map them with `diagnose netlink interface list`.
- `ofld-O` and `ofld-R` in `npu_state` are reported as they appear. The meaning of every `npu info` field depends on the NP model, so those lines are left in the raw output.
- Flags and offload reasons that Fortinet does not document show as "not documented".
- A session list is a snapshot. Counters and timers are from the moment you ran the command.

## Online activity and privacy

Nothing leaves this computer. The output is parsed locally and is not saved unless you export it or add it to a project. Use the [Obfuscator](obfuscator.md) before sharing raw session output.

## Export and projects

**Export** saves the filtered sessions as HTML, PDF, Markdown or plain text, or adds them to a project. The report holds a table of up to 2,000 sessions and the notes for each. Use **Export > Redacted...** to replace addresses before sharing.

## Platform notes

Works the same on macOS, Windows and Linux.

## Troubleshooting

**"No sessions found".** The paste does not contain `session info:` lines. Copy the full output of `diagnose sys session list`.

**"input larger than 20 MB".** Set a session filter on the FortiGate to narrow the output.

**The total is much higher than the sessions parsed.** A session filter was active, or the terminal cut the output. Check `diagnose sys session filter` and your terminal's scrollback.

## Related tools

- [Debug Flow Parser](debug-flow.md) to follow a single packet through the FortiGate.
- [FortiGate Sniffer to PCAP](forti-sniffer.md) to capture the traffic itself.
- [Fortinet Command Builder](forti-builder.md) for other diagnose commands.
