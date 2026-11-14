# Debug Flow Parser

> Turn FortiGate `diagnose debug flow` output into one readable card per packet trace: tuple, interfaces, session, route, policy, NAT, IPsec and the verdict, with every fact linked to its log line.

**Sidebar group:** Fortinet · **Works offline:** yes · **Needs admin rights:** no

## When to use it

- Traffic is blocked and you need to know quickly whether it was policy, routing (RPF), or no session, from a long flow trace.
- You want to see which policy ID matched and which NAT was applied, without reading every line.
- You have hundreds of traces mixed together and want to filter to the denied or dropped ones.
- You want a clean summary of a trace to attach to a ticket or a project.

## Quick start

1. On the FortiGate, run a filtered flow trace. The [Fortinet Command Builder](forti-builder.md) Debug Flow tab builds the commands; keep **Show function names** on for best results.
2. Generate the traffic, then copy the output, or log the session to a file.
3. Paste the output into the box, or click **Open file...**.
4. Click **Parse**.
5. Read the summary line of verdict counts.
6. Click a trace header to open it. Click a **line N** link to jump to the event it came from.
7. Use the verdict filter and search box to narrow a large capture.
8. Use **Export** to save a report or add it to a project.

## Inputs and options

| Field | What it means | Default / accepted values |
|---|---|---|
| Text box | `diagnose debug flow` output. Lines without `trace_id=` and `msg=` are ignored, so prompts and other output can stay in. Lines hard-wrapped by a terminal are joined back onto their record. | Empty; up to 20 MB |
| Parse | Parses the text. | |
| Open file... | Loads a `.txt`, `.log` or any text file (up to 20 MB) and parses it. | |
| Verdict filter | Show all verdicts, or only allowed, denied, dropped, existing session, or no verdict in log. | all verdicts |
| Search | Matches the tuple, interfaces, policy and any message text in a trace. | Empty |

## Reading the results

**Summary line.** The number of traces, then counts per verdict: allowed, denied, dropped, existing session, no verdict. It also shows the number of unreadable trace lines (lines with `trace_id=` that could not be parsed) and a note if parsing stopped at 5,000 traces.

**Trace header**, one per `trace_id`, in the order they first appear:

- **Verdict badge**:
  - `allowed`: the log says `Allowed by Policy-N`.
  - `denied`: the log says `Denied by forward policy check (policy N)`. Policy 0 is the implicit deny.
  - `dropped`: the log reports a drop, for example `reverse path check fail, drop`, `no session matched`, `iprope_in_check() check failed, drop`, or another `denied by ...` check.
  - `existing session`: the packet matched an existing session, so no policy decision appears for it.
  - `no verdict in log`: the output does not say what happened.
- **Tuple**: protocol, source and destination with ports (for example `TCP 192.0.2.10:51514 > 198.51.100.20:443`). ICMP shows addresses only.
- **Ingress > egress** interfaces, the policy if known, and the trace ID and first line number.

**Open trace.** A facts table, notes, then the events.

- **Facts**, each with a **line N** link: Verdict (the stated text), Ingress, Egress, Session (`new session <id>` or `existing session <id>, original/reply direction`), Route (`gateway <gw> via <interface>`, or `policy route N matched`), Policy (`policy N matched, action accept`), NAT (SNAT, DNAT, or VIP), IPsec (into tunnel, encrypted to peer, decrypted), and TCP flags.
- **Notes**: conclusions that are inferred, not stated, labelled as such. Examples: no verdict in the log (cut off, offloaded to the NP, or trace count exhausted); forwarded in an existing session; the `received a packet` line is missing so the tuple is unknown; an SD-WAN rule mentioned; ICMP id and type fields.
- **Events**: each log line with its line number, function name (if present) and message. Recognized messages get a plain-language note and a color by kind (drop, deny, allow, session, route, policy, NAT, IPsec, offload). For example, `reverse path check fail` explains RPF, and `Denied by forward policy check (policy 0)` explains the implicit deny. Only the first 500 events of a trace are kept.

If the input has exactly one trace, it opens automatically.

Worked example. Input (shortened):

```
id=65308 trace_id=12 func=print_pkt_detail line=5895 msg="vd-root:0 received a packet(proto=6, 192.0.2.10:51514->198.51.100.20:443) tun_id=0.0.0.0 from port2. flag [S], seq 1234567, ack 0, win 64240"
id=65308 trace_id=12 func=init_ip_session_common line=6076 msg="allocate a new session-0001a2b3, tun_id=0.0.0.0"
id=65308 trace_id=12 func=__vf_ip_route_input_rcu line=1990 msg="find a route: flag=00000000 gw-203.0.113.1 via wan1"
id=65308 trace_id=12 func=fw_forward_handler line=930 msg="Denied by forward policy check (policy 0)"
```

The trace shows `denied`, `TCP 192.0.2.10:51514 > 198.51.100.20:443`, `port2 > wan1`, Session `new session 0001a2b3`, Route `gateway 203.0.113.1 via wan1`, Verdict `Denied: no policy matched (implicit deny, policy 0)`, with a note to check the policy's interfaces, addresses, services and schedule.

## What the results do and do not tell you

- Verdicts come only from what the log states. The parser does not guess: a trace with no deciding line is shown as "no verdict in log".
- The plain-language notes are general explanations of common FortiOS messages, not an analysis of your configuration.
- Existing-session packets do not show a policy lookup. Look at the first packet of that session for the policy decision.
- Offloaded sessions disappear from debug flow after the first packets.
- Parsing depends on FortiOS message text. Wording that differs between versions may leave some facts empty; the raw events are always shown.
- Limits: 20 MB of input, 5,000 traces, 500 events per trace.

## Online activity and privacy

Nothing leaves this computer. Parsing is local. The pasted text is not saved by the app unless you export or add the result to a project. Debug output contains internal addresses and policy IDs; use **Redacted...** when sharing. See [Export and redaction](../export-and-redaction.md) and [Privacy](../privacy.md).

## Export and projects

When there are traces, the **Export** menu offers HTML, PDF, Markdown and plain text, **Redacted...**, and **Add to project**. The report contains a table of up to 200 traces (trace ID, packet tuple, interfaces, verdict, policy and line range), the note that verdicts are reported only where the log states them, and a detail section for the first 50 traces with their facts, notes and event lines. See [Projects and notes](../projects-and-notes.md).

## Platform notes

No differences between macOS, Windows and Linux.

## Troubleshooting

**"No debug flow lines found (looking for lines with trace_id= and msg=)."** The text is not debug flow output, or the `trace_id=` and `msg=` fields were lost when copying.

**Many "unreadable trace lines".** Lines contain `trace_id=` but no `msg=`, usually from damaged copying. Log the SSH session to a file and open that instead.

**Tuple shows `? ? > ?`.** The `received a packet` line for that trace is missing; the output probably starts mid-trace.

**Most traces show "no verdict in log".** The trace count ran out, the output was cut off, or sessions were offloaded. Increase the trace count, or disable offload on the policy for the test.

**Error "input larger than 20 MB" or "file larger than 20 MB".** Split the log, or filter the flow trace more tightly.

**Error "could not read <path>: ...".** The file could not be opened.

## Related tools

- [Fortinet Command Builder](forti-builder.md)
- [SSH](ssh.md)
- [FortiGate Sniffer to PCAP](forti-sniffer.md)
- [Visual Traceroute](traceroute.md)
