# Visual Traceroute

> Repeated, MTR-style traceroute to an IPv4 destination with per-hop latency, loss, jitter, ECMP responders, automatic findings and a Path MTU test, without admin rights.

**Sidebar group:** Troubleshooting · **Works offline:** no (sends probes toward the destination, and optional reverse DNS lookups) · **Needs admin rights:** no

## When to use it

- Find where along a path latency rises or loss begins, and tell real forwarding loss apart from routers that rate-limit ICMP.
- Watch a path over many cycles while a user reports intermittent slowness.
- Check for a Path MTU problem (for example over a VPN or tunnel) and spot PMTUD black holes that cause large transfers to stall.
- See whether a hop is load-balanced (several routers answer at the same TTL).

## Quick start

1. Open **Visual Traceroute** from the Troubleshooting group. The header shows the probe method this OS will use.
2. In **Host or IPv4**, enter a destination such as `192.0.2.80` or `www.example.com`.
3. Leave **Mode** on **Fixed cycles** with 5 cycles, or choose **Continuous** to run until you stop it.
4. Keep **Path MTU** and **Reverse DNS** checked unless you want fewer packets and lookups.
5. Click **Trace** (or press Enter). The tables and charts update after every cycle.
6. Read the **Path Summary** tiles and findings, then click any hop for its detail.
7. Click **Stop** to end a continuous run. Use **Export** once the run is finished.

## Inputs and options

| Field | What it means | Default / accepted values |
|---|---|---|
| Host or IPv4 | The destination. A host name is resolved through the system resolver and the first IPv4 address is used. | Empty. Required. IPv6 addresses, and names with only IPv6 addresses, are rejected: IPv6 traceroute is not supported yet. |
| Mode | **Fixed cycles** stops after the cycle count. **Continuous** runs until you click **Stop**. | Fixed cycles |
| Cycles | Number of cycles in fixed mode. Shown only in that mode. | 5. Range 1 to 1000. |
| Interval (ms) | Pause between cycles. | 1000. Clamped to 200 to 60000. |
| Max hops | Highest TTL probed. Once the destination answers, later cycles probe only up to the destination's hop. | 30. Range 1 to 64. |
| Packet (bytes) | Total IP packet size of each trace probe, including the 28 bytes of IP and ICMP headers. | 60. Range 28 to 1500. |
| Path MTU | After the destination first answers, run a don't-fragment size search once. | On |
| Reverse DNS | Look up PTR names for the routers that answer. | On |
| Trace / Stop | Start the run, or stop it. Stop is checked during the interval and between cycles; probes already in flight finish first. | |

Each probe waits up to 2 seconds for an answer. That timeout is fixed.

## Reading the results

While running, the status line shows **Tracing, cycle N...**. When finished it shows **Done after N cycles** or **Stopped after N cycles**.

### Path Summary

Tiles: **Destination** (what you typed, plus the resolved IP if different), **Reached** (Yes or No), **Hops** (path length so far), **Latency** (average RTT to the destination, with jitter below), **Loss** (destination loss), **Path MTU** (bytes, `...` while measuring, `n/a` if not measured) and **Cycles**.

Below the tiles is a list of findings, each with a colored severity and a **hop N** link that opens that hop's detail:

| Severity | Finding | When it appears |
|---|---|---|
| Critical | `N% loss to the destination, starting at hop T` | The destination loses 5% or more of probes. The onset is the first hop from which every later answering hop also loses 5% or more. |
| Serious | `destination not reached; last reply from hop T` | The destination never answered. |
| Serious | `hop T reports ...` | A hop returned ICMP destination unreachable (network, host, protocol or port unreachable, fragmentation needed, administratively prohibited or filtered). |
| Warning | `latency rises N ms at hop T and stays high` | Average RTT jumps by at least 20 ms and at least 25% of the destination's average, and the rise is still there at the destination. |
| Info | `hop T drops N% of probes but the destination does not; likely ICMP rate limiting, not real loss` | A middle hop shows 5% or more loss while the destination stays under 5%. |

Loss and latency findings need at least 5 probes at a hop. If the destination is reached after 5 or more cycles with no findings, the panel says **No loss or latency problems found on this path.**

### Hop Table

One row per TTL: **Hop**, **Host** (PTR name with the IP below, or the IP, or `* no reply`; a **+N more** tag when several routers answered at that TTL), **Loss** (a dot marks any loss), **Sent**, **Last**, **Avg**, **Best**, **Worst**, **StDev** and **Jitter**. Times are in ms, with one decimal under 10 ms. Jitter is the average difference between consecutive RTTs. Click a row to open its detail.

The panel notes: a hop with loss but a clean destination is usually a router rate-limiting ICMP, not real loss.

### Path Latency

A line of the average RTT per hop, with a shaded band from best to worst. Silent hops break the line and show `*` on the baseline. Hover to see a hop's values, use the left and right arrow keys to move between hops, and click or press Enter to open the hop detail.

### Path MTU

Shows the result in bytes (or **Unknown**), the note (for example "full-size packets reach the destination" or "a router on the path reported a smaller MTU"), **Limited by** with the router that sent a fragmentation-needed message, and a table of each size probed and its result (`fits`, `too big (frag-needed from ..., MTU ...)`, `too big for the local interface`, `no reply`). If large packets vanished without a fragmentation-needed reply, a **Serious** banner reports a **PMTUD black hole**: expect stalls on large transfers; check MSS clamping or ICMP filtering.

### Per-Hop Charts

One small chart per hop showing RTT per cycle, with lost probes marked on the baseline. All small charts share the same scale (shown in the legend) so hops compare honestly. The last 300 samples per hop are kept.

### Hop Detail

For the selected hop: Avg, Best, Worst, StDev, Jitter and Loss (with received of sent), an ICMP unreachable banner if one was seen, a larger **RTT history** chart (oldest to latest), and a **Responders** table with each IP, hostname, reply count and share. If several routers answer, the panel notes the path is load-balanced (ECMP). If none answered: "No router answered at this TTL. It may not send ICMP Time Exceeded, which is common and harmless if later hops answer."

### Worked example

Trace to `www.example.com` (resolves to `203.0.113.80`), 20 cycles:

```
Hop  Host                       Loss  Sent  Avg   Best  Worst
1    192.0.2.1                  0%    20    1.2   0.9   2.4
2    198.51.100.1               0%    20    8.4   7.9   11
3    * no reply                 100%  20
4    198.51.100.33  +1 more     35%   20    14    12    22
5    203.0.113.1                0%    20    41    39    48
6    203.0.113.80               0%    20    42    40    50

Info     hop 4 drops 35% of probes but the destination does not; likely ICMP rate limiting, not real loss
Warning  latency rises 27 ms at hop 5 and stays high
Path MTU 1400 bytes. A router on the path reported a smaller MTU. Limited by 198.51.100.33
```

Hop 3 silence is harmless because later hops answer. The loss at hop 4 does not carry through, so it is rate limiting. The 27 ms rise at hop 5 persists to the destination, so that segment (often a long-haul link) adds the latency. Hop 4 has two responders: ECMP.

## What the results do and do not tell you

- **Failed ICMP does not mean a service is down.** Many routers and hosts drop or rate-limit ICMP. A destination that ignores echo can be fully reachable on TCP ports; check with [Port Scanner](port-scanner.md) or [Socket Tools](socket-tools.md).
- Loss at a middle hop only matters if it carries through to the destination. The findings apply that rule.
- RTT to a router measures how fast its control plane answers ICMP, which is often slower than forwarding. Treat a single slow hop with a fast destination as noise.
- The path is the forward path only. The return path can differ and is not visible.
- Every TTL is probed in parallel each cycle. Path length is fixed by the lowest TTL that reached the destination.
- Path MTU is searched by binary search between 576 and 1500 bytes with don't-fragment set. Each lost size is retried once so a single drop is not taken as a limit. The search never goes above 1500, so jumbo-frame paths read as 1500. If the destination does not answer ICMP echo at 576 bytes, the result is "Path MTU cannot be measured".
- A black hole verdict is an inference: larger packets were dropped and no router sent fragmentation-needed. Filtering of the probes themselves can look the same.
- Router hostnames come from PTR records, which the router owner controls. Each new router gets a 1.5 second lookup budget per cycle; slow lookups simply leave the name blank.

## Online activity and privacy

When you click **Trace**, the tool resolves the destination name (if you typed one), then each cycle sends one probe per TTL from 1 up to the max hops (or the destination's hop once known) toward the destination. On macOS, Windows and Linux with ICMP sockets allowed, these are ICMP echo requests; on Linux without ICMP socket permission they are UDP datagrams to ports starting at 33434. Routers along the path answer with ICMP Time Exceeded. With **Path MTU** on, the tool also sends a short series of don't-fragment probes at TTL 64 (a binary search, with one retry for each lost size) after the destination first answers. With **Reverse DNS** on, it sends PTR queries for each new router address to your system resolver.

Nothing is sent until you click. Results stay in memory unless you export or add them to a project.

## Export and projects

When a run is finished, the **Export** menu offers HTML, PDF, Markdown and Plain text, **Redacted...**, and **Add to project**. See [Export and redaction](../export-and-redaction.md) and [Projects and notes](../projects-and-notes.md).

The report contains a **Path** section (target and resolved IP, probe method, cycles, destination reached, destination average and loss), the hop table (Hop, Address, Name, Loss, Sent, Last, Avg, Best, Worst, StDev), a note about rate limiting, a **Findings** section (each finding with the same severity as in the panel: Critical and Serious as failures, Warning as a warning, Info as information, with the label and hop in the category), and a **Path MTU** section (MTU, limiting router, black hole suspected, note). Jitter, per-cycle RTT history, the charts and the MTU step table are not in the report.

## Platform notes

The header shows the method in use:

- **macOS:** "ICMP echo (unprivileged datagram socket)". No privileges needed.
- **Windows:** "ICMP echo (IcmpSendEcho2)", the system ICMP API, which needs no admin rights.
- **Linux:** "ICMP echo (unprivileged datagram socket)" when your group is allowed by `net.ipv4.ping_group_range`. Otherwise "UDP probes (ICMP datagram sockets are not allowed by net.ipv4.ping_group_range for this user)". In UDP mode, the destination is reached when it returns ICMP port unreachable, as with classic traceroute. Router errors are read from the socket error queue, like `tracepath`. To use ICMP mode, widen `net.ipv4.ping_group_range` to include your group (a system-wide sysctl change, which needs root once).

On other operating systems the tool reports "traceroute is not supported on this OS".

## Troubleshooting

**"Enter a host or IPv4 address."** The destination field is empty.

**"IPv6 traceroute is not supported yet" / "'...' has only IPv6 addresses ...".** Use an IPv4 address or a name with an A record.

**"could not resolve '...'" / "'...' did not resolve to an address".** Check the name with [Dig](dig.md).

**"could not open an ICMP socket: ..." or "could not open a probe socket: ...".** The OS refused the probe socket. On Linux, check `net.ipv4.ping_group_range`; security software can also block it.

**"IcmpCreateFile failed (error N)".** Windows could not open the ICMP API. Check endpoint security software.

**Every hop shows `* no reply` and the destination is not reached.** ICMP or the UDP probes are filtered near you, or outbound ICMP is blocked by a local firewall. Test TCP reachability with [Port Scanner](port-scanner.md).

**Path MTU is Unknown.** The destination does not answer echo, so the size search cannot complete.

## Related tools

- [MTU Calculator](mtu-calculator.md) to work out tunnel and MSS overhead once you know the Path MTU.
- [Connectivity Monitor](conn-monitor.md) to keep checking ICMP, TCP, DNS and HTTP reachability over time.
- [Port Scanner](port-scanner.md) and [Socket Tools](socket-tools.md) for TCP and UDP checks.
- [Dig](dig.md) for name resolution.
