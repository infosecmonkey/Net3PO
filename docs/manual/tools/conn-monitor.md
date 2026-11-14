# Connectivity Monitor

> Probe up to 20 targets on a fixed interval with TCP connect, HTTP GET or ICMP echo, graph their latency, and record outage windows.

**Sidebar group:** Troubleshooting · **Works offline:** no (probes the targets you list while running) · **Needs admin rights:** no

## When to use it

- Leave it running during a change window or failover test to get exact start and end times of any outage.
- Catch intermittent drops that a single ping or one-off test misses.
- Compare layers at once: ICMP to a gateway, TCP to a service port and an HTTP health URL, side by side, to see which layer fails first.
- Produce a timestamped CSV of every probe for a ticket or a post-incident review.

## Quick start

1. Open **Connectivity Monitor** from the Troubleshooting group.
2. In the first row, choose a probe type (**TCP**, **HTTP** or **ICMP**) and enter the address. For TCP, also enter the port (for example `192.0.2.10` port `443`). For HTTP, enter a URL such as `https://app.example.com/health`.
3. Click **+ Add target** for more rows (up to 20).
4. Set **Every (s)** and **Timeout (ms)**, or keep the defaults.
5. Click **Start**. Each target gets a card with a status dot, a latency graph and statistics.
6. Click **Stop** when done. The history is kept: **Resume** continues into it, **Clear** discards it.
7. Use **Export samples (CSV)** for raw data, or **Export** for a report with outage windows.

## Inputs and options

| Field | What it means | Default / accepted values |
|---|---|---|
| Probe type | **TCP** (connect to a port), **HTTP** (GET a URL) or **ICMP** (echo request). | TCP |
| Address | TCP and ICMP: host name or IP. HTTP: an `http://` or `https://` URL (no scheme means `https://`). | Empty. Rows with an empty address are skipped. ICMP is IPv4 only. |
| Port | TCP only. | Empty. 1 to 65535. Required for TCP. |
| × | Remove the row. Disabled when only one row is left. | |
| + Add target | Add a row. | Up to 20 targets. |
| Every (s) | Probe interval for each target. | 5. 1 to 3600. |
| Timeout (ms) | Limit for each probe. It is capped at the interval. | 2000. 200 to 30000. |
| Start / Resume / Stop / Clear | Start probing, continue into existing history, stop, or discard the history. | |

Targets and settings cannot be changed while running.

## Reading the results

The hint under the controls shows what each probe measures and, once started, the ICMP method in use on this OS.

A status bar above the cards shows **Running** or **Stopped**, a note if the oldest samples were dropped (more than 10,000 per target), and how many probes ran past the interval.

Each target card shows:

- **Status dot and header:** green when the last probe succeeded, red when it failed; the target, probe type, and **up** or **down** with the last status (`connected`, `refused`, `timed out`, `200`, `503`, `echo reply`, `no reply`, `unreachable`, `DNS failed` and so on).
- **Latency graph:** the last 300 samples. The line is the measured time of successful probes; red vertical marks are failed probes. The scale runs to the highest value shown (**graph peak**).
- **Statistics:** **Success** percentage of all samples, **Last** time, **Min / avg / max** over successful probes.
- **Detail** of the last failure, for example `RST received`, `no answer within the timeout`, `ICMP unreachable code 1 from 198.51.100.1`, or "No reply. A device may simply drop ICMP; this alone does not mean the host or its services are down."
- **Outages** (collapsed): one row per run of consecutive failed probes with **Start**, **End** (the first successful probe after it, or `ongoing`), **Duration**, **Failed** probe count and **First failure** status.

What counts as up:

| Probe | Up when | Time measured |
|---|---|---|
| TCP | The TCP connection completes. A refusal is a failure, but its time is still recorded. | The connect call. |
| HTTP | The server returns a status below 400. Redirects are not followed, so a 301 or 302 counts as up. | The whole request, including DNS, connect, TLS and response. |
| ICMP | An echo reply comes back from the target. | Echo round trip. |

Worked example: three targets, every 5 s.

```
● 192.0.2.1          ICMP echo    up · echo reply     Success 100.0% of 720
● 192.0.2.10:443     TCP connect  up · connected      Success 99.3% of 720
● https://app.example.com/health  HTTP GET  down · 503   Success 97.1% of 720

Outages (https://app.example.com/health)
Start            End              Duration  Failed  First failure
14:02:10         14:03:55         1m 45s    21      503
14:20:05         ongoing          -         4       failed
```

ICMP to the gateway never failed and TCP had only brief misses, so the network path held while the application returned 503. That points at the service rather than the network.

## What the results do and do not tell you

- **A failed ICMP probe does not mean the service is down.** Devices often drop or rate-limit ICMP. Use a TCP or HTTP probe on the service itself.
- **TCP connect time is socket connect time, not packet-level SYN timing.** A refusal means a reset came back (reachable, nothing listening). A timeout alone does not show where traffic was dropped.
- HTTP times the whole request, so DNS and TLS time are included. A 4xx or 5xx is an answer from the server, but counts as down because the service is not serving that URL correctly. Certificate validation is always on; a certificate error counts as a failure. The HTTP timeout is applied in whole seconds (rounded down, minimum 1 s).
- Each target's probes never overlap. A slow probe delays that target's next probe instead of stacking up; the status bar counts these overruns.
- An outage is a run of consecutive failed probes. Its duration runs from the first failed probe to the first successful one, so the real outage may be up to one interval shorter or longer.
- Host names are resolved again for every probe. TCP uses the first address returned (IPv4 or IPv6); ICMP uses the first IPv4 address. DNS time is not part of the TCP or ICMP measurement.
- The UI keeps up to 10,000 samples per target. Older ones are dropped and no longer count in statistics, outages or exports.

## Online activity and privacy

When you click **Start** or **Resume**, each target is probed once per interval until you click **Stop**:

- **TCP:** one TCP connection to the host and port, closed immediately. No data is sent.
- **HTTP:** one HTTP/1.1 GET request to the URL, with the default headers of [HTTP Troubleshooter](http-troubleshooter.md) (User-Agent `Net3PO/<version>`, `Connection: close`).
- **ICMP:** one 64-byte echo request (on Linux without ICMP socket permission, a UDP probe instead; see Platform notes).

Host names are resolved through the system resolver for each probe. Nothing is sent before you click Start, and probing stops when you click Stop. Samples are held in memory only; nothing is written to disk unless you export.

## Export and projects

- **Export samples (CSV)** saves every kept sample, oldest first, with columns `timestamp_utc, target, probe, result, status, ms, detail`. Timestamps are ISO 8601 UTC. The file is limited to 50 MB.
- **Export** offers HTML, PDF, Markdown and Plain text, **Redacted...**, and **Add to project**. See [Export and redaction](../export-and-redaction.md) and [Projects and notes](../projects-and-notes.md). The report has a **Summary** table (Target, Probe, Samples, Success, Min / avg / max, Outages), a paragraph stating the interval and what each probe measures (including that a failed ICMP probe does not establish that a service is down), and one **Outages** table per target that had any. Individual samples are not in the report; use the CSV for those.

## Platform notes

ICMP uses the same unprivileged probe as [Visual Traceroute](traceroute.md), and the hint shows which:

- **macOS:** ICMP echo over an unprivileged datagram socket.
- **Windows:** ICMP echo through the system API (IcmpSendEcho2). No admin rights needed. TCP probes turn off SYN retransmission so a refused port is reported at once instead of after about two seconds.
- **Linux:** ICMP echo over a datagram socket when `net.ipv4.ping_group_range` allows your group. Otherwise the tool falls back to UDP probes, and a target counts as up when it answers with ICMP port unreachable. In that mode, results reflect UDP reachability rather than echo replies.

## Troubleshooting

**"Add at least one target."** Every row's address is empty.

**"...: TCP needs a port".** Enter a port for each TCP row.

**"...: ICMP monitoring supports IPv4 only".** Use an IPv4 address or a name with an A record, or switch that target to TCP.

**URL errors such as "unsupported scheme ..." or "not a valid host: ...".** An HTTP row's URL is not valid. See [HTTP Troubleshooter](http-troubleshooter.md) for the URL rules.

**"at most 20 targets".** Remove some rows.

**Status `DNS failed`.** The name did not resolve at probe time. Check it with [Dig](dig.md).

**Status `cannot probe`.** The OS refused the ICMP socket. On Linux, check `net.ipv4.ping_group_range`; endpoint security software can also block it.

**HTTP target always `failed` with a certificate error.** Validation uses the bundled public root store, so an internal CA is not trusted. Probe the port with TCP instead, or check it in [TLS Inspector](tls-inspector.md).

**"N probes ran past the interval".** Probes take longer than the interval (often DNS or a slow HTTP endpoint). Increase **Every (s)** or lower **Timeout (ms)**.

**"export larger than 50 MB".** Clear old history, or export in smaller runs.

## Related tools

- [Visual Traceroute](traceroute.md) to find where a path fails once you know when.
- [Socket Tools](socket-tools.md) for one-off TCP connect timing with statistics.
- [HTTP Troubleshooter](http-troubleshooter.md) to dig into a failing HTTP target.
- [Port Scanner](port-scanner.md) to check which ports are open before monitoring them.
- [NTP Checker](ntp-checker.md) to confirm clock offset before correlating outage times with logs.
