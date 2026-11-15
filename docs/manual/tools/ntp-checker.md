# NTP Checker

> Query one or more NTP servers several times and compare their time with this computer's clock: offset, round-trip delay, stratum and reference.

**Sidebar group:** Troubleshooting · **Works offline:** no (sends NTP queries to the servers you list) · **Needs admin rights:** no

## When to use it

- Check whether an NTP server a firewall, switch or domain controller points at is actually answering, and with what stratum.
- Measure how far this computer's clock is from a reference before you chase Kerberos, certificate or log correlation problems.
- Compare several servers side by side to spot one that is badly off, unsynchronized or rate-limiting you.
- Confirm that UDP 123 gets through a firewall path.

## Quick start

1. Open **NTP Checker** from the Troubleshooting group.
2. In **Servers**, enter one server per line (or separated by spaces or commas), for example `ntp1.example.com` and `192.0.2.123`.
3. Leave **Samples**, **Interval (ms)** and **Timeout (ms)** at their defaults, or adjust them.
4. Click **Check**. All servers are queried in parallel, and samples appear as they arrive.
5. Read the verdict on the right of each server card, then the summary line and the sample table.
6. Use **Export** to save the results or add them to a project.

## Inputs and options

| Field | What it means | Default / accepted values |
|---|---|---|
| Servers | NTP servers to query: host name, IP address, or `host:port`. Separate with new lines, spaces or commas. IPv6 with a port uses brackets, for example `[2001:db8::123]:123`. A bare IPv6 address, with or without brackets, uses port 123. | Empty. 1 to 10 servers. Port 123 if none is given. |
| Samples | How many queries to send to each server. | 4. Range 1 to 10. |
| Interval (ms) | Wait between samples to the same server. | 1000. Range 200 to 10000. |
| Timeout (ms) | How long to wait for each reply. | 2000. Range 200 to 10000. |
| Check | Starts the run. Shows **Checking...** while running. | |

Values outside the ranges are clamped by the backend. A host name that resolves to several addresses uses the first IPv4 address, or the first address if there is no IPv4.

## Reading the results

A line above the cards reminds you: **Positive offset: this computer is behind the server.**

Each server gets a card:

- **Header:** the server as you typed it, the resolved address and port, the stratum and reference ID from the latest answered sample, and the leap indicator if it is not zero.
- **Verdict** (right side, colored):
  - green **within N ms** when the best offset is 100 ms or less,
  - amber **offset N ms** when it is over 100 ms and up to 1 second,
  - red **this computer is N s off this server** when it is over 1 second,
  - amber **no replies (inconclusive)** when no sample was answered,
  - red with the error text when the server name could not be resolved.
- **Summary line:** **Best offset** (from the sample with the lowest round-trip delay, which is the most trustworthy), **Range** (lowest to highest offset), **Jitter** (standard deviation of the offsets), **Min delay** and **answered/sent**.
- **Sample table:** **#**, **Time (UTC)** when the sample was sent, **Offset**, **Delay**, and **Result** (`ok` or the error for that sample).

The reference ID is shown as text (such as `GPS` or `PPS`) for stratum 0 and 1 servers, and as a dotted IPv4 value for stratum 2 and higher. Over IPv6, that dotted value is a hash, not a real address.

Worked example: you check `192.0.2.123` with 4 samples.

```
192.0.2.123   192.0.2.123:123   stratum 2, ref 198.51.100.7      within 3 ms
Best offset 2.84 ms   Range 2.10 ms to 4.95 ms   Jitter 1.07 ms   Min delay 11.20 ms   4/4 answered
#  Time (UTC)     Offset    Delay     Result
1  14:02:11.204   4.95 ms   18.40 ms  ok
2  14:02:12.231   2.84 ms   11.20 ms  ok
...
```

The best offset is taken from sample 2, which had the lowest delay. This computer is about 3 ms behind the server.

## What the results do and do not tell you

- The tool is read-only. It never changes the local clock.
- Offset and delay use the standard NTP calculation (RFC 5905): offset is ((T2 - T1) + (T3 - T4)) / 2 and delay is (T4 - T1) - (T3 - T2). An asymmetric network path skews the offset by up to half the asymmetry.
- **No reply is inconclusive.** The tool's own wording: the server may be down, filtered or rate-limiting, and a timeout alone does not prove which.
- An ICMP port unreachable reply is reported as "nothing answers NTP on that address", which is a stronger signal than silence.
- Replies are checked: a reply must be a server-mode packet whose origin timestamp matches the request. Stray datagrams that do not match are ignored and the tool keeps waiting.
- A stratum 0 reply is a Kiss-o'-Death and is reported as an error for that sample (RATE: slow down; DENY or RSTR: the server refuses this client).
- A server reporting leap indicator 3 is flagged as unsynchronized, and that sample is not counted.
- Each sample is a single SNTP-style query (version 4, client mode). This is not a full NTP association, and it does not measure the server's accuracy against true time, only against this computer.
- Each name lookup has a 5 second limit. There is no Stop button: a run ends when every server has finished its samples.

## Online activity and privacy

When you click **Check**, the tool resolves each host name through the system resolver, then sends one 48-byte NTP client request per sample from a fresh UDP socket to each server on UDP 123 (or the port you gave). With the defaults that is 4 packets per server, 1 second apart. Nothing is sent before you click.

Results stay in memory for the session. Nothing is written to disk unless you export or add to a project.

## Export and projects

The **Export** menu (shown when a run is finished) offers HTML, PDF, Markdown and Plain text, **Redacted...**, and **Add to project**. See [Export and redaction](../export-and-redaction.md) and [Projects and notes](../projects-and-notes.md).

The report has a **Servers** table (Server, Address, Answered, Stratum, Reference, Best offset, Jitter, Min delay), a paragraph explaining the offset sign and that no reply is inconclusive and the local clock was not changed, then one section per server with the sample table (#, Time (UTC), Offset, Delay, Stratum, Reference, Result), or the resolution error.

## Platform notes

The tool uses ordinary UDP sockets with an ephemeral source port, so it needs no privileges on macOS, Windows or Linux. Whether an ICMP port unreachable is reported as "nothing answers NTP" depends on the OS passing that error to the socket; otherwise the sample shows a timeout.

## Troubleshooting

**"Enter at least one NTP server."** The Servers box is empty.

**"at most 10 servers".** Split the list into several runs.

**"could not resolve ..." or "resolving ... timed out".** The name did not resolve within 5 seconds. Check the spelling or use an IP address. Try [Dig](dig.md) to see what DNS returns.

**"bad port in ...".** The text after the last colon is not a port. For IPv6 with a port, use `[2001:db8::123]:123`.

**"no reply within the timeout ..."** The server did not answer. It may be down, UDP 123 may be filtered, or the server may be rate-limiting you. Raise the timeout or interval and try again.

**"ICMP port unreachable: nothing answers NTP on that address".** The host is up but nothing listens on that port.

**"Kiss-o'-Death RATE ..." / "... refuses to serve this client".** The server is limiting or blocking you. Increase the interval, reduce samples, or use another server.

**"server reports it is unsynchronized (leap indicator 3)".** The server itself has no valid time source. Do not use it as a reference.

## Related tools

- [Timestamp Converter](timestamp-converter.md) to convert epoch and log timestamps once you know the clock offset.
- [Connectivity Monitor](conn-monitor.md) to keep watching reachability over time.
- [Socket Tools](socket-tools.md) for generic UDP send and listen tests.
- [Event Log](event-log.md) and [Syslog Server](syslog-server.md), where clock offset affects log correlation.
