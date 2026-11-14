# Port Scanner

> TCP connect scan of a host, a list of hosts or an IPv4 subnet, streaming open ports as they are found.

**Sidebar group:** Troubleshooting · **Works offline:** no (connects to the targets you enter) · **Needs admin rights:** no

Only scan hosts you are authorized to test.

## When to use it

- Check which TCP services a host actually exposes from where you sit, for example after a firewall policy change.
- Confirm a service port (SSH, HTTPS, RDP, a management port) is reachable before you troubleshoot the application.
- Sweep a small subnet for hosts listening on a specific port, such as 22 or 3389.
- Compare reachability from two network locations by running the same scan from each.

## Quick start

1. Open **Port Scanner** from the Troubleshooting group.
2. In **Host, IP, or subnet**, enter a target such as `192.0.2.10`, `host.example.com` or `192.0.2.0/28`.
3. Leave **Ports** at `common`, or enter a list such as `22,80,443,8000-8100`.
4. Pick a timing preset: **polite**, **normal** or **aggressive**.
5. Click **Scan** (or press Enter). Open ports appear in the table as they are found.
6. Click **Cancel** to stop early. The summary still shows what was checked.
7. Use **Export** to save the results or add them to a project.

## Inputs and options

| Field | What it means | Default / accepted values |
|---|---|---|
| Host, IP, or subnet | One or more targets separated by commas, spaces or new lines. Each can be an IPv4 or IPv6 address, a host name, or an IPv4 CIDR. | Empty. Required. A CIDR shorter than /31 skips the network and broadcast addresses; /31 and /32 include all addresses. IPv6 CIDRs are not supported. At most 65,536 addresses in total. |
| Ports | Which TCP ports to try on every target. | `common` (a built-in list of about 110 commonly interesting ports). Also `all` or `*` for 1 to 65535, or a comma-separated list of ports and `A-B` ranges. Duplicates are removed. |
| polite / normal / aggressive | Timing preset: how many connections run at once and how long each waits. | **normal** (128 at once, 1000 ms timeout). **polite** is 32 at once, 1500 ms. **aggressive** is 512 at once, 600 ms. |
| Scan / Cancel | Start the scan, or stop it while it runs. | |

A host name resolves through the system resolver, and only the first address returned is scanned.

## Reading the results

- **Progress bar and line:** checks done out of total host-port checks, the number of open ports so far, and "scanning..." while running.
- **Results table:** one row per open port, sorted by host then port. Columns are **Host**, **Port**, **State** (always the green **open** badge, because only open ports are listed) and **Service**, a best-effort name from the port number (for example `ssh`, `https`, `ms-wbt-rdp`). The service name is a label for the well-known port, not a detection of what is really listening.
- **Summary:** **Done** or **Cancelled**, open ports across how many hosts, and the total number of host-port checks and elapsed time.

Worked example: target `192.0.2.0/29`, ports `22,443,3389`, preset **normal**.

```
18 / 18 checks · 3 open
Host          Port   State   Service
192.0.2.1     443    open    https
192.0.2.4     22     open    ssh
192.0.2.4     3389   open    ms-wbt-rdp
Done: 3 open across 2 of 6 hosts (18 host-port checks in 1.1s).
```

A /29 has six usable hosts, so 6 x 3 = 18 checks.

## What the results do and do not tell you

- This is a TCP connect scan: each check is a full connection attempt through the operating system. It is not a SYN scan and it does not grab banners or fingerprint services.
- **Open** means a TCP connection completed. A firewall or load balancer that answers on behalf of a host can make a port look open.
- Ports that are not open are counted, not listed. **Closed** means the connection was refused or the host was unreachable. **Filtered** means no answer before the timeout (or the OS reported a timeout). These counts appear in the export.
- Filtered is inconclusive: the port may be dropped by a firewall, or the host may be down or slow. A short timeout (the aggressive preset) can mark slow open ports as filtered on high-latency paths. Use **polite** for distant or rate-limited targets.
- Only TCP is scanned. For UDP tests use [Socket Tools](socket-tools.md).
- Large scans take time: a /24 with `all` ports is over 16 million checks.

## Online activity and privacy

When you click **Scan**, the tool resolves any host names through the system resolver, then opens TCP connections from this computer to every target and port in the list, up to the preset's concurrency. Connections that succeed are closed immediately; no data is sent on them. Nothing is sent before you click, and **Cancel** stops new connections (ones already in flight finish or time out).

Scans may trigger IDS or IPS alerts and appear in firewall logs on the target network. Results are kept in memory only, unless you export or add them to a project.

## Export and projects

When a scan finishes or is cancelled, the **Export** menu appears with HTML, PDF, Markdown and Plain text, **Redacted...**, and **Add to project**. See [Export and redaction](../export-and-redaction.md) and [Projects and notes](../projects-and-notes.md).

The report has a **Summary** (Target, Ports, Timing, Method "TCP connect", Status complete or cancelled, the open count across hosts, the number of checks and elapsed time, and the closed and filtered counts) and an **Open ports** table (Host, Port as `N/tcp`, Service). Closed and filtered ports are not listed individually.

## Platform notes

- No privileges are needed on any OS, because the scan uses normal TCP sockets.
- On Windows, a refused connection is normally retried for about two seconds before it is reported, which would make closed ports look filtered under short timeouts. The tool turns off SYN retransmissions on each scan socket so refusals are reported immediately, as on macOS and Linux. This is best effort; if the OS rejects the setting, the default behavior stays.
- Very high concurrency can hit OS limits on open sockets or local ports. If results look wrong with **aggressive**, try **normal**.

## Troubleshooting

**"Enter a host or IP to scan."** The target field is empty.

**"'...' is not a valid CIDR".** Check the address and prefix, for example `192.0.2.0/24`.

**"IPv6 ranges are not supported; scan a specific IPv6 host instead".** Enter individual IPv6 addresses.

**"target set too large (N addresses, max 65536); narrow the range".** Use a longer prefix or several runs.

**"'...' is not a valid port or range", "port N is out of range (1-65535)", "range A-B is backwards".** Fix the Ports field. Separate entries with commas, and write ranges low to high.

**"could not resolve '...'".** The host name did not resolve. Check it with [Dig](dig.md) or use the IP.

**Everything shows as filtered.** A firewall is dropping the probes, the host is down, or the timeout is too short for the path. Try **polite**, or check reachability with [Visual Traceroute](traceroute.md).

## Related tools

- [Visual Traceroute](traceroute.md) to see where traffic stops.
- [Socket Tools](socket-tools.md) to send data to an open port, test UDP, or measure connect timing.
- [HTTP Troubleshooter](http-troubleshooter.md) to test a web service on an open port.
- [TLS Inspector](tls-inspector.md) to inspect the certificate on an open TLS port.
- [Connectivity Monitor](conn-monitor.md) to watch a port over time.
