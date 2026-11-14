# Socket Tools

> Send a TCP or UDP payload and see what comes back, listen on a TCP or UDP port to see who connects and what they send, and time repeated TCP connects to one port.

**Sidebar group:** Troubleshooting · **Works offline:** partly (Send and Connection timing contact the target you name; Listen only receives, and you can test it locally) · **Needs admin rights:** no for sending and timing; listening on ports below 1024 can need admin/root (see Platform notes)

## When to use it

- Check that a firewall rule actually passes TCP or UDP traffic end to end: run **Listen** on one machine and **Send** from another.
- Poke a service by hand: send `HELO`, an HTTP request line, or a few hex bytes, and read the raw reply with timestamps.
- Measure how consistent TCP connect times are to a server, and count refusals and timeouts over many attempts.
- Stand up a temporary fake service (with an optional banner) so a device under test has something to connect to.

## Quick start

Firewall test between two machines:

1. On the receiving machine, open **Socket Tools**, choose the **Listen** tab, pick **TCP** or **UDP**, set **Port** (for example `9000`) and click **Start listening**.
2. Allow the port in that machine's host firewall if prompted.
3. On the sending machine, open the **Send** tab. Enter the receiver's address in **Host** (for example `192.0.2.50`) and the same **Port**, and choose the same protocol.
4. Type a payload such as `hello\r\n` and click **Send**.
5. On the listener, the connection (TCP) and the data appear in the log with timestamps and the peer address.
6. On the sender, read the log: connect time, bytes sent, any reply, and the **Done** reason and note.
7. Click **Stop** on the listener when finished.

The three tabs stay active when you switch between them, so a listener keeps running while you use Send or Connection timing.

## Inputs and options

### Send tab

| Field | What it means | Default / accepted values |
|---|---|---|
| Host | Target host name or IP. A name that resolves to both IPv4 and IPv6 uses the IPv4 address. | Empty. Required. |
| Port | Target port. | Empty. 1 to 65535. Required. |
| Protocol | **TCP** or **UDP**. | TCP |
| Payload | Bytes to send. **Text** mode understands the escapes `\r`, `\n`, `\t`, `\0`, `\\` and `\xHH`. **Hex** mode takes hex bytes and ignores spaces, colons, dashes, commas and `0x` prefixes. | Empty (TCP connects and sends nothing; UDP sends an empty datagram). Up to 64 KB. |
| Wait for replies (ms) | How long to keep reading replies after sending. | 3000. 0 to 120000. |
| Connect timeout (ms) | TCP only: limit for the connection attempt. | 5000. 100 to 60000. |
| Send / Stop | Start, or stop waiting for replies early. | |
| Hex view | Show received data as a hex dump instead of escaped text. | Off |

### Listen tab

| Field | What it means | Default / accepted values |
|---|---|---|
| Protocol | **TCP** or **UDP**. | TCP |
| Bind address | Local IP to listen on. Enter `::` to listen on IPv6. | Empty means all IPv4 addresses (`0.0.0.0`). Must be an IP that exists on this computer. |
| Port | Local port. | 9000. 1 to 65535. |
| Echo data back | Send every received chunk back to its sender. | Off |
| Reply on connect (optional) | A payload sent once to each new TCP connection, or once to each new UDP sender. Text or Hex, with the same rules as the Send payload. | Empty |
| Start listening / Stop | Bind and listen, or stop and close all connections. | |
| Hex view | Show received data as a hex dump. | Off |

### Connection timing tab

| Field | What it means | Default / accepted values |
|---|---|---|
| Host | Target host name or IP (IPv4 preferred when both exist). | Empty. Required. |
| Port | Target TCP port. | Empty. Required. |
| Count | Number of connect attempts. | 20. 1 to 10000. |
| Interval (ms) | Time from the start of one attempt to the start of the next. | 1000. Minimum 100. |
| Timeout (ms) | Limit for each attempt. | 3000. 100 to 60000. |
| Start / Stop | Begin the run, or end it early. | |

## Reading the results

### Send log

Each line has a local timestamp (to the millisecond):

- **Target 192.0.2.50:9000**: the resolved address.
- **Connected in N ms from <local address:port>** (TCP only).
- **Sent N bytes**.
- **Received N bytes at +N ms**: time since the payload was sent, followed by the data as escaped text (non-printable bytes as `\xHH`, line breaks shown as `\n`) or a hex dump with offsets and an ASCII column. Only the first 4096 bytes of each chunk are shown.
- **Done:** the reason (`wait time over`, `the server closed the connection`, `the server reset the connection`, `ICMP port unreachable received`, `1 MB received; stopped reading`, or `stopped`) and the total received, plus a note when it helps:
  - TCP, no reply: "Connected and sent, but no reply. Many services wait for a specific request before answering."
  - UDP, no reply: "No reply. UDP silence is inconclusive: the port may be open and ignoring this payload, filtered, or closed with ICMP blocked."
  - UDP, ICMP port unreachable: "The target (or a device on the path) reported the port as unreachable: most likely nothing listens there."

### Listen log

A status line shows **Listening on TCP 0.0.0.0:9000 · N bytes received. Your firewall may need to allow it.** Log lines:

- **Listening on ...** when the bind succeeds.
- **#N connection from <peer>** for each TCP connection (numbered).
- **#N <peer> sent N bytes** (TCP) or **<peer> sent N bytes** (UDP), followed by the data.
- **#N <peer> closed: <reason>, N bytes**, where reason is `closed by peer`, `listener stopped`, `echo failed`, `could not send the reply` or an error.
- **Rejected <peer>: more than 64 connections open** when the connection limit is reached.
- **Stopped** when the listener ends.

The log keeps the last 2000 lines; a counter shows how many older lines were dropped.

### Connection timing

- A header with the resolved address and attempt count.
- A bar chart, one bar per attempt: connected attempts scaled by connect time, failed attempts drawn full height in their outcome color.
- When the run ends, a summary: **Attempts**, **Connected** (with percentage), **Refused**, **Timed out**, **Other errors**, **Connect time min / avg / max** and **Std dev / p95**. Times count only successful connects.
- A log of every attempt: time, number, outcome (`connected`, `refused`, `timed out`, `error`), time in ms, and detail such as `refused (RST received)`, `no answer within 3000 ms`, `host unreachable`, `network unreachable (no route)` or `blocked locally (permission denied)`.

Worked example: timing `192.0.2.80` port 443, count 20.

```
192.0.2.80:443 · 20 attempts
Attempts                       20
Connected                      19 (95%)
Refused                        0
Timed out                      1
Connect time min / avg / max   11.42 ms / 13.08 ms / 19.77 ms
Std dev / p95                  1.85 ms / 17.10 ms
```

One attempt in 20 timed out while the rest were steady around 13 ms. That points to occasional drops on the path or at the server, but a timeout alone does not show where or why.

## What the results do and do not tell you

- **Connect time is socket connect time, not packet-level SYN timing.** The tool's wording: it times the operating system's TCP connect call, not SYN/SYN-ACK on the wire. It includes local OS overhead.
- **Refused** means a TCP reset came back: the host (or a device rejecting on its behalf) is reachable but nothing is listening. **A timeout alone does not show where or why traffic was dropped.**
- **UDP silence is inconclusive.** The port may be open and ignoring this payload, filtered, or closed with ICMP blocked. Many UDP services only answer a correctly formed request.
- An ICMP port unreachable reply to UDP is reported only if the OS passes it to the socket and nothing on the path filters it.
- TCP with no reply does not mean the service is broken. Many protocols (HTTP, TLS) wait for the client to speak first.
- Received data is shown as text or hex only; it is never rendered or run.
- Limits: payloads up to 64 KB, the sender stops reading after 1 MB of replies, the listener accepts up to 64 simultaneous TCP connections, and the UDP listener sends its reply-on-connect banner to at most 10,000 distinct senders. Name lookups time out after 10 seconds.

## Online activity and privacy

- **Send:** when you click **Send**, the tool resolves the host name (system resolver), then opens one TCP connection to the host and port and writes your payload, or sends one UDP datagram with your payload from an ephemeral local port. It then only listens for replies.
- **Listen:** when you click **Start listening**, the tool opens a port on this computer. It sends nothing unless you enable **Echo data back** (returns received bytes to their sender) or set a **Reply on connect** payload. While it runs, anyone who can reach that port can connect and send data. Stop it when you are done.
- **Connection timing:** when you click **Start**, the tool opens and immediately closes one TCP connection per attempt to the target, at the interval you set. No data is sent on these connections.

Logs are kept in memory only. Nothing is written to disk unless you export.

## Export and projects

**Send** and **Connection timing** have an **Export** menu with HTML, PDF, Markdown and Plain text, **Redacted...**, and **Add to project**. See [Export and redaction](../export-and-redaction.md) and [Projects and notes](../projects-and-notes.md). **Listen** has no export.

- **Send report:** an **Exchange** table (Time, Event, Detail) with the resolved address, connect time and local address, bytes sent, each reply with its offset and the first 500 characters of its text view, and the Done reason and note. The payload you sent is not included, only its size.
- **Connection timing report:** a **Summary** (the same statistics as the panel), an **Attempts** table (#, Time, Result, Connect time, Detail), and the note that connect time is measured around the OS connect call, is not packet-level SYN/SYN-ACK timing, and that a timeout alone does not show where traffic was dropped or why.

## Platform notes

- **Windows:** Windows normally retries a SYN for about two seconds after a reset, which would turn a refused port into a timeout. Send and Connection timing turn off SYN retransmissions on their sockets so refusals are reported at once, as on macOS and Linux. This is best effort.
- **Listening on low ports:** binding to ports below 1024 can fail with "permission denied" depending on the OS and its settings; Linux requires root or the right capability by default. Use a port of 1024 or higher where possible. Never run the whole app as admin for this.
- **Host firewalls:** the macOS application firewall, Windows Defender Firewall and Linux firewalls (firewalld, ufw, nftables) may block incoming connections to the listener until you allow them. The listener status line reminds you of this.

## Troubleshooting

**"Enter a host and port."** Fill in both fields on Send or Connection timing.

**"could not resolve ..." / "resolving ... timed out".** Check the name with [Dig](dig.md) or use an IP.

**"connect to ...: refused (RST received)".** The host is reachable but nothing listens on that port, or a device rejects on its behalf.

**"connect to ...: no answer within N ms".** The connection was dropped silently, usually by a firewall, or the host is down.

**"bad escape \x..: use two hex digits" / "unknown escape \..; use \\ for a backslash" / "payload ends with a lone backslash".** Fix the text payload escapes. Write a literal backslash as `\\`.

**"hex payload has an odd number of digits" / "not hex: ..".** Each byte needs two hex digits.

**"payload larger than 64 KB".** Shorten the payload.

**"cannot bind ...: permission denied ..."** Use a port of 1024 or higher.

**"cannot bind ...: already in use."** Another program (or another listener) holds that port. Pick another port or stop the other program.

**"cannot bind ...: that address is not on this computer."** The bind address must be one of this computer's own IPs, or empty for all IPv4 addresses.

**Sender shows "wait time over" with no reply over TCP.** The service is waiting for a valid request. Send one (for example `GET / HTTP/1.1\r\nHost: example.com\r\n\r\n`), or use [HTTP Troubleshooter](http-troubleshooter.md) for web services.

## Related tools

- [Port Scanner](port-scanner.md) to find open TCP ports first.
- [HTTP Troubleshooter](http-troubleshooter.md) for HTTP and HTTPS requests with redirects and TLS.
- [Connectivity Monitor](conn-monitor.md) to watch TCP, ICMP, DNS and HTTP reachability over time.
- [Syslog Server](syslog-server.md) and [TFTP Server](tftp-server.md) for listeners that understand those protocols.
- [Encoder Workbench](encoder-workbench.md) to prepare or decode payload bytes.
