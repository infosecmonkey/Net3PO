# Syslog Server

> Run a temporary syslog receiver on UDP and TCP to collect messages from devices, or send generated test messages to another syslog server.

**Sidebar group:** Servers · **Works offline:** yes on the local network (it listens for, or sends, syslog only while you run it) · **Needs admin rights:** only to bind a port below 1024, such as 514 (see Platform notes)

## When to use it

- Check that a firewall, switch or appliance actually sends syslog, and what it sends, before pointing it at the SIEM.
- Collect logs from a device for a short troubleshooting window without a permanent log server.
- Test a SIEM or collector with known traffic using the **Send** tab.
- Check that syslog passes through a firewall or NAT between two sites.

## Quick start

Receive:

1. Open the **Receive** tab.
2. Set **Port**. 514 is standard; use 5140 if you do not want to grant admin rights.
3. Leave **UDP** and **TCP** both ticked, or pick one.
4. Click **Start**. The status line shows `Listening on port N (UDP + TCP)`.
5. Point the device at this computer's IP address and port, for example `192.0.2.50` port 5140.
6. Use **Filter text** and the severity list to narrow the view.
7. Click **Save** to write the shown messages to a text file, then **Stop**.

Send:

1. Open the **Send** tab, enter **Destination server** (for example `198.51.100.10`) and **Port**.
2. Pick **Transport**, **Format** and **Message type**, set **Count** and **Rate**, and click **Send**.

## Inputs and options

Receive tab:

| Field | What it means | Default / accepted values |
|---|---|---|
| Port | Port to listen on, for both UDP and TCP. | 514; 1 to 65535 |
| UDP | Listen on UDP. | On |
| TCP | Listen on TCP. Messages are read one per line (newline-delimited). | On |
| Filter text | Case-insensitive match against the raw message. | Empty |
| Severity list | Show messages at the chosen severity or worse (lower number). Messages without a parseable priority are always shown. | All severities |
| Save | Saves the currently shown (filtered) messages as raw lines, oldest first, to a `.txt` or `.log` file. | |
| Clear | Empties the message list. | |

Send tab:

| Field | What it means | Default / accepted values |
|---|---|---|
| Destination server | IP address or hostname of the receiver. | Required |
| Port | Destination port. | 514 |
| Transport | UDP, or TCP with RFC 6587 octet-counting framing (`<length> <message>`). | UDP |
| Format | RFC 3164 (`<PRI>Mmm dd hh:mm:ss host app[pid]: msg`) or RFC 5424 (`<PRI>1 timestamp host app pid msgid - msg`, UTC with milliseconds). | RFC 3164 |
| Message type | Built-in generator: mixed, ssh, sudo, kernel, cron, app, fortigate. `mixed` picks a random type per message. Disabled when an exact message is set. | mixed |
| Count (0 = until stopped) | Number of messages to send. | 20 |
| Rate (msg/s, 0 = max) | Messages per second. Accepts halves, such as 0.5. | 2 |
| Severity | Force a severity (0 emerg to 7 debug), or `auto` to use the generator's severity (info for a custom message). | auto |
| Exact message (overrides generator) | Under **Custom message / fields**. Sends this text every time. | Empty |
| Hostname | Host field in each message. Empty picks a random host name per message. | Empty |
| App (with custom message) | App or tag used with a custom message. | `testapp` |
| Facility (with custom message) | Facility used with a custom message (kern to local7). | local0 |

## Reading the results

Receive table, newest first:

- **Received**: local time the message arrived.
- **Source**: sender address and source port.
- Transport column: UDP or TCP.
- **Severity**: decoded from the `<PRI>` value, color coded: emerg, alert, crit and err in one color, warning in another, notice, info and debug in a third. A dash means no priority was found.
- **Host**, **Tag**: parsed from the header where possible. RFC 3164 parsing is a best-effort heuristic.
- **Message**: the message text. If the header cannot be parsed, the whole line is shown here.

The count next to the filter shows how many messages match.

Worked example. A device at `192.0.2.20` sends `<134>Nov 14 09:12:01 fw1 sshd[812]: Accepted publickey for admin from 203.0.113.5 port 50122 ssh2` over UDP. The row shows Source `192.0.2.20:51400` (the sender's source port), `UDP`, Severity `info` (134 = facility local0, severity 6), Host `fw1`, Tag `sshd`, and the message text.

Send tab: a running count (`N sent`) and a log of the last 2,000 lines sent, newest first, with index and severity.

## What the results do and do not tell you

- The list keeps the newest 10,000 messages. Older ones drop off the bottom; save regularly during long captures.
- One UDP datagram can carry several newline-separated messages; each becomes its own row. UDP datagrams up to 65,535 bytes are accepted.
- TCP input is split on newlines only. Senders that use octet-counting framing without newlines (including this tool's own Send tab over TCP) arrive as one long row. Use UDP, or a sender that ends each message with a newline.
- Structured data in RFC 5424 messages stays inside the message text.
- Timestamps in the Received column are local arrival times, not the device's timestamp.
- The receiver listens on IPv4 only (all IPv4 addresses on the chosen port).

## Online activity and privacy

The receiver listens on the chosen port on all IPv4 interfaces only between **Start** and **Stop**. Any host that can reach that port can send messages while it runs. Nothing is forwarded anywhere.

The Send tab sends messages only to the destination you enter, only when you click **Send**. Generated messages use random user names, host names and IP addresses; check that your SIEM team expects test traffic.

Received messages are held in memory and are lost on **Clear**, on the next **Start**, or when the app closes, unless you click **Save**.

## Export and projects

**Save** writes the shown messages as raw syslog lines, oldest first. There is no report export or "Add to project" for this tool. Saved logs may contain sensitive data from your devices; see [Privacy](../privacy.md).

## Platform notes

- Ports below 1024 (including 514) need admin or root rights on Linux, and may be refused elsewhere. The app never needs to run as admin: when binding fails with a permission error, the panel offers **Use port 5140 (no admin needed)**. Point senders at 5140, or forward 514 to 5140 on the host or firewall.
- On Linux you can also grant only the low-port capability to the app binary (`sudo setcap cap_net_bind_service=+ep <path to app>`).
- The OS firewall must allow inbound UDP and TCP on the port. Windows Defender Firewall and the macOS application firewall may prompt the first time.

## Troubleshooting

**Error "cannot bind UDP port 514: permission denied. Ports below 1024 need admin/root; try a port such as 5140."** Click **Use port 5140 (no admin needed)** and point senders at 5140.

**Error "cannot bind TCP port N: already in use."** Another syslog daemon or app holds the port. Stop it, or pick another port.

**Error "enable at least one of UDP or TCP".** Tick UDP, TCP or both.

**Started, but no messages arrive.** Check the device's syslog destination, port and transport, the OS firewall on this computer, and any firewall in between. Test locally with the **Send** tab to `127.0.0.1` over UDP.

**Error "Enter a destination server."** The Send tab needs a destination.

**Error "connect to <addr> timed out".** TCP send could not connect within 5 seconds. Check the receiver is listening on TCP.

**Error "could not resolve '...'".** The destination hostname did not resolve.

**Error "send failed: ...".** The socket refused the send, for example the TCP receiver closed the connection.

**Error "could not write <path>: ...".** Save failed. Pick another folder.

## Related tools

- [TFTP Server](tftp-server.md)
- [Windows Event Log](event-log.md)
- [IOC Extractor](ioc-extractor.md)
- [Regex Builder](regex-builder.md)
- [Socket Tools](socket-tools.md)
