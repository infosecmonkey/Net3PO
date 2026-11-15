# Throughput Tester

> Measure throughput with iperf3, as a client against an iperf3 server or as a server for another computer.

**Sidebar group:** Troubleshooting · **Works offline:** no (it sends test traffic to the server you enter, only when you click Start) · **Needs admin rights:** no (only to listen on a port below 1024 on macOS and Linux)

## When to use it

- Check what a WAN link, VPN tunnel or Wi-Fi network actually carries between two points.
- Test before and after a change: QoS policy, MTU, a new circuit, a firewall upgrade.
- Measure UDP loss and jitter at a set rate, as voice and video would see it.
- Let a colleague or a remote site test against this computer, using Server mode.

## Quick start

1. Install iperf3 if the status line says it is missing (see Platform notes). Net3PO does not bundle it.
2. Make sure an iperf3 server is running at the other end (`iperf3 -s`), or start one there with this tool's **Server** mode.
3. In **Client** mode, enter the server's hostname or IP address.
4. Leave Protocol on **TCP** and Direction on **Upload**, and click **Start**.
5. Watch the live chart. When the test ends, read the result cards.
6. Run again with Direction **Download** to test the other way, or **Both at once**.
7. Use **Export** to save the result or add it to a project.

## Inputs and options

The status line at the top shows the iperf3 version and path in use. **Choose iperf3...** selects the program by hand (for example `iperf3.exe` on Windows); **Detect** forgets that choice and searches the usual places again.

Client mode:

| Field | What it means | Default / accepted values |
|---|---|---|
| Server | The iperf3 server to test against. Press Enter to start. | Required. Hostname, IPv4 or IPv6 address |
| Port | The server's port (`-p`). | 5201 |
| Protocol | TCP measures the throughput TCP achieves; UDP sends at a fixed rate and measures loss and jitter (`-u`). | TCP |
| Direction | **Upload**: this computer sends. **Download**: the server sends (`-R`). **Both at once**: both directions at the same time (`--bidir`, iperf3 3.7 or later). | Upload |
| Duration (s) | Test length (`-t`). | 10; 1 to 600 |
| Parallel streams | Number of simultaneous connections (`-P`). Several streams often fill a fast or high-latency link that one stream cannot. | 1; 1 to 128 |
| Bitrate | Target rate (`-b`), such as `100M`, `1.5G` or `500K` bits per second. For UDP, iperf3 uses 1 Mbit/s if empty; for TCP, empty means unlimited. | Empty |
| Omit first (s) | Warm-up seconds left out of the totals (`-O`), to skip TCP slow start. Omitted intervals are shown greyed. | 0; 0 to 60 |
| IP version | Force IPv4 (`-4`) or IPv6 (`-6`). | Auto |

Server mode:

| Field | What it means | Default / accepted values |
|---|---|---|
| Port | Port to listen on, TCP and UDP (`-p`). | 5201 |
| Stop after one test | Exit after one client test (`-1`). | Off |

The exact iperf3 command is shown under the buttons once a test starts.

## Reading the results

While a test runs, the current rate for each direction is shown, and the chart draws one line per direction: **upload** (this computer sends) and **download** (the server sends). In Server mode the lines read **server sends** and **server receives**.

When the test ends, one card per direction shows:

- **Received**: the rate that arrived at the receiver. This is the throughput figure to quote.
- **Sent**: the rate at the sender, and the amount of data moved.
- **Retransmits** (TCP): segments the sender had to resend. A steady count points at loss, congestion or a shaper on the path.
- **Jitter** and **Loss** (UDP): variation in packet arrival and the share of packets that did not arrive, measured by the receiver.
- **CPU**: how busy this computer and the remote end were. Above about 85% the end host is likely the limit, not the network.

**Intervals** lists every one-second sample. **iperf3 messages** shows any warnings or server lines iperf3 printed.

In Server mode, each client test is listed with its remote address and result; the chart and cards show the latest test.

Worked example. A client tests to `iperf.example.net` over a VPN, TCP, 4 streams, 10 seconds. The upload card shows **Received 412 Mbit/s**, sent 415 Mbit/s, retransmits 1,830, CPU 22% local and 31% remote. Download shows 890 Mbit/s with few retransmits. The upload direction is losing packets (high retransmits with low CPU), so the next step is a UDP test at about 400M to measure loss in that direction.

## What the results do and do not tell you

- iperf3 measures what these two hosts can push through the path between them. CPU, NIC, TCP buffer sizes and other traffic on either host all affect the result.
- A single TCP stream on a high-latency path is often limited by the TCP window, not the link. Try more parallel streams before concluding the link is slow.
- UDP results depend on the rate you set. Sending above the path's capacity shows loss by design; sending below it shows what the path delivers at that rate.
- Retransmits are reported by the TCP sender only, so they appear on the upload card when this computer sends and on the download card when the server sends (if the server reports them).
- A result applies to the moment it was taken; repeat tests at different times before drawing conclusions about a link.
- Public iperf3 servers are often busy and allow one test at a time. "the server is busy running a test" means try again later or use another server.

## Online activity and privacy

Client mode sends test traffic to the server and port you enter, only when you click **Start**, for the duration you set. It stops by itself if the test runs 30 seconds past its expected end. Server mode listens on the chosen port from **Start server** until **Stop server** (or after one test with **Stop after one test**), and any computer that can reach the port can run a test against this one.

The path you chose for iperf3 is remembered on this computer. Results are kept only until the next test, unless you export them or add them to a project.

## Export and projects

**Export** writes a report with the command, local and remote addresses, protocol, streams and duration, the result per direction, CPU use, and every interval. A server report lists each client test. Both can be added to a project. See [Export and redaction](../export-and-redaction.md).

## Platform notes

- **Install iperf3:** macOS `brew install iperf3`; Ubuntu and Debian `sudo apt install iperf3`; RHEL and Fedora `sudo dnf install iperf3`; Windows: download an iperf3 build and select `iperf3.exe` with **Choose iperf3...**.
- **Where Net3PO looks:** `iperf3` on the PATH, plus `/opt/homebrew/bin`, `/usr/local/bin` and `/opt/local/bin` on macOS (apps started from the Dock do not see your shell's PATH), and `/usr/bin`, `/usr/local/bin` and `/snap/bin` on Linux.
- **Versions:** iperf3 3.17 or later shows results live; older versions report everything when each test ends. Bidirectional tests need 3.7 or later. iperf 2 is a different program and is not supported.
- **Server ports:** ports below 1024 need extra rights on macOS and Linux. The OS firewall may ask to allow incoming connections the first time Server mode runs.

## Troubleshooting

**"iperf3 was not found".** Install it, or use **Choose iperf3...** if it is somewhere unusual.

**"is iperf 2, which is not compatible".** The program found is iperf 2. Install iperf3.

**"unable to connect to server: Connection refused".** No iperf3 server is listening on that port, or a firewall rejected the connection.

**"the server is busy running a test".** The server allows one test at a time. Wait and try again.

**The test stops with "ran past its expected end".** The server stopped answering mid-test. Check the path and the server.

**UDP shows heavy loss at a low rate.** Check for a policer or shaper on the path, and compare with a lower rate.

**Server mode: "Address already in use".** Another program (often another iperf3) holds the port. Stop it or choose another port.

## Related tools

- [Connectivity Monitor](conn-monitor.md) to watch reachability and latency over time.
- [MTU Calculator](mtu-calculator.md) to check tunnel overhead when throughput is poor over a VPN.
- [Visual Traceroute](traceroute.md) to see the path between the two hosts.
- [Network Snapshot](net-snapshot.md) to record routes and interfaces before and after a test.
