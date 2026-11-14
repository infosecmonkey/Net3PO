# Wake-on-LAN

> Send Wake-on-LAN magic packets from the interface you choose, save devices for one-click wake, and optionally watch for the host to start answering on TCP.

**Sidebar group:** Troubleshooting · **Works offline:** partly (sends packets on your local network; a host name destination or check host needs DNS) · **Needs admin rights:** no

## When to use it

- Wake a lab server, workstation or switch-attached device that is powered off or asleep, without walking to it.
- Send from a specific interface on a multi-homed laptop (for example a USB Ethernet adapter on a lab VLAN instead of Wi-Fi).
- Test whether a router forwards subnet-directed broadcasts to a remote VLAN.
- Confirm that a host actually came up after the wake, not only that a packet left.

## Quick start

1. Open **Wake-on-LAN** from the Troubleshooting group.
2. Enter the target NIC's **MAC address**, for example `00:00:5e:00:53:10`.
3. Pick the **Source interface** on the target's segment. If **Destination** is empty, it fills in with that interface's subnet broadcast (for example `192.0.2.255`).
4. Leave **UDP port** at **9 (discard)** and **Packets** at 3 unless the device needs otherwise.
5. To confirm the wake, tick **Check reachability after sending**, enter the target's own IP in **Target host** (for example `192.0.2.50`) and keep the default ports.
6. Click **Wake**. A log entry shows what was sent and, if checking, whether the host answered.
7. Give the device a name and click **Save device** for one-click wake later.

## Inputs and options

| Field | What it means | Default / accepted values |
|---|---|---|
| Device name (to save) | Label for a saved device. Needed only to save. | Empty |
| MAC address | The target NIC's unicast MAC. Accepts `aa:bb:cc:dd:ee:ff`, `aa-bb-cc-dd-ee-ff`, `aabb.ccdd.eeff` or 12 hex digits. | Empty. Required. Multicast or broadcast MACs and all zeros are rejected. |
| Source interface | Interface the packets are sent from. Lists non-loopback IPv4 interfaces with address and prefix. Choosing one binds the socket to its address (sets the source IP) and, on macOS and Linux, tries to pin the socket to that device. | **OS default route** |
| Destination | Where the packets go: a subnet broadcast, `255.255.255.255`, a unicast IPv4 address, or a host name (resolved to its first IPv4 address). Suggestions list each interface's subnet broadcast and the limited broadcast. | Empty. Required. Filled automatically with the interface's subnet broadcast when you pick an interface and the field is empty or holds another suggestion. |
| UDP port | **9 (discard)**, **7 (echo)** or **Custom**. | 9 |
| Custom port | Shown when Custom is selected. | 9. 1 to 65535. |
| Packets | Number of magic packets, 100 ms apart. | 3. 1 to 10. |
| SecureOn password (optional, not saved) | Appended to the magic packet for NICs that require it. 4 bytes as `a.b.c.d` or 6 bytes in MAC notation. | Empty. Never saved with the device. |
| Check reachability after sending | After sending, poll TCP ports on the target until one answers. | Off. On automatically when a saved device with a check host is loaded. |
| Target host (its own IP or name) | The target's own address, not the broadcast address. | Empty. IPv4 only. |
| TCP ports | Ports to try, comma or space separated. | Empty means `22, 3389, 445, 80, 443`. Up to 8 ports. |
| Wait up to (s) | How long to keep checking. | 120. 5 to 600. |
| Notes (saved with the device) | Free text, such as location or BIOS setting. | Empty |
| Wake / Save device (Update device) / Clear (New device) / Stop check | Send, save or update the device, clear the form, or stop a running check. | |

**Saved devices** table: Name (with notes), MAC, Destination:port, Interface, Check host, and **Wake**, **Edit**, **Delete** buttons. **Wake** loads the device into the form and sends at once. **Delete** asks for confirmation. If a saved interface is no longer present, the form says so and uses the OS default.

## Reading the results

Each wake adds an entry to the **Log** (newest first, last 100 kept):

- **Header:** time, device name (or the MAC if unsaved), and the MAC.
- **Sent:** for example `3 magic packets (102 bytes) to 192.0.2.255:9 from 192.0.2.10 via en7`. A magic packet is 6 bytes of `FF` followed by the MAC 16 times (102 bytes), plus 4 or 6 bytes with a SecureOn password.
- **Woke?:** the reachability result:
  - `Not checked`
  - `Checking 192.0.2.50...`
  - `192.0.2.50 answered on TCP 22 after 38.2s` (green)
  - `192.0.2.50 refused TCP 3389 after 41.0s (port closed, but the host is up)` (green)
  - `No answer from 192.0.2.50 within 120s. Inconclusive: it may be awake with those ports filtered, still booting, or asleep.`
  - `Check of 192.0.2.50 stopped after ...` or `Check of ... failed: ...`
- **Delivery note:** how the packet travels, based on the destination:
  - **Limited broadcast** (255.255.255.255): reaches only the segment of the sending interface. Routers never forward it.
  - **Local subnet broadcast:** the broadcast of a local interface's subnet; reaches every host on that segment.
  - **Remote subnet broadcast:** ends in `.255` and is not on a local subnet. It arrives only if the routers on the path forward directed broadcasts to that subnet (usually off by default).
  - **Unicast:** one address. A sleeping host usually cannot answer ARP, so this works only with a static ARP entry or while the switch and router still remember the host.
- **Warnings**, for example that the chosen interface was not found, or that pinning to the device failed and 255.255.255.255 may leave by the default interface.

Worked example: MAC `00:00:5e:00:53:10`, interface `eth1 (192.0.2.10/24)`, destination `192.0.2.255`, check host `192.0.2.50`.

```
14:05:12  Lab server  00:00:5e:00:53:10
Sent    3 magic packets (102 bytes) to 192.0.2.255:9 from 192.0.2.10 via eth1
Woke?   192.0.2.50 answered on TCP 22 after 47.6s
Subnet broadcast of a local interface: reaches every host on that segment.
```

## What the results do and do not tell you

- **Sent only means the OS accepted the packets for sending.** It does not show that they reached the target or that it woke. The export says the same.
- The reachability check tries every listed port at once every 2 seconds, with a 1.5 second connect timeout per port. Either an accepted connection or a refusal proves the host's network stack is up. Timeouts and unreachable errors do not.
- **No answer is inconclusive:** the host may be awake with those ports filtered by its firewall, still booting, or asleep. Choose ports the target actually listens on or answers with a reset.
- Wake-on-LAN must be enabled in the target's firmware and OS, and many NICs only wake from certain power states. The tool cannot check those settings.
- Classification as remote broadcast is a guess based on a `.255` ending; other prefix lengths cannot be told apart from host addresses.
- Only IPv4 is supported.

## Online activity and privacy

When you click **Wake**, the tool resolves the destination if it is a name (system resolver, 5 second limit), then sends the chosen number of UDP datagrams containing the magic packet to the destination and port, from the chosen interface. With the check enabled, it then makes TCP connection attempts to the target host's ports every 2 seconds until one answers, the wait ends, or you click **Stop check**. Connections that succeed are closed at once; no data is sent. When the panel opens, it only reads the local interface list; nothing is sent.

Saved devices (name, MAC, destination, port, interface, packet count, check host, check ports and notes) are stored locally in the app data folder. The SecureOn password is never saved. The log is kept in memory for the session only.

## Export and projects

The **Export** menu above the log offers HTML, PDF, Markdown and Plain text, **Redacted...**, and **Add to project**. See [Export and redaction](../export-and-redaction.md) and [Projects and notes](../projects-and-notes.md).

The report has a **Requests** table (Time, Device, MAC, Sent, Reachability) with the note that a sent packet only means the OS accepted it, and a **Delivery notes** section explaining each delivery type used (remote broadcast and unicast marked as warnings) plus any warnings per request. The SecureOn password and the device notes are not included. MAC addresses are included; use **Redacted...** if you need to remove them.

## Platform notes

- No privileges are needed: the magic packet is a normal UDP datagram sent with broadcast enabled.
- **macOS:** choosing an interface also pins the socket to that device, so even 255.255.255.255 leaves by the interface you picked.
- **Linux:** pinning a socket to a device needs `CAP_NET_RAW`. Without it, the tool still binds to the interface's address and shows a warning: the source address is correct, but 255.255.255.255 may leave by the default interface. Use the interface's subnet broadcast address instead.
- **Windows:** the socket is bound to the interface's address only (no device pinning). Prefer the subnet broadcast address of the interface you want.
- Host firewalls rarely block outbound UDP, but endpoint security can refuse broadcasts; see Troubleshooting.

## Troubleshooting

**"'...' is not a MAC address (use aa:bb:cc:dd:ee:ff, aa-bb-..., aabb.ccdd.eeff or 12 hex digits)".** Fix the MAC format.

**"... is a multicast or broadcast MAC; Wake-on-LAN needs the NIC's unicast address".** Use the NIC's burned-in or assigned unicast MAC.

**"SecureOn password must be 4 bytes (a.b.c.d) or 6 bytes (MAC format)".** Check the password format, or leave it empty.

**"'...' is not a valid IPv4 address or host name".** Check the destination for typos.

**"could not resolve ..." / "... has no IPv4 address".** The name did not resolve to IPv4. Use an IP or check with [Dig](dig.md).

**"could not send to ...: ... The OS or a host firewall refused to send this broadcast."** Local security software blocked the broadcast. Allow Net3PO to send, or use a unicast destination.

**"could not send to 255.255.255.255: ... Pick an interface, or use its subnet broadcast address."** The OS could not route the limited broadcast. Select a source interface.

**"check the target's own address, not a broadcast address".** Put the host's own IP in **Target host**, not the broadcast.

**Packets sent but the host never answers.** Check that the source interface is on the target's VLAN, that WoL is enabled in BIOS/UEFI and the NIC driver, and for remote subnets that the router forwards directed broadcasts. Try more packets or a longer wait.

## Related tools

- [MAC Vendor](mac-vendor.md) to confirm which vendor a MAC belongs to.
- [Port Mapper](port-mapper.md) to find which switch port the target is on.
- [Subnet Calculator](subnet-calculator.md) to work out a remote subnet's broadcast address.
- [Connectivity Monitor](conn-monitor.md) to keep watching the host after it wakes.
