# SNMP Sweep

> Find SNMP v1 and v2c responders across a subnet or host list and read each one's sysName, sysDescr and sysObjectID.

**Sidebar group:** Discovery and SNMP · **Works offline:** no (queries every target address, only when you click Sweep) · **Needs admin rights:** no

## When to use it

- Inventory which devices on a management subnet answer SNMP with a given community.
- Check that a community change rolled out to every device in a range.
- Identify unknown devices by their sysDescr and sysObjectID before walking them in detail.
- Spot devices still answering a default or retired community.

Only sweep networks you are authorized to query. The panel says the same.

## Quick start

1. Enter a subnet or list in **Subnet or hosts**, for example `192.0.2.0/24`.
2. Leave **Port** at 161 unless your devices use another port.
3. Pick **Version** (v1 or v2c).
4. Enter the **Community**.
5. Click **Sweep**. The progress bar fills and responders appear in the table as they answer.
6. Click **Cancel** to stop early. Results found so far stay in the table.
7. When the sweep ends, use **Export** to save the list or add it to a project.

## Inputs and options

| Field | What it means | Default / accepted values |
|---|---|---|
| Subnet or hosts | Targets to probe. Separate entries with commas, spaces or new lines. Accepts single IPv4 or IPv6 addresses, hostnames, and IPv4 CIDR blocks. | Required. IPv4 CIDRs only; at most 65,536 addresses in total |
| Port | UDP port to query on every target. | 161; 1 to 65535 |
| Version | SNMP version. SNMPv3 is not offered in the sweep; use [SNMP Walk](snmp-walk.md) for v3 devices. | v1 or v2c; default v2c |
| Community | Community string sent to every target. | `public` (selected on focus so you can type over it) |

Fixed settings, not shown in the panel: each probe waits 1 second for a reply with no retries, and up to 64 hosts are probed at the same time.

For CIDR blocks shorter than /31, the network and broadcast addresses are skipped. A /31 or /32 includes every address. A hostname resolves to its first address; if it does not resolve, the sweep stops with an error before probing anything.

## Reading the results

- **Progress bar**: hosts probed out of the total, plus how many are responding. It updates every 16 hosts.
- **Status line**: when the sweep ends, for example `Done: 3 SNMP responders of 254 hosts.` or `Cancelled: ...`.
- **Results table**, sorted by IP address:
  - **Host**: the responding address.
  - **sysName**: the device's configured name (sysName.0).
  - **sysDescr**: the device description (sysDescr.0), usually vendor, model and software version.
  - **sysObjectID**: the vendor object ID (sysObjectID.0). If a loaded MIB knows the OID, the name is shown with the dotted form in brackets.

Octet strings with only printable characters show as text; anything else shows as hex bytes. An empty cell means the agent did not return that value.

Worked example. Sweeping `198.51.100.0/28` with v2c:

| Host | sysName | sysDescr | sysObjectID |
|---|---|---|---|
| 198.51.100.1 | core1.example.com | Example router OS 15.2 | 1.3.6.1.4.1.32473.1.1 |
| 198.51.100.5 | ap-lobby | Example wireless AP 8.10 | 1.3.6.1.4.1.32473.2.7 |

The status line would read `Done: 2 SNMP responders of 14 hosts.`

## What the results do and do not tell you

- A host counts as a responder only if it answered the first request within 1 second. For v2c that is one GETBULK for all three values; for v1 it is a GET for sysDescr.0, followed by GETs for sysName.0 and sysObjectID.0.
- A missing host does not prove SNMP is off. The community may be wrong (agents usually drop such requests silently), an ACL may block this computer, the reply may have been slower than 1 second, or the packet may have been lost. There are no retries.
- Responders only tell you that the community works for at least the system group. They say nothing about write access.
- IPv6 ranges are not supported. List IPv6 hosts one by one.

## Online activity and privacy

When you click **Sweep**, the app resolves any hostnames with the OS resolver and sends SNMP requests over UDP to every target address. Nothing is sent at other times. A sweep is visible on the network and may trigger IDS alerts or SNMP authentication-failure traps on devices that reject the community.

The community is kept in the panel only for the current session. It is not saved to disk and is not written to exported reports. v1 and v2c carry the community in clear text on the wire.

## Export and projects

After a sweep ends, the **Export** menu offers HTML, PDF, Markdown and plain text, a **Redacted...** option, and **Add to project**. See [Export and redaction](../export-and-redaction.md) and [Projects and notes](../projects-and-notes.md).

The report contains the targets, port, version, the result line, and a table of IP, sysName, sysDescr and sysObjectID (or "No SNMP responders found."). The community string is not included.

## Platform notes

The sweep uses normal UDP sockets on macOS, Windows and Linux and needs no elevated privileges. A host firewall must allow the outbound requests and the replies. Large sweeps open many short-lived sockets at once; endpoint security software on some systems may rate-limit or flag this.

## Troubleshooting

**Error "Enter a subnet (e.g. 10.0.0.0/24) or host list."** The targets field is empty.

**Error "'...' is not a valid CIDR".** A token with a slash is not a valid IPv4 CIDR.

**Error "IPv6 ranges are not supported; scan a specific IPv6 host instead".** You entered an IPv6 prefix. List IPv6 hosts individually.

**Error "target set too large (N addresses, max 65536); narrow the range".** Split the range into smaller sweeps.

**Error "could not resolve '...': ...".** A hostname in the list did not resolve. Fix or remove it.

**No responders at all.** Check the community and version, confirm the devices allow SNMP from this computer's address, and try one known device in [SNMP Walk](snmp-walk.md), which gives a specific error message.

**sysObjectID shows only numbers.** No loaded MIB defines that OID. Load the vendor MIB in [SNMP Walk](snmp-walk.md) before sweeping; the name registry is shared.

## Related tools

- [SNMP Walk](snmp-walk.md)
- [Switch Port Mapper](port-mapper.md)
- [Port Scanner](port-scanner.md)
- [Subnet Calculator](subnet-calculator.md)
