# SNMP Walk

> Walk an OID subtree on one SNMP agent over v1, v2c or v3 and list every value it returns.

**Sidebar group:** Discovery and SNMP · **Works offline:** no (queries the agent you name, only when you click Walk) · **Needs admin rights:** no

## When to use it

- Confirm that an SNMP agent answers and that your community or v3 user is set up correctly before adding the device to a monitoring system.
- Read a table (interfaces, ARP, a vendor enterprise subtree) without installing net-snmp.
- Test a vendor MIB: load the MIB file and check that the agent's OIDs translate to names.
- Debug SNMPv3 auth and privacy mismatches with a clear error message.

## Quick start

1. Enter the agent in **Host or IP**, for example `192.0.2.10`.
2. Leave **Port** at 161 unless the agent listens elsewhere.
3. Pick the **Version**. For v1 or v2c, enter the **Community**. For v3, fill in **Username**, **Auth**, **Auth password**, **Privacy** and **Privacy password**.
4. Set **Start OID**. The default `1.3.6.1.2.1` (mib-2) walks the standard MIBs. Use a name such as `system` or `ifTable` for a smaller walk.
5. Optional: click **Load MIB** to add names from a vendor MIB file.
6. Click **Walk**. Rows stream into the table as they arrive. Click **Cancel** to stop early.
7. When the walk finishes, use **Export** to save or add the result to a project.

## Inputs and options

| Field | What it means | Default / accepted values |
|---|---|---|
| Host or IP | The SNMP agent to query. A hostname is resolved by the OS. | Required |
| Port | UDP port of the agent. | 161; 1 to 65535 |
| Version | SNMP version. v1 uses GETNEXT; v2c and v3 use GETBULK (20 repetitions per request). | v1, v2c, v3; default v2c |
| Community | Community string for v1 and v2c. Hidden when v3 is selected. | `public` (selected on focus so you can type over it) |
| Username | SNMPv3 user name (v3 only). | Empty |
| Auth | SNMPv3 authentication protocol (v3 only). | none, md5, sha1, sha224, sha256, sha384, sha512; default sha1 |
| Auth password | SNMPv3 auth key. Disabled when Auth is none. | Empty |
| Privacy | SNMPv3 privacy cipher. Disabled when Auth is none. | none, des, aes128, aes192, aes256; default aes128 |
| Privacy password | SNMPv3 privacy key. Disabled when Privacy or Auth is none. | Empty |
| Start OID (name or dotted) | Root of the subtree to walk. Accepts dotted numbers (`1.3.6.1.2.1.2`), a known name (`interfaces`), or a name plus suffix (`sysDescr.0`). | `1.3.6.1.2.1` |
| Load MIB | Opens a file picker for a MIB file (`.mib`, `.txt`, `.my` or any file) and adds its OID names to the name registry. | None |

The v3 security level follows what you fill in: if Auth is none or the auth password is empty, the request is noAuthNoPriv. If Privacy is none or the privacy password is empty, it is authNoPriv. Otherwise it is authPriv.

The per-request timeout is fixed at 3 seconds, with no retries.

## Reading the results

The header line shows how many MIB names are currently loaded. The built-in set covers the common MIB-II names (system, interfaces, ifTable columns, ip, tcp, udp, snmp, host and the top-level tree).

The results table has four columns:

- **OID**: the full dotted OID returned by the agent.
- **Name**: the OID translated with the longest known name prefix, plus the remaining index (for example `sysDescr.0`, `ifDescr.3`). If no name matches, the dotted form is shown.
- **Type**: the SNMP value type, such as `OctetString`, `Integer`, `Counter32`, `Timeticks`, `ObjectIdentifier`.
- **Value**: the value. Octet strings that contain only printable ASCII (plus tab, CR, LF) are shown as text. Anything else is shown as space-separated hex bytes, which is how MAC addresses and binary fields appear.

After the walk, a status line reads `Done: N values.` or `Cancelled: N values.` Below the table, the row count is shown.

Worked example. Walking `system` on `192.0.2.10` with v2c might return:

| OID | Name | Type | Value |
|---|---|---|---|
| 1.3.6.1.2.1.1.1.0 | sysDescr.0 | OctetString | Example switch OS 1.2 |
| 1.3.6.1.2.1.1.3.0 | sysUpTime.0 | Timeticks | 8640000 |
| 1.3.6.1.2.1.1.5.0 | sysName.0 | OctetString | sw1.example.com |
| 1.3.6.1.2.1.2.2.1.6.1 | ifPhysAddress.1 | OctetString | 00 00 5e 00 53 01 |

## What the results do and do not tell you

- The walk stops when the agent returns an OID outside the start subtree, stops advancing, or returns nothing more. It does not query anything outside the subtree you chose.
- The backend stops after 100,000 values. The table shows at most 50,000 rows and marks the count "(display capped)" when it reaches that.
- Names come from the built-in list and any MIB files you loaded. The MIB loader extracts `name ... ::= { parent n }` assignments only. It does not parse types, ranges or textual conventions, so values are never decoded into enumerations (an `ifOperStatus` of 1 stays `1`).
- Loaded MIB names are held in memory for the current session and are shared with [SNMP Sweep](snmp-sweep.md). They are not saved; load the file again after restarting the app.
- What you see is what the agent's view allows for that community or user. Missing subtrees can mean a restricted view, not missing data.

## Online activity and privacy

When you click **Walk**, the app sends SNMP requests over UDP to the host and port you entered, and nothing else. For v3 it first sends an unauthenticated engine discovery request, as SNMPv3 requires. Nothing is sent at any other time.

Communities and v3 passwords are kept in the panel only for the current session. They are not saved to disk and are not written to exported reports. Note that v1 and v2c send the community in clear text on the wire.

## Export and projects

When the walk has rows and is no longer running, the **Export** menu offers HTML, PDF, Markdown and plain text, a **Redacted...** option, and **Add to project**. See [Export and redaction](../export-and-redaction.md) and [Projects and notes](../projects-and-notes.md).

The report contains the agent (`host:port`), version, start OID, the result line and the full table of OID, name, type and value. It states that community strings and SNMPv3 credentials are not included.

## Platform notes

The walk uses normal UDP sockets and behaves the same on macOS, Windows and Linux. No elevated privileges are needed. A host firewall must allow the outbound request and the reply.

## Troubleshooting

**Error "Enter a target host or IP."** The host field is empty. Enter an address or name.

**Error "invalid start OID '...'".** The start OID is not dotted numbers or a known name. Use dotted form, or load the MIB that defines the name.

**Error "no response from the agent within the timeout".** The agent did not answer within 3 seconds. Check the address, port, ACLs on the device, and firewalls in between. For v3, check that the username, auth protocol and password, and privacy protocol and password match the device exactly (AES256 vs AES128, or SHA256 vs SHA1, are common mismatches).

**Error "v3 engine discovery failed: ...".** The agent did not answer the SNMPv3 discovery request. Same checks as above, plus confirm SNMPv3 is enabled on the device.

**Error "authentication failed: the agent rejected the auth credentials."** Wrong v3 user, auth protocol or auth password.

**Error "privacy/crypto error: ...".** The privacy settings do not match the device.

**Error "SNMPv3 auth parameters kept changing".** The agent's boot or time counters changed repeatedly during the walk (for example during a reboot). Try again once the device is stable.

**Error "community string mismatch."** The reply carried a different community. Check the community.

**Error "connect failed: ...".** The local socket could not be set up, often because the host name did not resolve.

**Error "could not read <path>: ...".** The MIB file could not be read as text. Check the file and its permissions.

**The walk returns nothing.** The start OID may be outside the agent's view, or the subtree is empty. Try `system` first to confirm access.

## Related tools

- [SNMP Sweep](snmp-sweep.md)
- [Switch Port Mapper](port-mapper.md)
- [MAC Vendor Lookup](mac-vendor.md)
- [Port Scanner](port-scanner.md)
