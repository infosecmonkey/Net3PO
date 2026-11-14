# MAC Vendor Lookup

> Resolve a MAC address to its registered vendor from a bundled copy of the IEEE OUI registry, and show whether it is locally administered or multicast.

**Sidebar group:** Utilities · **Works offline:** yes · **Needs admin rights:** no

## When to use it

- Identify an unknown device from a switch MAC table, ARP cache or DHCP lease (printer, phone, camera, hypervisor NIC).
- Check whether an address on a port is randomized (a phone's private Wi-Fi address) or a real hardware address.
- Tell whether a destination MAC in a capture is unicast or a multicast or group address.
- Confirm the vendor behind an address before blocking it or opening a ticket with the device owner.

## Quick start

1. Open **MAC Vendor Lookup**.
2. Check the dataset line at the top. It should show the number of assignments loaded.
3. Paste a MAC address in any common format, such as `00-00-0c-12-34-56`, `0000.0c12.3456` or `00:00:0C:12:34:56`.
4. Read the vendor name in large text. The lookup runs as you type.
5. Check **Administration** and **Cast** below it.
6. Use **Export** to save the result or add it to a project.

## Inputs and options

| Field | What it means | Default / accepted values |
|---|---|---|
| MAC address | The address to look up. | Empty. Hex digits with any mix of `:`, `-`, `.` or space as separators, any case. 3 to 8 whole octets (6 to 16 hex digits). A 3-octet OUI on its own, such as `00:00:0C`, is enough. |

There are no other options.

## Reading the results

**Dataset line** (above the input):

- Normal: "N assignments loaded (MA-L x, MA-M y, MA-S z)". ", from file" is added when the build used a local copy of the registry.
- Warning: "Seed dataset (N entries). Build with network, or set OUI_DATA_FILE, to load the full IEEE registry." This build has only a small sample set, so most lookups will find no vendor.

**Vendor**: the registered organization name, or "No matching vendor in the dataset".

**Table**:

| Row | Meaning |
|---|---|
| MAC | The octets you entered, uppercase, colon-separated |
| OUI | The first three octets |
| Assignment | The matched registry prefix in hex and its block (only when a vendor was found) |
| Administration | "Universally administered (OUI)" or "Locally administered" (the second-lowest bit of the first octet is set) |
| Cast | "Unicast" or "Multicast / group" (the lowest bit of the first octet is set) |

Lookup is longest prefix first. The IEEE registry has three block sizes: MA-L (24 bits, the classic OUI), MA-M (28 bits) and MA-S (36 bits). Small vendors often get an MA-M or MA-S block carved out of an MA-L that is registered to "IEEE Registration Authority". With at least 5 octets entered, the tool checks MA-S, then MA-M, then MA-L, so you get the small vendor rather than the registration authority. With only 3 octets, only MA-L can match.

### Worked example

Input `0000.0c12.3456`:

- Vendor: Cisco Systems, Inc
- MAC: `00:00:0C:12:34:56`
- OUI: `00:00:0C`
- Assignment: `00000C (MA-L)`
- Administration: Universally administered (OUI)
- Cast: Unicast

Input `3A:5F:21:00:02:0A` (a typical randomized address): the first octet `3A` has the locally administered bit set. Usually no vendor is found, and a note explains: "The locally administered bit is set, so this address was assigned locally and has no IEEE vendor."

## What the results do and do not tell you

- The vendor is who registered the prefix with the IEEE, not necessarily who built the device. NICs, Wi-Fi modules and virtual machines often carry the chip or hypervisor vendor's prefix.
- MAC addresses are trivial to change. A vendor match is a hint, not proof of what a device is.
- Locally administered addresses (randomized phone addresses, many virtual and container interfaces) are looked up anyway, but any match does not describe the device.
- The registry is captured when the app is built. Assignments made after that build are not known until a newer release.
- Input must be whole octets: 3 to 8 octets.

## Online activity and privacy

None. The IEEE registry is fetched when the app is built and embedded in the app; lookups never go online. Nothing you type is saved unless you export. See [Privacy](../privacy.md).

## Export and projects

**Export** appears once there is a result. Formats: HTML, PDF, Markdown, Plain text and **Redacted...** (see [Export and redaction](../export-and-redaction.md)), plus **Add to project**. The report contains the MAC, vendor (or "(not in the registry)"), registry block and prefix, whether it is locally administered (with a short explanation), multicast yes or no, and the dataset source and size. See [Projects and notes](../projects-and-notes.md).

## Platform notes

Same on macOS, Windows and Linux.

## Troubleshooting

**"'x' is not a hex digit".** The input has a character other than hex digits and the separators `:`, `-`, `.` and space. Remove labels such as `MAC=`.

**"MAC must be whole octets (an even number of hex digits)".** A digit is missing or extra. Cisco dotted form needs four digits per group (`0000.0c12.3456`); leading zeros cannot be dropped.

**"need at least 3 octets (24 bits) to look up a vendor".** Enter at least the first six hex digits.

**"too many octets (maximum 8)".** Paste one address at a time.

**Every lookup says "No matching vendor in the dataset".** Check the dataset line. If it says "Seed dataset", this build did not include the full registry. Use an official release, or rebuild with network access or with `OUI_DATA_FILE` pointing at a downloaded registry CSV.

## Related tools

- [Switch Port Mapper](port-mapper.md)
- [DHCP Monitor](dhcp-monitor.md)
- [SNMP Walk](snmp-walk.md)
- [Wake-on-LAN](wake-on-lan.md)
- [Connection Monitor](conn-monitor.md)
