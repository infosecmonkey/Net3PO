# Subnet Calculator

> Calculate and split IPv4 and IPv6 networks, aggregate an address list into the fewest exact prefixes, find overlaps, and compare two address lists.

**Sidebar group:** Utilities · **Works offline:** yes · **Needs admin rights:** no

## When to use it

- Check the netmask, wildcard, broadcast and host range of a prefix before writing an interface, ACL or route.
- Carve a block into equal subnets, for example a /24 into /26s for a site plan.
- Collapse a messy list of addresses, ranges and prefixes from a firewall object group into a clean prefix list, and spot duplicates or nested entries.
- Compare two lists (old and new object group, or two devices' allow lists) to see what is only in one, only in the other, and in both.

## Quick start

1. Open **Subnet Calculator** and stay on the **Calculate and split** tab.
2. Type a network such as `192.0.2.0/24` and press Enter or click **Calculate**.
3. Read the breakdown grid (network, netmask, broadcast, host range and so on).
4. To split it, set **Split into /** to the new prefix length, for example `26`, and click **Split**.
5. For a list of addresses, switch to **Aggregate and overlap**, paste the list and click **Aggregate**.
6. To compare two lists, switch to **Compare sets**, paste one list into **Set A** and the other into **Set B**, and click **Compare**.
7. Use **Export** to save the result or add it to a project.

## Inputs and options

### Calculate and split

| Field | What it means | Default / accepted values |
|---|---|---|
| Address box | The network or address to analyze. | Empty. Accepts `192.0.2.0/24`, `192.0.2.0/255.255.255.0` (IPv4 dotted netmask, must be contiguous), `2001:db8::/48`, or a bare address (treated as /32 or /128). Spaces around the `/` are ignored. Host bits are allowed; the network is computed from them. |
| Calculate | Runs the breakdown. Enter in the address box does the same. | |
| Split into / | Prefix length for the split. Must be longer (a larger number) than the current prefix. | 28. 1 to 32 for IPv4, 1 to 128 for IPv6. |
| Split | Lists the subnets of the new size inside the network in the address box. | |

IPv6 accepts only a prefix length, not a netmask.

### Aggregate and overlap

| Field | What it means | Default / accepted values |
|---|---|---|
| Addresses | The list to normalize and aggregate. | One entry per line, or separated by commas, semicolons, spaces or tabs. Each entry can be a prefix (`198.51.100.0/24`), a bare address, an IPv4 address with a dotted netmask (`198.51.100.0/255.255.255.0`), or a range (`192.0.2.10 - 192.0.2.20`, spaces around the dash optional). Anything after `#` on a line is a comment. |
| Aggregate | Runs the aggregation and overlap check. | |

### Compare sets

| Field | What it means | Default / accepted values |
|---|---|---|
| Set A | First list. | Same formats as Aggregate. |
| Set B | Second list. | Same formats as Aggregate. |
| Compare | Computes only in A, only in B, and in both. | |

## Reading the results

### Calculate

For IPv4 the grid shows: **Address** (as typed), **Network** (CIDR), **Netmask** with its hex form, **Wildcard** (inverse mask, for ACLs), **Broadcast**, **Host range**, **Usable hosts**, **Total addresses**, **Class** (classful letter, for reference only), **Type**, and the address, netmask and network in binary.

**Type** is one of: Unspecified, Limited broadcast, Loopback, Link-local (APIPA), Private (RFC 1918), Shared / CGN (RFC 6598), Multicast, Reserved (RFC 1112), Documentation (RFC 5737) or Public. It is based on the address you typed, not on the network address.

A /31 is treated as a point-to-point link (RFC 3021): both addresses are usable, 2 hosts. A /32 is a single host.

Example: `198.51.100.77/27` gives Network `198.51.100.64/27`, Netmask `255.255.255.224 (0xffffffe0)`, Wildcard `0.0.0.31`, Broadcast `198.51.100.95`, Host range `198.51.100.65 - 198.51.100.94`, Usable hosts 30, Total addresses 32, Class C, Type Documentation (RFC 5737).

For IPv6 the grid shows: **Address** (compressed), **Expanded**, **Network**, **Network (expanded)**, **Host range** (first and last address, expanded), **Total addresses** (exact, up to 2^128) and **Type** (Unspecified, Loopback, Multicast, Link-local (fe80::/10), Unique local (fc00::/7), Global unicast or Reserved).

### Split

The heading shows the parent network, the new prefix and the total number of subnets. The table lists **Network**, **Broadcast**, **Host range** and **Hosts** (usable) for each subnet. For IPv6 there is no broadcast, so the Broadcast column shows the last address of the subnet and Hosts shows the total address count.

Example: `192.0.2.0/24` split into /26 gives 4 subnets:

| Network | Broadcast | Host range | Hosts |
|---|---|---|---|
| 192.0.2.0/26 | 192.0.2.63 | 192.0.2.1 - 192.0.2.62 | 62 |
| 192.0.2.64/26 | 192.0.2.127 | 192.0.2.65 - 192.0.2.126 | 62 |
| 192.0.2.128/26 | 192.0.2.191 | 192.0.2.129 - 192.0.2.190 | 62 |
| 192.0.2.192/26 | 192.0.2.255 | 192.0.2.193 - 192.0.2.254 | 62 |

At most 4,096 subnets are listed. When there are more, a note says "Showing the first N subnets", and the heading still shows the true total.

### Aggregate

A summary line reads "N entries in, M prefixes out". IPv4 and IPv6 are listed separately, each with its prefix count, the number of unique addresses covered, and a **Copy** button that copies the list one prefix per line.

The output covers exactly the addresses in the input, nothing more. Overlapping and adjacent entries are merged, then each merged range is cut into the largest aligned prefixes that fit inside it.

Example input:

```
192.0.2.0/25
192.0.2.128/26
192.0.2.192/27
192.0.2.10 - 192.0.2.20   # already inside the /25
```

Output: `192.0.2.0/25`, `192.0.2.128/26`, `192.0.2.192/27` (224 addresses). The tool does not return `192.0.2.0/24`, because that would add 192.0.2.224 to 192.0.2.255, which were never in the list. On its own, the range `192.0.2.10 - 192.0.2.20` becomes `192.0.2.10/31`, `192.0.2.12/30`, `192.0.2.16/30`, `192.0.2.20/32`.

Below the lists:

- **Overlaps in the input**: pairs of entries that share addresses, with their line numbers. The relation is "duplicate of" (same range), "contains" (the first fully covers the second) or "partly overlaps". In the example above: `line 1: 192.0.2.0/25 contains line 4: 192.0.2.10-192.0.2.20`.
- **Normalized**: entries with host bits set, for example `192.0.2.77/24` noted as "host bits set; treated as 192.0.2.0/24".
- **Input: N entries skipped**: entries that could not be parsed, with the line and reason (up to 200 shown on screen).

### Compare

A summary line says either "A and B cover exactly the same addresses." or "A and B differ." For each address family that has data, three lists follow: **Only in A**, **Only in B** and **In both**, each as exact prefixes with a count and a Copy button. Skipped entries are listed separately for Set A and Set B.

The comparison is by address coverage, not by text. `192.0.2.0/25` plus `192.0.2.128/25` in A and `192.0.2.0/24` in B are reported as identical.

## What the results do and do not tell you

- **Type** and **Class** are labels from fixed address ranges. They do not tell you how a block is routed or used on your network.
- Splits list at most 4,096 subnets. Very large IPv6 totals are shown rounded in the heading.
- Aggregate and compare read at most 20,000 entries per list and at most 2 MB of text. Each output list stops at 50,000 prefixes ("List truncated at 50,000 prefixes."), and at most 1,000 overlaps are reported.
- IPv4 and IPv6 are never merged with each other. A range that mixes them is rejected.
- Overlap findings are within one list only. Compare does not list overlaps.

## Online activity and privacy

None. All calculation runs locally. Nothing is saved unless you export or add a result to a project. See [Privacy](../privacy.md).

## Export and projects

Each tab has its own **Export** button once there is a result. Formats: HTML, PDF, Markdown, Plain text, and **Redacted...** (see [Export and redaction](../export-and-redaction.md)). **Add to project** lists recent projects and **New project...**.

- Calculate and split: the breakdown grid and, if you split, the subnet table (only the listed subnets, with a note if the list was cut).
- Aggregate: the IPv4 and IPv6 prefix lists, overlaps, and input problems (skipped and normalized entries).
- Compare: only in A, only in B and in both per family, plus input problems.

See [Projects and notes](../projects-and-notes.md).

## Platform notes

Same on macOS, Windows and Linux.

## Troubleshooting

**"enter an address, for example 10.1.1.0/24 or 2001:db8::/48".** The address box is empty.

**"could not parse '...' as an IPv4 or IPv6 address".** The part before `/` is not a valid address. Check for typos or a trailing character.

**"'...' is not a valid IPv4 netmask (bits must be contiguous)".** A dotted mask like `255.0.255.0` was used. Use a contiguous mask or a prefix length.

**"prefix /33 is out of range for IPv4 (0 to 32)".** The prefix length is too large for the address family (128 is the IPv6 limit).

**"new prefix /24 must be larger than the current prefix /24".** The split size must be a smaller subnet than the network. Raise the **Split into /** value.

**An entry is skipped with "netmask is not contiguous", "range start is after its end" or "range mixes IPv4 and IPv6".** Fix that line. The rest of the list is still processed.

**"Only the first 20,000 entries were read."** Split the list into smaller batches.

## Related tools

- [MTU Calculator](mtu-calculator.md)
- [Filter Builder](filter-builder.md)
- [Config Diff](config-diff.md)
- [Port Scanner](port-scanner.md)
- [SNMP Sweep](snmp-sweep.md)
