# DNS Analyzer

> Audit a domain's mail and DNS posture in one pass: SPF, DMARC, DKIM, MX, DNSSEC and nameserver health.

**Sidebar group:** Analysis · **Works offline:** no (every check is a live DNS query, sent only when you click Analyze) · **Needs admin rights:** no

## When to use it

- A customer's mail is landing in spam or being rejected and you want to see SPF, DMARC and DKIM side by side.
- You are reviewing a domain before or after a mail migration and need to confirm MX, SPF lookup count and DKIM keys.
- You suspect a zone is out of sync between nameservers, or a DNSSEC chain is broken.
- The [Email Header Analyzer](email-analyzer.md) found a DKIM selector and you want to check its key.

## Quick start

1. Open **DNS Analyzer** from the Analysis group.
2. Type the domain in **Domain**, for example `example.com`.
3. Leave **Server (optional)** empty to use the system resolver, or enter a resolver IP such as `192.0.2.53`.
4. If you know the sender's DKIM selector, add it to **DKIM selectors (optional)**.
5. Click **Analyze** (or press Enter in any field).
6. Read the six sections from top to bottom. Expand **Records** under a section to see the raw data.
7. Use **Export** to save a report or add it to a project.

## Inputs and options

| Field | What it means | Default / accepted values |
|---|---|---|
| Domain | The domain to audit. A trailing dot is removed. | Required. Must be a valid DNS name. |
| Server (optional) | Resolver to send every query to. | Empty means the system resolver. Otherwise an IP address, optionally with `:port` (for example `192.0.2.53` or `[2001:db8::53]:5353`). Port 53 if none is given. |
| DKIM selectors (optional) | Extra selectors to probe at `<selector>._domainkey.<domain>`. | Separate with spaces or commas. Your selectors are tried first, then a built-in list of about 40 common ones (`google`, `selector1`, `selector2`, `default`, `k1`, `fm1`, `protonmail`, `zoho`, `mandrill` and others). |
| Analyze | Runs all checks. | The button shows "Analyzing..." while it runs. |

With a custom server, each query uses UDP and TCP with a 5 second timeout and 2 attempts.

## Reading the results

A line at the top shows **Resolved via** followed by the resolver used ("system resolver" or the address you entered), with the **Export** menu beside it.

Below are six sections, always in this order: **SPF**, **DMARC**, **DKIM**, **MX**, **DNSSEC**, **NS**. Each has a status badge and a list of findings, each with a colored dot.

| Badge / dot | Meaning |
|---|---|
| PASS (green) | The check met the expected state. |
| INFO (blue) | A fact worth knowing, not a problem. |
| WARN (amber) | A weakness or partial configuration. |
| FAIL (red) | A misconfiguration or missing control. |

The section badge is FAIL if any finding failed, otherwise WARN if any finding warned, otherwise PASS. Info findings do not lower the status, so a section that holds only Info findings (for example "Zone is not signed with DNSSEC.") shows a PASS badge. Read the findings, not just the badge.

**SPF.** Counts SPF records at the apex (exactly one is allowed), reports the final `all` qualifier (`-all` pass, `~all` info, `?all` warn, `+all` fail, missing warn), then walks `include:` and `redirect=` targets to count DNS lookups against the limit of 10. It also flags void lookups (targets with no SPF record; more than 2 is a fail), use of the deprecated `ptr` mechanism, and very long records. The walk stops after 25 lookups and reports "SPF requires more than N DNS lookups".

**DMARC.** Reads `_dmarc.<domain>`. Reports the policy (`p=reject` pass, `p=quarantine` and `p=none` warn, missing or unknown fail), whether aggregate reporting (`rua`) is configured, and `pct` below 100.

**DKIM.** Probes every selector in parallel. For each hit it reports the key type and size: RSA under 1024 bits fails, under 2048 warns, Ed25519 passes with a note to pair it with an RSA selector. Empty `p=` is reported as a revoked key, and `t=y` as testing mode. Before probing, the tool queries a random selector name to detect a wildcard `*._domainkey` record. If one exists, built-in selectors are skipped and only the ones you supplied are checked, where they differ from the wildcard.

**MX.** Lists up to 16 MX records sorted by preference, with the addresses each exchanger resolves to. It flags exchangers that are IP addresses or do not resolve, a Null MX (`0 .`, RFC 7505) and a Null MX mixed with real records. With no MX at all it checks whether the apex has an address that senders would fall back to.

**DNSSEC.** Checks for a DS record at the parent and a DNSKEY in the zone. Both present passes; DS without DNSKEY fails (broken chain); DNSKEY without DS warns.

**NS.** Lists up to 8 nameservers with their addresses. For each one it sends an SOA query directly to its first address on port 53 (3 second timeout) and compares serials. It reports fewer than 2 nameservers, servers that did not answer, serial disagreement, nameservers that do not resolve, whether any nameserver has IPv6, and when all nameservers share one parent domain.

Example, for `example.com` resolved via `192.0.2.53`:

```
SPF     WARN  One SPF record present.
              Ends with ~all (softfail).
              SPF uses 9 of 10 allowed DNS lookups; close to the limit.
DMARC   WARN  Policy p=none (monitor only); does not block spoofed mail.
              Aggregate reporting (rua) is configured.
DKIM    PASS  Selector 'selector1' has a 2048-bit RSA key.
MX      PASS  2 MX records.
NS      PASS  2 nameservers listed.
              All answering nameservers agree on SOA serial 2026111401.
```

The NS records list would show entries such as `ns1.example.net (198.51.100.10, 2001:db8::10)`.

## What the results do and do not tell you

- DKIM selectors are chosen by the sender, so a missing DKIM result only means none of the probed names answered. The tool says so: "Selectors are chosen by the sender; if you know yours, add it."
- The DNSSEC check looks for the presence of DS and DNSKEY records. It does not validate signatures.
- A wildcard `*._domainkey` record makes selector probing meaningless; the tool reports it instead of listing false hits.
- The "provider diversity" note compares only the last two labels of each nameserver name. It is a rough guide.
- SOA serials come from the first address of each nameserver only. If that address is unreachable, the server is listed under "No SOA answer from".
- Results reflect what your chosen resolver returns right now, including any caching.

## Online activity and privacy

Clicking **Analyze** sends DNS queries for the domain, its `_dmarc` and `_domainkey` names, SPF include targets, MX and NS hosts. They go to the system resolver or the server you entered. NS consistency also queries each listed nameserver directly. Nothing is sent until you click. No results are saved unless you export them or add them to a project.

## Export and projects

The **Export** menu offers HTML, PDF, Markdown and Plain text, a **Redacted...** option, and **Add to project**. See [Export and redaction](../export-and-redaction.md) and [Projects and notes](../projects-and-notes.md).

The report is titled "DNS audit: <domain>". It starts with a Summary (domain, resolver, counts of fail, warn, pass and info sections, and one line per section), then one section per check with all findings and the raw records.

## Platform notes

No differences between macOS, Windows and Linux. With the Server field empty, the tool reads the operating system's DNS configuration.

## Troubleshooting

**"Enter a domain to analyze."** The Domain field is empty.

**"'<domain>' is not a valid domain".** The name could not be parsed as a DNS name. Check for spaces or a URL (enter only the host name).

**"server '<value>' must be an IP address, optionally with :port".** The Server field takes an IP address, not a host name.

**"could not read system DNS config".** The system resolver configuration could not be loaded. Enter a resolver IP in Server.

**"MX lookup failed".** The MX query errored (timeout or server failure), not just returned no records. Try another resolver.

**Every nameserver is listed under "No SOA answer from".** Outbound UDP port 53 to arbitrary servers is likely blocked by a firewall. The other sections still work through your resolver.

## Related tools

- [Dig](dig.md) for individual record queries.
- [Email Header Analyzer](email-analyzer.md), which can open this tool for a DKIM domain and selector.
- [TLS Inspector](tls-inspector.md) to check the certificates on the MX hosts.
