# IOC Extractor

> Pull IPs, domains, URLs, email addresses and hash candidates out of pasted text, including defanged input, and defang or refang text in place.

**Sidebar group:** Analysis · **Works offline:** yes (nothing is resolved, fetched or opened) · **Needs admin rights:** no

## When to use it

- You have an alert, a threat report or a block of logs and need a clean, deduplicated list of indicators to block or search for.
- A vendor report has defanged indicators (`hxxps://`, `[.]`, `[at]`) and you need them back in normal form for a firewall or SIEM query.
- You are writing a ticket or email and want every indicator in the text defanged so nothing is clickable.
- You want to see quickly which addresses in a log are private or documentation ranges and which are public.

## Quick start

1. Open **IOC Extractor** from the Analysis group.
2. Paste the text into the box: logs, an alert, a threat report or an email.
3. Click **Extract**.
4. Review the groups (URLs, Domains, IPv4 addresses and so on). Tick **Hide private and documentation addresses** to focus on public ones.
5. Untick **Show defanged** if you need the live form for a block list.
6. Click **Copy** on a group, or **Copy all as CSV**.
7. Use **Export** for a defanged report or to add the list to a project.

To rewrite the text itself, click **Defang text** or **Refang text** instead of Extract.

## Inputs and options

| Field | What it means | Default / accepted values |
|---|---|---|
| Text box | The text to scan. | Up to 5 MB. |
| Extract | Finds and groups indicators. | |
| Defang text | Rewrites the text in the box with indicators defanged. | |
| Refang text | Rewrites the text in the box with indicators back in normal form. Nothing is opened. | |
| Show defanged | Shows (and copies) indicators in defanged form. | On. |
| Hide private and documentation addresses | Hides indicators flagged private, loopback, link-local, documentation, carrier-grade NAT, unique local or not a host address. | Off. |
| Copy (per group) | Copies that group's values, one per line, in the form currently shown. | |
| Copy all as CSV | Copies every shown indicator as CSV with columns `type,value,count,line,column,notes`. | Uses the defanged or normal form as shown. |

Defanged forms recognized on input include `hxxp://`, `hxxps://`, `hxxp[:]//`, `fxp://`, `[://]`, `[:]//`, `[.]`, `(.)`, `{.}`, `[dot]`, `(dot)`, `{dot}`, `[:]`, `[@]`, `[at]`, `(at)`, `{at}` and `\.`.

## Reading the results

A bar shows the number of distinct indicators (with "stopped at 50,000" if the limit was hit), the two checkboxes, and the copy and export buttons.

Indicators are grouped in this order: **URLs**, **Domains**, **IPv4 addresses**, **IPv6 addresses**, **Email addresses**, **SHA-256 candidates**, **SHA-1 candidates**, **MD5 candidates**, **SHA-512 candidates**. Each group shows its count and a **Copy** button. Each row shows:

- The value (defanged or normal).
- `×N` when it appeared more than once.
- `line N`, the line where it first appeared. Hover to see how it was written there.
- Flags, for example:
  - "was defanged in the input"
  - "host of a URL" (the host of each URL is also listed as a domain or IP)
  - "private (RFC 1918)", "loopback", "link-local", "carrier-grade NAT (RFC 6598)", "documentation range", "unique local (private)", "not a host address"
  - "uncommon top-level label; may not be a domain"
  - "weak candidate: all digits or all letters" for hash candidates

Defanging rewrites dots in hosts as `[.]`, the scheme as `hxxp`/`hxxps`, `@` as `[@]` and IPv6 colons as `[:]`. URL paths keep their dots.

Example input:

```
Beacon to hxxps://cdn[.]example[.]net/a/b.php?id=1 from 192.0.2.15
Reply to billing[at]example.org, then 198.51.100[.]7
```

Gives URL `hxxps://cdn[.]example[.]net/a/b.php?id=1` (was defanged in the input), domain `cdn[.]example[.]net` (was defanged in the input, host of a URL), IPv4 `192[.]0[.]2[.]15` (documentation range), IPv4 `198[.]51[.]100[.]7` (was defanged in the input, documentation range) and email `billing[@]example[.]org` (was defanged in the input).

## What the results do and do not tell you

- Extraction is by pattern. "Nothing here was resolved, fetched or checked against reputation sources."
- "Hash entries are candidates by length (32, 40, 64 or 128 hex digits), not confirmed hashes." A 32-digit hex string could be a GUID without dashes or any other token.
- Domain detection uses a list of common generic labels and treats other two-letter labels as country codes, except common file extensions (`.py`, `.js`, `.sh` and others). File names such as `report.pdf` or `setup.exe` are not reported as domains. Longer unknown labels are kept with the "uncommon top-level label" flag.
- Values are normalized (refanged, lowercased where case does not matter) and deduplicated by type and value.
- Limits: 5 MB input, 50,000 distinct indicators.

## Online activity and privacy

Nothing goes online. Indicators are never resolved, fetched or opened, including after **Refang text**. The text is not saved unless you export or add to a project.

## Export and projects

The **Export** menu offers HTML, PDF, Markdown, Plain text, **Redacted...** and **Add to project**. See [Export and redaction](../export-and-redaction.md) and [Projects and notes](../projects-and-notes.md).

The report is titled "Indicators of compromise". It has one table per group with the defanged indicator, how many times it was seen, where it first appeared (line and column) and its flags, plus a note on how the list was made. Indicators in the report are always defanged, whatever **Show defanged** is set to. Hidden indicators (when **Hide private and documentation addresses** is ticked) are left out. The original text is not included.

## Platform notes

No differences between macOS, Windows and Linux.

## Troubleshooting

**"input larger than 5 MB".** Split the text and extract in parts.

**"No indicators found."** The text has no matching patterns, or everything is hidden by **Hide private and documentation addresses**.

**A file name shows up as a domain.** Its extension is not in the built-in file extension list. Ignore it or check the flags.

**A known indicator is missing.** Check how it was defanged. Forms not in the list above (for example `[dot ]` with a space) are not refanged.

## Related tools

- [Email Header Analyzer](email-analyzer.md), which lists a message's indicators with the same defanging.
- [Script Decoder](script-decoder.md) to decode obfuscated scripts and pull their indicators.
- [Encoder Workbench](encoder-workbench.md) to decode Base64 or URL-encoded text before extracting.
- [Grep Builder](grep-builder.md) to search logs for the indicators you found.
