# Regex Builder

> Paste sample data and build a regular expression live, with match highlighting, a capture group table, a replacement preview and a library of tested network recipes.

**Sidebar group:** Utilities · **Works offline:** yes · **Needs admin rights:** no

## When to use it

- Write a pattern to pull source and destination addresses out of firewall logs before you put it in a SIEM parser, script or `grep`.
- Check that a pattern for an IP, MAC, interface name or syslog timestamp matches what you expect and nothing more.
- Try a search-and-replace on a config before running it in an editor or `sed`.
- Find out whether a pattern needs PCRE features (lookaround, backreferences) or works with plain `grep -E`.

## Quick start

1. Open **Regex Builder**.
2. Paste sample lines into **Sample text**, or pick one from **Load sample...**.
3. Pick a recipe from **Recipes** (filter by typing, for example `mac` or `syslog`), or type a pattern into **Pattern**.
4. Watch the highlights in the sample and the match count. Results update as you type.
5. Use the **Tokens** palette to insert pieces such as `\b`, `{n,m}` or `(?<name>...)` at the caret.
6. Turn on flags as needed, and check the **Capture groups** table.
7. Click **Open in Grep Builder** to turn the pattern into a `grep` command.

## Inputs and options

| Field | What it means | Default / accepted values |
|---|---|---|
| Engine | **Standard (grep -E, linear time)**: character classes, groups, alternation, anchors, Unicode. No backreferences or lookaround. Cannot ReDoS. **PCRE-style (grep -P)**: adds lookahead, lookbehind and backreferences. Backtracks, so it runs under a backtrack limit. | Standard |
| Pattern | The regular expression. | Empty |
| Clear | Empties the pattern. | |
| Open in Grep Builder | Opens [Grep Builder](grep-builder.md) with this pattern, in extended mode for Standard or Perl mode for PCRE-style. | |
| Recipes | Tested patterns grouped as IPv4, IPv6 and L2, Hosts and URLs, Logs and General (for example IPv4/CIDR, Wildcard mask, Private IPv4 (RFC 1918), MAC address, Interface name, Syslog timestamp (RFC 3164), FortiGate srcip / dstip, UUID). Click to replace the pattern; Shift-click to insert at the caret. Hover a recipe for help and an example. | Open |
| Filter | Narrows the recipe list by name, help text or group. | Empty |
| Tokens | Building blocks in groups: Anchors, Characters, Quantifiers, Groups, PCRE only, Escapes. Click to insert at the caret. Clicking a PCRE-only token (`\1`, `(?=...)`, `(?!...)`, `(?<=...)`, `(?<!...)`) switches the engine to PCRE-style. | Collapsed |
| ignore case (i) | Case-insensitive match. | Off |
| multiline (m) | `^` and `$` match at each line start and end, not only at the start and end of the text. | Off |
| dot matches newline (s) | `.` also matches line breaks. | Off |
| verbose (x) | Whitespace in the pattern is ignored and `#` starts a comment. | Off |
| Sample text | Text to match against. Up to 1,000,000 bytes. | Empty |
| Load sample... | Fills the sample with a built-in example: Network config, FortiGate traffic log, Cisco / Arista syslog, Server log. | |
| Replacement preview | Shows the sample with every match replaced. | Off |
| Replacement | Replacement string. `$1` refers to group 1, `${name}` to a named group. | Empty |

## Reading the results

1. **Status line**: "No matches" or "N matches". If there are more than 1,000 matches, it adds "(showing first 1,000)". The count is always the true total.
2. **Highlights**: every match is marked in the sample text.
3. **Capture groups** (only when the pattern has groups and matched): one row per match, with the full match and each group. Column headers are the group number, followed by the name for named groups. A `-` means the group did not take part in that match (for example the unused side of an alternation).
4. **Replacement preview**: the full sample after replacement.
5. **Error box**: replaces the status line when the pattern does not compile or a limit was hit.

### Worked example

Sample text:

```
date=2026-11-14 action="deny" srcip=192.0.2.10 dstip=198.51.100.20 dstport=443
date=2026-11-14 action="accept" srcip=192.0.2.11 dstip=203.0.113.5 dstport=53
```

Pattern:

```
srcip=(?<src>\d{1,3}(?:\.\d{1,3}){3}) dstip=(?<dst>\S+)
```

Status: "2 matches". The Capture groups table has columns **#**, **Match**, **1 src**, **2 dst**, with rows `192.0.2.10` / `198.51.100.20` and `192.0.2.11` / `203.0.113.5`. The `(?:...)` group is non-capturing, so it gets no column.

With **Replacement preview** on and replacement `${src} -> ${dst}`, the first line becomes `date=2026-11-14 action="deny" 192.0.2.10 -> 198.51.100.20 dstport=443`.

To keep only denied lines, a PCRE-style lookahead such as `^(?=.*action="deny").*$` with **multiline** on matches the first line only.

## What the results do and do not tell you

- The Standard engine follows Rust `regex` syntax (RE2 style). It matches `grep -E` behavior for most patterns but is not identical; for example it supports `\d`, `\w` and `(?<name>...)`, which plain POSIX `grep -E` does not. Check the generated command in [Grep Builder](grep-builder.md).
- The PCRE-style engine is `fancy-regex`, close to PCRE but not PCRE itself. Rare PCRE features may be missing or behave differently.
- PCRE-style matching stops after 1,000,000 backtracking steps and reports an error rather than hanging. The Standard engine always runs in linear time.
- Only the first 1,000 matches are detailed and highlighted.
- In a replacement, `$1a` is read as a group named `1a`. Write `${1}a` when a literal follows a group number.
- A recipe is a starting point. Recipes such as IPv4 address check octet ranges, but no regex can tell you whether an address is in use or reachable.

## Online activity and privacy

None. Matching runs locally. Pattern and sample text are not saved; they are lost when you close the app. See [Privacy](../privacy.md).

## Export and projects

This tool has no Export menu and no "Add to project". Copy the pattern from the Pattern field, or send it to [Grep Builder](grep-builder.md). You can still keep notes about this work in the project notes panel docked beside every tool; see [Projects and notes](../projects-and-notes.md).

## Platform notes

Same on macOS, Windows and Linux.

## Troubleshooting

**"invalid pattern: ..."** The pattern does not compile. The message from the engine points at the problem, for example an unclosed group. If it mentions look-around or backreferences, switch to PCRE-style.

**"backtrack limit exceeded (1000000 steps); simplify the pattern or reduce the input".** A PCRE-style pattern with nested quantifiers (such as `(a+)+`) backtracked too much. Make it more specific, or switch to Standard if you do not need lookaround.

**"sample text is too large (N bytes, limit 1000000)".** Paste a smaller sample.

**Matches are missing at the start of lines.** `^` and `$` only match at the very start and end of the text unless **multiline (m)** is on.

## Related tools

- [Grep Builder](grep-builder.md)
- [Packet Filter Builder](filter-builder.md)
- [IOC Extractor](ioc-extractor.md)
- [Syslog Server](syslog-server.md)
- [Event Log](event-log.md)
