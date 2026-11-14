# Config Diff

> Compare two configs side by side, with whitespace, case and line-ignore options, config section breadcrumbs and a unified diff you can save.

**Sidebar group:** Analysis · **Works offline:** yes · **Needs admin rights:** no

## When to use it

- You have two FortiGate backups and need to know what really changed, without version headers and UUIDs getting in the way.
- You are reviewing a change window and want before and after running configs from a switch or router compared line by line.
- You need a `.diff` file or a report of a config change for a change record or a ticket.
- A config was edited by hand and you want to check that only the intended lines moved.

## Quick start

1. Open **Config Diff** from the Analysis group.
2. Paste the older config into **Left (before)** and the newer one into **Right (after)**, or click **Open file** above each box.
3. The diff runs as you type. Read the summary line for added, removed and changed counts.
4. For FortiOS backups, click **FortiOS volatile** to ignore lines that change on every backup.
5. Adjust **whitespace**, **context** or **ignore case** if formatting noise hides the real changes.
6. Switch between **Side by side** and **Unified**. Use **Copy unified** or **Save .diff** to take the diff elsewhere.
7. Use **Export** for a report or to add the diff to a project.

Click **Load example** to see two short sample FortiOS configs compared.

## Inputs and options

| Field | What it means | Default / accepted values |
|---|---|---|
| Left (before) / Right (after) | The two texts to compare. The file name, if opened from disk, shows in the header. | Up to 5,000,000 bytes each. Invalid UTF-8 in files (for example Latin-1 backups) is replaced, not rejected. |
| Open file | Loads a file into that side. | `.conf`, `.cfg`, `.txt`, `.log`, or any file. |
| Swap | Swaps the two sides and their names. | |
| Load example | Fills both sides with a sample FortiOS change. | |
| Clear | Empties both sides. | |
| whitespace | How whitespace differences count. | exact; ignore trailing (default); ignore amount (-b), which treats runs of whitespace as one; ignore all (-w). |
| context | Unchanged lines shown around each change. | 0, 3 (default) or 10 lines, or full file. |
| algorithm | Line diff algorithm. Changes how insertions and deletions are grouped, not what counts as different. | histogram (default), patience, myers. |
| ignore case | Compare lines without regard to case. | Off. |
| ignore blank lines | Leave empty lines out of the comparison. | Off. |
| Ignore lines matching (regex) | Lines matching this regular expression are left out of the comparison on both sides. | Empty. |
| FortiOS volatile | Fills the pattern with `^#(config-version|conf_file_ver|buildno|global_vdom)|set uuid |\sENC\s`. | Skips version headers, UUIDs and ENC secrets. |

"Ignore options change what is compared, not what is shown." Rows always show the original text and the original line numbers.

## Reading the results

**Summary line.** "No differences", or `+N added`, `-N removed` and `~N changed`, followed by the line counts of each side and, when lines were ignored, how many on each side. The view switch, **Copy unified**, **Save .diff** and **Export** sit on the same line.

**Side by side.** Each change group (hunk) starts with a header such as `@@ -10,7 +10,8 @@` and, when the tool can find one, a breadcrumb of the enclosing config sections, for example `config firewall policy > edit 12`. Breadcrumbs work for FortiOS (`config` / `edit` blocks), Cisco and Arista style (`interface ...` followed by indented lines) and similar indented configs. Rows show left line number and text, right line number and text:

- Red rows on the left are removed lines; green rows on the right are added lines.
- A changed line appears on both sides, with the exact words that differ highlighted more strongly.
- Empty cells mark lines that exist on one side only.

Large diffs show the first 5,000 rows; a note says so. Save the unified diff for the rest, or reduce context.

**Unified.** The standard unified diff text, with `---`/`+++` file lines, `@@` hunk headers, and `+`/`-` lines colored.

Example: comparing two backups of a firewall at `192.0.2.1` with **FortiOS volatile** on, the only hunk is under `config firewall policy > edit 12`:

```
-        set service "HTTPS" "DNS"
+        set service "HTTPS" "DNS" "NTP"
+        set logtraffic all
```

The summary reads `+1 added  -0 removed  ~1 changed`, and the `set uuid` line that also differed is left out of the comparison (it adds to the ignored count) instead of showing as changed.

## What the results do and do not tell you

- The diff is textual. It does not understand configuration semantics, so a reordered block shows as removed and added lines even if the device would treat it the same.
- Ignored lines are hidden from the comparison only. If a meaningful line matches your ignore pattern, its change will not be reported.
- The FortiOS volatile pattern also ignores lines containing `ENC` secrets, so changed passwords or keys stored encrypted will not appear as differences.
- The line diff has a 2 second time budget. Past it the result is still a valid diff but may be less minimal than possible.
- The section breadcrumb looks back at most 5,000 lines and is based on indentation.

## Online activity and privacy

Nothing goes online. Files are read only when you open them, and the diff is written to disk only when you click **Save .diff**. Configs are not stored anywhere else unless you export or add to a project.

## Export and projects

**Copy unified** copies the unified diff text. **Save .diff** writes it to a file you choose (`.diff`, `.patch` or `.txt`).

The **Export** menu offers HTML, PDF, Markdown, Plain text, **Redacted...** and **Add to project**. See [Export and redaction](../export-and-redaction.md) and [Projects and notes](../projects-and-notes.md).

The report contains a summary (both names with line counts, the result, the whitespace mode, what was ignored, how many lines were ignored on each side, and the context setting) and the diff lines grouped by hunk. It does not include the full configs. Configs often contain addresses, names and secrets, so consider **Redacted...** before sharing.

## Platform notes

No differences between macOS, Windows and Linux.

## Troubleshooting

**"left input is too large (... bytes, limit 5000000)" or "<file> is too large".** Each side is limited to 5 MB. Diff a relevant section instead.

**"ignore pattern: ...".** The regular expression is invalid. Test it in the [Regex Builder](regex-builder.md).

**Every line shows as changed.** Indentation or spacing differs between the two files. Set whitespace to ignore amount (-b) or ignore all (-w).

**The breadcrumb is missing.** The change is at the top level or the config is not indented.

## Related tools

- [Regex Builder](regex-builder.md) to build and test an ignore pattern.
- [Fortinet Command Builder](forti-builder.md) to prepare the commands for a change you found.
- [SSH](ssh.md) to pull running configs from devices.
- [TFTP Server](tftp-server.md) to receive config backups from devices.
