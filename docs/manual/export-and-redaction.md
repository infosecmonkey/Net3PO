# Export and redaction

Most tools have an **Export** button. It saves the current result as a report, adds it to a
project, or both.

## Formats

| Format | Use it for |
|---|---|
| HTML | A self-contained page to open in any browser or attach to a ticket. |
| PDF | Formal handover and printing. |
| Markdown | Pasting into wikis, Git repos and tickets that render Markdown. |
| Plain text | Email bodies and terminals. |

Each report has a header (tool, target, time generated) and then the tool's content: summary
values, tables, findings with severity, code or raw output, and differences where relevant.
Your OS save dialog suggests a file name made from the tool, the target and a timestamp.

Reports never include passwords, SNMP communities, SNMPv3 keys or private keys entered in a
tool. Tool pages say exactly what each report contains.

## Add to project

**Export > Add to project** saves the result into a project instead of (or as well as) a file.
See [Projects and notes](projects-and-notes.md). Whole projects export from the Projects panel
in the same four formats, with every saved result and note.

## Redacted export

Use **Export > Redacted...** (or the same option in the Projects panel) before a report leaves
your organization, for example to a vendor TAC case or a public forum.

1. **Choose what to replace:** IP addresses, hostnames and domains, email addresses,
   usernames, and passwords, keys and tokens.
2. **Add rules** for names automatic detection cannot know, such as customer and site names.
   One per line:
   - `find` replaces the text with a numbered `[CUSTOM-n]` token
   - `find => replacement` uses your replacement
   - `re:regex => replacement` matches a regular expression
3. **Add exclusions** under **Keep (never replace)**: one per line, a domain (covers its
   subdomains), an IPv4 address or a CIDR range. Use it for public resolvers or vendor domains
   that should stay readable.
4. **Review the preview.** It lists every distinct value and its token, with a count of
   replacements. Secrets are masked in the list. You can filter the list.
5. **Save** in any of the four formats.

### How tokens work

- The same original value always gets the same token within one report, so `[IP-1]` in the
  summary is the same host as `[IP-1]` in a table. This keeps the report readable.
- Tokens are `[IP-n]`, `[HOST-n]`, `[USER-n]`, `[SECRET-n]` and `[CUSTOM-n]`. An email address
  becomes `[USER-n]@[HOST-n]`, and its domain keeps the same host token used elsewhere.
- Private key blocks are removed entirely.
- The mapping from tokens to original values is shown only in the dialog. It is never written
  into the exported file.
- Your categories, rules and exclusions are remembered on this computer for next time.

### Limits

Redaction finds values by pattern and by context (for example a `password=` field). It cannot
know every internal name. Always read the preview, and add rules for anything it missed.
