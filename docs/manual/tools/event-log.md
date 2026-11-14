# Windows Event Log

> Open a Windows event log (.evtx, XML export or CSV export) on any OS, filter it, and read each event with a plain explanation of what it means.

**Sidebar group:** Analysis · **Works offline:** yes (parsing is local) · **Needs admin rights:** no (it reads exported or copied log files, not the live Windows log)

## When to use it

- A customer sent you `Security.evtx` from a server and you need to find failed logons, account changes or log clears without a Windows machine.
- You are triaging a host and want Sysmon process, network and file events filtered by time, user or command line.
- Someone exported events from Event Viewer as XML or CSV, or with `wevtutil qe /f:xml` or `Export-Csv`, and you need to sort and search them.
- You want a quick count of the busiest event IDs over a period and a timeline of when they happened.

## Quick start

1. Open **Windows Event Log** from the Analysis group.
2. Click **Open log file...** and pick an `.evtx`, `.xml` or `.csv` file. A progress line counts events as they load; click **Stop** to keep what has loaded so far.
3. Check the summary line: format, event count and time span.
4. Type IDs into **Event IDs** (for example `4625`) or click a chip under **Event IDs** to filter to it.
5. Narrow further with **Text anywhere**, **Field**, **Level**, **Audit** or the time range. Click a bar in the timeline to zoom to that period.
6. Click a row to open the detail panel with the explanation, decoded fields and raw record.
7. Use **Export** to save the filtered view or add it to a project.

## Inputs and options

| Field | What it means | Default / accepted values |
|---|---|---|
| Open log file... | Loads one file. The format is detected from the content: EVTX signature, XML, or CSV. | `.evtx` up to 2 GB, XML or CSV up to 512 MB. Up to 500,000 events per file. |
| Stop | Cancels a load in progress and keeps the events read so far. | Shown while loading. |
| Event IDs | IDs and ranges to include, and `-` prefixed ones to exclude. | Comma or space separated, for example `4624, 4625, 4688-4690, -4634`. Empty means all. |
| Text anywhere | Case-insensitive search in provider, computer, message, field names and values, or an exact event ID. | Free text. |
| Field | Match on one named field. `Name` alone requires the field to exist; `Name=value` requires its value to contain the text (case-insensitive). | For example `TargetUserName=admin`. The field name is not case-sensitive. |
| Level | Event level. | Any, Critical, Error, Warning, Information (levels 0 and 4), Verbose. |
| Audit | Security audit outcome. | Any, Success, Failure. |
| From / To | Time range. Read as UTC, or as the file's local time when the export has no time zone (the label says which). | Date and time pickers. |
| Newest first | Reverses the sort order. | Off (oldest first). |
| Clear filter | Removes all filters. | |
| Channel, Provider and Computer chips | Toggle a value on or off. Several can be on at once. | Shown when the file has more than one value. Top 15 each. |
| Previous / Next | Page through matches. | 200 rows per page. |

Filters apply about 300 ms after you stop typing.

## Reading the results

**Summary line.** File name, format (EVTX, XML or CSV), number of events, and the time span in UTC (or "exporting computer's local time, zone unknown"). Warnings appear here when the 500,000 limit was reached, when loading was stopped, or when records could not be read. Click "N unreadable records skipped" to see up to 20 of the parse errors. CSV files add notes about time zones and date order (see below).

**Match line.** "N of M events match", plus a text summary of the active filter.

**Timeline.** About 60 bars covering the matching events. Hover a bar to see its period and count; click it to set From and To to that period.

**Facets.** **Event IDs** lists the 25 most frequent ID and provider pairs among the matches, with a short title when the tool knows the event (for example "4625 An account failed to log on"). Clicking one sets the ID filter and the provider. Channels, Providers and Computers chips show counts and toggle filters.

**Event table.** Time (UTC when known, otherwise as written with "(local, zone unknown)"), Level (or Audit Success / Audit Failure), ID, Event (title and provider), Computer, and Details: a one-line summary of the key fields. Failures, errors and critical events are highlighted red, warnings amber.

**Detail panel.** Opens when you click a row:

- Time as written and normalized, level, computer, record ID and user SID.
- An explanation for known events: a title, what the event means, which fields to look at (highlighted in the Fields table), and a caution. Explanations are keyed on both provider and ID. Covered events include Security 4624, 4625, 4634/4647, 4648, 4672, 4688, 4697, 4698 to 4702, 4719, 4720, 4722 to 4726, 4728/4732/4756, 4738, 4740, 4767, 4768, 4769, 4771, 4776, 4798/4799, 5140/5145 and 1102; EventLog 104, 6005, 6006 and 6008; Kernel-Power 41; Task Scheduler 106, 200 and 201; PowerShell 4103 and 4104; Terminal Services 21, 24, 25 and 1149; and Sysmon 1, 3, 5 to 8, 10 to 15, 17, 18, 22, 23, 25 and 26.
- Decoded values for coded fields: LogonType (for example 10 as "RemoteInteractive (Remote Desktop)") and Status, SubStatus and FailureReason codes.
- All event data fields, the rendered message when the file has one, and the raw record (collapsed).

Example: filter `4625` on a file from host `WS01` and the table shows rows such as `2026-11-13 14:05:10 UTC | Audit Failure | 4625 | An account failed to log on | WS01 | LogonType=3 TargetUserName=alice IpAddress=192.0.2.44`. The detail panel decodes the Status code into a reason.

## What the results do and do not tell you

- "Explanations are provider-specific. An event ID alone is not evidence of compromise; read the fields and the surrounding events." Routine events carry the note: "Routine on its own; context (who, from where, when, how often) decides whether it matters."
- CSV exports "use the exporting computer's local time without a time zone; times are shown as written and are not converted to UTC."
- In CSV, "Dates such as 03/04/2026 are read as month/day (US order). If this export used day/month, the order of events is wrong." Rows with unreadable times sort first.
- Limits: 500,000 events per file; field values cut at 4 KB and 200 fields per event; raw record text cut at 16 KB per record, and on very large logs kept only for the first records ("parsed fields are kept for all"). The three most recently opened files are kept in memory; older ones are dropped.
- The tool reads files. It does not query the live event log of the computer it runs on.

## Online activity and privacy

Nothing goes online. The file is read locally and kept in memory while the panel is open. Closing the panel releases it. Nothing is saved unless you export or add to a project.

## Export and projects

The **Export** menu offers HTML, PDF, Markdown, Plain text, **Redacted...** and **Add to project**. See [Export and redaction](../export-and-redaction.md) and [Projects and notes](../projects-and-notes.md).

The report contains the source (file, format, events loaded, unreadable count, time span, active filter and any warnings), the most frequent event IDs under the current filter with their meaning, and up to the first 500 matching events (time, ID, level, provider, computer, details). It does not include raw records or full field lists. Event logs hold user names, host names and addresses, so consider **Redacted...** before sharing.

## Platform notes

Works the same on macOS, Windows and Linux. On every platform the tool reads a log file you choose; on Windows it does not read the computer's live event log.

## Troubleshooting

**"unsupported format: open an .evtx file, an XML export or a CSV export".** The file is not one of the supported formats.

**"this .evtx file does not start with the EVTX signature; it may be damaged or not an event log".** The file is truncated or renamed. Export it again.

**"this CSV has no recognizable time and event ID columns (expected Event Viewer or PowerShell Export-Csv output)".** The CSV is from another tool or has renamed columns.

**"no events could be read: ...".** The first parse error is shown. The file may be empty or damaged.

**"file is too large (...)".** Over 2 GB for EVTX or 512 MB for XML or CSV. Filter on the source system with `wevtutil qe` and export less.

**"'<text>' is not an event ID or range" or "range '<text>' is backwards".** Fix the Event IDs field, for example `4688-4690`, not `4690-4688`.

**Times look hours off.** The file is a CSV or local-time export with no zone. Times are as written on the exporting computer.

## Related tools

- [IOC Extractor](ioc-extractor.md) to pull addresses and hashes out of copied event messages.
- [Script Decoder](script-decoder.md) for encoded PowerShell found in 4104 or 4688 events.
- [Timestamp Converter](timestamp-converter.md) for FILETIME or epoch values in fields.
- [Syslog Server](syslog-server.md) to collect live logs from network devices.
