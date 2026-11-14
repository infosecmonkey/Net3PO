# Timestamp Converter

> Paste a timestamp from a log, AD attribute or packet and see it in UTC, a chosen time zone and every other common format.

**Sidebar group:** Utilities · **Works offline:** yes · **Needs admin rights:** no

## When to use it

- Turn an epoch number from a firewall log, API response or SIEM export into a readable time, without guessing whether it is seconds or milliseconds.
- Decode Active Directory attributes such as `lastLogonTimestamp`, `pwdLastSet` or `accountExpires` (Windows FILETIME) and LDAP generalized time (`whenCreated`).
- Line up events from devices that log in different zones, or in syslog format with no year.
- Check what a local time means around a daylight saving change.

## Quick start

1. Open **Timestamp Converter**.
2. Paste a timestamp into the input box. Results update as you type.
3. Pick a zone in **Show in** (start typing an IANA name such as `Europe/Madrid`), or click **This computer** or **UTC**.
4. Read the main card, headed "Read as ...". Check any notes under the heading.
5. Click **Copy** next to the format you need.
6. Click **Now** at any time to load the current time.

## Inputs and options

| Field | What it means | Default / accepted values |
|---|---|---|
| Timestamp | The value to convert. Leading and trailing spaces are ignored. | Empty. Up to 200 characters. See accepted formats below. |
| Now | Fills the box with the current Unix seconds and shows the current time in every format. | |
| Show in | IANA time zone used for the **Selected zone** row, and for reading inputs that carry no zone. | This computer's zone. The list offers every zone the system knows, plus UTC. |
| This computer (zone) | Resets **Show in** to the local zone. | |
| UTC | Sets **Show in** to UTC. | |

Accepted input formats:

- **Integers**: tried as Unix seconds, milliseconds, microseconds and nanoseconds, and as Windows FILETIME / AD (100 ns ticks since 1601-01-01 UTC). Negative numbers are allowed.
- **Hex with `0x`**: read only as FILETIME, for example `0x1DD7448D1F5D800`.
- **Decimal with a fraction**, such as `1794668400.25`: Unix seconds with fraction.
- **LDAP generalized time**: `YYYYMMDDHHMMSS`, optional `.f` or `,f` fraction, then `Z`, `+HHMM`, `-HHMM` or nothing.
- **ISO 8601 / RFC 3339**: with `Z`, with an offset, with a `[Zone/Name]` annotation, or with no zone.
- **RFC 2822** (email headers): `Sat, 14 Nov 2026 15:00:00 +0000`.
- **Syslog dates**: RFC 3164 `Nov 14 09:34:50` (no year) and device style `Nov 14 2026 09:34:50.123`, optionally followed by `UTC`, `GMT`, `Z` or an offset like `+01:00`.

## Reading the results

Each likely reading is a card headed **Read as** followed by how the input was interpreted (for example "Unix seconds", "Windows FILETIME / AD timestamp (100 ns since 1601)", "ISO 8601 without zone", "Syslog (RFC 3164) date"). Notes under the heading state anything that was assumed. The card then lists:

| Row | Content |
|---|---|
| UTC (ISO 8601) | `2026-11-14T15:00:00Z`, with fractional seconds only if present |
| Selected zone | Local time in the chosen zone with abbreviation and offset |
| Unix seconds | Whole seconds since 1970-01-01 UTC |
| Unix milliseconds | Milliseconds since 1970 |
| Windows FILETIME / AD | 100 ns ticks since 1601, or "before 1601" |
| LDAP generalized time | `YYYYMMDDHHMMSS.0Z` (UTC, whole seconds) |
| RFC 2822 | Email header form in UTC |

A reading is "likely" when it falls between 1990 and 2100. Readings outside that window are collapsed under "N other readings outside 1990 to 2100", showing only the UTC time. If no reading is likely, that section opens by itself.

### Worked example: FILETIME

Input `134391420000000000` with **Show in** set to `America/New_York`:

- Read as **Windows FILETIME / AD timestamp (100 ns since 1601)**
- UTC (ISO 8601): `2026-11-14T15:00:00Z`
- Selected zone: `2026-11-14 10:00:00 EST (UTC-05:00)`
- Unix seconds: `1794668400`, Unix milliseconds: `1794668400000`
- LDAP generalized time: `20261114150000.0Z`

Under "other readings" you would also see Unix nanoseconds, `1974-04-05T10:57:00Z`. That is a valid number of nanoseconds, but outside the 1990 to 2100 window, so it is shown as unlikely. Values of `0` or `9223372036854775807` get the note "AD uses 0 and 9223372036854775807 to mean never".

### Worked example: DST fold

Input `2026-11-01T01:30:00` with zone `America/New_York`. Clocks go back that night, so 01:30 happens twice. The tool shows two cards, never a guess:

- First occurrence, on daylight time: `2026-11-01T05:30:00Z`
- Second occurrence, on standard time: `2026-11-01T06:30:00Z`

Each card notes "This local time happens twice in America/New_York (clocks go back); this is the first (or second) occurrence" with its UTC offset.

For a local time that does not exist, such as `2026-03-08T02:30:00` in New York (clocks go forward), one card is shown with the note that the time does not exist, and it is "shown as if the old offset still applied".

### Notes you may see

- "No offset given; read as ZONE local time" or "No zone given; read as ZONE local time": the input had no zone, so the **Show in** zone was used. Change the zone and the result changes.
- "No year in the input; assumed 2026": RFC 3164 syslog dates take the current year in the selected zone.
- "With the assumed year this is in the future; the log may be from last year": the assumed date is more than a day ahead of now.
- "Zone "EST" not recognized (abbreviations are ambiguous); read as ZONE local time": only UTC, GMT, Z and numeric offsets are trusted after a syslog date.

A bare 14-digit number such as `20261114093450` is shown both as LDAP generalized time (if plausible) and as the numeric readings.

## What the results do and do not tell you

- For bare numbers the unit is inferred from the 1990 to 2100 window. If two units both land in that window, both cards are shown; you decide which is right.
- Inputs without a zone are interpreted in the **Show in** zone. That is an assumption, and it is stated on the card.
- Time zone abbreviations (EST, CET) in syslog dates are not interpreted.
- LDAP output is whole seconds only. Precision finer than 100 ns is lost in the FILETIME output.
- Input is limited to 200 characters.

## Online activity and privacy

None. Conversion and time zone data are local. Nothing is saved unless you export. See [Privacy](../privacy.md).

## Export and projects

**Export** appears once there is a reading. Formats: HTML, PDF, Markdown, Plain text and **Redacted...** (see [Export and redaction](../export-and-redaction.md)), plus **Add to project**. The report lists the input, the zone, and every reading (likely and unlikely, the latter marked "outside 1990 to 2100") with all format rows and notes. See [Projects and notes](../projects-and-notes.md).

## Platform notes

The **Show in** list comes from the system's time zone list, so it can differ slightly between operating systems. Conversion itself is the same on macOS, Windows and Linux.

## Troubleshooting

**"not a recognized timestamp. Try Unix seconds or ms, FILETIME, ISO 8601, LDAP generalized time, RFC 2822 or a syslog date."** The input matched none of the formats. Remove surrounding text such as field names or quotes.

**"unknown time zone: ..."** The **Show in** value is not a valid IANA zone name. Pick one from the list or click **UTC**.

**"number is out of range for every supported format".** The number is too large or small to be a valid date in any unit.

**"not a hex number".** The text after `0x` contains non-hex characters.

**"input longer than 200 characters".** Paste only the timestamp, not the whole log line.

**The result is a day or hours off.** The input probably had no zone and was read in the **Show in** zone. Check the note on the card and set the zone the device logs in.

## Related tools

- [Event Log](event-log.md)
- [Syslog Server](syslog-server.md)
- [NTP Checker](ntp-checker.md)
- [JWT and SAML](jwt-saml.md)
- [Encoder Workbench](encoder-workbench.md)
