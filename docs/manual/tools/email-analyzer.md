# Email Header Analyzer

> Parse a message's headers or a whole .eml file locally to trace the delivery route, read the authentication results, and flag sender tricks and lookalike domains.

**Sidebar group:** Analysis · **Works offline:** partly (parsing is local; "Who owns this IP", "Check blocklists" and the DNS Analyzer hand-off go online, only when you click them) · **Needs admin rights:** no

## When to use it

- A user reported a suspicious message and you need to know where it really came from.
- A customer says their mail is failing SPF, DKIM or DMARC at a recipient and has sent you a bounced or delivered copy.
- You are checking a possible invoice-fraud or lookalike-domain message against the customer's real domains.
- You want the indicators (addresses, domains, URLs, IPs) from a message in defanged form for a ticket, without opening the message in a mail client.

## Quick start

1. Open **Email Header Analyzer** from the Analysis group.
2. Paste the full header block into the text area, starting at the first `Received:` or `Return-Path:` line. Or click **Open .eml...** and pick a saved message (`.eml` or `.txt`).
3. Optional: in **Customer's genuine domains**, list the real domains (for example `example.com, example.net`) so lookalikes of them are flagged.
4. Click **Analyze** (opening a file analyzes it straight away).
5. Read **Findings** first, then **Sending server** and **Route**.
6. If you need ownership or reputation data, click **Who owns this IP** or **Check blocklists** next to an address.
7. Use **Export** to save the report or add it to a project.

## Inputs and options

| Field | What it means | Default / accepted values |
|---|---|---|
| Header text area | Raw header block or a full message (headers plus MIME body). | Up to 15 MB. Analyze is disabled while it is empty. |
| Customer's genuine domains (optional, for the lookalike check) | Domains you know are real, compared against every domain in the message. | Separate with spaces, commas or semicolons. Up to 100 entries. |
| Analyze | Parses the pasted text. | |
| Open .eml... | Opens a native file dialog, reads the file and analyzes it. Clears the text area. | `.eml` or `.txt`, up to 15 MB. |
| Clear | Empties the input and all results. | Shown once there is input or a result. |
| Blocklist checkboxes | Which DNS blocklists **Check blocklists** queries. | All five built-in lists are ticked: Spamhaus ZEN, SpamCop, Barracuda, PSBL, Mailspike. Hover a name for its usage note. |
| other list zone | One extra DNSBL zone to include. | Any DNS name, for example `dnsbl.example.org`. At most 12 lists per check. |
| Who owns this IP | Online owner lookup for that address. | One per public IP in the route. |
| Check blocklists | Online DNSBL lookup for that address. | IPv4 only; disabled for IPv6 addresses. |

## Reading the results

Next to the buttons a line shows the source ("Pasted text" or the file name) and whether the input was a "full message" or "headers only". Sections then appear in this order.

**Summary.** Subject, Date (with the parsed UTC time), From, Reply-To, Return-Path, Sender and other address headers, a combined Recipients line for To and Cc, and Message-ID.

**Findings.** Sorted worst first. Each has a badge (PASS, INFO, WARN, FAIL), a category (Sender, Route, Authentication, DKIM, Attachments, Headers and others), a title and a detail line. Examples of what is flagged:

- No From header, or more than one ("a known trick to show one sender while authenticating another").
- "Display name shows a different address": the display name contains an address at another domain.
- "Reply-To goes to a different domain" and "Return-Path domain differs from From".
- "Timestamps go backwards" (a hop dated more than 60 seconds before the previous one) and "Long delay between hops" (more than an hour).
- SPF, DKIM or DMARC reported as fail, softfail or permerror by the top Authentication-Results header ("This is the receiving system's own verdict, recorded in the header."). DMARC failures are FAIL, others WARN.
- "Results from more than one mail system", whether a DKIM signature aligns with From, and risky attachment types.
- Missing Message-ID or Date.

**Sending server.** Up to two estimates. "Most reliable" is the server that handed the message to the receiving organization, as recorded by that organization's own servers (the newest `by` host). "Earliest, forgeable" is the first public address in the Received chain, which servers outside the receiver's control wrote and can be forged. Each shows the IP, host name and hop number.

**Online checks** (under Sending server). Lists the public IPs from the route with the two lookup buttons. An **IP owner** result shows ASN, AS name, announced prefix, registry country, registry and allocation date, reverse DNS, and from RDAP: registered owner, network name, registered range, allocation type, country, record dates and abuse contact. The tool notes that "ASN and prefix show who routes the address today; RDAP shows who it is registered to. They can differ (cloud, hosting and leased ranges)." A **Blocklists** result lists each zone with a status: Listed, Not listed, Refused or Error, plus the list's own reason text when listed.

**Route** (oldest first). One row per Received header: hop number, time (UTC), delay from the previous hop, From (host, IP marked "private" when not public, rDNS and HELO when they differ), By, and With (protocol and TLS details). Rows with a backwards timestamp are highlighted. Expand **Received lines as written** for the raw text.

**Authentication claimed in the header.** Every Authentication-Results and ARC-Authentication-Results header, grouped by the system that wrote it, with each method's result and properties. Received-SPF lines and the number of ARC sets are shown too.

**DKIM signatures.** For each DKIM-Signature: `d=` domain, `s=` selector, alignment with From (`relaxed alignment`, `strict alignment` or "not aligned with From"), algorithm, canonicalization, the key record name, and the signed header list. Notes flag missing `d=`/`s=`, From not in `h=`, an expired `x=`, or empty `bh=`/`b=`. **Check in DNS Analyzer** opens the [DNS Analyzer](dns-analyzer.md) with that domain and selector and runs it.

**Domains.** Each domain in the message with the roles it appears in, a "displays as" note for internationalized names, and a **DNS Analyzer** button. **Lookalikes** lists domains that resemble another domain in the message, your list, or a common brand, with the reason (look-alike characters, same name with a different ending, one or two characters different, the name plus extra words, or an internationalized domain).

**Body and attachments** (full messages). Counts of text and HTML parts, and each attachment's name, type, size, and "risky type" for extensions such as `exe`, `js`, `lnk`, `iso`, `html`, `docm` and archive formats.

**Indicators.** Addresses, domains, URLs and IPs found in the headers and body, defanged, with where each was found. **Copy defanged** copies the list.

**Notable headers** (for example X-Mailer, X-Originating-IP, spam scores, List-Unsubscribe) and **All header fields** (collapsed) close the page.

Example route row: hop 3, `2026-11-14 09:12:05 UTC`, `+4s`, from `mail.example.net` `198.51.100.25`, by `mx1.example.com`, `ESMTPS` followed by the TLS version and cipher when the Received line records them.

## What the results do and do not tell you

- Authentication results are "written by mail systems along the route and copied here as found. Trust only results from your own receiving system; Net3PO has not verified them."
- "A header alone cannot prove a signature is valid: that needs the original message bytes and the public key." The DNS Analyzer can check that the key exists, its size, and whether it is revoked.
- Lookalike findings are prompts for review. A similar name is not proof of impersonation. The organizational domain is approximate: there is no full Public Suffix List, only a list of common multi-label suffixes.
- Received lines that could not be parsed are reported and shown as written.
- Limits: 15 MB input, 1000 header fields kept, header values clipped at 8 KB, 100 hops, the first 2 MB of each body part scanned for indicators.
- The body is never rendered, remote images are never loaded, and attachments are listed but not opened.

## Online activity and privacy

Parsing is entirely local. Three actions go online, only when clicked:

- **Who owns this IP**: reverse DNS and Team Cymru IP-to-ASN TXT queries through the system resolver, then one HTTPS RDAP request to the regional registry for that address (ARIN, RIPE NCC, APNIC, LACNIC or AFRINIC). 5 second DNS timeout, 10 second RDAP timeout, answers over 1 MB ignored.
- **Check blocklists**: one DNS query per chosen list through the system resolver, plus a TXT query for the reason when listed. 5 second timeout each.
- **Check in DNS Analyzer** / **DNS Analyzer**: runs the DNS Analyzer, which queries DNS.

Private and reserved addresses are never looked up. Message content is not saved anywhere unless you export it or add it to a project.

## Export and projects

The **Export** menu offers HTML, PDF, Markdown, Plain text, **Redacted...** and **Add to project**. See [Export and redaction](../export-and-redaction.md) and [Projects and notes](../projects-and-notes.md).

The report contains the summary and findings, the estimated sending server, the route table, the claimed authentication results (labeled as not verified by Net3PO), DKIM signatures, any IP owner and blocklist results you ran in this session, domains and lookalikes, the attachment list and the defanged indicators. It does not include the message body or the full header list.

## Platform notes

No differences between macOS, Windows and Linux. Online lookups use the operating system's DNS configuration.

## Troubleshooting

**"no email header fields were found; paste the full header block, starting at the first header line".** The paste started mid-header or is not an email. Copy the raw source ("Show original" or "View source" in most clients).

**"input is too large (... bytes; limit 15728640)".** The file or paste is over 15 MB. Save only the headers.

**"No Received headers".** The header was copied from a client view that hides them. Use the raw source.

**Spamhaus shows Refused.** "queries through public or open resolvers are refused; use your own resolver or Spamhaus DQS". Your system resolver is a large public resolver. Barracuda may also not answer unregistered resolvers.

**"blocklist checks here cover IPv4 only; most DNS blocklists do not list IPv6 senders".** The button is disabled for IPv6 addresses.

**"choose at least one blocklist".** Tick a list or fill in "other list zone".

**"... is a private or reserved address; there is nothing to look up".** Only public addresses can be looked up.

**RDAP errors** such as "the registry is rate limiting requests; try again later" or "the registry has no record for this address" appear under the owner result. The DNS-based fields are still shown.

## Related tools

- [DNS Analyzer](dns-analyzer.md) to audit the sender domain's SPF, DMARC and DKIM.
- [IOC Extractor](ioc-extractor.md) for indicators in other text.
- [Encoder Workbench](encoder-workbench.md) to decode encoded header words or body parts.
- [Dig](dig.md) for individual DNS queries.
