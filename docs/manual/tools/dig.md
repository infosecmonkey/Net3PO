# Dig

> Run single DNS queries against your system resolver or a server you name, and see the raw sections, flags and response code the way `dig` shows them.

**Sidebar group:** Troubleshooting · **Works offline:** no (every query is sent to a DNS server) · **Needs admin rights:** no

## When to use it

- Check what a specific resolver or authoritative server returns for a name, without trusting the OS cache.
- Compare answers between your system resolver and another server (for example an internal DNS server versus a public one).
- Look up reverse DNS for an IPv4 or IPv6 address without building the `in-addr.arpa` or `ip6.arpa` name by hand.
- Confirm MX, TXT, CAA, SRV or SOA records while working a mail, certificate or service discovery problem.

## Quick start

1. Open **Dig** from the Troubleshooting group in the sidebar.
2. Type the name in **Name or IP**, for example `example.com`.
3. Leave **Server (optional)** empty to use your system resolver, or enter a server IP such as `192.0.2.53` or `192.0.2.53:5353`.
4. Click a record type button (**A**, **AAAA**, **MX**, and so on). The query runs as soon as you click.
5. Read the response code, server, protocol and time at the top, then the Answer, Authority and Additional tables.
6. Click other type buttons to run more queries against the same name. Press **Enter** in either field to repeat the last selected type.
7. Use **Export** to save every query from this session as one report, or add it to a project.

## Inputs and options

| Field | What it means | Default / accepted values |
|---|---|---|
| Name or IP | The name to query. For **PTR**, you can type an IP address and the tool builds the reverse name for you (`192.0.2.10` becomes `10.2.0.192.in-addr.arpa.`; IPv6 addresses become nibble-format `ip6.arpa.` names). For any other type, the input must be a valid DNS name. | Empty. Required. |
| Server (optional) | The DNS server to ask. Must be an IP address, optionally with a port. IPv6 with a port uses brackets, for example `[2001:db8::53]:53`. Host names are not accepted here. | Empty means the first name server in your system DNS configuration. If none can be read, the tool falls back to `1.1.1.1` port 53. Port defaults to 53. |
| Record type buttons | **A, AAAA, MX, TXT, NS, CNAME, SOA, PTR, SRV, CAA.** Clicking one selects it and runs the query. The selected type is highlighted. | **A** is selected at start. Only these ten types are supported. |
| Clear | Empties the list of queries kept for the export. | |

All queries use class IN. The buttons are disabled while a query is running.

## Reading the results

After a query, the panel shows, top to bottom:

- **Export row:** how many queries from this session the export will include, a **Clear** link and the **Export** menu.
- **Meta line:** the response code (`NOERROR`, `NXDOMAIN`, `SERVFAIL`, `REFUSED`, `FORMERR`, `NOTIMP` or another code), then the server address and port, the protocol (`UDP` or `TCP`) and the query time in milliseconds.
- **Flags:** the header flags that were set, using dig's names: `qr` (this is a response), `aa` (authoritative answer), `tc` (truncated), `rd` (recursion desired), `ra` (recursion available), `ad` (authentic data, set by a validating resolver).
- **Question line:** the query as sent, for example `;; example.com. IN MX`.
- **Answer, Authority, Additional:** one table per non-empty section, with **Name**, **TTL**, **Type** and **Data**. Data is shown in zone-file style.
- If there are no answer records, a note says so and repeats the response code.

Worked example: you query `example.com` type **MX** against `192.0.2.53`.

```
NOERROR   192.0.2.53:53 · UDP · 18 ms   flags: qr rd ra
;; example.com. IN MX

Answer
Name           TTL    Type  Data
example.com.   3600   MX    10 mail1.example.com.
example.com.   3600   MX    20 mail2.example.com.
```

`ra` is set, so the server offered recursion. `aa` is absent, so this answer came from a recursive resolver, not the authoritative server. A query for a name that does not exist would show `NXDOMAIN` and usually an SOA record in the Authority section.

## What the results do and do not tell you

- The answer is what one server returned at one moment. A different resolver, or the same one after a TTL expires, can return something else.
- With the server field empty, the tool asks only the first resolver in your system configuration. It does not try the others, and it does not use the OS resolver cache or hosts file.
- The query goes over UDP first. If the response has the truncation (`tc`) flag set, the tool repeats it over TCP and the protocol shows `TCP`.
- Each query has a 5 second timeout. A timeout means no usable answer arrived in that time, not that the name does not exist.
- The `ad` flag reflects what the server reported. The tool does not validate DNSSEC itself. For DNSSEC, SPF, DMARC and NS consistency checks use [DNS Analyzer](dns-analyzer.md).
- Only the ten listed record types can be queried.

## Online activity and privacy

When you click a record type button (or press Enter), the tool sends one DNS query for the name and type to the chosen server: your system resolver, the server you typed, or `1.1.1.1` if no system resolver could be read. If the UDP answer is truncated, it opens one TCP connection to the same server and repeats the query. Nothing is sent until you click.

The last 30 queries of the session are held in memory for the export. They are not written to disk unless you export them or add them to a project. Clearing them or closing the app discards them.

## Export and projects

The **Export** menu offers HTML, PDF, Markdown and Plain text, a **Redacted...** option, and **Add to project** (see [Export and redaction](../export-and-redaction.md) and [Projects and notes](../projects-and-notes.md)).

The report title lists the queried names, and the subtitle lists the types run. Each query is one section, oldest first, with the question as the title, then the response code, server, protocol, query time and local time. The body shows the flags and one table with Section, Name, TTL, Type and Data for every Answer, Authority and Additional record, or "No records" with the response code. Only the last 30 queries are kept. Failed queries (timeouts, errors) are not included.

## Platform notes

The tool behaves the same on macOS, Windows and Linux. The only difference is where the system resolver comes from: the tool reads the OS DNS configuration (for example `/etc/resolv.conf` on Linux and macOS, the adapter settings on Windows) and uses the first server listed. On systems where that list points to a local stub resolver (such as `127.0.0.53` on some Linux distributions), that stub is what gets queried.

## Troubleshooting

**"Enter a name or IP to look up."** The name field is empty. Type a name before clicking a type.

**"'...' is not a valid DNS name".** The input could not be parsed as a DNS name. For an IP address, use the **PTR** button; other types need a name.

**"server '...' must be an IP address, optionally with :port".** The server field contains a host name or a malformed value. Enter an IP, `IP:port`, or `[IPv6]:port`.

**"query to ... timed out after 5s".** The server did not answer in time. Check that the IP is a DNS server, that UDP and TCP 53 (or your port) are allowed, and try another server.

**"query ... (UDP): ..." or "connect ... (TCP): ...".** The query failed at the network level, or the TCP retry after truncation could not connect. Check reachability to the server and whether TCP 53 is blocked.

**REFUSED.** The server answered but will not serve this query, often because it does not allow recursion for your address. Try your own resolver or the domain's authoritative server.

## Related tools

- [DNS Analyzer](dns-analyzer.md) for SPF, DMARC, DKIM, DNSSEC and NS consistency audits.
- [Email Analyzer](email-analyzer.md) for mail header and authentication work.
- [Port Scanner](port-scanner.md) to check that TCP 53 or other service ports are reachable.
- [Socket Tools](socket-tools.md) for raw UDP and TCP tests.
