# HTTP Troubleshooter

> Send an HTTP/1.1 request with any method, headers and body, follow redirects hop by hop, and see per-hop timings, TLS details, raw headers, the body and notes on the final response's security and caching headers.

**Sidebar group:** Troubleshooting · **Works offline:** no (sends the request to the server in the URL, or to the IP you name) · **Needs admin rights:** no

## When to use it

- Trace a redirect chain (HTTP to HTTPS, apex to `www`, SSO hops) and see exactly which hop returns what, with method changes and dropped credentials called out.
- Test an API endpoint with a specific method, headers and JSON body, and read the raw status and headers.
- Hit one backend server or a new load balancer VIP directly with **Connect to IP** while keeping the real Host header and SNI, for example before a DNS cutover.
- Split slow responses into DNS, TCP connect, TLS handshake and time to first byte.

## Quick start

1. Open **HTTP Troubleshooter** from the Troubleshooting group.
2. Pick a method (default **GET**) and enter a URL such as `https://www.example.com/login`. A URL without a scheme is treated as `https://`.
3. Add headers if needed with **+ Add header** (for example `Accept: application/json`).
4. For POST, PUT, PATCH or DELETE, enter a body and set `Content-Type` in the headers.
5. Open **Options** if you need to change redirects, the timeout, Connect to IP, or certificate validation.
6. Click **Send** (or press Enter in the URL field).
7. Click each entry in the **Requests** list to see that hop's timing, TLS, headers and body. Read **Header observations** for the final response.
8. Use **Export** to save the chain or add it to a project.

## Inputs and options

| Field | What it means | Default / accepted values |
|---|---|---|
| Method | **GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS**. | GET |
| URL | `http://` or `https://` URL. No scheme means `https://`. Fragments (`#...`) are dropped. Non-ASCII characters in the path are percent-encoded. | Empty. Required. Up to 8 KB. User names and passwords in the URL (`user:pass@host`) are refused. |
| Headers | Name and value pairs. Rows with an empty name are ignored. **×** removes a row. | One empty row. Up to 50 headers, each value up to 16 KB, no line breaks. `Host`, `Content-Length`, `Transfer-Encoding` and `Connection` are set by the tool and cannot be added. |
| Body | Request body text. Shown for POST, PUT, PATCH and DELETE, or whenever it already has content. | Empty. Up to 1 MB. `Content-Length` is added for you. |
| Follow redirects | Follow 301, 302, 303, 307 and 308 responses. | On |
| Max | Most redirects to follow. Disabled when Follow redirects is off. | 10. Range 0 to 20. |
| Timeout (s) | Limit for the TCP connect and for each read and write on the socket. It is not a limit on the whole request. | 15. Range 1 to 120. |
| Connect to IP | Send requests for the URL's host to this IP instead of resolving the name. The Host header and TLS SNI keep the original host name. Applies to every hop whose host matches the original URL's host; redirects to other hosts resolve normally. | Empty (resolve the host). Must be an IPv4 or IPv6 address. |
| Skip certificate validation | Accept any certificate chain. Handshake signatures are still checked. Every result then carries a warning. | Off |

The tool adds `Host`, `User-Agent: Net3PO/<version>`, `Accept: */*`, `Accept-Encoding: identity` and `Connection: close` unless you set `User-Agent`, `Accept` or `Accept-Encoding` yourself. Each hop uses a fresh connection.

## Reading the results

If certificate validation was off, a banner says: **Certificate validation was off. TLS results below are not verified.**

### Requests

One entry per hop with a status badge (colored by class: 2xx, 3xx, 4xx, 5xx), the method, the URL and the total time. The last hop is selected after a run. If the chain stopped early, a box shows **Stopped:** and the reason (a later hop failed, a redirect loop, the redirect limit, or a Location that cannot be followed). The hops that worked are still shown.

### Timing and notes (selected hop)

A bar split into **DNS**, **Connect**, **TLS** and **First byte**, then a text line such as `DNS 12 ms, connect 24 ms, TLS 41 ms, first byte 88 ms, total 170 ms`, the address actually connected to, the HTTP version, and any interim 1xx codes (`100`, `103`) received before the final response. DNS is omitted when no lookup happened (IP literal or Connect to IP). First byte is measured from sending the request to the first response byte.

Notes under the timing explain what happened on that hop, for example:

- `Connected to 192.0.2.20:443 instead of resolving www.example.com; Host header and SNI kept as www.example.com.`
- `Not forwarded to login.example.net (different origin): Authorization, Cookie.`
- `302 changes POST to GET for the next request.`
- `Redirects from HTTPS to plain HTTP.`
- `Redirect status without a Location header.`
- `Body is gzip-encoded although identity was requested; shown as received, not decoded.`

### TLS

For HTTPS hops: **Protocol** with cipher suite and ALPN, **Validation** (`verified`, or `skipped (validation turned off)` highlighted), **Certificate** subject, **Issuer** and **Expires** date of the leaf certificate.

### Response headers

The status and reason, then every response header in the order received. **Request headers sent** (collapsed) lists the headers you supplied as they were sent on this hop, with credential values masked: `Authorization` and `Proxy-Authorization` show only the scheme, cookies show only names, and headers whose name contains `token`, `api-key`, `apikey` or `secret` are fully masked. The request body size is shown if one was sent.

### Body

Size, content type, and "first 256 KB shown" if truncated. Text bodies are shown as text; JSON can be shown with **Pretty** formatting. Binary bodies show the first 512 bytes as hex: never rendered or run. HEAD, 204 and 304 responses have no body.

### Header observations

Notes about the final response's headers, colored pass, info or warn: HSTS (missing on HTTPS, max-age 0, under 180 days, or sent over plain HTTP where browsers ignore it), Content-Security-Policy (missing on an HTML page, report-only, or allowing `'unsafe-inline'`, `'unsafe-eval'` or a `*` source), framing (X-Frame-Options or CSP frame-ancestors), `X-Content-Type-Options: nosniff`, Referrer-Policy, version strings in `Server`, `X-Powered-By` or `X-AspNet-Version`, cookie attributes (Secure, HttpOnly, SameSite, and SameSite=None without Secure), and CORS (`*`, `*` with credentials, or a specific origin). Observations are not produced when the chain ends on a redirect.

The panel's own wording: these are context for troubleshooting, not a security rating. They describe this response's headers only.

### Worked example

GET `http://example.com/app`, follow redirects on:

```
301  GET  http://example.com/app             38 ms
302  GET  https://www.example.com/app        95 ms
200  GET  https://www.example.com/app/home  110 ms

Hop 3: DNS 4 ms, connect 21 ms, TLS 44 ms, first byte 33 ms, total 110 ms · 203.0.113.10:443 · HTTP/1.1
TLS: TLS 1.3, TLS13_AES_128_GCM_SHA256, ALPN http/1.1 · verified · expires 2027-03-01

warn  No HSTS
pass  nosniff set
info  Version disclosed: nginx/1.24.0
```

The first hop upgrades to HTTPS and changes host. The final page works, but HSTS is missing, so browsers may still try plain HTTP first on later visits.

## What the results do and do not tell you

- **HTTP/1.1 only.** ALPN offers only `http/1.1`, so a server's HTTP/2 or HTTP/3 behavior is not tested. A site that only works over HTTP/2 will fail here.
- Certificates are validated against the bundled Mozilla root store (webpki-roots), not your OS trust store. A server using an internal or private CA will fail validation even if your browser trusts it. Use **Skip certificate validation** to see the response, and [TLS Inspector](tls-inspector.md) for chain details.
- Redirects follow browser rules: 303 becomes GET (HEAD stays HEAD), 301 and 302 turn POST into GET and drop the body, 307 and 308 keep the method and body. `Authorization`, `Proxy-Authorization` and `Cookie` are never forwarded to a different origin (scheme, host or port). Cookies set by one hop are not sent on the next: there is no cookie jar.
- Bodies are never decompressed. `Accept-Encoding: identity` is requested by default; a server that compresses anyway shows a note and the raw bytes.
- Only the first 256 KB of a body is read. When the server sent a Content-Length, the size shown is that declared length.
- Response parsing is bounded: 64 KB of headers, 200 header lines, 5 interim responses.
- No proxy is used, even if the OS has one configured. The request goes directly from this computer.
- When a host name resolves to several addresses, the tool tries up to 8 in order and uses the first that accepts the connection.
- Timings come from this computer's sockets. Connect time is the TCP handshake as seen by the OS, not packet-level SYN timing.

## Online activity and privacy

When you click **Send** (or press Enter), the tool resolves the host name with the system resolver (unless the host is an IP or you set Connect to IP), opens a TCP connection to the server, performs a TLS handshake for HTTPS, and sends your request with your headers and body. For each redirect it follows, it repeats this for the new URL. Nothing is sent until you click.

Anything you put in headers or the body (tokens, cookies, API keys) is sent to the server you target. Credential headers are dropped when a redirect crosses to another origin. Requests and responses are kept in memory for the session only; nothing is written to disk unless you export or add to a project.

## Export and projects

The **Export** menu offers HTML, PDF, Markdown and Plain text, **Redacted...**, and **Add to project**. See [Export and redaction](../export-and-redaction.md) and [Projects and notes](../projects-and-notes.md).

The report contains the **Request chain** table (#, Request, Status, Address, Timing), each hop's notes, the stop reason and the validation-off warning if they apply; **TLS (final hop)** (protocol, cipher, validation, certificate, issuer, expiry); **Final response** with every response header and the body size and type; and **Header observations** with the same "not a security rating" note.

Response bodies are left out of the report, because they often hold data that does not belong in one. Request headers and the request body are also not included. Response headers are included as received, so a `Set-Cookie` value from the server will appear; use **Redacted...** or review before sharing.

## Platform notes

The tool uses ordinary TCP sockets and a built-in TLS stack (rustls), so it behaves the same on macOS, Windows and Linux and needs no privileges. Because the TLS stack and root store are bundled, OS-level certificate settings, enterprise root CAs and TLS inspection proxies' CAs are not used.

## Troubleshooting

**"Enter a URL."** The URL field is empty.

**"unsupported scheme ...: use http or https".** Only `http://` and `https://` are supported.

**"credentials in the URL are not sent; use an Authorization header instead".** Remove `user:pass@` and add an `Authorization` header.

**"not a valid host: ..." / "invalid port".** Check the host and port in the URL.

**"... is set by Net3PO; remove it".** Delete the `Host`, `Content-Length`, `Transfer-Encoding` or `Connection` header row. To target a different server while keeping the Host header, use **Connect to IP**.

**"invalid header name" / "header ... contains a line break".** Header names must be HTTP tokens; values cannot contain line breaks.

**"not an IP address: ...".** The Connect to IP field must hold an IP address, not a name.

**"could not resolve ...".** DNS failed. Check with [Dig](dig.md), or use Connect to IP.

**"...: connection refused" / "...: no answer within N s".** Nothing listens on that port, or a firewall drops the connection. Check with [Port Scanner](port-scanner.md).

**"certificate not accepted: .... Turn off certificate validation to see the response anyway (the result will say so)."** The chain did not validate against the bundled roots, the name did not match, or the certificate is expired. Inspect it with [TLS Inspector](tls-inspector.md).

**"TLS handshake failed: ...".** No common protocol or cipher, or the server is not speaking TLS on that port.

**"not an HTTP response (got ...); wrong port or scheme?".** You probably used `http://` against a TLS port, or the port runs another protocol.

**"timed out waiting for the server" / "the server closed the connection early".** The server stopped responding, or closed before sending the full response. Raise the timeout if the endpoint is slow.

**"Stopped: stopped after N redirects" / "redirect loop at ...".** The chain is longer than Max, or it loops. Raise Max, or fix the redirect rules.

## Related tools

- [TLS Inspector](tls-inspector.md) for certificate chains, names and protocol support.
- [Dig](dig.md) to check what the host name resolves to.
- [Socket Tools](socket-tools.md) to send raw bytes to a port and measure connect timing.
- [JWT and SAML](jwt-saml.md) to decode tokens seen in headers or bodies.
- [Encoder Workbench](encoder-workbench.md) for Base64, URL and other encodings.
