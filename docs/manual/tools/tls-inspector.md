# TLS Inspector

> Inspect a live TLS endpoint (with STARTTLS for SMTP, IMAP, POP3 and FTP), or decode certificates and CSRs offline.

**Sidebar group:** Analysis · **Works offline:** partly (the Decode PEM / DER tab is offline; Inspect and "Test versions and ciphers" connect to the target, only when you click them) · **Needs admin rights:** no

## When to use it

- A browser or client reports a certificate error and you need to see the chain the server actually sends, and why it fails.
- You are checking a mail server's STARTTLS certificate on port 587, 143, 110 or 21.
- You want to test one node behind a load balancer or VIP while keeping the public hostname for SNI.
- Someone sent you a certificate, bundle or CSR and you want to read its subject, SANs, key, validity and fingerprints before installing or signing it.

## Quick start

1. Open **TLS Inspector** from the Analysis group. The **Live endpoint** tab is selected.
2. Enter a **Host**: a hostname, an IP address, or a URL such as `https://www.example.com/login`.
3. Check **Port** (443 by default). For a mail or FTP server, pick the protocol under **STARTTLS**; the port changes to match.
4. Click **Inspect** (or press Enter).
5. Read **Connection** for what was negotiated and **Evaluation** for trust and hostname results.
6. Expand certificates under **Presented chain** for details.
7. Optional: click **Test versions and ciphers** to see which TLS 1.2 and 1.3 suites the server accepts.
8. Use **Export** to save a report or add it to a project.

To decode offline, switch to **Decode PEM / DER**, paste one or more PEM blocks and click **Decode**, or click **Open file...**.

## Inputs and options

**Live endpoint tab**

| Field | What it means | Default / accepted values |
|---|---|---|
| Host | Target to connect to. A scheme, path, query and `user@` are stripped from URLs. | Hostname, IPv4, IPv6, `host:port`, `[2001:db8::1]:443` or a URL. |
| Port | TCP port. | 443. Changes automatically with STARTTLS until you edit it: SMTP 587, IMAP 143, POP3 110, FTP 21. 1 to 65535. A port typed in Host (`host:8443`, or a URL with a port) takes priority; the Port field then shows that port and is locked. |
| STARTTLS | Plain-text upgrade before the handshake. | None (direct TLS), SMTP, IMAP, POP3, FTP. |
| Connect to IP (optional), under Advanced | Connect to this address instead of resolving the host. The hostname is still used for SNI and checks. | Empty (resolve the host). Must be an IP address. |
| Send SNI, under Advanced | Include the hostname in the TLS ClientHello. | On. |
| Inspect | Connect, run STARTTLS if chosen, handshake, and evaluate. | |
| Test versions and ciphers | One separate handshake per TLS 1.2 and 1.3 suite this build supports, run in parallel. | Shown after a successful Inspect. |

**Decode PEM / DER tab**

| Field | What it means | Default / accepted values |
|---|---|---|
| Certificates or CSR (PEM) | Pasted PEM text. Several blocks (a chain or bundle) are fine. | Up to 1 MB and 50 items. |
| Decode | Decode the pasted text. | |
| Open file... | Read a file from disk. PEM or a single DER blob. | `.pem`, `.crt`, `.cer`, `.der`, `.csr`, `.req`, `.p7b`, `.txt`. Up to 1 MB. |

## Reading the results

**Connection** (as measured). Connected to (the address and port used), SNI sent, Protocol (for example TLS 1.3), Cipher suite, Key exchange group, ALPN (the client offers `h2` and `http/1.1`), and Timing for connect, STARTTLS and handshake in milliseconds. With STARTTLS, **STARTTLS exchange** shows the plain-text conversation, lines prefixed `S:` (server) and `C:` (client).

**Evaluation** (Net3PO's checks, not the server's claims). Green for pass, red for fail, amber for chain notes:

- "Chain leads to a trusted root", or "Not trusted:" with the reason, such as "no path to a trusted root (self-signed, private CA, or a missing intermediate)", "a certificate in the chain is expired" or "the certificate is not allowed for TLS server use".
- "<name> is covered by <SAN>", or "No SAN covers <name>". The hostname check is reported separately from chain trust.
- Chain notes: certificates out of order, "The server sends its root certificate; harmless but unnecessary", and "Only the leaf was sent; clients without the intermediate cached will fail".

A hint names the store used: the Mozilla root store bundled with Net3PO and its root count.

**Versions and ciphers.** A header shows how many suites were accepted out of those tested. Each row lists the version, suite name and result: accepted, rejected (with the alert, or "connection closed (common way to refuse)"), or error.

**Presented chain.** One card per certificate, in the order the server sent it (up to 10). The leaf is open by default. Each card has a validity pill ("N days left", "expired N days ago" or "not valid yet"), plus CA and self-signed pills when they apply. The summary line shows the subject, issuer, validity dates, key and signature algorithm. Notes flag expiry within 30 days, RSA keys under 2048 bits, SHA-1 or MD5 signatures, missing SANs, and validity over 398 days. **Details** lists subject, issuer, SANs, validity, key, signature, type (CA with path length, or end entity), key usage, extended key usage, serial, OCSP, CRL and CA issuer URLs, the certificate SHA-256 and the SPKI SHA-256.

**Decode results.** The same cards, titled "Certificate N" or "CSR N". A CSR card shows "signature OK" or "bad signature" (whether it verifies with its own key), plus subject, SANs, key and signature. Warnings list skipped blocks, PEM errors or "no certificate or CSR found".

Example: inspecting `mail.example.com` on port 587 with SMTP shows `Connected to 192.0.2.25:587`, `SNI sent mail.example.com`, `Protocol TLS 1.3`, a STARTTLS exchange beginning `S: 220 mail.example.com ESMTP`, `C: EHLO net3po.invalid`, and in Evaluation "mail.example.com is covered by *.example.com".

## What the results do and do not tell you

- Trust is evaluated locally against the bundled Mozilla root store. "Your OS or browser may trust different roots. Revocation is not checked."
- The handshake records whatever certificate the server presents, even an untrusted one, so you can still read a broken chain.
- "Only modern TLS 1.2 and 1.3 suites can be offered by this build. TLS 1.0/1.1, CBC and static RSA suites are not tested, so their absence here says nothing about the server."
- "Decoding shows what a certificate says. It does not establish trust or check revocation."
- Timeouts: 8 seconds for connect and I/O. STARTTLS replies are capped at 8 KB per line, 200 lines per reply and 64 KB before TLS.

## Online activity and privacy

**Inspect** resolves the host (unless you set Connect to IP), opens one TCP connection and performs one handshake. **Test versions and ciphers** opens one connection per suite tested, in parallel. Both run only when clicked. For SMTP the client introduces itself as `EHLO net3po.invalid`.

Decoding is offline. If a pasted block is a private key, it is not parsed, stored or included in any report, and it is removed from the text box after decoding. Nothing is saved unless you export or add to a project.

## Export and projects

Both tabs have an **Export** menu: HTML, PDF, Markdown, Plain text, **Redacted...** and **Add to project**. See [Export and redaction](../export-and-redaction.md) and [Projects and notes](../projects-and-notes.md).

The live report holds the measured connection (with the STARTTLS transcript), the evaluation findings with the trust-store note, one section per presented certificate, and the version and cipher table if you ran it. The decode report holds one section per certificate or CSR and a notes section. Private keys are never part of a report.

## Platform notes

No differences between macOS, Windows and Linux. Trust uses the bundled root store on every platform, not the operating system's store.

## Troubleshooting

**"enter a hostname or IP address".** The Host field is empty.

**"not a valid hostname" or "invalid port".** Check the Host entry for stray characters.

**"<address>: connection refused" or "no answer within 8 s".** Nothing is listening, or a firewall drops the traffic. Check the port.

**"TLS handshake failed: the server did not answer with TLS (wrong port, or STARTTLS needed?)".** The port speaks plain text first. Choose the right STARTTLS mode.

**"the server refused the handshake (no shared version, cipher or curve)".** The server only offers something this build cannot negotiate, such as TLS 1.0/1.1 or CBC suites.

**"the server does not recognise the SNI name".** Check the hostname, or try with Send SNI off.

**"STARTTLS: the server does not offer STARTTLS"** or "STARTTLS refused". The service does not support or allow the upgrade.

**"file larger than 1 MB; certificates and CSRs are much smaller".** You opened the wrong file.

## Related tools

- [Certificate Converter](cert-converter.md) to convert certificates and keys between PEM, DER, P7B and PFX.
- [HTTP Troubleshooter](http-troubleshooter.md) for HTTP-level checks on the same host.
- [Port Scanner](port-scanner.md) to find which TLS ports are open.
- [DNS Analyzer](dns-analyzer.md) to check MX hosts before testing their STARTTLS.
- [JWT / SAML Inspector](jwt-saml.md) to read certificates embedded in SAML messages.
