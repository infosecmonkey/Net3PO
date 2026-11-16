# DNS Benchmark

> Compare DNS resolvers over UDP, TCP, DNS over TLS (DoT) and DNS over HTTPS (DoH). Measures cached and uncached lookup times and loss, and checks DNSSEC validation and NXDOMAIN hijacking.

**Sidebar group:** Troubleshooting · **Works offline:** no (queries go to the resolvers you pick, only when you click Run) · **Needs admin rights:** no

## When to use it

- Pick the fastest resolver for a site, a home office or a lab.
- Compare the resolver this computer uses (DHCP, firewall, ISP) with public ones.
- Check that an internal resolver or firewall DNS proxy answers over DoT or DoH.
- Find resolvers that do not validate DNSSEC, or that answer for names that do not exist (NXDOMAIN hijacking, common on ISP resolvers).

## Quick start

1. Tick the resolvers to test. This computer's resolvers and four public ones are ticked by default.
2. Pick the transports. UDP, DoT and DoH are on by default.
3. Click **Run**. Results appear per resolver as each one finishes.
4. Click a public or custom resolver in the results for commands that switch this computer to it.

## Inputs and options

| Option | What it means | Default / accepted values |
|---|---|---|
| This computer | The resolvers the OS is configured with. | Ticked |
| Public | Built-in public resolvers (Cloudflare, Cloudflare Security, Google, Quad9, OpenDNS, AdGuard, CleanBrowsing, Control D). Hover for addresses and endpoints. | Cloudflare, Google, Quad9, OpenDNS ticked |
| Custom | Your own resolvers: an IP address, plus an optional DoH URL and DoT host name. Saved in the app data folder. | None |
| UDP, TCP, DoT, DoH | How queries are sent. A resolver is tested only over the transports it offers. | UDP, DoT, DoH |
| Also test public resolvers over IPv6 | Adds each public resolver's IPv6 address as a separate entry. | Off |
| DNSSEC and NXDOMAIN checks | Runs the checks below after the timing rounds. | On |
| Rounds | Measured queries of each kind per resolver and transport. | 10; 1 to 50 |

## What it measures

Resolvers are tested at the same time, each on its own. Within a resolver the transports take turns, so a network hiccup affects them alike.

- **Warm-up:** each transport connects, then sends a few popular names (not measured) so the resolver has them cached.
- **Cached:** popular names (google.com, wikipedia.org and so on). Shows how fast the resolver answers from its cache, which is most of everyday browsing.
- **Uncached:** a random name under a large zone that is not DNSSEC signed (google.com, microsoft.com, amazon.com, facebook.com). The resolver has to ask that zone's authoritative servers, so this shows its full lookup time.
- **Median / p90:** the middle value and the 90th percentile of the successful queries, in milliseconds.
- **Loss:** percent of queries with no usable answer (timeout, error, SERVFAIL or REFUSED). The higher of the cached and uncached loss is shown.
- **Connect:** TCP or TLS handshake time. DoT and DoH keep one connection open, so their per-query times do not include the handshake. For DoH, Connect is the first request including the connection.

A transport that fails three queries in a row is given up for the rest of the run.

## Checks

| Check | How | Result |
|---|---|---|
| DNSSEC | Queries `cloudflare.com` (signed) and `dnssec-failed.org` (deliberately broken) with the DNSSEC OK bit. | **Validates**: AD set on the signed name and SERVFAIL on the broken one. **Does not validate**: the broken name resolves. **Unknown**: anything else. |
| NXDOMAIN | Queries a random `.com` name, and watches the random names from the uncached rounds. | **Correct**: NXDOMAIN. **Hijacked**: the resolver returned addresses for a name that does not exist, usually a search or ad page. |

## Switching this computer's DNS

Net3PO does not change system settings. Click a resolver in the results for copy-ready commands for Windows (PowerShell as administrator), macOS (`networksetup`) and Linux (`resolvectl` or `nmcli`), with revert and cache flush commands. Replace the value in angle brackets with your interface, network service or connection name; the first command of each OS lists them.

## What the results do and do not tell you

- Results are from this computer and this network, right now. Run it at different times before deciding.
- Anycast resolvers answer from the nearest site; a VPN changes which site that is.
- A filtering resolver may answer blocked names differently; that does not show as loss.
- DoH is tested over HTTP/1.1. Servers that require HTTP/2 (Quad9's DoH, for example) are not tested over DoH, and say so.
- DoH and DoT connect to the resolver's IP address and check its certificate against the DoH URL's host or the DoT host name.

## Online activity and privacy

DNS queries for the test names go to the resolvers you tick, only when you click **Run**. Custom resolvers are stored in the app data folder as `dns_resolvers`. See [Privacy](../privacy.md).

## Troubleshooting

**DoT or DoH shows "timed out" or "Connection refused".** The network blocks TCP 853 or 443 to that address, or the resolver does not offer that transport on that address.

**DoH shows "server requires HTTP/2".** The server does not accept HTTP/1.1. Use DoT or UDP for that resolver.

**Certificate errors on DoT or DoH.** The host name does not match the server's certificate, or a firewall inspects TLS. Check the DoT host or DoH URL, or inspect the server with the [TLS Inspector](tls-inspector.md).

**This computer's resolver is 127.0.0.53 or similar.** That is a local stub (for example systemd-resolved); it forwards to the real resolvers, which [Network Snapshot](net-snapshot.md) lists.

**Every resolver shows 100% loss.** UDP and TCP 53 are blocked to the internet. Try DoT or DoH, or test the resolver your network provides.

## Related tools

- [Dig](dig.md) for single queries against one resolver.
- [DNS Analyzer](dns-analyzer.md) for zone audits (SPF, DMARC, DKIM, DNSSEC, NS).
- [Network Snapshot](net-snapshot.md) to see the DNS servers per interface.
- [TLS Inspector](tls-inspector.md) for DoT and DoH certificates.
