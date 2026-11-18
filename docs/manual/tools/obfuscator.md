# Obfuscator

> Replace IP addresses, hostnames, accounts, secrets, MAC addresses and serial numbers in pasted text before it goes to an AI assistant, a support ticket or an email, then put the real values back into the reply.

**Sidebar group:** Utilities · **Works offline:** yes · **Needs admin rights:** no

## When to use it

- You want help from an AI assistant with a FortiGate config, a debug log or command output, without sending your addresses, device names, accounts or secrets.
- You are opening a vendor support case and need to attach output without customer details.
- You are emailing a colleague outside the organization and want to strip identifying details first.
- The assistant answered using the replaced values, and you want the answer with your real addresses and names before you act on it.

## Quick start

1. Open **Obfuscator** from the Utilities group.
2. Leave every category ticked, or untick what you want to keep readable.
3. Paste the text and click **Obfuscate** (or press Ctrl or Cmd + Enter).
4. Read the highlighted output and the **Replacements** table. Add rules for anything that was missed and obfuscate again.
5. Click **Copy output** and paste it where you need it.
6. When the reply comes back, open **Restore**, paste the reply and click **Restore**.
7. Click **Copy** to take the reply with your real values.

## Inputs and options

| Field | What it means | Default / accepted values |
|---|---|---|
| IP addresses | IPv4 and IPv6 addresses. Masks such as `255.255.255.0`, loopback, multicast and documentation ranges are kept. | On |
| Hostnames and domains | Domain names, plus device names from `set hostname`, `hostname`, `sysname` and `Hostname:` lines. A device name is then replaced everywhere it appears, for example in the CLI prompt. | On |
| Email addresses | Each address becomes `[USER-n]@[HOST-n]`, with the domain sharing its host token. | On |
| Usernames | `user=` style fields, `DOMAIN\user`, `set username`, and the account names under FortiOS `config system admin`, `config user local` and `config system snmp user`, plus `config user group` members. `admin` and `root` are kept. | On |
| Passwords, keys and tokens | Every FortiOS `set <name> ENC <value>`, Cisco secrets, `password=` style fields, SNMP community names, AWS, GitHub and Slack keys, JWTs and bearer tokens. Private key blocks are removed. | On |
| MAC addresses | `00:11:22:33:44:55`, `00-11-22-33-44-55` and `0011.2233.4455`. Broadcast and multicast MACs are kept. | On |
| Serial numbers | Fortinet serial numbers (FortiGate, FortiAP, FortiSwitch and others) and `Serial-Number:` or `serial=` fields. | On |
| Certificates | Removes PEM certificate blocks, which name the organization. | On |
| Addresses | **Fake addresses that keep subnets and vendors**, or **Numbered tokens** (`[IP-1]`, `[MAC-1]`). | Fake addresses |
| Rules | One per line: `find` gives a numbered `[CUSTOM-n]` token, `find => replacement` uses your replacement, `re:regex => replacement` matches a regular expression. Use it for customer, site and project names. | Empty |
| Keep (never replace) | One per line: a domain (covers its subdomains), an IPv4 address or a CIDR range. | Empty |
| Put secrets back too | On the Restore tab: also restore `[SECRET-n]` tokens. Leave it off when the restored text goes into a ticket. | Off |

Your categories, rules and exclusions are remembered on this computer.

## Reading the results

The output shows every replacement highlighted by type: IPs blue, hosts green, users purple, secrets red, MACs amber, serials pink and rule matches light green. The line above it counts the replacements by type, plus any private keys and certificates removed.

The **Replacements** table lists each distinct original value, what replaced it and how often it appeared in this paste. Secrets are masked until you tick **Show secrets**.

### Fake addresses

With **Fake addresses that keep subnets and vendors**, an assistant can still reason about routing, policies and ARP tables:

- Private addresses stay private and public addresses stay public.
- Two addresses in the same /8, /16 or /24 stay in the same fake /8, /16 or /24.
- The last octet is kept, and `0` and `255` are kept in the middle octets. `10.20.30.0/24`, its gateway `.1` and `10.20.0.0/16` still read as a network, a gateway and a supernet.
- In subnets where only zeros or 255s could change, such as `10.0.0.x` and `192.168.0.x`, the last octet is changed instead (`.0` and `.255` stay).
- IPv6 works per 16-bit group: the /48 and /64 structure is kept, as are zero groups and link-local and unique-local prefixes.
- MAC addresses keep their vendor prefix (OUI), notation and letter case.

Example, with documentation-style values:

```text
set ip 10.20.30.1 255.255.255.0      ->  set ip 10.84.158.1 255.255.255.0
set gateway 10.20.30.254             ->  set gateway 10.84.158.254
set password ENC SH2xyz...           ->  set password ENC [SECRET-1]
set macaddr 00:09:0f:aa:bb:cc        ->  set macaddr 00:09:0f:9d:06:8e
```

Subnets that do not end on an octet boundary (a /20, a /27) keep their host part but not their exact boundary.

### Sessions

A session holds a random key and the mapping from original values to replacements. Every paste in the same session reuses it, so a config pasted now and a log pasted later use the same fakes and tokens. The header shows how many values the session has mapped. **New session** discards the mapping and the key, after asking.

### Restore

Restore finds this session's tokens and fake addresses in the reply, wherever and however the reply writes them (a fake address with a `/24` after it, a MAC in another notation), and puts the original values back in one pass. Tokens the session never produced, such as an `[IP-9]` the assistant made up, are left as they are and listed. Fixed replacements from your rules are restored as whole words.

## What the results do and do not tell you

- Detection uses patterns and context (a `password=` field, a FortiOS section). It cannot know every internal name, ticket number or customer name. Always read the output and add rules for anything left.
- Object names in configs (interface aliases, address objects, tunnel names, comments) are not replaced unless a rule matches them, because the config needs them to make sense.
- Fake addresses are a keyed pseudonym, not encryption. They hide the real values from the reader, but the structure (which hosts share a subnet, the last octet) stays visible on purpose.
- Pasting already-obfuscated text into the same session replaces the fakes a second time. Paste original text.
- Text is limited to 5 MB. Output over 1 MB is shown without highlighting.

## Online activity and privacy

Nothing leaves this computer. The session mapping and key are kept in memory only. They survive switching tools, are cleared when you quit the app or start a new session, and are never written to disk. Only the checkbox settings, rules and exclusions are saved, in the app data folder.

## Export and projects

The Obfuscator has no export. Copy the output instead. To redact a tool's report, use **Export > Redacted...**, described in [Export and redaction](../export-and-redaction.md).

## Platform notes

Works the same on macOS, Windows and Linux.

## Troubleshooting

**"the text is larger than 5 MB".** Split the text and obfuscate it in parts in the same session.

**"the session holds too many values".** Start a new session.

**"rule n is not a valid regular expression".** Fix or remove that `re:` line in Rules.

**Restore changed nothing.** The reply was obfuscated in an earlier session, or the app was restarted since. Restore only works with the current session.

**A name was not replaced.** Add it as a rule, for example `Acme Widgets => Customer`.

## Related tools

- [Export and redaction](../export-and-redaction.md), the same engine for tool reports.
- [IOC Extractor](ioc-extractor.md) to list the indicators in a text.
- [Config Diff](config-diff.md) to compare configs before sharing them.
