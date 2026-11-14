# MTU Calculator

> Stack encapsulations (PPPoE, VLAN, MPLS, GRE, IP-in-IP, VXLAN, WireGuard, IPsec ESP) on a link MTU and see the byte-by-byte overhead, the inner IP MTU and the TCP MSS to clamp.

**Sidebar group:** Utilities · **Works offline:** yes · **Needs admin rights:** no

## When to use it

- Pick the tunnel interface MTU and the TCP MSS clamp for a new IPsec, GRE or GRE-over-IPsec tunnel.
- Explain why large transfers stall over a VPN while pings and small pages work (classic MTU black hole).
- Check how much a PPPoE uplink, MPLS label stack or VXLAN overlay eats from a 1500 or 9000 byte path.
- Document the math behind an MTU change for a change request.

## Quick start

1. Open **MTU Calculator**. It starts with a 1500 byte link and one IPsec ESP tunnel layer (AES-GCM).
2. Set **Link IP MTU** to the IP MTU of the underlying link, or click **1500** or **9000**.
3. Either pick a **Preset**, or build the stack yourself with **+ add layer...**. Add layers outermost first.
4. Set each layer's options (outer IP version, cipher, flags).
5. Reorder with the up and down arrows, remove with the x button.
6. Read the inner IP MTU and MSS values, then check the byte breakdown and notes. Results update as you change anything.

## Inputs and options

| Field | What it means | Default / accepted values |
|---|---|---|
| Link IP MTU | IP MTU of the underlying link, before any encapsulation in the stack. | 1500. 68 to 65535. Buttons set 1500 or 9000. |
| Preset | Replaces the link MTU and layers with a common setup. | IPsec tunnel, AES-GCM; IPsec tunnel, AES-CBC + SHA-256, NAT-T; GRE over IPsec (transport); GRE; VXLAN; WireGuard over IPv6; PPPoE (DSL/fiber); PPPoE + IPsec tunnel, AES-GCM. All use 1500. |
| + add layer... | Appends a layer at the inner end of the stack. | Up to 12 layers. |
| PPPoE | PPPoE 6 bytes plus PPP 2 bytes. | No options. |
| 802.1Q VLAN tag | 1 tag or 2 tags (QinQ). | 1 tag. Counts 0 bytes against the IP MTU (see notes). |
| MPLS | Label stack, 4 bytes per label. | labels: 1 (1 to 8). |
| GRE | Outer IP header plus 4 byte GRE header. **key**, **sequence** and **checksum** each add 4 bytes. | outer IPv4, no flags. |
| IP-in-IP | Outer IP header only. | outer IPv4. |
| VXLAN | Outer IP, UDP 8, VXLAN 8, inner Ethernet 14. **inner VLAN tag** adds 4. | outer IPv4, no inner tag. |
| WireGuard | Outer IP, UDP 8, message header 16, Poly1305 tag 16. | outer IPv4. |
| IPsec ESP | **tunnel mode** (adds an outer IP header) or **transport mode**. Cipher: AES-GCM, ChaCha20-Poly1305, AES-CBC, 3DES/DES-CBC, NULL. Integrity: no separate integrity (AEAD), HMAC-SHA1 / MD5 (12), HMAC-SHA256 (16), HMAC-SHA384 (24), HMAC-SHA512 (32). **NAT-T** adds an 8 byte UDP header. | tunnel mode, outer IPv4, AES-GCM, no separate integrity, NAT-T off. |

Picking an AEAD cipher (AES-GCM, ChaCha20-Poly1305) sets integrity to none. Picking a CBC cipher while integrity is none sets it to HMAC-SHA256.

ESP cipher sizes used: AES-CBC IV 16, padding to 16. 3DES/DES-CBC IV 8, padding to 8. AES-GCM and ChaCha20-Poly1305 IV 8, padding to 4, 16 byte tag. NULL: no IV, padding to 4.

## Reading the results

The summary row shows four numbers:

- **inner IP MTU**: the largest inner IP packet that fits without fragmentation. Use it as the tunnel interface MTU.
- **TCP MSS, IPv4 inside**: inner MTU minus 40 (20 IP + 20 TCP).
- **TCP MSS, IPv6 inside**: inner MTU minus 60 (40 IP + 20 TCP).
- **bytes overhead**: link MTU minus inner MTU, including ESP padding at full size.

The breakdown table lists every header from the outside in, starting with the **link IP MTU** and ending with **left for the inner packet**. Each row names its layer number, the part and its size. ESP padding shows as a range, such as "2 to 17", because it depends on packet size. The inner MTU uses the largest packet that fits, and a note states what the padding actually costs at that size.

Notes below the table state the assumptions.

### Worked example: GRE over IPsec

Choose the **GRE over IPsec (transport)** preset: link 1500, layer 1 ESP transport mode with AES-CBC and HMAC-SHA1, layer 2 GRE with outer IPv4.

| Layer | Part | Bytes |
|---|---|---|
| | link IP MTU | 1500 |
| 1. ESP transport | IPv4 header of the protected packet (layer 2) | 20 |
| 1. ESP transport | ESP header (SPI, sequence) | 8 |
| 1. ESP transport | AES-CBC IV | 16 |
| 1. ESP transport | padding and trailer (pad length, next header); 16 alignment | 2 to 17 |
| 1. ESP transport | integrity check value | 12 |
| 2. GRE | GRE base header | 4 |
| | left for the inner packet | 1434 |

Result: inner IP MTU 1434, MSS 1394 (IPv4) and 1374 (IPv6), 66 bytes overhead. In transport mode the GRE packet's own IPv4 header stays outside ESP, so it is counted once under the ESP layer and not again under GRE. After the fixed headers, 1444 bytes remain; the largest ESP payload that fills whole 16 byte blocks with its 2 byte trailer is 1438, so padding costs 6 bytes here. The note reads "ESP padding varies with packet size (0 to 15 bytes plus a 2-byte trailer); the inner MTU uses the largest packet that fits, which costs 6 bytes here".

Other reference values at 1500: plain GRE 1476 (MSS 1436), GRE with key 1472, VXLAN 1450, PPPoE 1492 (MSS 1452), WireGuard 1440 over IPv4 and 1420 over IPv6.

## What the results do and do not tell you

- This is arithmetic on header sizes. It does not measure your path. Use [Traceroute](traceroute.md) in Path MTU mode to test a real path.
- It assumes no IP options, no IPv6 extension headers and TCP without options. TCP timestamps use 12 of the MSS bytes in practice.
- 802.1Q tags add 4 bytes per tag to the Ethernet frame, not the IP packet. They only lower the IP MTU on links that cannot carry the larger frame, so they count 0 here.
- PPPoE is a link-layer header. If you place it after a tunnel layer, a note says to put it before any tunnel.
- WireGuard pads inner packets to 16 bytes only when the MTU allows. The common 1420 figure assumes an IPv6 outer header.
- If the inner MTU is below 1280, a note warns that IPv6 cannot run over the path without fragmentation.
- Vendor implementations can add their own overhead (for example extra ESP options or proprietary headers). Treat the result as the protocol minimum.

## Online activity and privacy

None. All calculation is local. Nothing is saved unless you export. See [Privacy](../privacy.md).

## Export and projects

**Export** appears next to the summary when there is no error. Formats: HTML, PDF, Markdown, Plain text and **Redacted...** (see [Export and redaction](../export-and-redaction.md)), plus **Add to project**. The report title names the layer stack. It contains the link MTU, inner MTU, both MSS values and overhead, the byte breakdown table, and the assumption notes. See [Projects and notes](../projects-and-notes.md).

## Platform notes

Same on macOS, Windows and Linux.

## Troubleshooting

**"link MTU must be 68 to 65535".** Enter a link MTU in that range.

**"at most 12 layers".** Remove layers.

**"layer N: AES-GCM and ChaCha20-Poly1305 include their own integrity tag; choose no separate integrity".** Set integrity to "no separate integrity (AEAD)" for that layer.

**"layer N: a CBC cipher needs an integrity algorithm ..."** Choose an HMAC for the CBC cipher.

**"layer N: ESP transport mode protects a tunnel's packet (for example GRE); add the GRE or IP-in-IP layer after it, or use tunnel mode".** Transport mode needs a GRE, IP-in-IP, VXLAN or WireGuard layer directly below it in the list.

**"after layer N only X bytes remain; that is below the 68-byte IPv4 minimum".** The stack does not fit in the link MTU. Raise the link MTU or remove layers.

## Related tools

- [Traceroute](traceroute.md)
- [Subnet Calculator](subnet-calculator.md)
- [Fortinet Command Builder](forti-builder.md)
- [Debug Flow](debug-flow.md)
- [PCAP Inspector](pcap-inspector.md)
