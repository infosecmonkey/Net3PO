# Certificate Converter

> Read certificates, chains, private keys and CSRs in any common format, see how the chain fits together and which key matches, then save them as PEM, DER, P7B, PFX or another key format.

**Sidebar group:** Analysis · **Works offline:** yes · **Needs admin rights:** no

## When to use it

- A CA sent a `.p7b` or a `.cer` and the firewall, load balancer or web server wants PEM.
- You need a `.pfx` for Windows, IIS, Azure or a FortiGate import, and have a certificate, key and intermediates as separate files.
- You have a `.pfx` and need the certificate, chain and key as PEM files.
- An import fails with "key does not match" and you want to know which key goes with which certificate.
- A chain is incomplete and you need to know which intermediate is missing.

It replaces the usual `openssl pkcs12`, `openssl x509`, `openssl crl2pkcs7` and `openssl pkey` commands, on every OS, without OpenSSL installed.

## Quick start

1. Click **Open files**, drop files on the window, or click **Paste text** and paste PEM blocks.
2. If a PFX or encrypted key is loaded, type its **Password** and press Enter.
3. Check the **Chain** and **Private keys** sections.
4. Under **Convert**, pick a format and click **Save...**. For certificate PEM you can also **Show** or **Copy** the text.

## What it reads

| Input | Notes |
|---|---|
| PEM certificates and bundles | `BEGIN CERTIFICATE`, any number per file, any order. |
| DER certificates | `.cer`, `.der`, `.crt` in binary. |
| P7B / PKCS#7 | Binary or `BEGIN PKCS7`, including the indefinite-length form Windows writes. |
| PFX / PKCS#12 | Modern (AES, SHA-256) and legacy (3DES, RC2-40, SHA-1). Needs the password. |
| Private keys | PKCS#8 (`BEGIN PRIVATE KEY`), encrypted PKCS#8 (`BEGIN ENCRYPTED PRIVATE KEY`), RSA (`BEGIN RSA PRIVATE KEY`, PKCS#1), EC (`BEGIN EC PRIVATE KEY`, SEC1), and DER versions. RSA, EC P-256, P-384, P-521 and Ed25519. |
| Legacy encrypted PEM keys | `Proc-Type: 4,ENCRYPTED` with AES-128/192/256-CBC or DES-EDE3-CBC. |
| CSRs | `BEGIN CERTIFICATE REQUEST`; shown with the key they match. |
| Bare base64 | A DER or PFX file pasted as base64 without PEM lines. |

Duplicates are dropped. Up to 20 files of 10 MB each.

## Chain and key matching

- **Chain** starts at the certificate a loaded key matches (or, without a key, the one that issued nothing else), then follows each issuer. Roles: **Leaf**, **Intermediate**, **Root**, or **Self-signed** when the leaf issued itself.
- **Issuer not loaded** names the certificate needed to complete the chain.
- **Other certificates** are loaded but not part of this chain.
- **Private keys** shows each key's type and the certificate it matches, by comparing the public key (RSA modulus and exponent, EC point, Ed25519 key). "Matches no loaded certificate" usually means the wrong key file.
- Click a certificate for subject, issuer, SANs, validity, key, signature algorithm, serial, key usage, SHA-256 and SHA-1 fingerprints, and notes such as weak keys or SHA-1 signatures.

## Output formats

| Format | Contains | Typical use |
|---|---|---|
| PEM chain | Leaf, then intermediates; optionally the root | Web servers, load balancers, FortiGate certificate import |
| PEM certificate | Leaf only | Devices that take the chain separately |
| DER certificate | Leaf only, binary | Windows `.cer`, some appliances |
| P7B / PKCS#7 | Leaf and intermediates, binary or PEM; optionally the root | Windows, Java, chain without a key |
| PFX / PKCS#12 | Key, leaf and chain, password protected | Windows, IIS, Azure, FortiGate, macOS Keychain |
| Key, PKCS#8 PEM | Private key, unencrypted | Most modern software |
| Key, traditional PEM | `RSA PRIVATE KEY` or `EC PRIVATE KEY`, unencrypted | Older software that rejects PKCS#8 |
| Key, DER | PKCS#8, binary, unencrypted | Java and some appliances |

**Include the root** is off by default: servers should not send the root, since clients already have it.

**PFX** needs a password. The default encryption is AES-256 with a SHA-256 MAC, as OpenSSL 3 writes. Tick **Legacy encryption** for 3DES with a SHA-1 MAC when an older device or Windows Server 2016 or earlier refuses the file. The PFX is only written when the key matches the leaf.

## What the results do and do not tell you

- The chain is built from what you loaded. It does not check revocation or whether the root is trusted; use the [TLS Inspector](tls-inspector.md) against the live server for that.
- "Key matches" compares public keys. It does not test that the key can sign.
- Ed25519 keys have no traditional PEM format; use PKCS#8.

## Online activity and privacy

None. Files are read only when you open or drop them, and nothing is saved by the app. Private keys and passwords stay in memory until you click **Clear** or quit the app; key files are written only where you choose in the save dialog. Unencrypted key outputs are marked as such. See [Privacy](../privacy.md).

## Troubleshooting

**"A PFX or encrypted key needs its password."** Type the password in the **Password** box and press Enter.

**"The password did not open a PFX or encrypted key."** Check the password. Some exports use an empty password; clear the box and press Enter.

**"Matches no loaded certificate."** The key belongs to another certificate, often an earlier renewal. Load the matching certificate or the right key.

**"Issuer not loaded."** Download the intermediate from the CA (the certificate's CA Issuers URL, shown in the [TLS Inspector](tls-inspector.md)) and add it.

**"Unsupported encryption scheme"** on a PFX. The file uses an algorithm this tool does not read. Export it again from the source with AES or 3DES.

**"unsupported key encryption"** on a legacy PEM key. Only AES-CBC and DES-EDE3-CBC are supported; re-export the key as PKCS#8.

## Related tools

- [TLS Inspector](tls-inspector.md) to decode a certificate or inspect a live server's chain.
- [JWT / SAML Inspector](jwt-saml.md) for certificates inside SAML metadata.
- [Fortinet Command Builder](forti-builder.md) for FortiGate configuration.
