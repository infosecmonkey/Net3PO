# JWT / SAML Inspector

> Decode JWTs and SAML messages, check a JWT signature with a key you supply, and compare times, issuer and audience with what your application expects.

**Sidebar group:** Analysis · **Works offline:** yes (nothing is fetched, saved or logged) · **Needs admin rights:** no

## When to use it

- An SSO login fails and you need to see the claims, audience and validity window in the token or assertion.
- You are troubleshooting a FortiGate SAML VPN or admin login and have `diagnose debug application samld -1` output, a SAML-tracer export or a HAR file.
- You want to confirm a JWT verifies with the issuer's public key or shared secret, and that the algorithm is the one your app pins.
- You suspect clock skew between an identity provider and a service provider.

## Quick start

**JWT**

1. Open **JWT / SAML Inspector** and stay on the **JWT** tab.
2. Paste the token into the box. A leading `Bearer ` is stripped.
3. The token decodes as you type. Read **Decoded**, **Signature** and **Application checks**.
4. To verify the signature, paste the HMAC secret or the issuer's PEM public key or certificate into **Key**.
5. Fill in **Expected issuer**, **Expected audience** and **Expected algorithm** to compare them with the token.
6. Use **Export** to save a report or add it to a project.

**SAML**

1. Switch to the **SAML** tab.
2. Paste a capture, a URL with `SAMLRequest=`, a `SAMLResponse` value or the XML. Or click **Open capture...**.
3. If several messages are found, click the one you want in the list of chips.
4. Fill in the expected IdP issuer, audience and ACS URL.
5. Read the message fields, **Checks** and **Signatures**. Expand **Decoded XML** for the full message.

## Inputs and options

**JWT tab**

| Field | What it means | Default / accepted values |
|---|---|---|
| Token box | The JWT to decode. Whitespace is removed and a `Bearer ` prefix is stripped. | Compact JWS, three dot-separated parts, up to 64 KB. |
| Expected issuer (iss) | Compared exactly with the `iss` claim. | Empty means not checked. |
| Expected audience (aud) | Must appear in `aud` (string or array). | Empty means not checked. |
| Expected algorithm | Pins the algorithm. If the header names a different one, the signature is reported invalid. | "use the header's (not pinned)", HS256, HS384, HS512, RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384, EdDSA. |
| Clock skew allowed (s) | Grace period for `exp`, `nbf` and `iat`. | 60. 0 to 3600. |
| Key | HMAC secret (for HS*) or a PEM public key or certificate (for RS*, PS*, ES*, EdDSA). | Kept in memory only. |

**SAML tab**

| Field | What it means | Default / accepted values |
|---|---|---|
| Input box | Any text holding SAML. | SAML-tracer JSON, browser HAR, FortiGate samld debug output, an HTML login form, a URL or form body with `SAMLRequest=` / `SAMLResponse=`, a Base64 value or raw XML. Up to 32 MB. |
| Open capture... | Loads a file into the box. | `.json`, `.har`, `.txt`, `.log`, `.xml`, `.html`, or any file. Up to 32 MB. |
| Message chips | Shown when more than one message is found. Pick one to inspect. | Up to 50 messages, duplicates dropped. Hover for source and line. |
| Expected IdP issuer | Compared with the assertion issuer (or the response issuer if the assertion has none). | Empty means not checked. |
| Expected audience (SP entity ID) | Must appear among the assertion's audiences. | Empty means not checked. |
| Expected ACS URL (Destination / Recipient) | Compared with the Destination attribute and the SubjectConfirmation Recipient. | Empty means not checked. |
| Clock skew allowed (s) | Grace period for NotBefore and NotOnOrAfter. | 60. 0 to 3600. |

## Reading the results

**JWT.** A bar shows the header's `alg` and the Export menu. Three panels follow:

- **Decoded**: the header and claims as formatted JSON, and a table of `exp`, `nbf` and `iat` as UTC times.
- **Signature**: one of "valid", "invalid", "not checked (no key)", "unsigned (alg none)" or "could not check", with a detail line. "Could not check" carries the reason, for example "an HMAC algorithm needs the shared secret, not a public key (this is the classic algorithm-confusion mistake)" or "algorithm ES256 does not match a RSA key, or is not supported". If the header holds `jku`, `x5u`, `jwk`, `x5c` or `kid`, they are listed under **Key references in the header**: "Shown only. Net3PO never fetches keys a token points to; trusting them would let the token choose its own key."
- **Application checks**: pass (green), fail (red) or info lines for Expiry (exp), Not before (nbf), Issued at (iat) in the future, Issuer (iss), Audience (aud), and an Algorithm note when a signature verified with an unpinned algorithm. A token with no `exp` gets "no exp claim: the token never expires on its own".

Example: a token with `"iss": "https://idp.example.com"`, `"aud": "api.example.net"` and an `exp` two hours ago shows Signature "not checked (no key)" and the check "Expiry (exp): expired 2 h ago". With Expected audience set to `app.example.org` you also get "token audience ["api.example.net"] does not include "app.example.org"".

**SAML.** When messages are found, a line says which one (for example "Found a Response (SAMLResponse parameter, line 12).") or shows chips to choose from. A bar shows the binding: "POST binding (Base64)", "POST binding (Base64, URL-encoded)", "Redirect binding (Base64 + DEFLATE)" or "raw XML".

- **Message panel**: message type, binding, ID, issue instant, Destination, InResponseTo, issuer, status, assertion issuer, NameID and format, Recipient, NotBefore, NotOnOrAfter, SubjectConfirmation NotOnOrAfter, audiences, AuthnInstant and SessionIndex (empty fields are hidden), then the **Attributes** table.
- **Checks**: Status (pass on Success), the Conditions and SubjectConfirmation time windows against your clock and skew, Audience, Destination, Recipient and Issuer against your expectations, "no XML signature present" (fail), SHA-1 signatures (fail), an expired embedded signing certificate (info) and an encrypted assertion (info).
- **Signatures**: for each XML signature, what it covers (Response or Assertion), the signature and digest methods, a SHA-1 tag when weak, and the embedded certificate's subject, expiry and SHA-256 fingerprint.

## What the results do and do not tell you

- Decoded, signature-valid and application-valid are separate results. A token can decode cleanly and still fail every check.
- For JWTs, the signature is verified cryptographically only when you supply the key. Encrypted JWTs (JWE, five parts) cannot be read: "its claims cannot be read without the decryption key".
- "XML signatures are located and described here, not cryptographically verified. Compare the certificate fingerprint with the one your SP trusts."
- An encrypted assertion's contents need the SP's private key and are not shown.
- The "no XML signature present" check also fires for messages that are normally signed outside the XML, such as a Redirect-binding AuthnRequest. Judge it by message type.
- Limits: JWT 64 KB; one SAML message 1 MB of input and 4 MB of decoded XML, nesting depth 64; Decoded XML display is cut at 200,000 characters.

## Online activity and privacy

Nothing goes online. Key references in a token are shown, never followed. Tokens, keys and messages stay in memory only and are not saved or logged.

## Export and projects

Each tab has an **Export** menu: HTML, PDF, Markdown, Plain text, **Redacted...** and **Add to project**. See [Export and redaction](../export-and-redaction.md) and [Projects and notes](../projects-and-notes.md).

The JWT report holds the decoded header and claims, the signature state and detail, any key references (marked not followed) and the application checks. The SAML report holds the message fields, attributes, the signatures table and the checks. Reports never include the raw token, message or key. Decoded claims and attributes can still contain user names and email addresses, so use **Redacted...** before sharing.

## Platform notes

No differences between macOS, Windows and Linux.

## Troubleshooting

**"a JWT has three dot-separated parts; this has N".** The paste is truncated or includes extra text.

**"the header is not JSON" or "the ... is not valid base64url".** The token is damaged, or it is not a JWT.

**"no PEM public key or certificate found".** For RS, PS, ES or EdDSA tokens, paste a `-----BEGIN PUBLIC KEY-----` or `-----BEGIN CERTIFICATE-----` block. JWKS JSON is not accepted.

**Signature "invalid" with a message about the expected algorithm.** The header's `alg` differs from Expected algorithm. That is the intended protection.

**"No SAML message found. Paste a SAML-tracer export, a HAR file, ...".** No recognizable SAML was in the text. For FortiGate, paste the `diagnose debug application samld -1` output captured during a login.

**"not SAML XML, Base64 or a SAMLResponse/SAMLRequest parameter" or "decoded data is neither XML nor DEFLATE-compressed XML".** The value was cut short or double-encoded.

**"capture larger than 32 MB".** Trim the HAR or log to the login.

## Related tools

- [TLS Inspector](tls-inspector.md) to decode the IdP signing certificate in full.
- [Encoder Workbench](encoder-workbench.md) for other Base64, URL and compression layers.
- [Timestamp Converter](timestamp-converter.md) for epoch values in claims.
- [Debug Flow Parser](debug-flow.md) for FortiGate session-level troubleshooting.
