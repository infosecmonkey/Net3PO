# Encoder Workbench

> Chain Base64, Base32, hex, URL, HTML entity, ROT13 and compression steps, and see each intermediate result as text or hex.

**Sidebar group:** Analysis · **Works offline:** yes (nothing is executed or rendered) · **Needs admin rights:** no

## When to use it

- A log field, URL parameter or alert holds an encoded blob and you need to peel it back one step at a time.
- You want to check what a value looks like after URL encoding or Base64 before putting it into a config, API call or test.
- A payload is Base64 of gzip of something else, and you want to see each stage instead of guessing.
- The [Script Decoder](script-decoder.md) could not resolve a custom chain and you want to decode the payload by hand.

## Quick start

1. Open **Encoder Workbench** from the Analysis group.
2. Paste the text into **Input**. Tick **input is hex bytes** if you are pasting hex.
3. Pick a step from **+ add step...**, for example **Base64 decode**.
4. Read the step's result. If the bar under the last step says **Looks like it could be:**, click a suggestion to add that step.
5. Keep adding steps until the result is readable. Reorder with the arrows or remove a step with the cross on its chip.
6. Click **Copy result** for the final output, or **Export** for a report.

## Inputs and options

| Field | What it means | Default / accepted values |
|---|---|---|
| Input | Text to encode or decode. | Up to 5 MB. |
| input is hex bytes | Treat the input as hex bytes instead of text. | Off. Spaces are allowed in the hex. |
| + add step... | Appends a step to the chain. | See the list below. Up to 30 steps. |
| Step chips | Each step in order, with move up, move down and remove buttons. | |
| Clear | Removes all steps. | Shown when there are steps. |
| Text / Hex (per result) | Switches a result between text and a hex dump. | Shown when the result is valid text. |
| Suggestions | One-click steps guessed from what the final result looks like. | |
| Copy result | Copies the final result (text, or hex for binary output). | |

Available steps:

- **Decode**: Base64 decode, Base64url decode, Base32 decode, Hex decode, Base85 decode, URL decode, URL decode (+ as space), HTML entity decode.
- **Encode**: Base64 encode, Base64url encode (no padding), Base32 encode, Hex encode (lowercase), URL encode, HTML entity encode.
- **Other**: ROT13, Gzip decompress, Zlib/deflate decompress, XZ/LZMA decompress, Gzip compress.

The chain recalculates about 200 ms after any change. Base64 decoding is lenient: characters outside the alphabet are dropped and padding is optional.

## Reading the results

With no steps, the input is shown with its byte count. With steps, each one gets a box headed by its number and name:

- The byte count of its output and a **Text** / **Hex** toggle.
- The output as text, or "Binary content, shown as hex." with a hex dump (offset, hex bytes, ASCII) when it is not valid text.
- A note when something was partly handled, for example "N unrecognized named reference(s) left as written" after HTML entity decode.
- A hint when the output looks like a JWT or a SAML message (see below).
- If a step fails, its box shows **Stopped here:** with the reason, and later steps are not run.

Below the last successful step, **Looks like it could be:** offers next steps based on the bytes: Gzip, XZ or Zlib decompress from their magic bytes, Hex decode for even-length hex, Base64 or Base64url decode for strings in those alphabets, URL decode when `%XX` escapes are present, and HTML entity decode when entities are present.

Example: input `H4sIAAAAAAAA/...` (Base64 text). Add **Base64 decode**: the result is binary and shown as hex starting `1f 8b`, and the bar suggests **+ Gzip decompress**. Add it: the result is readable text, for example `GET /login?next=https%3A%2F%2Fapp.example.com%2F`, and the bar now suggests **+ URL decode**. One more click gives `GET /login?next=https://app.example.com/`.

## What the results do and do not tell you

- "Decoded output is shown as text only; nothing was executed or rendered."
- Suggestions are guesses from the shape of the data. A string of letters and digits can match Base64 by accident.
- For a JWT: "Base64url-decoding each part shows its header and claims, but nothing here checks its signature or validity." Use the [JWT / SAML Inspector](jwt-saml.md) for that.
- For SAML: "Decoding shows its XML; nothing here validates its signature or conditions."
- Limits: 5 MB input, 30 steps, 10 MB output per step. On screen, text is shown up to the first 256 KB and hex up to the first 4 KB.

## Online activity and privacy

Nothing goes online. Input and results stay in memory and are not saved unless you export or add to a project.

## Export and projects

The **Export** menu appears next to **Copy result** when the whole chain succeeded. It offers HTML, PDF, Markdown, Plain text, **Redacted...** and **Add to project**. See [Export and redaction](../export-and-redaction.md) and [Projects and notes](../projects-and-notes.md).

The report lists the steps (number, name, ok or failed, bytes out, and any note or error, starting with the input size) and the first 4 KB of the final output as text, or the first 64 lines of its hex dump for binary output. The original input is not included separately.

## Platform notes

No differences between macOS, Windows and Linux.

## Troubleshooting

**"Stopped here: not valid Base64, or larger than 10 MB when decoded".** The data at that step is not in that encoding (or decodes to more than 10 MB). Check the step order, or try Base64url.

**"Stopped here: bad percent escape at byte N".** URL decode found a `%` not followed by two hex digits.

**"input is not valid hex".** Untick **input is hex bytes**, or remove non-hex characters.

**"input larger than 5 MB" or "more than 30 steps".** Reduce the input or the chain.

**"output larger than 10 MB".** A step (usually decompression) produced too much data and was stopped.

**Copied result is shorter than expected.** Very large text results are displayed, and copied, up to the first 256 KB.

## Related tools

- [Script Decoder](script-decoder.md) for automatic decoding of obfuscated scripts.
- [JWT / SAML Inspector](jwt-saml.md) to read and check tokens and SAML messages.
- [Hash Calculator](hash-calculator.md) to hash a decoded value.
- [IOC Extractor](ioc-extractor.md) to pull indicators from decoded text.
