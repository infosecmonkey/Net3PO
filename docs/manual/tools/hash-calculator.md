# Hash Calculator

> Compute SHA-256, SHA-512, SHA-1 and MD5 for text or a file, and check the result against an expected digest.

**Sidebar group:** Utilities · **Works offline:** yes · **Needs admin rights:** no

## When to use it

- Verify a firmware image, ISO or installer against the checksum on the vendor's download page before you load it on a device.
- Get the hash of a suspicious file to look it up in your threat intel platform, or to record it in an incident note.
- Confirm two copies of a config or capture are byte-identical.
- Hash a short string, such as a test value, to compare with what an application or script produced.

## Quick start

1. Open **Hash Calculator**.
2. For a file, click the **File** tab, then **Choose file...** and pick the file. For text, stay on **Text** and type or paste into the box.
3. Wait for the progress bar to finish (files only). Large files can be stopped with **Stop**.
4. Paste the vendor's checksum into **Expected digest (optional)**.
5. Read the verdict line: green for a match, red for no match. The matching row is highlighted.
6. Click **Copy** next to any digest, or use **Export** to save the result.

## Inputs and options

| Field | What it means | Default / accepted values |
|---|---|---|
| Text / File tabs | Choose what to hash. Switching tabs clears the current digests. | Text |
| Text box (Text tab) | Hashed as UTF-8 bytes exactly as typed. Digests update as you type. | Empty |
| Choose file... (File tab) | Opens the system file picker. The file is read in 1 MB chunks and never modified. | Any file you can read |
| Stop | Appears while a file is being hashed. Cancels the read; the panel shows "Stopped." | |
| Expected digest (optional) | A digest to check against all four computed digests. | Hex in any case. Spaces and colons are removed. Also accepts a `sha256sum` / `md5sum` line (digest, then file name), `SHA256 (file) = <digest>` (BSD style) and `sha256:<digest>` or `sha256=<digest>` forms. |

## Reading the results

From top to bottom:

1. **Verdict line** (only when an expected digest is entered). One of:
   - "Matches the SHA-256 digest. A match shows the bytes are the same as whatever produced this digest; it says nothing about whether that source is trustworthy." (green)
   - "Does not match: the expected value looks like SHA-256, and the SHA-256 digest differs." (red). The algorithm is guessed from the length: 32 hex digits is MD5, 40 is SHA-1, 64 is SHA-256, 128 is SHA-512.
   - "Does not match, and its length (N hex digits) fits none of SHA-256, SHA-512, SHA-1 or MD5." (red)
   - "The expected value is not hexadecimal." (red)
2. **Byte count** of what was hashed.
3. **Digest table**: SHA-256, SHA-512, SHA-1 and MD5 in lowercase hex. SHA-1 and MD5 carry a **legacy** badge. The row that matched the expected digest is highlighted.

The expected value is compared with every algorithm, so you do not need to say which one it is.

### Worked example

On the **Text** tab, type `hello` (five characters, no newline):

- Bytes: 5
- SHA-256: `2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824`
- MD5: `5d41402abc4b2a76b9719d911017c592`

Paste `MD5 (hello.txt) = 5D41402ABC4B2A76B9719D911017C592` into **Expected digest**. The verdict reads "Matches the MD5 digest", and the MD5 row is highlighted.

Now press Enter in the text box so it holds `hello` plus a newline. The SHA-256 becomes `5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03` and the check fails. This is the usual reason a hash of typed text differs from `echo hello | sha256sum`, which also includes the newline.

## What the results do and do not tell you

- A match proves the bytes are the same as whatever produced the expected digest. It does not prove the source is trustworthy. If the checksum came from the same compromised page as the file, it proves nothing.
- MD5 and SHA-1 are legacy formats. They are fine for spotting corruption, not for proving a file was not tampered with. Prefer SHA-256 or SHA-512 when the vendor publishes them.
- Text is hashed exactly as typed. A trailing newline, a trailing space, or CRLF instead of LF line endings change every digest.
- Only the four listed algorithms are supported. There is no HMAC, CRC or SHA-3.
- Files are streamed, so there is no size limit beyond read time.

## Online activity and privacy

None. Hashing runs locally, and no digest is sent to any lookup service. The file is opened read-only. Nothing is saved unless you export. See [Privacy](../privacy.md).

## Export and projects

**Export** appears once digests exist. Formats: HTML, PDF, Markdown, Plain text and **Redacted...** (see [Export and redaction](../export-and-redaction.md)), plus **Add to project**. The report includes the source (the file name, or "text input"), the byte count, all four digests with legacy labels, the legacy note, and, if an expected digest was entered, a pass or fail finding with the normalized expected value. It does not include the text you hashed or the file's full path. See [Projects and notes](../projects-and-notes.md).

## Platform notes

Same on macOS, Windows and Linux. The file picker is the native one for each OS.

## Troubleshooting

**"could not open PATH: ..."** The file cannot be opened, usually a permission problem or a file that was moved. Check you can open it in another app.

**"reading PATH: ..."** A read error part way through, for example a removed USB drive or network share. Copy the file locally and try again.

**"Stopped."** You clicked **Stop**. Choose the file again to restart.

**The vendor checksum does not match.** Check the algorithm the vendor lists, and that you downloaded the exact build and file named. If the verdict says the length fits no algorithm, part of the digest is missing or extra characters were pasted.

**A `sha256sum` line from a Windows path is not recognized.** A drive letter colon in the file name can confuse the line parsing. Paste only the digest.

## Related tools

- [IOC Extractor](ioc-extractor.md)
- [Encoder Workbench](encoder-workbench.md)
- [Script Decoder](script-decoder.md)
- [PCAP Inspector](pcap-inspector.md)
- [TFTP Server](tftp-server.md)
