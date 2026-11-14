# Troubleshooting and FAQ

Each tool page has its own **Troubleshooting** section. This page covers problems common to
the whole app.

## Installing and starting

**macOS says the app "cannot be opened" or "is damaged".** Builds are not yet notarized. Use
**System Settings > Privacy & Security > Open Anyway**, or run
`xattr -dr com.apple.quarantine /Applications/Net3PO.app`.

**Windows SmartScreen blocks the installer.** Builds are not yet code-signed. Click
**More info > Run anyway**.

**The AppImage does nothing on Ubuntu.** Install FUSE 2: `sudo apt install libfuse2`
(`libfuse2t64` on 24.04). Or use the `.deb`.

**I only have an `.rpm` on Ubuntu.** Every release also has a `.deb` and an `.AppImage` under
**Assets** on the release page.

## Permissions and ports

**"Permission denied" or "address in use" when starting a server.** Ports below 1024 (syslog
514, TFTP 69) need extra rights on macOS and Linux. Pick a port above 1024 (for example 5514 or
6969) and point the device at it, or grant the right for that port only as the tool explains.
"Address in use" means another program already listens there; stop it or pick another port.

**A tool says it needs privileges.** Net3PO never needs to run as administrator. The message
names the one thing that tool needs on your OS. Other tools keep working.

**The OS firewall asks to allow Net3PO.** Allow it only if you want the listeners (Syslog, TFTP,
DHCP Monitor, Socket Tools listen mode) to receive traffic from other hosts.

## Results

**A scan or check says "filtered", "no answer" or "inconclusive".** That is deliberate. Silence
can mean a firewall, rate limiting or a dead host, and the tool does not guess. Read the tool's
**What the results do and do not tell you** section.

**Results differ from another tool.** Check which DNS server, source interface and timeout each
tool used. Net3PO shows these in the result.

## Notes and projects

**My note did not save.** Notes are drafts until you click **Save**, and a project must be
selected. The draft is kept even if you hide the panel or quit.

**Where are my projects?** In the app data folder; see [Privacy and data](privacy.md).

## Reporting a problem

Open an issue on [GitHub](https://github.com/infosecmonkey/Net3PO/issues) with your OS and
Net3PO version (shown in the About dialog), the steps, and the message shown. Never attach
real device configs, captures or logs from production networks; the repository is public.
Use [redacted export](export-and-redaction.md#redacted-export) or made-up data instead.
