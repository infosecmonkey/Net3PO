# Installing Net3PO

Net3PO is free and open source (Apache-2.0). Download installers from the
[latest release](https://github.com/infosecmonkey/Net3PO/releases/latest) (older ones are on the
[Releases page](https://github.com/infosecmonkey/Net3PO/releases)). Each release lists
`SHA256SUMS.txt`; check your download against it before installing.

| Platform | File | Notes |
|---|---|---|
| macOS (Apple Silicon and Intel) | `Net3PO_<version>_universal.dmg` | One universal build for both chip types. |
| Windows 10/11 (x64) | `Net3PO_<version>_x64-setup.exe` or `..._x64_en-US.msi` | Use the `.msi` for managed deployment. |
| Ubuntu, Debian | `Net3PO_<version>_amd64.deb` or `..._arm64.deb` | |
| RHEL, Fedora, Rocky, Alma | `Net3PO-<version>-1.x86_64.rpm` or `...-1.aarch64.rpm` | |
| Any Linux | `Net3PO_<version>_amd64.AppImage` or `..._aarch64.AppImage` | Portable, no install. |

**Pick the Linux file for your CPU.** Run `uname -m`: `x86_64` means the `amd64` / `x86_64`
files, `aarch64` means the `arm64` / `aarch64` files. A Linux VM on an Apple Silicon Mac
(Parallels, UTM, VMware Fusion) is ARM64. Installing the wrong one fails with
"Depends: libwebkit2gtk-4.1-0:amd64 but it is not installable".

## Verify the download

```
# macOS / Linux
shasum -a 256 Net3PO_*        # compare with SHA256SUMS.txt
# Windows (PowerShell)
Get-FileHash .\Net3PO_*_x64-setup.exe -Algorithm SHA256
```

## macOS

1. Open the `.dmg` and drag **Net3PO** to **Applications**.
2. Current builds are not yet notarized by Apple, so the first launch is blocked. Open
   **System Settings > Privacy & Security**, scroll to the message about Net3PO and click
   **Open Anyway**. Or, in Terminal: `xattr -dr com.apple.quarantine /Applications/Net3PO.app`.

## Windows

1. Run the `.exe` (per-user install) or the `.msi`.
2. Current builds are not yet code-signed, so SmartScreen may warn. Click **More info >
   Run anyway**.
3. WebView2 is required. It ships with Windows 10/11; the installer fetches it if missing.

## Ubuntu and Debian

```
sudo apt install ./Net3PO_<version>_amd64.deb
```

Use `apt` with the `./` path (not `dpkg -i`) so dependencies are installed. Do not convert
the `.rpm` with `alien`; use the `.deb`.

## RHEL family

```
sudo dnf install ./Net3PO-<version>-1.x86_64.rpm
```

## AppImage

```
chmod +x Net3PO_<version>_amd64.AppImage
./Net3PO_<version>_amd64.AppImage
```

On Ubuntu 22.04 and later, AppImages need FUSE 2: `sudo apt install libfuse2`
(`libfuse2t64` on 24.04).

## Privileges

Net3PO never needs to run as administrator or root. A few tools need extra rights for one
specific job, such as binding a port below 1024 (Syslog 514, TFTP 69, DHCP 67/68 on Linux)
or sending ICMP. Those tools detect the problem and tell you what is needed for that tool
only. See each tool's **Platform notes**.

## Optional software

- **libpcap / Npcap:** Net3PO never bundles a capture driver. Live capture in
  [LLDP / CDP Neighbors](tools/lldp.md) loads the one you install: libpcap is part of macOS
  (capture needs Wireshark's ChmodBPF), Linux needs the libpcap package (and CAP_NET_RAW),
  and on Windows you install Npcap from npcap.com. Without it, the app works normally and
  capture files can still be read.

## Updating and uninstalling

**Check for updates** in About (or in Settings > Updates) asks GitHub for the latest release.
If there is a newer version, it shows the version and release notes; **Install and restart**
downloads it, checks it against Net3PO's signing key, installs it and restarts the app. This
works on macOS, Windows and the Linux AppImage. Copies installed from a `.deb` or `.rpm` show
**Open release page** instead, because the package manager has to install the new version.
To be told about new versions automatically, turn on **Check for updates when Net3PO starts**
in Settings; it is off by default. Updates start working from version 0.3.3: earlier versions
have to be updated by hand once.

You can also install the new version over the old one by hand. Your projects, notes, saved SSH hosts and settings
are kept (see [Privacy and data](privacy.md) for where they live). Uninstall with the normal
OS method (drag to Trash, Apps and Features, `sudo apt remove net3-po`, `sudo dnf remove net3-po`);
your data folder is left in place until you delete it.
