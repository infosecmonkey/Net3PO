# TFTP Server

> Serve files from a chosen folder over TFTP, read-only by default, with optional uploads for config backups.

**Sidebar group:** Servers · **Works offline:** yes on the local network (it listens only while you run it) · **Needs admin rights:** only to bind a port below 1024, such as 69 (see Platform notes)

## When to use it

- Load firmware or a boot image onto a switch, router, firewall or IP phone that only supports TFTP.
- Back up a device configuration with `copy running-config tftp:` or the vendor equivalent (enable **Writable** first).
- Serve PXE or provisioning files to a lab device for a short test.
- Confirm that TFTP passes through a firewall or ACL.

## Quick start

1. Click **Choose folder** and pick the folder to serve. Put the files the device needs in it.
2. Set **Port**. 69 is standard; use 6969 if you do not want to grant admin rights and the client can use another port.
3. Tick **Writable (accept uploads)** only if the device needs to send files to you.
4. Click **Start**. The status line shows `Serving <folder> on UDP <port> (read-only)` or `(read + write)`.
5. On the device, point the TFTP transfer at this computer's IP address, for example `192.0.2.50`.
6. Watch the transfer table for progress and the result.
7. Click **Stop** when done.

## Inputs and options

| Field | What it means | Default / accepted values |
|---|---|---|
| Choose folder | The root folder. Every request is confined to this folder and its subfolders. | Required |
| Port | UDP port for incoming requests. Each transfer then runs on its own random high port, as TFTP specifies. | 69; 1 to 65535 |
| Writable (accept uploads) | Accept write requests (PUT). When off, write requests are refused with an access violation. | Off |

When Writable is on and the server is stopped, the panel warns: any client that can reach this port can create or overwrite files in the chosen folder.

Supported TFTP options (RFC 2347 to 2349): `blksize` (clamped to 8 to 65464 bytes), `tsize` (the real file size on reads, echoed on writes) and `timeout` (1 to 255, acknowledged). Without options, the block size is 512 bytes.

## Reading the results

The status line shows the folder, port and mode while running, and `Stopped.` afterwards.

The transfer table, newest first:

- **Dir**: `GET` (the client downloads from you) or `PUT` (the client uploads to you).
- **File**: the file name as requested by the client.
- **Client**: the client's address and port.
- **Size**: bytes transferred so far, updated every 64 blocks and at the end.
- **Status**: `active`, `done`, the failure reason (for example `illegal TFTP operation`, or `access violation` if the file cannot be written), or `rejected:` and the reason.

Requests refused before the transfer starts (file not found, uploads while Writable is off, paths outside the folder, malformed requests) are answered with a TFTP error to the client and added as a `rejected` row, so you can see what the device asked for. The table keeps the newest 500 rows.

Worked example. A switch at `192.0.2.20` runs `copy tftp://192.0.2.50/fw.bin flash:`. The table shows `GET`, `fw.bin`, `192.0.2.20:49152`, the growing size, then `done`. A later `copy running-config tftp://192.0.2.50/sw1.cfg` with Writable on shows `PUT`, `sw1.cfg`, and `done`. With Writable off, the switch reports an access violation error and the table shows `PUT`, `sw1.cfg`, `rejected: upload refused: uploads are off`.

## What the results do and do not tell you

- `done` means the last block was acknowledged (GET) or received (PUT). TFTP has no checksum; verify firmware hashes with the [Hash Calculator](hash-calculator.md).
- File names with `..`, an absolute path, a backslash or a NUL are refused, and the resolved path must stay inside the folder (symlinks are resolved before the check on reads).
- Uploads can go into existing subfolders only; subfolders are not created. An existing file with the same name is replaced once the upload completes.
- An upload is received into a hidden temporary file in the same folder and renamed into place at the end. A failed or cancelled upload leaves any existing file untouched, and a symlink or hard link at the target name is replaced rather than followed, so a write cannot land outside the folder.
- Transfer mode (`netascii` or `octet`) is not converted; every file is sent and stored byte for byte.
- Each transfer waits 3 seconds per block and retries 5 times, then fails. The server listens on IPv4 only.
- A file being served is read into memory first, so very large images use that much RAM during the transfer. Uploads have no size limit beyond free disk space.

## Online activity and privacy

The server listens on the chosen UDP port on all IPv4 interfaces only between **Start** and **Stop**. Any host that can reach the port can read any file in the folder, and with Writable on, write files to it. TFTP has no authentication or encryption, so files cross the network in clear text. Serve a folder that holds only what the device needs.

The app keeps nothing beyond the files clients upload into your folder. The transfer table is cleared on the next Start.

## Export and projects

There is no export or "Add to project" for this tool. Uploaded files are saved directly in the served folder.

## Platform notes

- Ports below 1024 (including 69) need admin or root rights on Linux, and may be refused elsewhere. The app never needs to run as admin: when binding fails with a permission error, the panel offers **Use port 6969 (no admin needed)**. The client must then be told to use that port, or forward 69 to 6969 on the host or firewall.
- On Linux you can grant only the low-port capability to the app binary (`sudo setcap cap_net_bind_service=+ep <path to app>`).
- The OS firewall must allow inbound UDP on the port and on the high ports used for each transfer. Windows Defender Firewall and the macOS application firewall may prompt the first time; allow the app, not just port 69.

## Troubleshooting

**Error "Choose a folder to serve first." or "choose a folder to serve".** No folder is set, or it no longer exists.

**Error "cannot bind UDP port 69: permission denied. Ports below 1024 need admin/root; try a port such as 6969."** Click **Use port 6969 (no admin needed)**.

**Error "cannot bind UDP port N: already in use."** Another TFTP server (often a built-in OS service) holds the port. Stop it or pick another port.

**Client reports "file not found" and no row appears.** The file is not in the folder, or the name's case does not match (Linux and some macOS volumes are case sensitive).

**Client reports "access violation" on a PUT and no row appears.** Writable is off, or the target subfolder does not exist. If a row appears with `access violation`, the file could not be created or written (folder permissions, disk full).

**Client reports "path escapes the served directory".** The client asked for a path outside the folder.

**Status "illegal TFTP operation" partway through.** The client stopped acknowledging (timeout after 5 retries), sent an error, or you clicked Stop. A firewall blocking the per-transfer high port often shows as a transfer that starts but never progresses.

**Nothing appears in the table and the client times out.** The request is not reaching this computer. Check the device can reach the IP, the port, and the OS firewall.

## Related tools

- [Syslog Server](syslog-server.md)
- [Hash Calculator](hash-calculator.md)
- [DHCP Monitor](dhcp-monitor.md) (shows the next-server a DHCP server hands out)
- [SSH](ssh.md)
