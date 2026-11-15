# SFTP

> Browse a server's files over SSH and move files both ways, using the same saved connections, keychain passwords and pinned host keys as the SSH tool.

**Sidebar group:** Remote · **Works offline:** no (connects to the host you pick, only when you click it) · **Needs admin rights:** no

## When to use it

- Pull a config backup, a debug log or a packet capture off a server or appliance.
- Push a firmware image, a certificate or a script to a device that accepts SFTP.
- Look around a server's folders without opening a shell.

## Quick start

1. Save the device in the [SSH](ssh.md) tool first (or use quick connect for a one-off).
2. Open **SFTP** and click the connection in the list.
3. On first connect, compare the fingerprint in **Verify host key** with the device, then click **Trust and connect**. A host already trusted in the SSH tool connects straight away.
4. The login folder opens. Double-click folders to go in, **Up** (or Backspace) to go back.
5. To download, select one or more files and click **Download**, or double-click a file. Pick the local folder.
6. To upload, click **Upload...** and pick one or more files. They go into the folder you are looking at.

For a one-off login, type `user@host` or `user@host:port` in the box at the top of the list and press Enter or click **Go**.

## Inputs and options

| Control | What it does |
|---|---|
| Quick connect box | `user@host` or `user@host:port` (IPv6 in brackets). Password auth only. Nothing is saved except the pinned host key. |
| Search connections | Filters by name, host, user and group. |
| Connection row | Click to connect. Connections are edited in the SSH tool. |
| Path box | The current folder. Type a path and press Enter to jump there. |
| Up, Refresh | Parent folder; reload the listing (also Backspace and F5). |
| Upload... | Pick local files to send to the current folder. |
| Download | Save the selected files to a local folder you pick. The last folder is offered next time. |
| New folder, Rename, Delete | Create a folder in the current folder; rename the selected entry (also F2); delete the selected files and empty folders (also Cmd+Backspace or Ctrl+Backspace), after a confirmation. |
| Disconnect | Close the session. |

Selecting: click a row, Ctrl or Cmd click to add or remove, Shift click for a range. Enter opens the selected folder or downloads the selected file.

## Reading the results

**Listing.** Folders first, then files, sorted by name. Columns: size, modified time (your local time zone) and permissions in `ls -l` style, for example `-rw-r--r--`. A symbolic link shows an arrow after its name; a link to a folder opens like a folder.

**Transfers.** Each upload (↑) and download (↓) gets a row with a progress bar, bytes done, total and speed, and a **Cancel** button. Finished rows show **Done** with the size, or **Failed** or **Stopped** with the reason. **Clear finished** tidies the list. Transfers keep running while you browse other folders or use other tools.

**Existing files.** If the target already exists, you are asked whether to replace it. Answering no skips that file.

## What the results do and do not tell you

- Downloads are written to `<name>.part` and renamed only when complete; uploads are written to `.<name>.net3po-part` on the server and renamed into place. A failed or cancelled transfer removes its partial file and never leaves a half-written file under the real name. When replacing a file on the server, the old one is removed only after the new one has fully arrived.
- File names from the server are made safe before they are written locally: slashes, backslashes, `..`, control characters, characters Windows does not allow (`< > : " | ? *`) and device names such as `CON` are replaced or prefixed, so a hostile server cannot write outside the folder you picked.
- Files only: folders cannot be downloaded or uploaded as a whole yet, and a folder must be empty before it can be deleted.
- One server at a time: connecting to another closes the current session (and cancels its transfers).
- Limits: 10,000 entries shown per folder (a note says when a listing is cut); 20 seconds for any single reply from the server; the same connect timeout and keepalives as the SSH tool.
- Owner and group are not shown, and permissions cannot be changed.

## Online activity and privacy

The app opens an SSH connection to the host and port you pick, only when you click a connection or use quick connect, and moves only the files you choose. Nothing else is sent.

Connections, keychain secrets and pinned host keys are the same ones the SSH tool uses; see [SSH](ssh.md#online-activity-and-privacy) for where each is stored. The listing and transfer list are held in memory only.

See [Privacy](../privacy.md).

## Export and projects

There is no export or "Add to project". Downloaded files are ordinary files in the folder you picked.

## Platform notes

- The server must have the SFTP subsystem enabled. OpenSSH does by default. On network devices it is often a separate setting, and some only allow SCP; those cannot be used here.
- Keychain behavior on each OS is as described in [SSH](ssh.md#platform-notes).

## Troubleshooting

**Error "the server did not start SFTP (is the SFTP subsystem enabled?)" or "could not start SFTP: ...".** The login worked but the server refused SFTP. Enable it on the device, or check that this user is allowed to use it.

**Error "permission denied".** The user cannot read that file or write to that folder.

**Error "no such file or folder".** The path does not exist, or was removed since the listing was loaded. Click **Refresh**.

**Error "could not delete <name> (folders must be empty): ...".** Delete the folder's contents first.

**Error "the server did not answer in time".** No reply within 20 seconds. The connection may have dropped; disconnect and connect again.

**Error "SFTP session is closed; connect again".** The session ended. Click the connection again.

**Connection, password and host key errors.** These are the same as in the SSH tool; see [SSH troubleshooting](ssh.md#troubleshooting).

## Related tools

- [SSH](ssh.md)
- [TFTP Server](tftp-server.md)
- [PCAP Inspector](pcap-inspector.md)
- [Config Diff](config-diff.md)
