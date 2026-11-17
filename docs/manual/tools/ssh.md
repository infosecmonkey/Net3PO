# SSH

> An SSH terminal with saved connections in groups, passwords and key passphrases in the OS keychain, and host keys pinned on first connect. Sessions keep running while you use other tools.

**Sidebar group:** Remote · **Works offline:** no (connects to the host you pick, only when you click it) · **Needs admin rights:** no

## When to use it

- Log in to switches, firewalls, routers and servers without leaving the app.
- Keep a session open on a device while you build commands in the [Fortinet Command Builder](forti-builder.md) and send them straight to it.
- Keep a tidy list of devices per site or customer, with notes, without storing passwords in a plain file.
- Work in another tool with the device terminal docked underneath it.

## Quick start

1. Click **+ Group** and name it (for example `Site A`). Groups are optional, and shared with SFTP, RDP and VNC.
2. Click **+ Connection** (or the **+** on a group row).
3. Fill in **Name**, **Host** (for example `192.0.2.1` or `fw1.example.com`), **Port**, **User** and **Authentication**.
4. For password auth, type the password and leave **Save in OS keychain** ticked, or leave it empty to be asked on each connect. For key auth, pick the **Key file** and enter the passphrase if it has one.
5. Click **Save**, then click the connection in the list.
6. On first connect, compare the fingerprint in **Verify host key** with the device, then click **Trust and connect**.
7. The session opens in a tab. Open more connections for more tabs.
8. Switch to another tool: the SSH session bar appears at the top. Click **Dock terminal** to work in the session under that tool.

For a one-off login, type `user@host` or `user@host:port` in the box at the top of the list and press Enter or click **Go**.

## Inputs and options

Connection list (left side):

| Control | What it does |
|---|---|
| Quick connect box | `user@host` or `user@host:port` (IPv6 in brackets, for example `admin@[2001:db8::1]:2222`). Password auth only. Nothing is saved except the pinned host key. |
| Search connections | Filters by name, host, user and notes. |
| + Connection, + Group | Create a connection or a group. |
| Group row | Collapse or expand (`+` / `-`), with a count. Row buttons: **+** add a connection to this group, **e** rename, **x** delete (its members in every tool move to Ungrouped). |
| Connection row | Click to connect. Hover shows notes, or `user@host:port`. Row buttons: **e** edit, **x** delete (also removes its saved secret from the keychain). |

Connection editor:

| Field | What it means | Default / accepted values |
|---|---|---|
| Name | Label in the list. If empty, the host is used. | Empty |
| Group | Group to file it under. | Ungrouped |
| Host | Host name, IPv4 or IPv6 address. | Required |
| Port | SSH port. | 22; 1 to 65535 |
| User | Login name. At most 64 characters, no spaces. | Required |
| Authentication | **Password** or **Private key**. | Password |
| Key file | Path to the private key (key auth only). **Browse** opens a file picker. | Empty |
| Password / Key passphrase | The secret for this connection. When one is saved, the field reads "Saved in keychain (type to replace)". | Empty |
| Save in OS keychain | Store the typed secret in the OS keychain when you click Save. If unticked, a typed secret is not kept. | On |
| Remove saved secret | Deletes the saved secret from the keychain (shown only when one exists). | |
| Notes | Free text, for example site, rack or ticket. Searchable. | Empty |

Password prompt: if a password connection has no saved password, or the saved one is rejected, a prompt asks for it. For a saved connection it offers **Save in OS keychain after a successful login**. A key that needs a passphrase prompts the same way.

## Reading the results

**Tabs.** Each session is a tab with a status dot. A closed session keeps its tab and scrollback, with the reason printed in the terminal, for example `[remote shell exited with status 0]`, `[connection closed]` or `[closed]`. Click **x** on a tab to disconnect and close it.

**Terminal.** An xterm-compatible terminal (`xterm-256color`) that resizes with the window. It keeps 5,000 lines of scrollback. When you switch tools and come back, the last 2 MB of output is replayed so the screen is as you left it. To copy, select text and press Cmd+C on macOS or Ctrl+Shift+C on Windows and Linux; without a selection, Ctrl+C goes to the remote host as usual.

**Host key dialogs.**

- **Verify host key** (first connect to a host and port): shows the key algorithm and the SHA256 fingerprint in OpenSSH format, for example `SHA256:` followed by 43 characters. Check it on the device (for example `get system status` on FortiOS, or `ssh-keygen -lf` on the server's host key) before clicking **Trust and connect**.
- **Host key changed**: the presented key differs from the one pinned earlier. It shows the previously pinned fingerprint and the one presented now. This happens after a rebuild or key regeneration, but it is also what interception looks like. The connection does not proceed (no password is sent) unless you click **Accept new key and connect**.

**Session bar (in other tools).** While at least one session exists and you are in another tool, a bar across the top lists the sessions. Click one to jump back to the SSH tool, or, if the terminal is docked, to show it in the dock. **Dock terminal** / **Hide terminal** toggles the docked terminal.

**Docked terminal.** The active session under the current tool. Drag the top edge to resize it (minimum 120 px, up to 85% of the window). Buttons: **Expand** (open the SSH tool), **Close session** (disconnect), **Hide**.

**Sending from other tools.** The [Fortinet Command Builder](forti-builder.md) can type generated commands into an open session. Multi-line commands are sent line by line, each followed by Enter, and that session becomes active.

## What the results do and do not tell you

- Host key trust is trust on first use. The first fingerprint is only as good as your check against the device. Keys are pinned per host name or address and port, so `fw1.example.com` and `192.0.2.1` are pinned separately.
- A host key is pinned only after a successful login.
- Only interactive shell sessions are supported here; file transfer is in the [SFTP](sftp.md) tool. There is no port forwarding, agent forwarding, SSH agent authentication or keyboard-interactive (one-time password) login.
- Limits: 16 open sessions at once; 15 seconds to connect and complete the handshake; keepalives every 30 seconds, and the session drops after 3 missed replies; a single paste or write is limited to 64 KB.

## Online activity and privacy

The app opens a TCP connection to the host and port you pick, only when you click a connection or use quick connect. Nothing else is sent.

What is stored, and where:

- **Connections and groups** (name, host, port, user, auth type, key file path, notes) are saved in the app data folder as `ssh_connections` and `ssh_groups`. They contain no passwords.
- **Passwords and key passphrases** are stored only in the OS keychain, under the service name `OmniPacket SSH`, one entry per saved connection. They are never sent back to the user interface; the editor only learns whether a secret exists. A secret typed in the connection editor is saved when you click Save. A secret typed in the connect prompt is saved only after a successful login, and only if you ticked the box. Quick connect never saves a secret.
- **Pinned host keys** (host, port, algorithm, SHA256 fingerprint, date) are saved in the app data folder as `ssh_known_hosts`. They are separate from your OpenSSH `known_hosts` file, which is not read or changed.
- **Private keys** are read from the path you give at connect time and are not copied.
- Terminal output is held in memory only and is gone when you close the tab or the app.

See [Privacy](../privacy.md).

## Export and projects

There is no export or "Add to project" for SSH sessions. Copy text from the terminal if you need it in a report or [project note](../projects-and-notes.md).

## Platform notes

- **macOS:** secrets go to the Keychain.
- **Windows:** secrets go to Windows Credential Manager.
- **Linux:** secrets go to the desktop secret service (for example GNOME Keyring or KWallet). If none is running, saving fails with "keychain unavailable" or "could not save to the keychain"; you can still connect and type the password each time.
- A leading `~` in the key path is expanded to your home folder (`~/.ssh/id_ed25519`). `~user` forms are not.

## Troubleshooting

**Error "Host and user are required." / "Port must be 1 to 65535."** Fill in the editor fields.

**Error "Quick connect takes user@host or user@host:port."** Check the quick connect format.

**Error "'...' is not a valid host name or IP address".** The host contains characters not allowed in a host name.

**Error "user name must be at most 64 characters without spaces".** Fix the user name.

**Error "timed out connecting to <host>:<port>".** No TCP connection or SSH handshake within 15 seconds. Check reachability, the port, and ACLs or trusted hosts on the device.

**Error "could not connect to <host>:<port>: ...".** The TCP connection was refused or the SSH handshake failed (for example no shared algorithms).

**Password prompt with "authentication failed: check the user name and credentials".** The server rejected the password. Re-enter it. If a saved password is wrong, edit the connection and type a new one.

**Prompt "could not load the key (if it has a passphrase, enter it)".** The key is encrypted. Enter the passphrase. If it still fails, check the path and key format.

**Error "authentication error: ...".** The SSH library reported a protocol error during login.

**Error "could not start a terminal" / "could not start a shell".** The server refused a PTY or shell for this user.

**Error "too many open sessions (limit 16); close one first".** Close a tab.

**Message "[Net3PO] could not save to the keychain: ..." in the terminal.** Login worked but the secret was not saved. See Platform notes.

**"Host key changed" after a device replacement or RMA.** Confirm the new fingerprint on the console or with the device owner, then accept it.

## Related tools

- [SFTP](sftp.md)
- [Fortinet Command Builder](forti-builder.md)
- [Debug Flow Parser](debug-flow.md)
- [FortiGate Sniffer to PCAP](forti-sniffer.md)
- [Port Scanner](port-scanner.md)
- [Socket Tools](socket-tools.md)
