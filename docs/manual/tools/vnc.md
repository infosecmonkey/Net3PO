# VNC

> Open VNC sessions in the VNC viewer installed on this computer, from a list of saved hosts or quick connect.

**Sidebar group:** Remote · **Works offline:** no (the viewer connects to the host you pick, only when you click it) · **Needs admin rights:** no

The VNC tool shows in the sidebar only when a VNC viewer is available: one found on this computer, or a custom program set in [Settings](settings.md). On macOS the built-in Screen Sharing app is always found.

## When to use it

- Reach lab machines, appliances with a VNC console, and Linux or macOS desktops.
- Keep VNC targets in one list next to your other tools.

## Quick start

1. Click **+ Host**, enter **Name**, **Host** and **Port**, then **Save**.
2. Click the host. The viewer opens and asks for the password.

For a one-off session, type `host`, `host:port` or `user@host:port` in quick connect and press Enter or click **Go**.

## Check server

**Check** (next to quick connect) and **?** (on a saved host) connect to the server and list the login methods it offers, with which viewers can use them. Use it when a viewer says "No supported authentication methods" or closes right after connecting.

Only the server's greeting is read: no method is selected, nothing is logged in and no password is sent.

| Offered | Who can log in |
|---|---|
| None, or VNC password | Any viewer |
| Apple macOS login only (types 30 to 36) | macOS Screen Sharing and Remmina. For other viewers, turn on the VNC password on the Mac (see Troubleshooting). |
| VeNCrypt or TLS only | TigerVNC Viewer and Remmina |
| RealVNC only | RealVNC Viewer, unless the server is set to VNC password |

## Inputs and options

| Field | What it means | Default / accepted values |
|---|---|---|
| Name | Label in the list. If empty, the host is used. | Empty |
| Group | Shared group to file it under. **+ Group** creates one. | Ungrouped |
| Host | Host name, IPv4 or IPv6 address. | Required |
| Port | TCP port (not a display number: display `:1` is port 5901). | 5900; 1 to 65535 |
| User | Optional. Used by Screen Sharing and Remmina; most other viewers ignore it. | Empty |
| Notes | Free text. Searchable. | Empty |

The list shows hosts under their group, collapsible with `+` / `-`. Hover a group for **+** (add a host to it), **e** (rename) and **x** (delete). Groups without hosts in this tool are hidden.

Groups are shared by SSH, SFTP, RDP and VNC: a group such as a customer or site holds that site's SSH connections, RDP hosts and VNC hosts. Create, rename or delete a group in any of these tools and the others follow. Deleting a group moves its members in every tool to Ungrouped.

## Which viewer opens

| OS | Found automatically | How the session is handed over |
|---|---|---|
| Windows | RealVNC, TigerVNC, TightVNC, UltraVNC viewers | `host::port` |
| macOS | Screen Sharing (built in), RealVNC Viewer | `vnc://user@host:port`, or `host::port` |
| Linux | Remmina, TigerVNC (`vncviewer`), KRDC | `vnc://user@host:port`, or `host::port` |

## What the results do and do not tell you

- "Opened ... in ..." means the viewer started. Whether the connection works is shown by the viewer.
- No password is stored by this tool or passed to the viewer.
- VNC itself is often unencrypted. Prefer an SSH tunnel or a VPN to reach VNC servers across untrusted networks.

## Online activity and privacy

The viewer you open connects to the host. **Check** opens one TCP connection to the host and port, reads the greeting and closes it. Saved hosts are stored in the app data folder as `vnc_hosts`; groups as `ssh_groups`. See [Privacy](../privacy.md).

## Troubleshooting

**The VNC tool is not in the sidebar.** No viewer was found and none is set, or it is turned off in [Settings](settings.md).

**Error "No VNC client is set up. Choose one in Settings."** As above.

**The viewer opens on the wrong port.** Enter the TCP port (5900 plus the display number), not the display number.

**The viewer says "No supported authentication methods".** The server offers no login method the viewer supports. Click **Check** to see what it offers. Common cases:

- **macOS target.** Screen Sharing offers only Apple's login by default. On the Mac, open System Settings > General > Sharing, click (i) next to Screen Sharing, turn on **VNC viewers may control screen with password** and set a password. Or use Remmina, or Screen Sharing from another Mac.
- **RealVNC Server.** Use RealVNC Viewer, or set the server's Authentication to VNC password and Encryption to Prefer off.
- **TLS-only servers** (wayvnc, GNOME Remote Desktop, TigerVNC with VeNCrypt). Use TigerVNC Viewer or Remmina.

**Check says "not a VNC server".** Something else answers on that port, for example SSH or a web server.

**Errors about the client.** See [RDP troubleshooting](rdp.md#troubleshooting); they are the same.

## Related tools

- [RDP](rdp.md)
- [SSH](ssh.md)
- [Settings](settings.md)
