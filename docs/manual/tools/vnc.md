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

## Inputs and options

| Field | What it means | Default / accepted values |
|---|---|---|
| Name | Label in the list. If empty, the host is used. | Empty |
| Host | Host name, IPv4 or IPv6 address. | Required |
| Port | TCP port (not a display number: display `:1` is port 5901). | 5900; 1 to 65535 |
| User | Optional. Used by Screen Sharing and Remmina; most other viewers ignore it. | Empty |
| Notes | Free text. Searchable. | Empty |

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

This tool sends nothing itself; the viewer you open connects to the host. Saved hosts are stored in the app data folder as `vnc_hosts`. See [Privacy](../privacy.md).

## Troubleshooting

**The VNC tool is not in the sidebar.** No viewer was found and none is set, or it is turned off in [Settings](settings.md).

**Error "No VNC client is set up. Choose one in Settings."** As above.

**The viewer opens on the wrong port.** Enter the TCP port (5900 plus the display number), not the display number.

**Errors about the client.** See [RDP troubleshooting](rdp.md#troubleshooting); they are the same.

## Related tools

- [RDP](rdp.md)
- [SSH](ssh.md)
- [Settings](settings.md)
