# RDP

> Open Remote Desktop sessions in the RDP client installed on this computer, from a list of saved hosts or quick connect.

**Sidebar group:** Remote · **Works offline:** no (the client connects to the host you pick, only when you click it) · **Needs admin rights:** no

The RDP tool shows in the sidebar only when an RDP client is available: one found on this computer, or a custom program set in [Settings](settings.md).

## When to use it

- Keep jump servers, domain controllers and Windows hosts per site in one list next to your other tools.
- Open a session without hunting for the client or retyping the address and user.

## Quick start

1. Click **+ Host**, enter **Name**, **Host** (for example `192.0.2.10` or `jump1.example.com`), **Port** and optionally **User** (for example `CORP\jane`), then **Save**.
2. Click the host. Your RDP client opens and asks for the password.

For a one-off session, type `host`, `host:port` or `user@host:port` in the box at the top of the list and press Enter or click **Go**.

## Inputs and options

| Field | What it means | Default / accepted values |
|---|---|---|
| Name | Label in the list. If empty, the host is used. | Empty |
| Host | Host name, IPv4 or IPv6 address. | Required |
| Port | RDP port. | 3389; 1 to 65535 |
| User | Optional user name, including a domain (`CORP\jane` or `jane@corp.example.com`). | Empty |
| Full screen | Start the session full screen (clients that read `.rdp` files, and FreeRDP). | Off |
| Notes | Free text. Searchable. | Empty |

The line **Client:** shows which program will open; **Change in Settings** goes to [Settings](settings.md).

## Which client opens

| OS | Found automatically | How the session is handed over |
|---|---|---|
| Windows | Remote Desktop Connection (`mstsc`, built in) | A temporary `.rdp` file |
| macOS | Windows App, or the older Microsoft Remote Desktop | A temporary `.rdp` file opened with the app |
| Linux | Remmina, KRDC, FreeRDP (`sdl-freerdp3`, `xfreerdp3`, `xfreerdp`) | `rdp://user@host:port`, or FreeRDP `/v:host:port /u:user` |

The temporary `.rdp` file holds only the address, user, screen mode and "prompt for credentials". It is written to the system temp folder (`net3po-rdp`) and deleted two minutes later.

## What the results do and do not tell you

- "Opened ... in ..." means the client program started. Whether the connection works is shown by the client itself.
- No password is stored by this tool or passed to the client. The client asks, and may offer to remember it in its own credential store.
- Session options beyond full screen (gateways, drive and printer redirection, multiple monitors) are set in the client.

## Online activity and privacy

This tool sends nothing itself; the client you open connects to the host. Saved hosts (name, host, port, user, full screen, notes) are stored in the app data folder as `rdp_hosts`. See [Privacy](../privacy.md).

## Platform notes

- **Linux, FreeRDP:** `xfreerdp` asks for the password on the terminal it was started from. When it is opened from the app there is no terminal, so prefer Remmina or `sdl-freerdp3`, which ask in a window.
- **macOS:** Windows App may add the host to its own list when it opens the file.

## Troubleshooting

**The RDP tool is not in the sidebar.** No RDP client was found and none is set. Install one (see the table) and click **Detect again** in [Settings](settings.md), or set a custom program.

**Error "No RDP client is set up. Choose one in Settings."** As above.

**Error "the client chosen in Settings is no longer installed; pick another in Settings".** The client was removed. Pick another in Settings.

**Error "could not start ...".** The program could not be run. Check it in Settings.

**Error "Quick connect takes host, host:port or user@host:port."** Check the format; put IPv6 addresses in brackets.

## Related tools

- [VNC](vnc.md)
- [SSH](ssh.md)
- [Settings](settings.md)
