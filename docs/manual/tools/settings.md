# Settings

> App settings, saved on this computer. Open them with the gear button at the top of the sidebar.

**Works offline:** yes · **Needs admin rights:** no

## Remote clients

Chooses the program the [RDP](rdp.md) and [VNC](vnc.md) tools open. Each has three modes:

| Mode | What it does |
|---|---|
| Use an installed client | Picks from the clients found on this computer. With more than one, choose which. The tool shows in the sidebar when at least one is found. |
| Custom program | Any program you pick, with an argument template. The tool shows when a program is set. |
| Off | Hides the tool. |

**Detect again** looks for clients again, for example after installing one.

### Argument templates

The template is split on spaces into arguments, then placeholders are filled in, so a value with spaces stays one argument.

| Placeholder | Value |
|---|---|
| `{host}` | Host name or address |
| `{port}` | Port |
| `{user}` | User name (an argument that is only an empty `{user}` is left out) |
| `{target}` | `host:port`, IPv6 in brackets |
| `{file}` | RDP only: a temporary `.rdp` file with the address, user and screen mode |

Defaults: RDP `{file}`, VNC `{host}::{port}`. Examples: FreeRDP `/v:{target} /u:{user}`; TigerVNC `{host}::{port}`. There is no password placeholder. On macOS, picking an `.app` opens it with the arguments.

## Where settings are stored

In the app data folder, as `settings`. See [Privacy](../privacy.md).

## Troubleshooting

**Error "unknown placeholder {...} in the argument template".** Only the placeholders above are allowed.

**Error "the custom client ... was not found; check Settings".** The program path is wrong or the program was removed.
