// Recommended RDP and VNC clients per OS, shown in Settings. Net3PO does not
// bundle or download any of them; the user installs one.

import type { Protocol } from "$lib/settings.svelte";

export interface Recommendation {
  name: string;
  /** Why or when to pick it. */
  note: string;
  /** Install commands, one per package family, copied with a button. */
  install: { label: string; command: string }[];
}

type Os = "windows" | "macos" | "linux";

const LIST: Record<Os, Record<Protocol, Recommendation[]>> = {
  windows: {
    rdp: [
      {
        name: "Remote Desktop Connection (mstsc)",
        note: "Built in. Nothing to install.",
        install: [],
      },
    ],
    vnc: [
      { name: "TigerVNC Viewer", note: "Free and open source. Installer from tigervnc.org.", install: [] },
      { name: "RealVNC Viewer", note: "Free viewer. Installer from realvnc.com.", install: [] },
      { name: "TightVNC or UltraVNC", note: "Free. Install the viewer component.", install: [] },
    ],
  },
  macos: {
    rdp: [
      {
        name: "Windows App",
        note: "Microsoft's free RDP client (formerly Microsoft Remote Desktop). Install from the Mac App Store.",
        install: [],
      },
    ],
    vnc: [
      { name: "Screen Sharing", note: "Built in. Nothing to install.", install: [] },
      { name: "RealVNC Viewer", note: "Free viewer. Installer from realvnc.com.", install: [] },
    ],
  },
  linux: {
    rdp: [
      {
        name: "Remmina",
        note: "Recommended. Opens from a desktop launcher and asks for the password in a window. On Debian and Ubuntu the RDP plugin is a separate package.",
        install: [
          { label: "Debian / Ubuntu", command: "sudo apt install remmina remmina-plugin-rdp" },
          { label: "Fedora / RHEL (EPEL)", command: "sudo dnf install remmina remmina-plugins-rdp" },
        ],
      },
      {
        name: "FreeRDP",
        note: "Command-line client. Asks for the password on a terminal. Package names vary by release.",
        install: [
          { label: "Debian / Ubuntu", command: "sudo apt install freerdp3-x11" },
          { label: "Fedora / RHEL", command: "sudo dnf install freerdp" },
        ],
      },
      { name: "KRDC", note: "KDE's remote desktop client.", install: [] },
    ],
    vnc: [
      {
        name: "Remmina",
        note: "Recommended. Same client as RDP; the VNC plugin is a separate package.",
        install: [
          { label: "Debian / Ubuntu", command: "sudo apt install remmina remmina-plugin-vnc" },
          { label: "Fedora / RHEL (EPEL)", command: "sudo dnf install remmina remmina-plugins-vnc" },
        ],
      },
      {
        name: "TigerVNC Viewer",
        note: "Small standalone viewer.",
        install: [
          { label: "Debian / Ubuntu", command: "sudo apt install tigervnc-viewer" },
          { label: "Fedora / RHEL", command: "sudo dnf install tigervnc" },
        ],
      },
    ],
  },
};

/** Recommendations for `os` (`std::env::consts::OS`); other Unix-likes get the Linux list. */
export function recommended(os: string | undefined, p: Protocol): Recommendation[] {
  const key: Os = os === "windows" || os === "macos" ? os : "linux";
  return LIST[key][p];
}
