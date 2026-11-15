// Types mirroring the Rust LLDP/CDP module, and the export report.

import { generatedNow } from "$lib/report/export";
import type { Report, Section } from "$lib/report/types";

export interface Device {
  name: string;
  description: string;
  loopback: boolean;
  up: boolean;
}

export interface Status {
  available: boolean;
  version: string;
  error: string;
  devices: Device[];
}

export interface Neighbor {
  protocol: "LLDP" | "CDP" | null;
  sourceMac: string;
  chassisId: string;
  chassisIdType: string;
  portId: string;
  portIdType: string;
  portDescription: string;
  systemName: string;
  systemDescription: string;
  capabilities: string[];
  enabledCapabilities: string[];
  management: string[];
  ttl: number | null;
  portVlan: number | null;
  vlans: { id: number; name: string }[];
  voiceVlan: number | null;
  voicePolicy: string;
  mtu: number | null;
  link: string;
  poe: string;
  platform: string;
  inventory: { label: string; value: string }[];
  notes: string[];
}

export interface Seen {
  neighbor: Neighbor;
  firstMs: number;
  lastMs: number;
  count: number;
}

export interface FileResult {
  format: string;
  packets: number;
  frames: number;
  neighbors: Seen[];
  warnings: string[];
}

export type LldpEvent =
  | { type: "started"; device: string; link: number }
  | { type: "neighbor"; seen: Seen }
  | { type: "warning"; message: string }
  | { type: "done"; frames: number; cancelled: boolean };

export function key(n: Neighbor): string {
  return `${n.protocol}|${n.chassisId}|${n.portId}|${n.sourceMac}`;
}

/** "RACK-SWITCH port49" style headline. */
export function headline(n: Neighbor): { device: string; port: string } {
  return {
    device: n.systemName || n.chassisId || n.sourceMac,
    port: n.portId || n.portDescription || "unknown port",
  };
}

/** Label/value rows for a neighbor, skipping empty fields. */
export function rows(s: Seen): { key: string; value: string }[] {
  const n = s.neighbor;
  const out: { key: string; value: string }[] = [];
  const add = (key: string, value: string | number | null | undefined) => {
    if (value !== null && value !== undefined && String(value).trim() !== "") out.push({ key, value: String(value) });
  };
  add("Protocol", n.protocol);
  add("Port", n.portId ? `${n.portId}${n.portIdType ? ` (${n.portIdType})` : ""}` : "");
  if (n.portDescription && n.portDescription !== n.portId) add("Port description", n.portDescription);
  add("System name", n.systemName);
  add("Chassis ID", n.chassisId ? `${n.chassisId}${n.chassisIdType ? ` (${n.chassisIdType})` : ""}` : "");
  add("Management address", n.management.join(", "));
  add("Port VLAN (untagged)", n.portVlan);
  add("Voice VLAN", n.voiceVlan === null ? "" : `${n.voiceVlan}${n.voicePolicy ? ` (${n.voicePolicy})` : ""}`);
  add("VLAN names", n.vlans.map((v) => `${v.id} ${v.name}`).join(", "));
  add("Link", n.link);
  add("Power (PoE)", n.poe);
  add("Max frame size", n.mtu);
  add("Capabilities", capText(n));
  add("Platform", n.platform);
  add("System description", n.systemDescription);
  for (const f of n.inventory) add(f.label, f.value);
  add("Hold time", n.ttl === null ? "" : `${n.ttl} s`);
  add("Source MAC", n.sourceMac);
  add("Announcements", s.count);
  add("First seen", new Date(s.firstMs).toLocaleString());
  add("Last seen", new Date(s.lastMs).toLocaleString());
  add("Decoder notes", n.notes.join("; "));
  return out;
}

function capText(n: Neighbor): string {
  if (!n.capabilities.length) return "";
  return n.capabilities
    .map((c) => (n.protocol === "LLDP" && !n.enabledCapabilities.includes(c) ? `${c} (not enabled)` : c))
    .join(", ");
}

const CAVEAT =
  "LLDP and CDP are what the neighbor says about itself. They are not authenticated: any device on the segment can send them, so treat them as a strong hint, not proof. A port with discovery disabled, or a hub, media converter or unmanaged switch in between, shows nothing or shows the wrong neighbor.";

export function buildLldpReport(neighbors: Seen[], source: string, version: string): Report {
  const sections: Section[] = [
    {
      title: "Capture",
      blocks: [
        {
          type: "keyValues",
          items: [
            { key: "Source", value: source || "-" },
            { key: "Capture library", value: version || "-" },
            { key: "Neighbors", value: String(neighbors.length) },
          ],
        },
        { type: "paragraph", text: CAVEAT },
      ],
    },
  ];
  for (const s of neighbors) {
    const h = headline(s.neighbor);
    sections.push({
      title: `${h.device}, ${h.port}`,
      blocks: [{ type: "keyValues", items: rows(s) }],
    });
  }
  return {
    title: "LLDP / CDP neighbors",
    subtitle: source,
    generated: generatedNow(),
    tool: "LLDP / CDP Neighbors",
    sections,
  };
}
