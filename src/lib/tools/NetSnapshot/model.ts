// Types mirroring the Rust snapshot model, plus the export reports.

import { generatedNow } from "$lib/report/export";
import type { Finding, Report, Section } from "$lib/report/types";

export interface Interface {
  name: string;
  mac: string | null;
  mtu: number | null;
  up: boolean | null;
  addrs: string[];
}

export interface Route {
  family: string;
  dest: string;
  gateway: string;
  iface: string;
  metric: number | null;
}

export interface DnsScope {
  scope: string;
  servers: string[];
  search: string[];
}

export interface Neighbor {
  ip: string;
  mac: string;
  iface: string;
  state: string;
}

export interface Listener {
  proto: string;
  addr: string;
  port: number;
  process: string | null;
  pid: number | null;
}

export interface Source {
  section: string;
  command: string;
  ok: boolean;
  note: string;
}

export interface Snapshot {
  id: string;
  label: string;
  taken: string;
  host: string;
  os: string;
  interfaces: Interface[];
  routes: Route[];
  dns: DnsScope[];
  neighbors: Neighbor[];
  listeners: Listener[];
  sources: Source[];
}

export interface Summary {
  id: string;
  label: string;
  taken: string;
  host: string;
  os: string;
  interfaces: number;
  routes: number;
  listeners: number;
  failed: number;
}

export interface Change {
  kind: "added" | "removed" | "changed";
  key: string;
  before: string;
  after: string;
  fields: string[];
}

export interface SectionDiff {
  section: string;
  changes: Change[];
  unchanged: number;
}

export type SectionId = "interfaces" | "routes" | "dns" | "neighbors" | "listeners";

export const SECTION_TABS: { id: SectionId; label: string }[] = [
  { id: "interfaces", label: "Interfaces" },
  { id: "routes", label: "Routes" },
  { id: "dns", label: "DNS" },
  { id: "neighbors", label: "Neighbors" },
  { id: "listeners", label: "Listening ports" },
];

/** Headers and rows for one section, used by the panel and the report. */
export function sectionTable(s: Snapshot, id: SectionId): { headers: string[]; rows: string[][] } {
  const dash = (v: unknown) => (v === null || v === undefined || v === "" ? "-" : String(v));
  switch (id) {
    case "interfaces":
      return {
        headers: ["Name", "State", "MTU", "MAC", "Addresses"],
        rows: s.interfaces.map((i) => [
          i.name,
          i.up === null ? "-" : i.up ? "up" : "down",
          dash(i.mtu),
          dash(i.mac),
          i.addrs.join("\n") || "-",
        ]),
      };
    case "routes":
      return {
        headers: ["Family", "Destination", "Gateway", "Interface", "Metric"],
        rows: s.routes.map((r) => [r.family, r.dest, r.gateway || "on-link", dash(r.iface), dash(r.metric)]),
      };
    case "dns":
      return {
        headers: ["Scope", "Servers", "Search domains"],
        rows: s.dns.map((d) => [d.scope, d.servers.join("\n") || "-", d.search.join(" ") || "-"]),
      };
    case "neighbors":
      return {
        headers: ["IP address", "MAC", "Interface", "State"],
        rows: s.neighbors.map((n) => [n.ip, n.mac || "(incomplete)", dash(n.iface), dash(n.state)]),
      };
    case "listeners":
      return {
        headers: ["Protocol", "Address", "Port", "Process", "PID"],
        rows: s.listeners.map((l) => [l.proto, l.addr, String(l.port), dash(l.process), dash(l.pid)]),
      };
  }
}

export function sectionCount(s: Snapshot, id: SectionId): number {
  return s[id].length;
}

/** "Nov 14, 2026, 6:05 PM" from an RFC 3339 string. */
export function when(taken: string): string {
  const d = new Date(taken);
  return isNaN(d.getTime()) ? taken : d.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

export function title(s: { label: string; taken: string; host: string }): string {
  return s.label || `${s.host || "Snapshot"} ${when(s.taken)}`;
}

const SECTION_NOTE =
  "Read with the operating system's own commands, without administrator rights. Without root, Linux and macOS may not name the process behind another user's sockets.";

export function buildSnapshotReport(s: Snapshot): Report {
  const sections: Section[] = [
    {
      title: "Summary",
      blocks: [
        {
          type: "keyValues",
          items: [
            { key: "Label", value: s.label || "-" },
            { key: "Taken", value: when(s.taken) },
            { key: "Host", value: s.host || "-" },
            { key: "OS", value: s.os },
            ...SECTION_TABS.map((t) => ({ key: t.label, value: String(sectionCount(s, t.id)) })),
          ],
        },
        { type: "paragraph", text: SECTION_NOTE },
        {
          type: "table",
          headers: ["Section", "Source", "Result"],
          rows: s.sources.map((x) => [x.section, x.command, x.ok ? x.note || "ok" : `failed: ${x.note}`]),
        },
      ],
    },
  ];
  for (const t of SECTION_TABS) {
    const { headers, rows } = sectionTable(s, t.id);
    sections.push({
      title: t.label,
      blocks: rows.length ? [{ type: "table", headers, rows }] : [{ type: "paragraph", text: "None recorded." }],
    });
  }
  return {
    title: "Network snapshot",
    subtitle: title(s),
    generated: generatedNow(),
    tool: "Network Snapshot",
    sections,
  };
}

/** Changes worth calling out at the top of a comparison. */
export function notable(diffs: SectionDiff[]): Finding[] {
  const out: Finding[] = [];
  for (const d of diffs) {
    for (const c of d.changes) {
      if (d.section === "Neighbors" && c.kind === "changed" && c.fields.includes("MAC")) {
        out.push({
          severity: "warn",
          category: "Neighbors",
          title: `MAC address changed for ${c.key}`,
          detail: `${c.before} -> ${c.after}. Expected after a device or NIC swap, a failover or a VRRP/HSRP change; otherwise worth checking for ARP spoofing.`,
        });
      }
      if (d.section === "Routes" && c.key.includes(" default ")) {
        out.push({
          severity: "warn",
          category: "Routes",
          title: `Default route ${c.kind}`,
          detail: c.kind === "removed" ? c.before : c.kind === "added" ? c.after : `${c.before} -> ${c.after}`,
        });
      }
      if (d.section === "DNS" && c.kind !== "removed") {
        out.push({
          severity: "info",
          category: "DNS",
          title: `DNS ${c.kind}: ${c.key}`,
          detail: c.kind === "added" ? c.after : `${c.before} -> ${c.after}`,
        });
      }
      if (d.section === "Listening ports" && c.kind === "added") {
        out.push({ severity: "info", category: "Listening ports", title: `New listener ${c.key}`, detail: c.after });
      }
    }
  }
  return out;
}

export function buildCompareReport(a: Summary, b: Summary, diffs: SectionDiff[]): Report {
  const total = diffs.reduce((n, d) => n + d.changes.length, 0);
  const findings = notable(diffs);
  const sections: Section[] = [
    {
      title: "Summary",
      blocks: [
        {
          type: "keyValues",
          items: [
            { key: "Before (A)", value: `${title(a)} (${a.host || "-"}, ${a.os})` },
            { key: "After (B)", value: `${title(b)} (${b.host || "-"}, ${b.os})` },
            { key: "Differences", value: String(total) },
          ],
        },
        {
          type: "table",
          headers: ["Section", "Added", "Removed", "Changed", "Unchanged"],
          rows: diffs.map((d) => [
            d.section,
            String(d.changes.filter((c) => c.kind === "added").length),
            String(d.changes.filter((c) => c.kind === "removed").length),
            String(d.changes.filter((c) => c.kind === "changed").length),
            String(d.unchanged),
          ]),
        },
        {
          type: "paragraph",
          text: "Neighbor state changes (reachable, stale) and new process IDs for the same program are not counted as changes. Neighbor and listener lists are point-in-time: an entry missing from one snapshot may simply have aged out or been idle.",
        },
      ],
    },
  ];
  if (findings.length) sections.push({ title: "Notable changes", blocks: [{ type: "findings", items: findings }] });
  for (const d of diffs) {
    if (!d.changes.length) continue;
    sections.push({
      title: d.section,
      subtitle: `${d.changes.length} difference${d.changes.length === 1 ? "" : "s"}, ${d.unchanged} unchanged`,
      blocks: [
        {
          type: "table",
          headers: ["Change", "Before (A)", "After (B)", "Fields"],
          rows: d.changes.map((c) => [c.kind, c.before || "-", c.after || "-", c.fields.join(", ") || "-"]),
        },
      ],
    });
  }
  return {
    title: "Network snapshot comparison",
    subtitle: `${title(a)} vs ${title(b)}`,
    generated: generatedNow(),
    tool: "Network Snapshot",
    sections,
  };
}
