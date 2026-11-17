// Types mirroring `tools::fgt_session::core`, helpers, filter commands and
// the export report.

import type { Report, Section } from "$lib/report/types";

export interface Endpoint {
  addr: string;
  port: number;
}

export interface Hook {
  hook: string;
  dir: string;
  act: string;
  src: Endpoint;
  dst: Endpoint;
  nat: Endpoint | null;
}

export interface Flag {
  name: string;
  meaning: string | null;
}

export interface Field {
  key: string;
  value: string;
}

export interface Session {
  index: number;
  line: number;
  ipv6: boolean;
  proto: number | null;
  protoName: string;
  protoState: string;
  stateText: string | null;
  duration: number | null;
  expire: number | null;
  timeout: number | null;
  flags: Flag[];
  orgBytes: number | null;
  orgPackets: number | null;
  replyBytes: number | null;
  replyPackets: number | null;
  txBps: number | null;
  rxBps: number | null;
  devOrg: string | null;
  devReply: string | null;
  gwyOrg: string | null;
  gwyReply: string | null;
  hooks: Hook[];
  src: Endpoint | null;
  dst: Endpoint | null;
  snat: Endpoint | null;
  dnat: Endpoint | null;
  srcMac: string | null;
  dstMac: string | null;
  policyId: string | null;
  vd: string | null;
  serial: string | null;
  app: string | null;
  urlCat: string | null;
  tunnel: string | null;
  helper: string | null;
  user: string | null;
  shapers: Field[];
  npuState: string | null;
  offloadOrg: boolean;
  offloadReply: boolean;
  noOffload: Flag[];
  fields: Field[];
  notes: string[];
  raw: string;
}

export interface Parsed {
  sessions: Session[];
  totalReported: number | null;
  truncated: boolean;
  error: string | null;
}

export const ep = (e: Endpoint | null) => (e ? (e.addr.includes(":") ? `[${e.addr}]:${e.port}` : `${e.addr}:${e.port}`) : "?");

export function bytes(n: number | null): string {
  if (n === null) return "";
  if (n < 1024) return `${n} B`;
  const u = ["KB", "MB", "GB", "TB"];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < u.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v < 10 ? v.toFixed(1) : Math.round(v)} ${u[i]}`;
}

export function secs(n: number | null): string {
  if (n === null) return "";
  if (n < 60) return `${n}s`;
  const d = Math.floor(n / 86400);
  const h = Math.floor((n % 86400) / 3600);
  const m = Math.floor((n % 3600) / 60);
  if (d) return `${d}d ${h}h`;
  if (h) return `${h}h ${m}m`;
  return `${m}m ${n % 60}s`;
}

export const total = (s: Session) => (s.orgBytes ?? 0) + (s.replyBytes ?? 0);

export type Offload = "both" | "partial" | "none" | "unknown";

export function offload(s: Session): Offload {
  if (s.offloadOrg && s.offloadReply) return "both";
  if (s.offloadOrg || s.offloadReply) return "partial";
  if (s.noOffload.length) return "none";
  return "unknown";
}

export const OFFLOAD_LABEL: Record<Offload, string> = {
  both: "offloaded",
  partial: "one direction",
  none: "not offloaded",
  unknown: "no offload info",
};

export function nat(s: Session): string {
  const parts: string[] = [];
  if (s.snat) parts.push(`SNAT ${ep(s.snat)}`);
  if (s.dnat) parts.push(`DNAT ${ep(s.dnat)}`);
  return parts.join(", ");
}

/** CLI to show this session again on the FortiGate. */
export function filterCommands(s: Session): string {
  const base = s.ipv6 ? "diagnose sys session6" : "diagnose sys session";
  const lines = [`${base} filter clear`];
  if (s.src) lines.push(`${base} filter src ${s.src.addr}`);
  if (s.dst) lines.push(`${base} filter dst ${s.dst.addr}`);
  if (s.dst && (s.proto === 6 || s.proto === 17 || s.proto === 132)) lines.push(`${base} filter dport ${s.dst.port}`);
  if (s.proto !== null) lines.push(`${base} filter proto ${s.proto}`);
  lines.push(`${base} list`);
  return lines.join("\n");
}

export function searchText(s: Session): string {
  return [
    s.protoName,
    ep(s.src),
    ep(s.dst),
    nat(s),
    s.policyId ? `policy ${s.policyId}` : "",
    s.devOrg ?? "",
    s.serial ?? "",
    s.flags.map((f) => f.name).join(" "),
    s.noOffload.map((f) => f.name).join(" "),
    s.tunnel ?? "",
    s.user ?? "",
    s.srcMac ?? "",
    s.dstMac ?? "",
  ]
    .join(" ")
    .toLowerCase();
}

export interface Count {
  key: string;
  count: number;
  bytes: number;
}

export function countBy(list: Session[], key: (s: Session) => string | null): Count[] {
  const m = new Map<string, Count>();
  for (const s of list) {
    const k = key(s);
    if (!k) continue;
    const c = m.get(k) ?? { key: k, count: 0, bytes: 0 };
    c.count++;
    c.bytes += total(s);
    m.set(k, c);
  }
  return [...m.values()];
}

export function facts(s: Session): { key: string; value: string }[] {
  const rows: { key: string; value: string }[] = [];
  const add = (key: string, v: string | null | undefined) => v && rows.push({ key, value: v });
  add("Protocol", `${s.protoName}${s.proto !== null ? ` (${s.proto})` : ""}`);
  add("State", s.stateText ? `${s.stateText} (proto_state=${s.protoState})` : s.protoState);
  add("Source", ep(s.src));
  add("Destination", ep(s.dst));
  add("NAT", nat(s));
  add("Policy", s.policyId);
  add("VDOM index", s.vd);
  add("Interfaces (original)", s.devOrg ? `${s.devOrg} (interface index)` : null);
  add("Interfaces (reply)", s.devReply);
  add("Gateway (original / reply)", s.gwyOrg || s.gwyReply ? `${s.gwyOrg ?? "?"} / ${s.gwyReply ?? "?"}` : null);
  add("Bytes / packets (original)", s.orgBytes !== null ? `${bytes(s.orgBytes)} / ${s.orgPackets ?? "?"}` : null);
  add("Bytes / packets (reply)", s.replyBytes !== null ? `${bytes(s.replyBytes)} / ${s.replyPackets ?? "?"}` : null);
  add("Rate (tx / rx)", s.txBps !== null ? `${s.txBps} / ${s.rxBps ?? 0} B/s` : null);
  add("Age", secs(s.duration));
  add("Expires in", s.expire !== null ? `${secs(s.expire)} of ${secs(s.timeout)}` : null);
  add("Source MAC", s.srcMac);
  add("Destination MAC", s.dstMac);
  add("VPN tunnel", s.tunnel);
  add("Session helper", s.helper);
  add("User", s.user);
  add("Application ID", s.app);
  add("URL category ID", s.urlCat);
  for (const sh of s.shapers) add(sh.key, sh.value);
  add("Session serial", s.serial);
  add("npu_state", s.npuState ? `${s.npuState}${s.offloadOrg ? " ofld-O" : ""}${s.offloadReply ? " ofld-R" : ""}` : null);
  return rows;
}

export function buildSessionReport(p: Parsed, list: Session[]): Report {
  const rows = list.slice(0, 2000);
  const sections: Section[] = [
    {
      title: "Sessions",
      blocks: [
        {
          type: "keyValues",
          items: [
            { key: "Sessions parsed", value: String(p.sessions.length) },
            { key: "Total reported by FortiGate", value: p.totalReported !== null ? String(p.totalReported) : "not in output" },
            { key: "In this report", value: String(rows.length) },
          ],
        },
        {
          type: "table",
          headers: ["#", "Proto", "Source", "Destination", "NAT", "Policy", "Bytes", "Age", "Expires", "Offload"],
          rows: rows.map((s) => [
            String(s.index),
            `${s.protoName} ${s.stateText ?? ""}`.trim(),
            ep(s.src),
            ep(s.dst),
            nat(s),
            s.policyId ?? "",
            `${bytes(s.orgBytes)} / ${bytes(s.replyBytes)}`,
            secs(s.duration),
            secs(s.expire),
            OFFLOAD_LABEL[offload(s)],
          ]),
        },
      ],
    },
  ];
  const noted = rows.filter((s) => s.notes.length).slice(0, 200);
  if (noted.length) {
    sections.push({
      title: "Notes",
      blocks: [
        {
          type: "table",
          headers: ["#", "Session", "Notes"],
          rows: noted.map((s) => [String(s.index), `${s.protoName} ${ep(s.src)} > ${ep(s.dst)}`, s.notes.join(" ")]),
        },
      ],
    });
  }
  return {
    title: "FortiGate session list",
    subtitle: `${list.length} session${list.length === 1 ? "" : "s"}`,
    tool: "Session List Parser",
    sections,
  } as Report;
}
