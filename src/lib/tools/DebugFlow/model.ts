// Types mirroring `tools::debug_flow::core`, and the export report.

import type { Report, Section } from "$lib/report/types";

export type Verdict = "allowed" | "denied" | "dropped" | "existingSession" | "unknown";

export interface Fact {
  value: string;
  line: number;
}

export interface Event {
  line: number;
  func: string;
  msg: string;
  note: string | null;
  kind: string;
}

export interface Trace {
  traceId: number;
  firstLine: number;
  proto: string | null;
  src: string | null;
  dst: string | null;
  inIface: Fact | null;
  outIface: Fact | null;
  tcpFlags: string | null;
  session: Fact | null;
  route: Fact | null;
  policy: Fact | null;
  nat: Fact[];
  ipsec: Fact[];
  verdict: Verdict;
  verdictText: Fact | null;
  notes: string[];
  events: Event[];
  eventsTruncated: boolean;
}

export interface Parsed {
  traces: Trace[];
  unparsed: number;
  otherLines: number;
  truncated: boolean;
  error: string | null;
}

export const VERDICT_LABEL: Record<Verdict, string> = {
  allowed: "allowed",
  denied: "denied",
  dropped: "dropped",
  existingSession: "existing session",
  unknown: "no verdict in log",
};

export function tuple(t: Trace): string {
  return `${t.proto ?? "?"} ${t.src ?? "?"} > ${t.dst ?? "?"}`;
}

export function facts(t: Trace): { key: string; value: string; line: number | null }[] {
  const rows: { key: string; value: string; line: number | null }[] = [];
  const add = (key: string, f: Fact | null) => f && rows.push({ key, value: f.value, line: f.line });
  add("Verdict", t.verdictText);
  add("Ingress", t.inIface);
  add("Egress", t.outIface);
  add("Session", t.session);
  add("Route", t.route);
  add("Policy", t.policy);
  t.nat.forEach((n) => add("NAT", n));
  t.ipsec.forEach((n) => add("IPsec", n));
  if (t.tcpFlags) rows.push({ key: "TCP flags", value: t.tcpFlags, line: null });
  return rows;
}

export function buildFlowReport(p: Parsed): Report {
  const list = p.traces.slice(0, 200);
  const sections: Section[] = [
    {
      title: "Traces",
      blocks: [
        {
          type: "table",
          headers: ["Trace", "Packet", "In > Out", "Verdict", "Policy", "Lines"],
          rows: list.map((t) => [
            String(t.traceId),
            tuple(t),
            `${t.inIface?.value ?? "?"} > ${t.outIface?.value ?? "?"}`,
            t.verdictText?.value ?? VERDICT_LABEL[t.verdict],
            t.policy?.value ?? "",
            `${t.firstLine}${t.events.length ? `-${t.events[t.events.length - 1].line}` : ""}`,
          ]),
        },
        { type: "paragraph", text: "Verdicts are reported only where the log states them. 'No verdict in log' means the output does not say what happened to that packet." },
      ],
    },
    ...list.slice(0, 50).map((t) => ({
      title: `Trace ${t.traceId}: ${tuple(t)}`,
      blocks: [
        { type: "keyValues" as const, items: facts(t).map((f) => ({ key: f.key, value: f.line ? `${f.value} (line ${f.line})` : f.value })) },
        ...t.notes.map((n) => ({ type: "paragraph" as const, text: n })),
        { type: "code" as const, text: t.events.map((e) => `${e.line}: ${e.func ? `${e.func}: ` : ""}${e.msg}`).join("\n") },
      ],
    })),
  ];
  return {
    title: "FortiGate debug flow",
    subtitle: `${p.traces.length} trace${p.traces.length === 1 ? "" : "s"}`,
    tool: "Debug Flow Parser",
    sections,
  };
}
