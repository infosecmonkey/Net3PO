// Types mirroring `tools::conn_monitor`, plus history statistics and
// outage windows computed from the samples kept in the UI.

export type Kind = "tcp" | "http" | "icmp";

export interface TargetDef {
  id: number;
  kind: Kind;
  address: string;
  port: number | null;
}

export interface Sample {
  target: number;
  seq: number;
  atMs: number;
  ok: boolean;
  ms: number | null;
  status: string;
  detail: string;
}

export type MonitorEvent =
  | { type: "started"; icmpMethod: string }
  | { type: "sample"; sample: Sample }
  | { type: "overrun"; target: number; ms: number }
  | { type: "stopped" };

export interface Outage {
  startMs: number;
  /** First successful sample after the failures; null while ongoing. */
  endMs: number | null;
  failures: number;
  firstStatus: string;
}

export interface TargetStats {
  samples: number;
  ok: number;
  minMs: number | null;
  avgMs: number | null;
  maxMs: number | null;
  lastMs: number | null;
  outages: Outage[];
}

export const KIND_LABEL: Record<Kind, string> = { tcp: "TCP connect", http: "HTTP GET", icmp: "ICMP echo" };

export function targetLabel(t: TargetDef): string {
  return t.kind === "tcp" ? `${t.address}:${t.port ?? ""}` : t.address;
}

/** Runs of consecutive failures. A run ends at the next success. */
export function outages(samples: Sample[]): Outage[] {
  const out: Outage[] = [];
  let cur: Outage | null = null;
  for (const s of samples) {
    if (!s.ok) {
      if (cur) cur.failures++;
      else cur = { startMs: s.atMs, endMs: null, failures: 1, firstStatus: s.status };
    } else if (cur) {
      cur.endMs = s.atMs;
      out.push(cur);
      cur = null;
    }
  }
  if (cur) out.push(cur);
  return out;
}

export function stats(samples: Sample[]): TargetStats {
  const times = samples.filter((s) => s.ok && s.ms !== null).map((s) => s.ms as number);
  const last = [...samples].reverse().find((s) => s.ok && s.ms !== null);
  return {
    samples: samples.length,
    ok: samples.filter((s) => s.ok).length,
    minMs: times.length ? Math.min(...times) : null,
    avgMs: times.length ? times.reduce((a, b) => a + b, 0) / times.length : null,
    maxMs: times.length ? Math.max(...times) : null,
    lastMs: last?.ms ?? null,
    outages: outages(samples),
  };
}

export function duration(ms: number): string {
  const s = Math.round(ms / 1000);
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m ${s % 60}s`;
  return `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`;
}

export function clock(ms: number): string {
  return new Date(ms).toLocaleString(undefined, { dateStyle: "short", timeStyle: "medium" });
}

function csvCell(v: string): string {
  return /[",\n]/.test(v) ? `"${v.replace(/"/g, '""')}"` : v;
}

/** Every kept sample, oldest first, as CSV with ISO timestamps. */
export function toCsv(targets: TargetDef[], history: Map<number, Sample[]>): string {
  const rows = ["timestamp_utc,target,probe,result,status,ms,detail"];
  const all = targets.flatMap((t) => (history.get(t.id) ?? []).map((s) => ({ t, s })));
  all.sort((a, b) => a.s.atMs - b.s.atMs);
  for (const { t, s } of all) {
    rows.push(
      [new Date(s.atMs).toISOString(), targetLabel(t), t.kind, s.ok ? "ok" : "fail", s.status, s.ms === null ? "" : s.ms.toFixed(2), s.detail]
        .map(csvCell)
        .join(","),
    );
  }
  return rows.join("\n") + "\n";
}
