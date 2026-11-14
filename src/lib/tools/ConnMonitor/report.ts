// Export report for the connectivity monitor: per-target summary and
// outage windows, with each probe type's limits stated.

import type { Report, Section } from "$lib/report/types";
import { clock, duration, KIND_LABEL, stats, targetLabel, type Sample, type TargetDef } from "./model";

const fmt = (n: number | null) => (n === null ? "-" : `${n.toFixed(1)} ms`);

export function buildMonitorReport(targets: TargetDef[], history: Map<number, Sample[]>, intervalS: number): Report {
  const sections: Section[] = [
    {
      title: "Summary",
      blocks: [
        {
          type: "table",
          headers: ["Target", "Probe", "Samples", "Success", "Min / avg / max", "Outages"],
          rows: targets.map((t) => {
            const s = stats(history.get(t.id) ?? []);
            return [
              targetLabel(t),
              KIND_LABEL[t.kind],
              String(s.samples),
              s.samples ? `${((100 * s.ok) / s.samples).toFixed(1)}%` : "-",
              `${fmt(s.minMs)} / ${fmt(s.avgMs)} / ${fmt(s.maxMs)}`,
              String(s.outages.length),
            ];
          }),
        },
        {
          type: "paragraph",
          text: `Probed every ${intervalS} s. TCP times the connect call; HTTP times the whole request (status below 400 counts as up); ICMP measures echo round trip. A failed ICMP probe does not establish that a service is down, and a timeout alone does not show where traffic was dropped.`,
        },
      ],
    },
  ];
  for (const t of targets) {
    const s = stats(history.get(t.id) ?? []);
    if (!s.outages.length) continue;
    sections.push({
      title: `Outages: ${targetLabel(t)} (${KIND_LABEL[t.kind]})`,
      blocks: [
        {
          type: "table",
          headers: ["Start", "End", "Duration", "Failed probes", "First failure"],
          rows: s.outages.map((o) => [
            clock(o.startMs),
            o.endMs === null ? "ongoing" : clock(o.endMs),
            o.endMs === null ? "-" : duration(o.endMs - o.startMs),
            String(o.failures),
            o.firstStatus,
          ]),
        },
      ],
    });
  }
  return {
    title: "Connectivity monitor",
    subtitle: `${targets.length} target${targets.length === 1 ? "" : "s"}`,
    tool: "Connectivity Monitor",
    sections,
  };
}
