// Export report for Traceroute: per-hop statistics, findings and Path MTU.

import type { Report, ReportSeverity, Section } from "$lib/report/types";
import type { HopView, MtuResult, PathSummary, TraceFinding } from "$lib/tools/types";

/** How each finding kind is shown in the panel and in exports. */
export const SEVERITY: Record<TraceFinding["kind"], { label: string; cls: string; severity: ReportSeverity }> = {
  loss: { label: "Critical", cls: "critical", severity: "fail" },
  unreachable: { label: "Serious", cls: "serious", severity: "fail" },
  noReply: { label: "Serious", cls: "serious", severity: "fail" },
  latency: { label: "Warning", cls: "warning", severity: "warn" },
  rateLimit: { label: "Info", cls: "info", severity: "info" },
};

const ms = (v: number | null) => (v === null ? "-" : v.toFixed(1));

export function buildTraceReport(target: string, resolved: string, method: string, hops: HopView[], summary: PathSummary | null, mtu: MtuResult | null): Report | null {
  if (!hops.length) return null;
  const sections: Section[] = [
    {
      title: "Path",
      blocks: [
        {
          type: "keyValues",
          items: [
            { key: "Target", value: `${target}${resolved && resolved !== target ? ` (${resolved})` : ""}` },
            { key: "Probe method", value: method },
            ...(summary
              ? [
                  { key: "Cycles", value: String(summary.cycles) },
                  { key: "Destination reached", value: summary.reached ? "yes" : "no" },
                  { key: "Destination avg / loss", value: `${ms(summary.destAvgMs)} ms / ${summary.destLossPct === null ? "-" : `${summary.destLossPct.toFixed(0)}%`}` },
                ]
              : []),
          ],
        },
        {
          type: "table",
          headers: ["Hop", "Address", "Name", "Loss", "Sent", "Last", "Avg", "Best", "Worst", "StDev"],
          rows: hops.map((h) => [String(h.ttl), h.ip ?? "*", h.hostname ?? "", `${h.lossPct.toFixed(0)}%`, String(h.sent), ms(h.lastMs), ms(h.avgMs), ms(h.bestMs), ms(h.worstMs), ms(h.stdevMs)]),
        },
        { type: "paragraph", text: "Times in milliseconds. Loss at an intermediate hop that does not continue to later hops usually means that router limits ICMP replies, not that traffic is dropped." },
      ],
    },
  ];
  if (summary?.findings.length) {
    sections.push({
      title: "Findings",
      blocks: [{ type: "findings", items: summary.findings.map((f) => ({ severity: SEVERITY[f.kind].severity, title: f.message, category: [SEVERITY[f.kind].label, f.ttl === null ? "" : `hop ${f.ttl}`].filter(Boolean).join(", ") })) }],
    });
  }
  if (mtu) {
    sections.push({
      title: "Path MTU",
      blocks: [
        { type: "keyValues", items: [{ key: "Path MTU", value: mtu.mtu === null ? "not determined" : String(mtu.mtu) }, ...(mtu.limitedBy ? [{ key: "Limited by", value: mtu.limitedBy }] : []), { key: "Black hole suspected", value: mtu.blackHole ? "yes" : "no" }] },
        ...(mtu.note ? [{ type: "paragraph" as const, text: mtu.note }] : []),
      ],
    });
  }
  return { title: `Traceroute: ${target}`, subtitle: summary ? `${summary.hops} hops, ${summary.cycles} cycles` : "", tool: "Traceroute", sections };
}
