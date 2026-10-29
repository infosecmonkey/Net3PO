// Build an export report from a finished or cancelled port scan.

import type { Report } from "$lib/report/types";
import type { ScanEvent } from "$lib/tools/types";

export interface ScanReportInput {
  target: string;
  ports: string;
  preset: string;
  open: { host: string; port: number; service: string | null }[];
  summary: Extract<ScanEvent, { type: "done" }> | null;
}

export function buildScanReport(s: ScanReportInput): Report {
  const items = [
    { key: "Target", value: s.target },
    { key: "Ports", value: s.ports },
    { key: "Timing", value: s.preset },
    { key: "Method", value: "TCP connect" },
  ];
  if (s.summary) {
    items.push(
      { key: "Status", value: s.summary.cancelled ? "Cancelled" : "Complete" },
      {
        key: "Result",
        value: `${s.summary.open} open across ${s.summary.hostsWithOpen} of ${s.summary.hosts} host(s)`,
      },
      {
        key: "Checks",
        value: `${s.summary.total.toLocaleString()} host-port checks in ${(s.summary.elapsedMs / 1000).toFixed(1)}s`,
      },
      {
        key: "Not open",
        value: `${s.summary.closed} closed, ${s.summary.filtered} filtered`,
      },
    );
  }
  return {
    title: `Port scan: ${s.target}`,
    tool: "Port Scanner",
    sections: [
      { title: "Summary", blocks: [{ type: "keyValues", items }] },
      {
        title: "Open ports",
        blocks:
          s.open.length > 0
            ? [
                {
                  type: "table",
                  headers: ["Host", "Port", "Service"],
                  rows: s.open.map((p) => [p.host, `${p.port}/tcp`, p.service ?? ""]),
                },
              ]
            : [{ type: "paragraph", text: "No open ports found." }],
      },
    ],
  };
}
