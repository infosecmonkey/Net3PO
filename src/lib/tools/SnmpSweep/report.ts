// Build an export report from an SNMP sweep. Credentials (community strings,
// v3 secrets) are never included.

import type { Report } from "$lib/report/types";

export interface SweepReportInput {
  targets: string;
  port: number;
  version: string;
  summary: string;
  rows: { ip: string; name: string; descr: string; objid: string }[];
}

export function buildSweepReport(s: SweepReportInput): Report {
  return {
    title: `SNMP sweep: ${s.targets}`,
    tool: "SNMP Sweep",
    sections: [
      {
        title: "Summary",
        blocks: [
          {
            type: "keyValues",
            items: [
              { key: "Targets", value: s.targets },
              { key: "Port", value: `${s.port}/udp` },
              { key: "Version", value: s.version },
              { key: "Result", value: s.summary || `${s.rows.length} responder(s)` },
            ],
          },
        ],
      },
      {
        title: "Responders",
        blocks:
          s.rows.length > 0
            ? [
                {
                  type: "table",
                  headers: ["IP", "sysName", "sysDescr", "sysObjectID"],
                  rows: s.rows.map((r) => [r.ip, r.name, r.descr, r.objid]),
                },
              ]
            : [{ type: "paragraph", text: "No SNMP responders found." }],
      },
    ],
  };
}
