// Build an export report from a DNS analysis.

import type { Report, ReportSeverity } from "$lib/report/types";
import type { DnsAnalysis } from "$lib/tools/types";

export function buildDnsReport(a: DnsAnalysis): Report {
  const counts: Record<ReportSeverity, number> = { pass: 0, info: 0, warn: 0, fail: 0 };
  for (const s of a.sections) counts[s.status] += 1;

  return {
    title: `DNS audit: ${a.domain}`,
    subtitle: `Resolved via ${a.server}`,
    tool: "DNS Analyzer",
    sections: [
      {
        title: "Summary",
        blocks: [
          {
            type: "keyValues",
            items: [
              { key: "Domain", value: a.domain },
              { key: "Resolver", value: a.server },
              {
                key: "Checks",
                value: `${counts.fail} fail, ${counts.warn} warn, ${counts.pass} pass, ${counts.info} info`,
              },
            ],
          },
          {
            type: "findings",
            items: a.sections.map((s) => ({
              severity: s.status,
              title: s.name,
              detail: s.findings.find((f) => f.severity === s.status)?.message ?? "",
            })),
          },
        ],
      },
      ...a.sections.map((s) => ({
        title: s.name,
        blocks: [
          {
            type: "findings" as const,
            items: s.findings.map((f) => ({ severity: f.severity, title: f.message })),
          },
          ...(s.records.length > 0
            ? [{ type: "code" as const, text: s.records.join("\n") }]
            : []),
        ],
      })),
    ],
  };
}
