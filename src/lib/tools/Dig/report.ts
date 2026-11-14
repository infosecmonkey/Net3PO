// Export report for Dig: every query run this session, oldest first.

import type { Report, Section } from "$lib/report/types";
import type { DigResponse } from "$lib/tools/types";

export interface DigRun {
  at: Date;
  type: string;
  response: DigResponse;
}

export function buildDigReport(runs: DigRun[]): Report | null {
  if (!runs.length) return null;
  const names = [...new Set(runs.map((r) => r.response.question.split(/\s+/)[0]))];
  const sections: Section[] = runs.map((r) => {
    const resp = r.response;
    const rows = [
      ...resp.answers.map((x) => ["Answer", x.name, String(x.ttl), x.rtype, x.data]),
      ...resp.authority.map((x) => ["Authority", x.name, String(x.ttl), x.rtype, x.data]),
      ...resp.additional.map((x) => ["Additional", x.name, String(x.ttl), x.rtype, x.data]),
    ];
    return {
      title: resp.question,
      subtitle: `${resp.rcode} from ${resp.server} (${resp.protocol}, ${resp.queryTimeMs} ms) at ${r.at.toLocaleTimeString()}`,
      blocks: [
        ...(resp.flags.length ? [{ type: "paragraph" as const, text: `Flags: ${resp.flags.join(" ")}` }] : []),
        rows.length
          ? { type: "table" as const, headers: ["Section", "Name", "TTL", "Type", "Data"], rows }
          : { type: "paragraph" as const, text: `No records. Response code: ${resp.rcode}.` },
      ],
    };
  });
  return {
    title: `Dig: ${names.join(", ")}`,
    subtitle: `${runs.length} quer${runs.length === 1 ? "y" : "ies"}: ${runs.map((r) => r.type).join(", ")}`,
    tool: "Dig",
    sections,
  };
}
