// Export report for the timestamp converter.

import type { Report } from "$lib/report/types";
import { FORMAT_ROWS, type TsConversion } from "./types";

export function buildTimestampReport(input: string, zone: string, c: TsConversion): Report {
  return {
    title: `Timestamp: ${input}`,
    subtitle: `Shown in UTC and ${zone}`,
    tool: "Timestamp Converter",
    sections: c.readings.map((r) => ({
      title: `${r.label}${r.plausible ? "" : " (outside 1990 to 2100)"}`,
      blocks: [
        { type: "keyValues" as const, items: FORMAT_ROWS.map((f) => ({ key: f.label, value: r.formats[f.key] })) },
        ...r.notes.map((n) => ({ type: "paragraph" as const, text: n })),
      ],
    })),
  };
}
