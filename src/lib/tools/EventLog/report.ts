// Build an export report for the Windows Event Log Reader: what was loaded,
// the active filter, the busiest event IDs and the matching events.

import type { Report } from "$lib/report/types";
import type { EvtFilter, EvtLoadSummary, EvtQueryResult, EvtRow } from "$lib/tools/types";

/** A record's time for display: UTC when known, else as written. */
export function showTime(r: { timeRaw: string; timeUtcMs: number | null; zoneUnknown: boolean }): string {
  if (r.timeUtcMs !== null) return new Date(r.timeUtcMs).toISOString().replace("T", " ").replace("Z", " UTC");
  return r.zoneUnknown ? `${r.timeRaw} (local, zone unknown)` : r.timeRaw;
}

export function spanText(s: EvtLoadSummary): string {
  if (s.firstMs === null || s.lastMs === null) return "no readable times";
  const f = (ms: number) => new Date(ms).toISOString().replace("T", " ").slice(0, 19);
  return s.zoneUnknown
    ? `${f(s.firstMs)} to ${f(s.lastMs)} (exporting computer's local time, zone unknown)`
    : `${f(s.firstMs)} to ${f(s.lastMs)} UTC`;
}

export function filterText(f: EvtFilter): string {
  const parts: string[] = [];
  if (f.ids) parts.push(`IDs ${f.ids}`);
  if (f.providers.length) parts.push(`provider ${f.providers.join(", ")}`);
  if (f.channels.length) parts.push(`channel ${f.channels.join(", ")}`);
  if (f.computers.length) parts.push(`computer ${f.computers.join(", ")}`);
  if (f.levels.length) parts.push(`level ${f.levels.join(", ")}`);
  if (f.outcome) parts.push(`audit ${f.outcome}`);
  if (f.field) parts.push(`field ${f.field}`);
  if (f.text) parts.push(`text "${f.text}"`);
  if (f.fromMs !== null) parts.push(`from ${new Date(f.fromMs).toISOString()}`);
  if (f.toMs !== null) parts.push(`to ${new Date(f.toMs).toISOString()}`);
  return parts.length ? parts.join("; ") : "none (all events)";
}

export function buildEventReport(
  s: EvtLoadSummary,
  f: EvtFilter,
  q: EvtQueryResult,
  rows: EvtRow[],
): Report {
  return {
    title: `Event log: ${s.name}`,
    subtitle: `${q.matched.toLocaleString()} of ${q.total.toLocaleString()} events match`,
    tool: "Windows Event Log",
    sections: [
      {
        title: "Source",
        blocks: [
          {
            type: "keyValues",
            items: [
              { key: "File", value: s.name },
              { key: "Format", value: s.format.toUpperCase() },
              { key: "Events loaded", value: `${s.records.toLocaleString()}${s.truncated ? " (limit reached; file has more)" : ""}${s.cancelled ? " (load stopped early)" : ""}` },
              { key: "Unreadable records", value: String(s.errorCount) },
              { key: "Time span", value: spanText(s) },
              { key: "Filter", value: filterText(f) },
            ],
          },
          ...s.warnings.map((w) => ({ type: "paragraph" as const, text: w })),
        ],
      },
      {
        title: "Most frequent event IDs (filtered)",
        blocks: [
          {
            type: "table",
            headers: ["Event ID", "Provider", "Count", "Meaning"],
            rows: q.facets.ids.map((c) => {
              const [id, provider] = c.value.split("|");
              return [id, provider, String(c.count), c.label];
            }),
          },
          {
            type: "paragraph",
            text: "Explanations are provider-specific. An event ID alone is not evidence of compromise; read the fields and the surrounding events.",
          },
        ],
      },
      {
        title: `Matching events${q.matched > rows.length ? ` (first ${rows.length})` : ""}`,
        blocks: [
          {
            type: "table",
            headers: ["Time", "ID", "Level", "Provider", "Computer", "Details"],
            rows: rows.map((r) => [
              showTime(r),
              String(r.eventId),
              r.outcome || r.level,
              r.provider,
              r.computer,
              [r.title, r.summary].filter(Boolean).join(": "),
            ]),
          },
        ],
      },
    ],
  };
}
