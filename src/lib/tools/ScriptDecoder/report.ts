// Build an export report from a script decode. IOCs are exported defanged.

import type { Block, Report, Section } from "$lib/report/types";
import type { DecodeResult } from "$lib/tools/types";

/** Most characters of one layer included in a report. */
const MAX_LAYER_CHARS = 200_000;

export function buildDecodeReport(r: DecodeResult, source: string): Report {
  const decoded = r.layers.length - 1;
  const sections: Section[] = [
    {
      title: "Summary",
      blocks: [
        {
          type: "keyValues",
          items: [
            { key: "Source", value: source || "pasted script" },
            { key: "Language", value: r.layers[0]?.language || "unknown" },
            { key: "Decoded layers", value: String(decoded) },
            { key: "Indicators", value: String(r.iocs.length) },
            { key: "Flags", value: String(r.flags.length) },
            { key: "Method", value: "Static decoding; the script was not executed" },
          ],
        },
        ...(r.notes.length
          ? [{ type: "paragraph" as const, text: r.notes.join(" ") }]
          : []),
      ],
    },
  ];

  if (r.flags.length > 0) {
    sections.push({
      title: "Heuristic flags",
      subtitle: "Pattern matches, not proof of intent",
      blocks: [
        {
          type: "findings",
          items: r.flags.map((f) => ({
            severity: f.level,
            category: `Layer ${f.layer}${f.line ? `, line ${f.line}` : ""}`,
            title: f.title,
            detail: `${f.detail}${f.snippet ? `\n${f.snippet}` : ""}`,
          })),
        },
      ],
    });
  }

  if (r.iocs.length > 0) {
    sections.push({
      title: "Indicators",
      subtitle: "Defanged",
      blocks: [
        {
          type: "table",
          headers: ["Type", "Indicator", "Layer", "Note"],
          rows: r.iocs.map((i) => [i.kind, i.defanged, String(i.layer), i.private ? "private" : ""]),
        },
      ],
    });
  }

  for (const l of r.layers) {
    const blocks: Block[] = [
      {
        type: "keyValues",
        items: [
          { key: "Kind", value: l.language ? `${l.kind}, ${l.language}` : l.kind },
          { key: "Produced by", value: l.method },
          ...(l.parent !== null
            ? [{ key: "Found in", value: `layer ${l.parent}${l.line ? `, line ${l.line}` : ""}` }]
            : []),
          { key: "Size", value: `${l.size.toLocaleString()} bytes` },
        ],
      },
    ];
    const text = l.text.length > MAX_LAYER_CHARS ? l.text.slice(0, MAX_LAYER_CHARS) : l.text;
    blocks.push({ type: "code", text });
    if (l.truncated || l.text.length > MAX_LAYER_CHARS) {
      blocks.push({ type: "paragraph", text: "Layer text shortened for the report." });
    }
    if (l.strings.length > 0) {
      blocks.push({ type: "code", text: l.strings.join("\n") });
    }
    sections.push({ title: l.index === 0 ? "Layer 0: input" : `Layer ${l.index}`, blocks });
  }

  return {
    title: `Script decode: ${source || "pasted script"}`,
    tool: "Script Decoder",
    sections,
  };
}
