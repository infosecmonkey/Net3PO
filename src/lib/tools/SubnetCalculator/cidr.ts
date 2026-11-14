// Types mirroring `subnet_calculator::sets`, and export reports for the
// aggregate and compare tabs.

import type { Block, Report, Section } from "$lib/report/types";

export interface FamilySet {
  entries: number;
  prefixes: string[];
  truncated: boolean;
  addresses: string;
}

export interface Invalid {
  line: number;
  text: string;
  reason: string;
}

export interface Note {
  line: number;
  text: string;
  note: string;
}

export interface Overlap {
  kind: "duplicate" | "contains" | "partial";
  a: string;
  aLine: number;
  b: string;
  bLine: number;
}

export interface AggregateResult {
  v4: FamilySet;
  v6: FamilySet;
  invalid: Invalid[];
  notes: Note[];
  overlaps: Overlap[];
  overlapsTruncated: boolean;
  inputTruncated: boolean;
}

export interface FamilyCompare {
  onlyA: FamilySet;
  onlyB: FamilySet;
  both: FamilySet;
}

export interface CompareResult {
  v4: FamilyCompare;
  v6: FamilyCompare;
  invalidA: Invalid[];
  invalidB: Invalid[];
  identical: boolean;
}

export const OVERLAP_LABEL: Record<Overlap["kind"], string> = {
  duplicate: "duplicate of",
  contains: "contains",
  partial: "partly overlaps",
};

export function addressText(n: string): string {
  return /^\d+$/.test(n) && n.length < 16 ? Number(n).toLocaleString() : n;
}

function listBlock(title: string, s: FamilySet): Block[] {
  if (!s.prefixes.length) return [];
  return [
    { type: "paragraph", text: `${title}: ${s.prefixes.length} prefix${s.prefixes.length === 1 ? "" : "es"}, ${addressText(s.addresses)} addresses${s.truncated ? " (list truncated)" : ""}` },
    { type: "code", text: s.prefixes.join("\n") },
  ];
}

function invalidBlock(label: string, inv: Invalid[]): Block[] {
  return inv.length
    ? [{ type: "table", headers: [`${label} line`, "Entry", "Problem"], rows: inv.map((i) => [String(i.line), i.text, i.reason]) }]
    : [];
}

export function buildAggregateReport(r: AggregateResult): Report {
  const sections: Section[] = [
    {
      title: "Aggregated prefixes",
      blocks: [
        ...listBlock("IPv4", r.v4),
        ...listBlock("IPv6", r.v6),
        { type: "paragraph", text: "Aggregation covers exactly the input addresses: nothing is added or dropped." },
      ],
    },
  ];
  if (r.overlaps.length) {
    sections.push({
      title: "Overlapping entries",
      blocks: [
        { type: "table", headers: ["Line", "Entry", "Relation", "Line", "Entry"], rows: r.overlaps.map((o) => [String(o.aLine), o.a, OVERLAP_LABEL[o.kind], String(o.bLine), o.b]) },
        ...(r.overlapsTruncated ? [{ type: "paragraph" as const, text: "Only the first 1,000 overlaps are listed." }] : []),
      ],
    });
  }
  if (r.invalid.length || r.notes.length) {
    sections.push({
      title: "Input problems",
      blocks: [
        ...invalidBlock("Input", r.invalid),
        ...(r.notes.length ? [{ type: "table" as const, headers: ["Line", "Entry", "Note"], rows: r.notes.map((n) => [String(n.line), n.text, n.note]) }] : []),
      ],
    });
  }
  return {
    title: "Address aggregation",
    subtitle: `${r.v4.entries + r.v6.entries} entries in, ${r.v4.prefixes.length + r.v6.prefixes.length} prefixes out`,
    tool: "Subnet Calculator",
    sections,
  };
}

export function buildCompareReport(c: CompareResult): Report {
  const fam = (name: string, f: FamilyCompare): Section => ({
    title: name,
    blocks: [
      ...listBlock("Only in A", f.onlyA),
      ...listBlock("Only in B", f.onlyB),
      ...listBlock("In both", f.both),
    ],
  });
  const sections = [fam("IPv4", c.v4), fam("IPv6", c.v6)].filter((s) => s.blocks.length);
  if (c.invalidA.length || c.invalidB.length) {
    sections.push({ title: "Input problems", blocks: [...invalidBlock("A", c.invalidA), ...invalidBlock("B", c.invalidB)] });
  }
  return {
    title: "Address set comparison",
    subtitle: c.identical ? "A and B cover the same addresses" : "A and B differ",
    tool: "Subnet Calculator",
    sections,
  };
}
