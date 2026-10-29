// Build an export report from a config diff result.

import type { DiffLine, Report } from "$lib/report/types";
import type { DiffOptions, DiffResult } from "$lib/tools/types";

const WHITESPACE: Record<DiffOptions["whitespace"], string> = {
  exact: "exact",
  trailing: "ignore trailing",
  amount: "ignore amount (-b)",
  all: "ignore all (-w)",
};

/** Unified diff text to report lines, dropping the ---/+++ file header. */
function diffLines(unified: string): DiffLine[] {
  const out: DiffLine[] = [];
  for (const line of unified.replace(/\n$/, "").split("\n")) {
    if (line.startsWith("--- ") || line.startsWith("+++ ")) continue;
    if (line.startsWith("@@")) out.push({ kind: "hunk", text: line });
    else if (line.startsWith("+")) out.push({ kind: "add", text: line.slice(1) });
    else if (line.startsWith("-")) out.push({ kind: "del", text: line.slice(1) });
    else out.push({ kind: "context", text: line.slice(1) });
  }
  return out;
}

export function buildDiffReport(result: DiffResult, opts: DiffOptions): Report {
  const s = result.stats;
  const ignored = [
    opts.ignoreCase && "case",
    opts.ignoreBlankLines && "blank lines",
    opts.ignorePattern && `lines matching ${opts.ignorePattern}`,
  ].filter(Boolean);

  return {
    title: `Config diff: ${opts.leftName} vs ${opts.rightName}`,
    tool: "Config Diff",
    sections: [
      {
        title: "Summary",
        blocks: [
          {
            type: "keyValues",
            items: [
              { key: "Left", value: `${opts.leftName} (${s.leftLines} lines)` },
              { key: "Right", value: `${opts.rightName} (${s.rightLines} lines)` },
              {
                key: "Result",
                value: result.identical
                  ? "No differences"
                  : `${s.added} added, ${s.removed} removed, ${s.changed} changed`,
              },
              { key: "Whitespace", value: WHITESPACE[opts.whitespace] },
              { key: "Ignored", value: ignored.length ? ignored.join(", ") : "nothing" },
              {
                key: "Lines ignored",
                value: `${s.ignoredLeft} left, ${s.ignoredRight} right`,
              },
              {
                key: "Context",
                value: opts.context === null ? "full file" : `${opts.context} lines`,
              },
            ],
          },
        ],
      },
      {
        title: "Changes",
        subtitle: result.identical ? undefined : `${result.hunks.length} hunk(s)`,
        blocks: result.identical
          ? [{ type: "paragraph", text: "The compared lines are identical." }]
          : [{ type: "diff", lines: diffLines(result.unified) }],
      },
    ],
  };
}
