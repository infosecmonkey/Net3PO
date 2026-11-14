// Types mirroring `tools::hashes`, and the export report.

import type { Report } from "$lib/report/types";

export interface Digests {
  sha256: string;
  sha512: string;
  sha1: string;
  md5: string;
  bytes: number;
}

export interface Comparison {
  matched: string | null;
  expectedKind: string | null;
  normalized: string;
  message: string;
}

export const ALGOS: { key: keyof Omit<Digests, "bytes">; label: string; legacy: boolean }[] = [
  { key: "sha256", label: "SHA-256", legacy: false },
  { key: "sha512", label: "SHA-512", legacy: false },
  { key: "sha1", label: "SHA-1", legacy: true },
  { key: "md5", label: "MD5", legacy: true },
];

export function buildHashReport(source: string, d: Digests, cmp: Comparison | null): Report {
  return {
    title: `Hashes: ${source}`,
    subtitle: `${d.bytes.toLocaleString()} bytes`,
    tool: "Hash Calculator",
    sections: [
      {
        title: "Digests",
        blocks: [
          { type: "keyValues", items: ALGOS.map((a) => ({ key: a.legacy ? `${a.label} (legacy)` : a.label, value: d[a.key] })) },
          { type: "paragraph", text: "MD5 and SHA-1 are legacy integrity formats: good for spotting corruption, not for proving a file was not tampered with." },
        ],
      },
      ...(cmp && cmp.normalized
        ? [
            {
              title: "Comparison",
              blocks: [
                {
                  type: "findings" as const,
                  items: [{ severity: cmp.matched ? ("pass" as const) : ("fail" as const), title: cmp.matched ? `Matches ${cmp.matched}` : "No match", detail: `${cmp.message} Expected: ${cmp.normalized}` }],
                },
              ],
            },
          ]
        : []),
    ],
  };
}
