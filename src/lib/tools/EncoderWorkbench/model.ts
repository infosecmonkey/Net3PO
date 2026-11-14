// Types mirroring `tools::encoder::core`, the op catalog and the report.

import type { Report } from "$lib/report/types";

export type Op =
  | "base64Encode" | "base64Decode" | "base64UrlEncode" | "base64UrlDecode"
  | "base32Encode" | "base32Decode" | "hexEncode" | "hexDecode" | "base85Decode"
  | "urlEncode" | "urlDecode" | "urlDecodeForm" | "htmlEncode" | "htmlDecode"
  | "rot13" | "gzipCompress" | "gzipDecompress" | "inflate" | "lzmaDecompress";

export interface View {
  bytes: number;
  text: string | null;
  textTruncated: boolean;
  hex: string;
  hexTruncated: boolean;
  suggestions: Op[];
  hint: string | null;
}

export interface Step {
  op: Op;
  label: string;
  ok: boolean;
  error: string | null;
  note: string | null;
  view: View | null;
}

export interface Run {
  input: View;
  steps: Step[];
  error: string | null;
}

export const OP_GROUPS: { group: string; ops: [Op, string][] }[] = [
  { group: "Decode", ops: [["base64Decode", "Base64 decode"], ["base64UrlDecode", "Base64url decode"], ["base32Decode", "Base32 decode"], ["hexDecode", "Hex decode"], ["base85Decode", "Base85 decode"], ["urlDecode", "URL decode"], ["urlDecodeForm", "URL decode (+ as space)"], ["htmlDecode", "HTML entity decode"]] },
  { group: "Encode", ops: [["base64Encode", "Base64 encode"], ["base64UrlEncode", "Base64url encode"], ["base32Encode", "Base32 encode"], ["hexEncode", "Hex encode"], ["urlEncode", "URL encode"], ["htmlEncode", "HTML entity encode"]] },
  { group: "Other", ops: [["rot13", "ROT13"], ["gzipDecompress", "Gzip decompress"], ["inflate", "Zlib/deflate decompress"], ["lzmaDecompress", "XZ/LZMA decompress"], ["gzipCompress", "Gzip compress"]] },
];

export const OP_LABEL: Record<Op, string> = Object.fromEntries(OP_GROUPS.flatMap((g) => g.ops)) as Record<Op, string>;

export function buildCodecReport(r: Run): Report {
  const last = [...r.steps].reverse().find((s) => s.ok)?.view ?? r.input;
  const preview = last.text !== null ? last.text.slice(0, 4096) : last.hex.split("\n").slice(0, 64).join("\n");
  return {
    title: "Encoder workbench",
    subtitle: r.steps.map((s) => s.label).join(" > ") || "no steps",
    tool: "Encoder Workbench",
    sections: [
      {
        title: "Steps",
        blocks: [
          {
            type: "table",
            headers: ["#", "Step", "Result", "Bytes out", "Note"],
            rows: [
              ["0", "Input", "", String(r.input.bytes), ""],
              ...r.steps.map((s, i) => [String(i + 1), s.label, s.ok ? "ok" : "failed", s.view ? String(s.view.bytes) : "", s.error ?? s.note ?? ""]),
            ],
          },
        ],
      },
      {
        title: "Final output (first 4 KB)",
        blocks: [
          { type: "code", text: preview },
          { type: "paragraph", text: "Decoded output is shown as text only; nothing was executed or rendered." },
        ],
      },
    ],
  };
}
