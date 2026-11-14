// Types mirroring `tools::ioc`, grouping, CSV and the export report.

import type { Report } from "$lib/report/types";

export type IocKind = "url" | "domain" | "ipv4" | "ipv6" | "email" | "md5" | "sha1" | "sha256" | "sha512";

export interface Ioc {
  kind: IocKind;
  value: string;
  defanged: string;
  original: string;
  count: number;
  line: number;
  column: number;
  flags: string[];
}

export interface Extraction {
  iocs: Ioc[];
  truncated: boolean;
  error: string | null;
}

export const KIND_LABEL: Record<IocKind, string> = {
  url: "URLs",
  domain: "Domains",
  ipv4: "IPv4 addresses",
  ipv6: "IPv6 addresses",
  email: "Email addresses",
  md5: "MD5 candidates",
  sha1: "SHA-1 candidates",
  sha256: "SHA-256 candidates",
  sha512: "SHA-512 candidates",
};

export const KIND_ORDER: IocKind[] = ["url", "domain", "ipv4", "ipv6", "email", "sha256", "sha1", "md5", "sha512"];

/** Private, documentation and other non-routable addresses. */
export function isInternal(i: Ioc): boolean {
  return i.flags.some((f) => /private|loopback|link-local|documentation|carrier-grade|not a host|unique local/.test(f));
}

function cell(v: string): string {
  return /[",\n]/.test(v) ? `"${v.replace(/"/g, '""')}"` : v;
}

export function toCsv(list: Ioc[], defanged: boolean): string {
  const rows = ["type,value,count,line,column,notes"];
  for (const i of list) {
    rows.push([i.kind, defanged ? i.defanged : i.value, String(i.count), String(i.line), String(i.column), i.flags.join("; ")].map(cell).join(","));
  }
  return rows.join("\n") + "\n";
}

export function buildIocReport(list: Ioc[]): Report {
  const sections = KIND_ORDER.filter((k) => list.some((i) => i.kind === k)).map((k) => {
    const items = list.filter((i) => i.kind === k);
    return {
      title: `${KIND_LABEL[k]} (${items.length})`,
      blocks: [
        {
          type: "table" as const,
          headers: ["Indicator (defanged)", "Seen", "First at", "Notes"],
          rows: items.map((i) => [i.defanged, String(i.count), `line ${i.line}, col ${i.column}`, i.flags.join("; ")]),
        },
      ],
    };
  });
  return {
    title: "Indicators of compromise",
    subtitle: `${list.length} distinct indicator${list.length === 1 ? "" : "s"}`,
    tool: "IOC Extractor",
    sections: [
      ...sections,
      {
        title: "About this list",
        blocks: [
          {
            type: "paragraph",
            text: "Extracted offline by pattern. Indicators are defanged so they cannot be clicked. Hash entries are candidates by length, not confirmed hashes. Nothing here was resolved, fetched or checked against reputation sources.",
          },
        ],
      },
    ],
  };
}
