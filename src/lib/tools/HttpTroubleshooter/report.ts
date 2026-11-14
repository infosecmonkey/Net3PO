// Export report for the HTTP troubleshooter: the hop chain with timings,
// the final response headers and the header observations. Response bodies
// are left out; they often hold data that does not belong in a report.

import type { Report, Section } from "$lib/report/types";
import type { HttpHop, HttpResult } from "./types";

export function timingText(h: HttpHop): string {
  const t = h.timing;
  return [
    t.dnsMs !== null ? `DNS ${t.dnsMs} ms` : "",
    `connect ${t.connectMs} ms`,
    t.tlsMs !== null ? `TLS ${t.tlsMs} ms` : "",
    `first byte ${t.firstByteMs} ms`,
    `total ${t.totalMs} ms`,
  ]
    .filter(Boolean)
    .join(", ");
}

export function sizeText(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

export function buildHttpReport(r: HttpResult): Report {
  const last = r.hops[r.hops.length - 1];
  const sections: Section[] = [
    {
      title: "Request chain",
      blocks: [
        {
          type: "table",
          headers: ["#", "Request", "Status", "Address", "Timing"],
          rows: r.hops.map((h, i) => [String(i + 1), `${h.method} ${h.url}`, `${h.status} ${h.reason}`, h.address, timingText(h)]),
        },
        ...r.hops.flatMap((h, i) =>
          h.notes.map((n) => ({ type: "paragraph" as const, text: `Hop ${i + 1}: ${n}` })),
        ),
        ...(r.error ? [{ type: "paragraph" as const, text: `Stopped: ${r.error}` }] : []),
        ...(r.insecure
          ? [{ type: "paragraph" as const, text: "Certificate validation was turned off for this request. TLS results are not verified." }]
          : []),
      ],
    },
  ];
  if (last?.tls) {
    sections.push({
      title: "TLS (final hop)",
      blocks: [
        {
          type: "keyValues",
          items: [
            { key: "Protocol", value: last.tls.protocol },
            { key: "Cipher", value: last.tls.cipher },
            { key: "Validation", value: last.tls.validation },
            { key: "Certificate", value: last.tls.certSubject },
            { key: "Issuer", value: last.tls.certIssuer },
            { key: "Expires", value: new Date(last.tls.certNotAfterMs).toISOString().slice(0, 10) },
          ],
        },
      ],
    });
  }
  if (last) {
    sections.push({
      title: `Final response: ${last.status} ${last.reason}`,
      blocks: [
        { type: "table", headers: ["Header", "Value"], rows: last.headers.map(([n, v]) => [n, v]) },
        {
          type: "paragraph",
          text: `Body: ${sizeText(last.bodyLen)}${last.contentType ? `, ${last.contentType}` : ""}. Not included in this report.`,
        },
      ],
    });
  }
  if (r.observations.length) {
    sections.push({
      title: "Header observations",
      blocks: [
        {
          type: "findings",
          items: r.observations.map((o) => ({
            severity: o.severity,
            category: o.header,
            title: o.title,
            detail: o.detail,
          })),
        },
        {
          type: "paragraph",
          text: "Observations describe the headers on this response only. They are context for troubleshooting, not a security rating of the site.",
        },
      ],
    });
  }
  return {
    title: `HTTP: ${r.hops[0]?.method ?? ""} ${r.hops[0]?.url ?? ""}`,
    subtitle: last ? `${last.status} ${last.reason} after ${r.hops.length} request${r.hops.length === 1 ? "" : "s"}` : "",
    tool: "HTTP Troubleshooter",
    sections,
  };
}
