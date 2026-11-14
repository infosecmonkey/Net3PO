// Build an export report from an email analysis, including any online checks
// the user ran. Header claims and Net3PO's own checks stay in separate sections.

import type { Block, Report } from "$lib/report/types";
import type { EmailAnalysis, EmailBlocklistReport, EmailIpOwner } from "$lib/tools/types";

export const STATUS_LABEL: Record<string, string> = {
  listed: "Listed",
  notListed: "Not listed",
  refused: "Refused",
  error: "Error",
};

export function fmtDelay(s: number | null): string {
  if (s === null) return "";
  const sign = s < 0 ? "-" : "+";
  const a = Math.abs(s);
  if (a < 60) return `${sign}${a}s`;
  if (a < 3600) return `${sign}${Math.floor(a / 60)}m ${a % 60}s`;
  return `${sign}${Math.floor(a / 3600)}h ${Math.floor((a % 3600) / 60)}m`;
}

export function fmtUtc(ts: number | null): string {
  if (ts === null) return "";
  return new Date(ts * 1000).toISOString().replace("T", " ").replace(".000Z", " UTC");
}

export function ownerLines(o: EmailIpOwner): { key: string; value: string }[] {
  const rows = [{ key: "IP", value: o.ip }];
  if (o.origin) {
    rows.push(
      { key: "ASN", value: o.origin.asns.map((a) => `AS${a}`).join(", ") },
      { key: "AS name", value: o.asName || "(unknown)" },
      { key: "Announced prefix", value: o.origin.prefix },
      { key: "Country (registry)", value: o.origin.country },
      { key: "Registry", value: `${o.origin.registry.toUpperCase()}${o.origin.allocated ? `, allocated ${o.origin.allocated}` : ""}` },
    );
  } else {
    rows.push({ key: "ASN", value: "No routing data found" });
  }
  rows.push(
    { key: "Reverse DNS", value: o.ptr.length ? o.ptr.join(", ") : "(none)" },
    { key: "Source", value: `${o.source}, ${new Date(o.lookedUpMs).toLocaleString()}` },
  );
  return rows;
}

export function buildEmailReport(
  a: EmailAnalysis,
  owners: EmailIpOwner[],
  lists: EmailBlocklistReport[],
): Report {
  const from = a.addresses.find((x) => x.role === "From");
  const sections: Report["sections"] = [
    {
      title: "Summary",
      blocks: [
        {
          type: "keyValues",
          items: [
            { key: "Subject", value: a.subject || "(none)" },
            { key: "Date", value: a.date || "(none)" },
            { key: "From", value: from ? `${from.name ? `${from.name} ` : ""}<${from.address}>` : "(none)" },
            ...a.addresses
              .filter((x) => x.role === "Reply-To" || x.role === "Return-Path" || x.role === "Sender")
              .map((x) => ({ key: x.role, value: x.address })),
            { key: "Message-ID", value: a.messageId || "(none)" },
            { key: "Input", value: a.inputKind === "message" ? "Full message (.eml)" : "Headers only" },
          ],
        },
        {
          type: "findings",
          items: a.findings.map((f) => ({ severity: f.severity, category: f.category, title: f.title, detail: f.detail })),
        },
      ],
    },
  ];

  if (a.origin.length) {
    sections.push({
      title: "Sending server (estimated)",
      blocks: [
        {
          type: "findings",
          items: a.origin.map((o) => ({
            severity: "info" as const,
            category: o.basis === "handoff" ? "Handoff" : "Earliest",
            title: `${o.ip}${o.host ? ` (${o.host})` : ""}, hop ${o.hop}`,
            detail: o.explanation,
          })),
        },
      ],
    });
  }

  sections.push({
    title: "Route (oldest first)",
    blocks: [
      {
        type: "table",
        headers: ["#", "Time (UTC)", "Delay", "From", "IP", "By", "With"],
        rows: a.hops.map((h) => [
          String(h.index),
          fmtUtc(h.timestamp) || h.date,
          fmtDelay(h.delaySecs),
          [h.fromHost, h.helo && h.helo !== h.fromHost ? `helo ${h.helo}` : "", h.fromRdns ? `rDNS ${h.fromRdns}` : ""]
            .filter(Boolean)
            .join(", "),
          h.fromIp + (h.nonPublicIp ? " (private)" : ""),
          h.byHost,
          [h.protocol, h.tls].filter(Boolean).join(" "),
        ]),
      },
    ],
  });

  const claims: Block[] = a.authResults.map((r) => ({
    type: "table" as const,
    headers: [`${r.header}${r.instance ? ` i=${r.instance}` : ""} by ${r.authservId || "receiving system (not named)"}`, "Result", "Details"],
    rows: r.methods.map((m) => [m.method, m.result, m.props.map(([k, v]) => `${k}=${v}`).join(" ")]),
  }));
  if (a.receivedSpf.length) claims.push({ type: "code", text: a.receivedSpf.map((s) => `Received-SPF: ${s}`).join("\n") });
  sections.push({
    title: "Authentication claimed in the header",
    subtitle: "Written by mail systems along the route; not verified by Net3PO",
    blocks: claims.length ? claims : [{ type: "paragraph", text: "None present." }],
  });

  if (a.dkim.length) {
    sections.push({
      title: "DKIM signatures",
      subtitle: "Tags as written; validity needs the full message and the public key",
      blocks: [
        {
          type: "table",
          headers: ["Domain (d=)", "Selector (s=)", "Algorithm", "Alignment with From", "Key record"],
          rows: a.dkim.map((d) => [d.domain, d.selector, d.algorithm, d.alignment, d.keyName]),
        },
        ...a.dkim
          .filter((d) => d.notes.length)
          .map((d) => ({ type: "paragraph" as const, text: `${d.domain}: ${d.notes.join(" ")}` })),
      ],
    });
  }

  for (const o of owners) {
    const blocks: Block[] = [{ type: "keyValues", items: ownerLines(o) }];
    if (o.errors.length) blocks.push({ type: "paragraph", text: `Errors: ${o.errors.join("; ")}` });
    sections.push({ title: `IP owner: ${o.ip}`, subtitle: "Routing data from an online lookup run in Net3PO", blocks });
  }
  for (const l of lists) {
    sections.push({
      title: `Blocklists: ${l.ip}`,
      subtitle: `DNS blocklist lookups run in Net3PO, ${new Date(l.lookedUpMs).toLocaleString()}`,
      blocks: [
        {
          type: "table",
          headers: ["List", "Status", "Detail"],
          rows: l.results.map((r) => [r.zone, STATUS_LABEL[r.status] ?? r.status, [r.detail, r.reason].filter(Boolean).join(" ")]),
        },
      ],
    });
  }

  if (a.domains.length || a.lookalikes.length) {
    const blocks: Block[] = [
      {
        type: "table",
        headers: ["Domain", "Seen as"],
        rows: a.domains.map((d) => [d.unicode ? `${d.domain} (${d.unicode})` : d.domain, d.roles.join(", ")]),
      },
    ];
    if (a.lookalikes.length) {
      blocks.push({
        type: "table",
        headers: ["Domain", "Resembles", "Compared with", "Why"],
        rows: a.lookalikes.map((l) => [l.domain, l.resembles, l.against, l.reason]),
      });
    }
    sections.push({ title: "Domains", blocks });
  }

  if (a.attachments.length) {
    sections.push({
      title: "Attachments (listed, not opened)",
      blocks: [
        {
          type: "table",
          headers: ["Name", "Type", "Size", ""],
          rows: a.attachments.map((x) => [x.name, x.contentType, `${x.size} bytes`, x.risky ? "risky type" : ""]),
        },
      ],
    });
  }

  if (a.iocs.length) {
    sections.push({
      title: "Indicators (defanged)",
      blocks: [
        {
          type: "table",
          headers: ["Type", "Indicator", "Found in"],
          rows: a.iocs.map((i) => [i.kind, i.defanged, i.layer === 0 ? "headers" : "body"]),
        },
      ],
    });
  }

  return {
    title: `Email analysis: ${a.subject || from?.address || "message"}`,
    subtitle: from ? `From ${from.address}` : undefined,
    tool: "Email Header Analyzer",
    sections,
  };
}
