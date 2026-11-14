// Export reports for the TLS inspector. Measured results (what the server
// sent and negotiated) are kept apart from our own evaluation (trust and
// hostname checks). Private keys are never part of a report.

import type { Block, Finding, Report, Section } from "$lib/report/types";
import type { CertInfo, CsrInfo, DecodeResult, LiveResult, SuiteResult } from "./types";

export function day(ms: number): string {
  return new Date(ms).toISOString().slice(0, 10);
}

export function validityText(c: CertInfo): string {
  if (c.validity === "expired") return `expired ${-c.daysLeft} days ago`;
  if (c.validity === "notYetValid") return "not valid yet";
  return `${c.daysLeft} days left`;
}

export function keyText(k: { algorithm: string; bits: number; curve: string }): string {
  return [k.algorithm, k.curve || (k.bits ? `${k.bits} bits` : "")].filter(Boolean).join(" ");
}

export function sanText(s: { dns: string[]; ip: string[]; email: string[]; uri: string[] }): string {
  const all = [...s.dns, ...s.ip.map((i) => `IP ${i}`), ...s.email, ...s.uri];
  return all.length ? all.join(", ") : "(none)";
}

export function certRows(c: CertInfo): { key: string; value: string }[] {
  const rows = [
    { key: "Subject", value: c.subject },
    { key: "Issuer", value: c.issuer },
    { key: "SANs", value: sanText(c.sans) },
    { key: "Valid", value: `${day(c.notBeforeMs)} to ${day(c.notAfterMs)} (${validityText(c)})` },
    { key: "Key", value: keyText(c.key) },
    { key: "Signature", value: c.signatureAlgorithm },
    { key: "Type", value: c.isCa ? `CA${c.pathLen !== null ? `, path length ${c.pathLen}` : ""}${c.selfSigned ? ", self-signed" : ""}` : c.selfSigned ? "End entity, self-signed" : "End entity" },
  ];
  if (c.keyUsage.length) rows.push({ key: "Key usage", value: c.keyUsage.join(", ") });
  if (c.extendedKeyUsage.length) rows.push({ key: "Extended key usage", value: c.extendedKeyUsage.join(", ") });
  rows.push({ key: "Serial", value: c.serial });
  if (c.ocsp.length) rows.push({ key: "OCSP", value: c.ocsp.join(", ") });
  if (c.crl.length) rows.push({ key: "CRL", value: c.crl.join(", ") });
  if (c.caIssuers.length) rows.push({ key: "CA issuers", value: c.caIssuers.join(", ") });
  rows.push(
    { key: "SHA-256", value: c.sha256 },
    { key: "SPKI SHA-256", value: c.key.spkiSha256 },
  );
  return rows;
}

export function csrRows(c: CsrInfo): { key: string; value: string }[] {
  return [
    { key: "Subject", value: c.subject },
    { key: "SANs", value: sanText(c.sans) },
    { key: "Key", value: keyText(c.key) },
    { key: "Signature", value: `${c.signatureAlgorithm}, ${c.signatureValid ? "verifies with its own key" : "does NOT verify"}` },
  ];
}

function notesBlock(notes: string[]): Block[] {
  return notes.length
    ? [{ type: "findings", items: notes.map((n) => ({ severity: "warn" as const, title: n })) }]
    : [];
}

function certSection(c: CertInfo, title: string): Section {
  return { title, blocks: [{ type: "keyValues", items: certRows(c) }, ...notesBlock(c.notes)] };
}

export function liveFindings(r: LiveResult): Finding[] {
  const f: Finding[] = [];
  f.push(
    r.trust.chainTrusted
      ? { severity: "pass", title: "Chain leads to a trusted root", detail: r.trust.store }
      : { severity: "fail", title: "Chain is not trusted", detail: `${r.trust.chainError}. Checked against: ${r.trust.store}` },
  );
  f.push(
    r.trust.nameMatch
      ? { severity: "pass", title: `${r.trust.checkedName} is covered by ${r.trust.nameMatch}` }
      : { severity: "fail", title: `No SAN covers ${r.trust.checkedName}` },
  );
  for (const n of r.chainNotes) f.push({ severity: "warn", title: n });
  return f;
}

export function buildLiveReport(r: LiveResult, suites: SuiteResult[] | null): Report {
  const sections: Section[] = [
    {
      title: "Connection (measured)",
      blocks: [
        {
          type: "keyValues",
          items: [
            { key: "Target", value: `${r.host}:${r.port}` },
            { key: "Connected to", value: r.address },
            { key: "SNI sent", value: r.sniSent ?? "(none)" },
            { key: "STARTTLS", value: r.starttls === "none" ? "no" : r.starttls.toUpperCase() },
            { key: "Protocol", value: r.protocol },
            { key: "Cipher suite", value: r.cipherSuite },
            { key: "Key exchange", value: r.keyExchange || "(not reported)" },
            { key: "ALPN", value: r.alpn || "(none)" },
            {
              key: "Timing",
              value: `connect ${r.timing.connectMs} ms${r.timing.starttlsMs !== null ? `, STARTTLS ${r.timing.starttlsMs} ms` : ""}, handshake ${r.timing.handshakeMs} ms`,
            },
          ],
        },
        ...(r.transcript.length ? [{ type: "code" as const, text: r.transcript.join("\n") }] : []),
      ],
    },
    {
      title: "Evaluation (Net3PO checks)",
      blocks: [
        { type: "findings", items: liveFindings(r) },
        {
          type: "paragraph",
          text: "Trust is evaluated locally against the bundled Mozilla root store; your OS or browser may trust different roots. Revocation (OCSP, CRL) is not checked.",
        },
      ],
    },
    ...r.chain.map((c, i) =>
      certSection(c, `Presented certificate ${i + 1}${i === 0 ? " (leaf)" : ""}: ${c.subjectCn || c.subject}`),
    ),
  ];
  if (suites) {
    sections.push({
      title: "Version and cipher test (active)",
      blocks: [
        {
          type: "table",
          headers: ["Version", "Cipher suite", "Result", "Detail"],
          rows: suites.map((s) => [s.version, s.suite, s.support, s.detail]),
        },
        {
          type: "paragraph",
          text: "Only TLS 1.2 and 1.3 suites implemented by this build were offered. TLS 1.0/1.1, CBC and static RSA suites were not tested, so their absence here says nothing about the server.",
        },
      ],
    });
  }
  return {
    title: `TLS: ${r.host}:${r.port}`,
    subtitle: `${r.protocol}, ${r.trust.chainTrusted && r.trust.nameMatch ? "trusted" : "not trusted"}`,
    tool: "TLS Inspector",
    sections,
  };
}

export function buildDecodeReport(d: DecodeResult): Report {
  const sections: Section[] = d.items.map((item, i) =>
    item.type === "certificate"
      ? certSection(item.cert, `Certificate ${i + 1}: ${item.cert.subjectCn || item.cert.subject}`)
      : { title: `CSR ${i + 1}: ${item.csr.subjectCn || item.csr.subject}`, blocks: [{ type: "keyValues", items: csrRows(item.csr) }, ...notesBlock(item.csr.notes)] },
  );
  sections.push({
    title: "Notes",
    blocks: [
      {
        type: "paragraph",
        text: "Decoded offline. Decoding shows what each certificate says; it does not establish trust or check revocation.",
      },
      ...d.warnings.map((w) => ({ type: "paragraph" as const, text: w })),
    ],
  });
  return {
    title: "Certificate decode",
    subtitle: `${d.items.length} item${d.items.length === 1 ? "" : "s"}`,
    tool: "TLS Inspector",
    sections,
  };
}
