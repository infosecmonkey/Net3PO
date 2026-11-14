// Types mirroring `tools::jwt_saml`, and the export reports. Reports hold
// decoded content and checks, never the raw token, message or key.

import type { Report } from "$lib/report/types";

export interface Check {
  name: string;
  status: "pass" | "fail" | "info";
  detail: string;
}

export type SigState = "notChecked" | "valid" | "invalid" | "unsigned" | "unsupported";

export interface JwtResult {
  header: unknown;
  claims: unknown;
  alg: string;
  signature: SigState;
  signatureDetail: string;
  checks: Check[];
  keyRefs: string[];
  times: [string, number][];
}

export interface SignatureInfo {
  on: string;
  method: string;
  digest: string;
  weak: boolean;
  certSubject: string;
  certNotAfterMs: number | null;
  certSha256: string;
}

export interface SamlResult {
  binding: string;
  xml: string;
  message: string;
  id: string;
  issueInstant: string;
  destination: string;
  inResponseTo: string;
  issuer: string;
  status: string;
  assertionIssuer: string;
  nameId: string;
  nameIdFormat: string;
  recipient: string;
  notBefore: string;
  notOnOrAfter: string;
  confirmationNotOnOrAfter: string;
  audiences: string[];
  authnInstant: string;
  sessionIndex: string;
  attributes: [string, string[]][];
  signatures: SignatureInfo[];
  encryptedAssertion: boolean;
  checks: Check[];
}

export const SIG_LABEL: Record<SigState, string> = {
  notChecked: "not checked (no key)",
  valid: "valid",
  invalid: "invalid",
  unsigned: "unsigned (alg none)",
  unsupported: "could not check",
};

export function samlFields(r: SamlResult): [string, string][] {
  const rows: [string, string][] = [
    ["Message", r.message],
    ["Binding", r.binding],
    ["ID", r.id],
    ["Issue instant", r.issueInstant],
    ["Destination", r.destination],
    ["In response to", r.inResponseTo],
    ["Issuer", r.issuer],
    ["Status", r.status],
    ["Assertion issuer", r.assertionIssuer],
    ["NameID", r.nameId],
    ["NameID format", r.nameIdFormat.split(":").pop() ?? ""],
    ["Recipient", r.recipient],
    ["Not before", r.notBefore],
    ["Not on or after", r.notOnOrAfter],
    ["Confirmation not on or after", r.confirmationNotOnOrAfter],
    ["Audiences", r.audiences.join(", ")],
    ["Authn instant", r.authnInstant],
    ["Session index", r.sessionIndex],
  ];
  return rows.filter(([, v]) => v);
}

const checksBlock = (c: Check[]) => ({
  type: "findings" as const,
  items: c.map((x) => ({ severity: x.status === "pass" ? ("pass" as const) : x.status === "fail" ? ("fail" as const) : ("info" as const), title: x.name, detail: x.detail })),
});

export function buildJwtReport(r: JwtResult): Report {
  return {
    title: `JWT (${r.alg || "no alg"})`,
    subtitle: `Signature ${SIG_LABEL[r.signature]}`,
    tool: "JWT/SAML Inspector",
    sections: [
      { title: "Header", blocks: [{ type: "code", text: JSON.stringify(r.header, null, 2) }] },
      { title: "Claims", blocks: [{ type: "code", text: JSON.stringify(r.claims, null, 2) }] },
      { title: "Signature", blocks: [{ type: "paragraph", text: `${SIG_LABEL[r.signature]}: ${r.signatureDetail}` }, ...(r.keyRefs.length ? [{ type: "paragraph" as const, text: `Key references in the header (not followed): ${r.keyRefs.join("; ")}` }] : [])] },
      { title: "Application checks", blocks: [checksBlock(r.checks)] },
      { title: "Note", blocks: [{ type: "paragraph", text: "Decoded, signature-valid and application-valid are separate results. The raw token and any key are not included in this report." }] },
    ],
  };
}

export function buildSamlReport(r: SamlResult): Report {
  return {
    title: `SAML ${r.message}`,
    subtitle: r.binding,
    tool: "JWT/SAML Inspector",
    sections: [
      { title: "Message", blocks: [{ type: "keyValues", items: samlFields(r).map(([key, value]) => ({ key, value })) }] },
      ...(r.attributes.length ? [{ title: "Attributes", blocks: [{ type: "table" as const, headers: ["Attribute", "Values"], rows: r.attributes.map(([n, v]) => [n, v.join(", ")]) }] }] : []),
      {
        title: "Signatures",
        blocks: [
          r.signatures.length
            ? { type: "table" as const, headers: ["On", "Method", "Digest", "Certificate", "Cert SHA-256"], rows: r.signatures.map((s) => [s.on, s.method.split("#").pop() ?? s.method, s.digest.split("#").pop() ?? s.digest, s.certSubject, s.certSha256]) }
            : { type: "paragraph" as const, text: "No XML signature present." },
          { type: "paragraph", text: "XML signatures are located and described, not cryptographically verified by Net3PO." },
        ],
      },
      { title: "Checks", blocks: [checksBlock(r.checks)] },
    ],
  };
}
