// Types mirroring `tools::pcap_inspector`, formatting, and the report.

import type { Report } from "$lib/report/types";

export interface Count {
  name: string;
  packets: number;
  bytes: number;
}

export interface Conversation {
  proto: string;
  a: string;
  b: string;
  packets: number;
  bytes: number;
  firstNs: number;
  lastNs: number;
}

export interface DnsName {
  name: string;
  qtype: string;
  queries: number;
  responses: number;
  errors: [string, number][];
}

export interface Stats {
  packets: number;
  bytes: number;
  firstNs: number | null;
  lastNs: number | null;
  truncated: number;
  malformed: number;
  encrypted: number;
  linkTypes: string[];
  protocols: Count[];
  talkers: Count[];
  conversations: Conversation[];
  dns: DnsName[];
  tcpSyn: number;
  tcpRst: number;
  icmpUnreachable: number;
  keysCapped: boolean;
}

export interface OpenResult {
  name: string;
  format: string;
  stats: Stats;
  listed: number;
  warnings: string[];
  cancelled: boolean;
}

export interface Summary {
  index: number;
  tsNs: number;
  origLen: number;
  capLen: number;
  src: string;
  dst: string;
  proto: string;
  info: string;
  truncated: boolean;
  malformed: boolean;
  encrypted: boolean;
}

export interface Field {
  layer: string;
  name: string;
  value: string;
}

export interface PacketDetail {
  summary: Summary;
  fields: Field[];
  hex: string;
  malformed: string | null;
  link: string;
}

export interface Filter {
  text: string;
  proto: string;
  ip: string;
  port: number | null;
  onlyFlagged: boolean;
}

export function bytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1048576) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1073741824) return `${(n / 1048576).toFixed(1)} MB`;
  return `${(n / 1073741824).toFixed(2)} GB`;
}

export function clock(ns: number): string {
  if (!ns) return "";
  const d = new Date(Math.floor(ns / 1e6));
  const frac = String(Math.floor((ns % 1e9) / 1e3)).padStart(6, "0");
  return `${d.toISOString().slice(11, 19)}.${frac}`;
}

export function duration(s: Stats): string {
  if (s.firstNs === null || s.lastNs === null) return "-";
  const sec = (s.lastNs - s.firstNs) / 1e9;
  return sec < 60 ? `${sec.toFixed(3)} s` : `${Math.floor(sec / 60)} min ${Math.round(sec % 60)} s`;
}

export function buildPcapReport(r: OpenResult): Report {
  const s = r.stats;
  return {
    title: `Capture: ${r.name}`,
    subtitle: `${s.packets.toLocaleString()} packets, ${bytes(s.bytes)}, ${duration(s)}`,
    tool: "PCAP Inspector",
    sections: [
      {
        title: "Capture",
        blocks: [
          {
            type: "keyValues",
            items: [
              { key: "File", value: r.name },
              { key: "Format", value: r.format },
              { key: "Link types", value: s.linkTypes.join(", ") },
              { key: "Packets", value: s.packets.toLocaleString() },
              { key: "Bytes on the wire", value: bytes(s.bytes) },
              { key: "First packet (UTC)", value: s.firstNs ? new Date(s.firstNs / 1e6).toISOString() : "-" },
              { key: "Duration", value: duration(s) },
              { key: "Truncated by snaplen", value: String(s.truncated) },
              { key: "Malformed or undecoded", value: String(s.malformed) },
              { key: "Encrypted payloads", value: String(s.encrypted) },
              { key: "TCP SYN (new connections)", value: String(s.tcpSyn) },
              { key: "TCP resets", value: String(s.tcpRst) },
              { key: "ICMP unreachable", value: String(s.icmpUnreachable) },
            ],
          },
          ...r.warnings.map((w) => ({ type: "paragraph" as const, text: w })),
        ],
      },
      { title: "Protocols", blocks: [{ type: "table", headers: ["Protocol", "Packets", "Bytes"], rows: s.protocols.map((p) => [p.name, String(p.packets), bytes(p.bytes)]) }] },
      { title: "Top talkers (by bytes)", blocks: [{ type: "table", headers: ["Address", "Packets", "Bytes"], rows: s.talkers.slice(0, 25).map((t) => [t.name, String(t.packets), bytes(t.bytes)]) }] },
      {
        title: "Top conversations (by bytes)",
        blocks: [{ type: "table", headers: ["Protocol", "Endpoint A", "Endpoint B", "Packets", "Bytes"], rows: s.conversations.slice(0, 50).map((c) => [c.proto, c.a, c.b, String(c.packets), bytes(c.bytes)]) }],
      },
      ...(s.dns.length
        ? [
            {
              title: "DNS names",
              blocks: [
                {
                  type: "table" as const,
                  headers: ["Name", "Type", "Queries", "Responses", "Errors"],
                  rows: s.dns.slice(0, 200).map((d) => [d.name, d.qtype, String(d.queries), String(d.responses), d.errors.map(([c, n]) => `${c} x${n}`).join(", ")]),
                },
              ],
            },
          ]
        : []),
      {
        title: "About this summary",
        blocks: [
          {
            type: "paragraph",
            text: "Facts derived from the capture file only. Encrypted payloads are counted, not decrypted, and protocols the inspector does not decode are labelled as such. Open the file in Wireshark for full protocol analysis.",
          },
        ],
      },
    ],
  };
}

export interface SanitizeOptions {
  stripPayload: boolean;
  addresses: boolean;
  macs: boolean;
  key: string;
}

export interface SanitizeReport {
  packets: number;
  written: number;
  dropped: number;
  stripped: number;
  bytesRemoved: number;
  otherCut: number;
  addresses: number;
  macs: number;
  mapping: { kind: "ip" | "mac"; original: string; fake: string }[];
  key: string;
  format: string;
  warnings: string[];
  cancelled: boolean;
}

export interface ExtractOptions {
  http: boolean;
  ftp: boolean;
  tftp: boolean;
  voice: boolean;
  decompress: boolean;
}

export type ObjectKind = "http" | "ftp" | "tftp" | "voice";

export interface ExtractedObject {
  id: number;
  kind: ObjectKind;
  name: string;
  contentType: string;
  size: number;
  endpoints: string;
  detail: string;
  firstPacket: number;
  complete: boolean;
  sha256: string;
}

export interface ExtractResult {
  objects: ExtractedObject[];
  warnings: string[];
  cancelled: boolean;
}

export const OBJECT_KIND: Record<ObjectKind, string> = { http: "HTTP", ftp: "FTP", tftp: "TFTP", voice: "Voice" };
