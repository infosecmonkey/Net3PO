// Layers and results mirroring `tools::mtu_calc::core`, presets, report.

import type { Report } from "$lib/report/types";

export type IpVer = "v4" | "v6";
export type Cipher = "aesCbc" | "aesGcm" | "chaCha20Poly1305" | "desCbc" | "null";
export type Integrity = "sha1" | "sha256" | "sha384" | "sha512" | "none";

export type Layer =
  | { type: "pppoe" }
  | { type: "dot1q"; tags: number }
  | { type: "mpls"; labels: number }
  | { type: "gre"; outer: IpVer; key: boolean; seq: boolean; checksum: boolean }
  | { type: "ipInIp"; outer: IpVer }
  | { type: "vxlan"; outer: IpVer; innerVlan: boolean }
  | { type: "wireGuard"; outer: IpVer }
  | { type: "esp"; outer: IpVer; tunnel: boolean; cipher: Cipher; integrity: Integrity; natT: boolean };

export interface Row {
  layer: string;
  part: string;
  bytes: string;
}

export interface MtuResult {
  linkMtu: number;
  innerMtu: number;
  mssV4: number;
  mssV6: number;
  overhead: number;
  rows: Row[];
  notes: string[];
  errors: string[];
}

export const LAYER_LABEL: Record<Layer["type"], string> = {
  pppoe: "PPPoE",
  dot1q: "802.1Q VLAN tag",
  mpls: "MPLS",
  gre: "GRE",
  ipInIp: "IP-in-IP",
  vxlan: "VXLAN",
  wireGuard: "WireGuard",
  esp: "IPsec ESP",
};

export function newLayer(type: Layer["type"]): Layer {
  switch (type) {
    case "pppoe":
      return { type };
    case "dot1q":
      return { type, tags: 1 };
    case "mpls":
      return { type, labels: 1 };
    case "gre":
      return { type, outer: "v4", key: false, seq: false, checksum: false };
    case "ipInIp":
      return { type, outer: "v4" };
    case "vxlan":
      return { type, outer: "v4", innerVlan: false };
    case "wireGuard":
      return { type, outer: "v4" };
    case "esp":
      return { type, outer: "v4", tunnel: true, cipher: "aesGcm", integrity: "none", natT: false };
  }
}

export const PRESETS: { name: string; mtu: number; layers: () => Layer[] }[] = [
  { name: "IPsec tunnel, AES-GCM", mtu: 1500, layers: () => [newLayer("esp")] },
  { name: "IPsec tunnel, AES-CBC + SHA-256, NAT-T", mtu: 1500, layers: () => [{ type: "esp", outer: "v4", tunnel: true, cipher: "aesCbc", integrity: "sha256", natT: true }] },
  { name: "GRE over IPsec (transport)", mtu: 1500, layers: () => [{ type: "esp", outer: "v4", tunnel: false, cipher: "aesCbc", integrity: "sha1", natT: false }, newLayer("gre")] },
  { name: "GRE", mtu: 1500, layers: () => [newLayer("gre")] },
  { name: "VXLAN", mtu: 1500, layers: () => [newLayer("vxlan")] },
  { name: "WireGuard over IPv6", mtu: 1500, layers: () => [{ type: "wireGuard", outer: "v6" }] },
  { name: "PPPoE (DSL/fiber)", mtu: 1500, layers: () => [newLayer("pppoe")] },
  { name: "PPPoE + IPsec tunnel, AES-GCM", mtu: 1500, layers: () => [newLayer("pppoe"), newLayer("esp")] },
];

export function buildMtuReport(r: MtuResult, layers: Layer[]): Report {
  return {
    title: `MTU: ${layers.map((l) => LAYER_LABEL[l.type]).join(" + ") || "plain link"}`,
    subtitle: `Link MTU ${r.linkMtu}, inner MTU ${r.innerMtu}`,
    tool: "MTU Calculator",
    sections: [
      {
        title: "Result",
        blocks: [
          {
            type: "keyValues",
            items: [
              { key: "Link IP MTU", value: String(r.linkMtu) },
              { key: "Inner IP MTU", value: String(r.innerMtu) },
              { key: "TCP MSS (IPv4 inside)", value: String(r.mssV4) },
              { key: "TCP MSS (IPv6 inside)", value: String(r.mssV6) },
              { key: "Overhead at full size", value: `${r.overhead} bytes` },
            ],
          },
        ],
      },
      { title: "Byte breakdown, outside in", blocks: [{ type: "table", headers: ["Layer", "Part", "Bytes"], rows: r.rows.map((x) => [x.layer, x.part, x.bytes]) }] },
      { title: "Assumptions", blocks: r.notes.map((n) => ({ type: "paragraph" as const, text: n })) },
    ],
  };
}
