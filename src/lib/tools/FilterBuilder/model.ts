// Terms, groups and scenarios for the filter builder, mirroring
// `tools::filter_builder::core`, plus the export report.

import type { Report } from "$lib/report/types";

export type Dir = "any" | "src" | "dst";
export type L4 = "any" | "tcp" | "udp";
export type TermType = "host" | "net" | "port" | "proto" | "tcpFlags" | "vlan" | "mac" | "displayOnly";

export interface TermUI {
  id: number;
  type: TermType;
  negate: boolean;
  addr: string;
  cidr: string;
  ports: string;
  dir: Dir;
  l4: L4;
  name: string;
  flags: string[];
  exact: boolean;
  vlan: string;
  expr: string;
  label: string;
}

export interface GroupUI {
  id: number;
  terms: TermUI[];
}

export interface Output {
  text: string;
  error: string | null;
  notes: string[];
}

export interface Filters {
  bpf: Output;
  wireshark: Output;
  fortigate: Output;
  explanation: string;
  errors: string[];
}

let next = 1;
export const nextId = () => next++;

export function term(type: TermType, init: Partial<TermUI> = {}): TermUI {
  return {
    id: nextId(),
    type,
    negate: false,
    addr: "",
    cidr: "",
    ports: "",
    dir: "any",
    l4: "any",
    name: "tcp",
    flags: ["syn"],
    exact: false,
    vlan: "",
    expr: "",
    label: "",
    ...init,
  };
}

/** The JSON the Rust side expects for one term. */
export function toWire(t: TermUI): Record<string, unknown> {
  const base = { type: t.type, negate: t.negate };
  switch (t.type) {
    case "host":
      return { ...base, addr: t.addr, dir: t.dir };
    case "net":
      return { ...base, cidr: t.cidr, dir: t.dir };
    case "port":
      return { ...base, ports: t.ports, dir: t.dir, l4: t.l4 };
    case "proto":
      return { ...base, name: t.name };
    case "tcpFlags":
      return { ...base, flags: t.flags, exact: t.exact };
    case "vlan":
      return { ...base, id: t.vlan.trim() ? Number(t.vlan) : null };
    case "mac":
      return { ...base, addr: t.addr, dir: t.dir };
    case "displayOnly":
      return { ...base, expr: t.expr, label: t.label };
  }
}

export const TERM_LABEL: Record<TermType, string> = {
  host: "Host",
  net: "Network",
  port: "Port",
  proto: "Protocol",
  tcpFlags: "TCP flags",
  vlan: "VLAN",
  mac: "MAC address",
  displayOnly: "Display-only",
};

export const PROTOS = ["tcp", "udp", "icmp", "icmp6", "arp", "ip", "ip6", "esp", "gre", "sctp"];
export const FLAG_NAMES = ["syn", "ack", "fin", "rst", "psh", "urg"];

export interface Scenario {
  name: string;
  groups: () => TermUI[][];
}

const g = (...t: TermUI[]) => t;
export const SCENARIOS: Scenario[] = [
  { name: "DNS", groups: () => [g(term("port", { ports: "53" }))] },
  { name: "DHCP", groups: () => [g(term("port", { ports: "67-68", l4: "udp" }))] },
  { name: "HTTPS / TLS", groups: () => [g(term("port", { ports: "443", l4: "tcp" }))] },
  { name: "New TCP connections (SYN only)", groups: () => [g(term("tcpFlags", { flags: ["syn"], exact: true }))] },
  { name: "TCP resets", groups: () => [g(term("tcpFlags", { flags: ["rst"] }))] },
  { name: "ICMP and ICMPv6", groups: () => [g(term("proto", { name: "icmp" })), g(term("proto", { name: "icmp6" }))] },
  { name: "ARP", groups: () => [g(term("proto", { name: "arp" }))] },
  { name: "IPsec (IKE, NAT-T, ESP)", groups: () => [g(term("port", { ports: "500,4500", l4: "udp" })), g(term("proto", { name: "esp" }))] },
  { name: "BGP", groups: () => [g(term("port", { ports: "179", l4: "tcp" }))] },
  { name: "SNMP and traps", groups: () => [g(term("port", { ports: "161-162", l4: "udp" }))] },
  { name: "Syslog", groups: () => [g(term("port", { ports: "514" }))] },
  { name: "NTP", groups: () => [g(term("port", { ports: "123", l4: "udp" }))] },
  { name: "RADIUS", groups: () => [g(term("port", { ports: "1812-1813", l4: "udp" }))] },
  { name: "TCP retransmissions (display only)", groups: () => [g(term("displayOnly", { expr: "tcp.analysis.retransmission", label: "TCP retransmissions" }))] },
  { name: "TCP zero window (display only)", groups: () => [g(term("displayOnly", { expr: "tcp.analysis.zero_window", label: "TCP zero-window advertisements" }))] },
  { name: "DNS errors (display only)", groups: () => [g(term("displayOnly", { expr: "dns.flags.rcode != 0", label: "DNS responses with an error code" }))] },
];

export function buildFilterReport(f: Filters): Report {
  const out = (title: string, o: Output) => ({
    title,
    blocks: o.error
      ? [{ type: "paragraph" as const, text: o.error }]
      : [{ type: "code" as const, text: o.text }, ...o.notes.map((n) => ({ type: "paragraph" as const, text: n }))],
  });
  return {
    title: "Packet filters",
    subtitle: f.explanation,
    tool: "Packet Filter Builder",
    sections: [
      out("tcpdump / Wireshark capture filter (BPF)", f.bpf),
      out("Wireshark display filter", f.wireshark),
      out("FortiGate sniffer command", f.fortigate),
    ],
  };
}
