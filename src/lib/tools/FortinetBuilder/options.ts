// Option lists shared by the Fortinet builder forms. Values must stay within
// what the Rust builders accept.

export const PROTOCOLS: { label: string; number: number | null }[] = [
  { label: "Any", number: null },
  { label: "TCP (6)", number: 6 },
  { label: "UDP (17)", number: 17 },
  { label: "ICMP (1)", number: 1 },
  { label: "GRE (47)", number: 47 },
  { label: "ESP (50)", number: 50 },
];

/** Sniffer / BPF protocol keywords (`core::sniffer::PROTOCOLS`). */
export const BPF_PROTOCOLS = ["tcp", "udp", "icmp", "icmp6", "arp", "ip", "ip6", "esp", "gre"];

export const DIRECTIONS: { label: string; value: "any" | "src" | "dst" }[] = [
  { label: "Either", value: "any" },
  { label: "Source", value: "src" },
  { label: "Destination", value: "dst" },
];

export const VERBOSITY: { level: number; label: string }[] = [
  { level: 1, label: "1: headers only" },
  { level: 2, label: "2: headers and IP data" },
  { level: 3, label: "3: headers and Ethernet data" },
  { level: 4, label: "4: headers and interface names" },
  { level: 5, label: "5: IP data and interface names" },
  { level: 6, label: "6: Ethernet data and interface names" },
];

export const COMMON_INTERFACES = ["any", "port1", "port2", "wan1", "wan2", "internal"];

/** One-click BPF presets from FortiDebug Builder. */
export const BPF_PRESETS: { label: string; expr: string }[] = [
  { label: "TCP SYN", expr: "tcp[tcpflags] & tcp-syn != 0" },
  { label: "TCP RST", expr: "tcp[tcpflags] & tcp-rst != 0" },
  { label: "New TCP", expr: "tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn" },
  { label: "ICMP ping", expr: "icmp[icmptype] == icmp-echo" },
  { label: "ARP", expr: "arp" },
  { label: "VLAN any", expr: "vlan" },
  { label: "IPv6", expr: "ip6" },
  { label: "Broadcast", expr: "ether broadcast" },
  { label: "Multicast", expr: "ether multicast" },
];

export const ICMP_TYPES: { label: string; kind: string }[] = [
  { label: "Echo request (ping)", kind: "echo" },
  { label: "Echo reply", kind: "echoreply" },
  { label: "Destination unreachable", kind: "unreach" },
  { label: "Redirect", kind: "redirect" },
  { label: "Time exceeded", kind: "timxceed" },
  { label: "Source quench", kind: "sourcequench" },
];

export const TCP_FLAGS = ["syn", "ack", "fin", "rst", "push", "urg"];

/** `exec ping-options tos` keywords (`core::ping::TOS`). */
export const TOS_KEYWORDS = ["default", "lowcost", "lowdelay", "throughput", "reliability"];
