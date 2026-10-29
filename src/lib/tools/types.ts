// TypeScript mirrors of the Rust command return types. Field names use
// camelCase to match the serde rename on the Rust side.

export interface Ipv4Report {
  version: "ipv4";
  address: string;
  prefix: number;
  cidr: string;
  netmask: string;
  netmaskHex: string;
  wildcard: string;
  network: string;
  broadcast: string;
  hostMin: string;
  hostMax: string;
  totalAddresses: number;
  usableHosts: number;
  networkClass: string;
  addressType: string;
  addressBinary: string;
  netmaskBinary: string;
  networkBinary: string;
}

export interface Ipv6Report {
  version: "ipv6";
  addressCompressed: string;
  addressExpanded: string;
  prefix: number;
  cidr: string;
  networkCompressed: string;
  networkExpanded: string;
  hostMin: string;
  hostMax: string;
  totalAddresses: string;
  addressType: string;
}

export type SubnetReport = Ipv4Report | Ipv6Report;

export interface SubnetEntry {
  cidr: string;
  network: string;
  broadcast: string;
  hostMin: string;
  hostMax: string;
  usableHosts: string;
}

export interface SplitResult {
  parentCidr: string;
  newPrefix: number;
  totalSubnets: string;
  truncated: boolean;
  subnets: SubnetEntry[];
}

// Regex builder.

export type RegexEngine = "standard" | "pcre";

export interface RegexFlags {
  caseInsensitive: boolean;
  multiline: boolean;
  dotAll: boolean;
  ignoreWhitespace: boolean;
}

export interface GroupMatch {
  index: number;
  name: string | null;
  value: string | null;
  start: number | null;
  end: number | null;
}

export interface RegexMatch {
  start: number;
  end: number;
  value: string;
  groups: GroupMatch[];
}

export interface RegexResult {
  matches: RegexMatch[];
  total: number;
  truncated: boolean;
  groupNames: (string | null)[];
}

// Grep builder.

export type GrepMode = "basic" | "extended" | "perl" | "fixed";

export interface GrepOptions {
  pattern: string;
  mode: GrepMode;
  ignoreCase: boolean;
  invert: boolean;
  word: boolean;
  lineMatch: boolean;
  onlyMatching: boolean;
  lineNumber: boolean;
  count: boolean;
  filesWithMatches: boolean;
  recursive: boolean;
  color: boolean;
  before: number;
  after: number;
  context: number;
  paths: string[];
}

// MAC vendor lookup.

export interface MacInfo {
  normalized: string;
  oui: string;
  prefix: string | null;
  vendor: string | null;
  block: string | null;
  isMulticast: boolean;
  isLocallyAdministered: boolean;
}

export interface MacDbInfo {
  source: string;
  total: number;
  maL: number;
  maM: number;
  maS: number;
}

// FortiGate sniffer to PCAP.

export interface FgtOptions {
  skipEth0: boolean;
}

export interface FgtPacketMeta {
  index: number;
  time: string;
  interface: string | null;
  direction: string | null;
  length: number;
}

export interface FgtParseSummary {
  total: number;
  skippedEth0: number;
  totalBytes: number;
  shown: number;
  truncated: boolean;
  packets: FgtPacketMeta[];
}

export interface FgtSaveSummary {
  packets: number;
  bytesWritten: number;
  skippedEth0: number;
}

// Dig (DNS lookup).

export interface DnsRecord {
  name: string;
  ttl: number;
  rtype: string;
  data: string;
}

export interface DigResponse {
  server: string;
  protocol: string;
  rcode: string;
  flags: string[];
  queryTimeMs: number;
  question: string;
  answers: DnsRecord[];
  authority: DnsRecord[];
  additional: DnsRecord[];
}

// DNS analyzer.

export type Severity = "pass" | "info" | "warn" | "fail";

export interface DnsFinding {
  severity: Severity;
  message: string;
}

export interface DnsSection {
  name: string;
  status: Severity;
  findings: DnsFinding[];
  records: string[];
}

export interface DnsAnalysis {
  domain: string;
  server: string;
  sections: DnsSection[];
}

// Port scanner (streamed events).

export type ScanEvent =
  | { type: "open"; host: string; port: number; service: string | null }
  | { type: "progress"; done: number; total: number; open: number }
  | {
      type: "done";
      total: number;
      hosts: number;
      hostsWithOpen: number;
      open: number;
      closed: number;
      filtered: number;
      elapsedMs: number;
      cancelled: boolean;
    }
  | { type: "error"; message: string };

// Syslog server.

export interface SyslogMessageData {
  pri: number | null;
  facility: number | null;
  facilityName: string | null;
  severity: number | null;
  severityName: string | null;
  timestamp: string | null;
  host: string | null;
  tag: string | null;
  message: string;
  raw: string;
}

export type SyslogEvent =
  | { type: "started"; port: number; udp: boolean; tcp: boolean }
  | {
      type: "message";
      source: string;
      transport: string;
      data: SyslogMessageData;
    }
  | { type: "stopped" };

export type SyslogSendEvent =
  | { type: "sent"; index: number; severity: string; line: string }
  | { type: "done"; sent: number; cancelled: boolean };

// TFTP server.

export type TftpEvent =
  | { type: "started"; port: number; root: string; writable: boolean }
  | { type: "transferStart"; id: number; file: string; client: string; direction: string }
  | { type: "transferProgress"; id: number; bytes: number }
  | { type: "transferEnd"; id: number; bytes: number; ok: boolean; message: string }
  | { type: "stopped" };

// SNMP walk.

export type SnmpWalkEvent =
  | { type: "varbind"; oid: string; name: string; value: string; valueType: string }
  | { type: "done"; count: number; cancelled: boolean; error: string | null };

export type SnmpSweepEvent =
  | { type: "responder"; ip: string; sysDescr: string; sysName: string; sysObjectId: string }
  | { type: "progress"; done: number; total: number; found: number }
  | { type: "done"; total: number; found: number; cancelled: boolean };

// Switch port mapper.

export interface PortRow {
  ifIndex: number;
  name: string;
  descr: string;
  alias: string;
  adminStatus: string;
  operStatus: string;
  speed: string;
  pvid: number | null;
  vlans: number[];
  macCount: number;
  physical: boolean;
  uplink: boolean;
}

export interface MacRow {
  mac: string;
  vendor: string | null;
  vlan: number | null;
  ifIndex: number | null;
  port: string;
  ips: string[];
  onUplink: boolean;
}

export interface PortMap {
  sysName: string;
  sysDescr: string;
  source: string;
  ports: PortRow[];
  macs: MacRow[];
  warnings: string[];
  truncated: boolean;
}

export type PortMapEvent =
  | { type: "stage"; message: string }
  | { type: "done"; map: PortMap }
  | { type: "error"; message: string }
  | { type: "cancelled" };

// DHCP monitor.

export interface NetInterface {
  name: string;
  ip: string;
  prefix: number;
}

export interface DhcpOfferInfo {
  messageType: string;
  xid: string;
  clientMac: string;
  offeredIp: string | null;
  serverId: string | null;
  subnetMask: string | null;
  routers: string[];
  dns: string[];
  domain: string | null;
  leaseSecs: number | null;
  relay: string | null;
  nextServer: string | null;
}

export type DhcpServerStatus = "authorized" | "rogue" | "unverified";

export interface DhcpServerRecord {
  server: string;
  source: string;
  status: DhcpServerStatus;
  replies: number;
  firstSeenMs: number;
  lastSeenMs: number;
  last: DhcpOfferInfo;
}

export type DhcpEvent =
  | { type: "started"; interface: string }
  | { type: "probe"; n: number; xid: string; clientMac: string }
  | { type: "reply"; record: DhcpServerRecord; source: string; ours: boolean }
  | { type: "warning"; message: string }
  | { type: "stopped"; probes: number; servers: number; error: string | null };

// Visual traceroute.

export interface TraceResponder {
  ip: string;
  count: number;
  hostname: string | null;
}

export interface HopView {
  ttl: number;
  sent: number;
  received: number;
  lossPct: number;
  lastMs: number | null;
  avgMs: number | null;
  bestMs: number | null;
  worstMs: number | null;
  stdevMs: number | null;
  jitterMs: number | null;
  ip: string | null;
  hostname: string | null;
  responders: TraceResponder[];
  history: (number | null)[];
  unreachable: number | null;
}

export interface TraceFinding {
  kind: "loss" | "latency" | "rateLimit" | "unreachable" | "noReply";
  ttl: number | null;
  message: string;
}

export interface PathSummary {
  cycles: number;
  hops: number;
  reached: boolean;
  destAvgMs: number | null;
  destLossPct: number | null;
  findings: TraceFinding[];
}

export interface MtuResult {
  mtu: number | null;
  limitedBy: string | null;
  blackHole: boolean;
  note: string;
  steps: { size: number; result: string }[];
}

export type TraceEvent =
  | { type: "started"; target: string; ip: string; method: string }
  | { type: "cycle"; n: number; hops: HopView[]; summary: PathSummary }
  | { type: "mtuStarted" }
  | { type: "mtu"; result: MtuResult }
  | { type: "error"; message: string }
  | { type: "done"; cycles: number; cancelled: boolean };

// Fortinet command builder.

export type FortinetCategory = "session" | "flow" | "sniffer" | "ping" | "traceroute" | "vpn" | "ha";

export interface BuildError {
  field: string;
  message: string;
}

export interface SavedCommand {
  id: string;
  title: string;
  category: FortinetCategory;
  command: string;
  notes: string;
  /** ISO 8601. */
  createdAt: string;
}
