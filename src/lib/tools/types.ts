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
