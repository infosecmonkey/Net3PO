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

export interface RegexRecipe {
  id: string;
  group: string;
  label: string;
  pattern: string;
  help: string;
  examples: string[];
}

// Grep builder.

export type GrepMode = "basic" | "extended" | "perl" | "fixed";
export type GrepCombine = "all" | "any";
export type GrepTarget = "gnu" | "bsd";
export type FilenameDisplay = "auto" | "always" | "never";

export interface GrepCondition {
  pattern: string;
  exclude: boolean;
}

export interface GrepOptions {
  conditions: GrepCondition[];
  combine: GrepCombine;
  mode: GrepMode;
  target: GrepTarget;
  ignoreCase: boolean;
  word: boolean;
  lineMatch: boolean;
  onlyMatching: boolean;
  lineNumber: boolean;
  count: boolean;
  filesWithMatches: boolean;
  recursive: boolean;
  color: boolean;
  skipBinary: boolean;
  filename: FilenameDisplay;
  before: number;
  after: number;
  context: number;
  include: string;
  exclude: string;
  excludeDir: string;
  paths: string[];
}

export interface BuiltCommand {
  command: string;
  stages: number;
  warnings: string[];
}

export interface GrepPreview {
  matches: { start: number; end: number }[];
  linesTotal: number;
  linesKept: number;
  output: { number: number; text: string }[];
  truncated: boolean;
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

export type FortinetCategory = "session" | "flow" | "sniffer" | "ping" | "traceroute" | "vpn" | "ha" | "routing" | "system";

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

// Config diff.

export type DiffWhitespace = "exact" | "trailing" | "amount" | "all";
export type DiffAlgo = "histogram" | "patience" | "myers";

export interface DiffOptions {
  whitespace: DiffWhitespace;
  ignoreCase: boolean;
  ignoreBlankLines: boolean;
  ignorePattern: string;
  /** Unchanged lines around each change; null shows everything. */
  context: number | null;
  algorithm: DiffAlgo;
  leftName: string;
  rightName: string;
}

export interface DiffSide {
  number: number;
  text: string;
  spans: { start: number; end: number }[];
}

export interface DiffRow {
  kind: "equal" | "delete" | "insert" | "change";
  left: DiffSide | null;
  right: DiffSide | null;
}

export interface DiffHunk {
  header: string;
  section: string[];
  rows: DiffRow[];
}

export interface DiffStats {
  added: number;
  removed: number;
  changed: number;
  leftLines: number;
  rightLines: number;
  ignoredLeft: number;
  ignoredRight: number;
}

export interface DiffResult {
  identical: boolean;
  hunks: DiffHunk[];
  stats: DiffStats;
  unified: string;
}

// Script decoder.

export type LayerKind = "source" | "text" | "binary" | "marshal";

export interface DecodedLayer {
  index: number;
  parent: number | null;
  depth: number;
  kind: LayerKind;
  method: string;
  sink: string | null;
  line: number | null;
  text: string;
  strings: string[];
  size: number;
  truncated: boolean;
  /** python, bash, powershell, javascript or unknown; empty for binary. */
  language: string;
}

export type IocKind = "url" | "domain" | "ipv4" | "email" | "md5" | "sha1" | "sha256" | "path";

export interface Ioc {
  kind: IocKind;
  value: string;
  defanged: string;
  layer: number;
  private: boolean;
}

export interface DecodeFlag {
  level: "info" | "warn" | "fail";
  rule: string;
  title: string;
  detail: string;
  layer: number;
  line: number | null;
  snippet: string;
}

export interface DecodeResult {
  layers: DecodedLayer[];
  iocs: Ioc[];
  flags: DecodeFlag[];
  notes: string[];
}

// Email Header Analyzer

export type EmailSev = "pass" | "info" | "warn" | "fail";

export interface EmailFinding {
  severity: EmailSev;
  category: string;
  title: string;
  detail: string;
}

export interface EmailAddressRow {
  role: string;
  name: string;
  address: string;
  domain: string;
}

export interface EmailHop {
  index: number;
  fromHost: string;
  helo: string;
  fromIp: string;
  fromRdns: string;
  byHost: string;
  protocol: string;
  tls: string;
  id: string;
  forAddr: string;
  timestamp: number | null;
  date: string;
  delaySecs: number | null;
  nonPublicIp: boolean;
  parsed: boolean;
  raw: string;
}

export interface EmailOrigin {
  ip: string;
  host: string;
  hop: number;
  basis: "handoff" | "earliest";
  explanation: string;
}

export interface EmailAuthMethod {
  method: string;
  result: string;
  props: [string, string][];
}

export interface EmailAuthResults {
  header: string;
  authservId: string;
  instance: number | null;
  methods: EmailAuthMethod[];
}

export interface EmailDkim {
  domain: string;
  selector: string;
  algorithm: string;
  canonicalization: string;
  identity: string;
  signedHeaders: string[];
  timestamp: number | null;
  expires: number | null;
  bodyLength: number | null;
  alignment: "strict" | "relaxed" | "none";
  keyName: string;
  notes: string[];
}

export interface EmailLookalike {
  domain: string;
  resembles: string;
  against: "message" | "known" | "brand";
  reason: string;
}

export interface EmailAttachment {
  name: string;
  contentType: string;
  size: number;
  risky: boolean;
}

export interface EmailDomainRow {
  domain: string;
  unicode: string;
  roles: string[];
}

export interface EmailIoc {
  kind: string;
  value: string;
  defanged: string;
  layer: number;
  private: boolean;
}

export interface EmailAnalysis {
  inputKind: "headers" | "message";
  subject: string;
  date: string;
  dateTs: number | null;
  messageId: string;
  addresses: EmailAddressRow[];
  domains: EmailDomainRow[];
  hops: EmailHop[];
  origin: EmailOrigin[];
  authResults: EmailAuthResults[];
  receivedSpf: string[];
  dkim: EmailDkim[];
  arcSets: number;
  lookalikes: EmailLookalike[];
  attachments: EmailAttachment[];
  textParts: number;
  htmlParts: number;
  iocs: EmailIoc[];
  notableHeaders: [string, string][];
  headers: [string, string][];
  findings: EmailFinding[];
}

export interface EmailBlocklist {
  zone: string;
  name: string;
  note: string;
}

export interface EmailRdapContact {
  handle: string;
  name: string;
  roles: string[];
  emails: string[];
  phones: string[];
}

export interface EmailRdapNetwork {
  handle: string;
  name: string;
  range: string;
  cidrs: string[];
  country: string;
  netType: string;
  owner: string;
  abuse: EmailRdapContact[];
  registered: string;
  lastChanged: string;
}

export interface EmailIpOwner {
  ip: string;
  ptr: string[];
  origin: {
    asns: number[];
    prefix: string;
    country: string;
    registry: string;
    allocated: string;
  } | null;
  asName: string;
  rdap: EmailRdapNetwork | null;
  rdapUrl: string;
  source: string;
  lookedUpMs: number;
  errors: string[];
}

export type EmailListingStatus = "listed" | "notListed" | "refused" | "error";

export interface EmailBlocklistReport {
  ip: string;
  results: { zone: string; status: EmailListingStatus; detail: string; reason: string }[];
  lookedUpMs: number;
}
// Wake-on-LAN

export type WolDelivery = "limitedBroadcast" | "localBroadcast" | "remoteBroadcast" | "unicast";

export interface WolInterface {
  name: string;
  ip: string;
  prefix: number;
  broadcast: string;
}

/** A saved device profile. The SecureOn password is never saved. */
export interface WolDevice {
  id: string;
  name: string;
  mac: string;
  destination: string;
  port: number;
  interface: string;
  repeats: number;
  checkHost: string;
  checkPorts: string;
  notes: string;
}

export interface WolSendResult {
  mac: string;
  destination: string;
  port: number;
  delivery: WolDelivery;
  packets: number;
  bytes: number;
  source: string | null;
  interface: string;
  sentAtMs: number;
  warnings: string[];
}

export type WolCheckEvent =
  | { type: "started"; host: string; ports: number[] }
  | { type: "waiting"; elapsedMs: number }
  | { type: "up"; port: number; answer: "open" | "refused"; elapsedMs: number }
  | { type: "done"; reachable: boolean; cancelled: boolean; elapsedMs: number };
