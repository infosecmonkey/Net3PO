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
