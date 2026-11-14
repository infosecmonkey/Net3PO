// Catalog of tools shown in the sidebar, grouped by category. Tools are enabled
// as they are built; the rest appear disabled so the sidebar reflects the full
// roadmap. The component is lazy-loaded by the shell when a tool is selected.

import type { Component } from "svelte";
import type { IconName } from "$lib/components/icons/icons";

export interface ToolDef {
  id: string;
  name: string;
  category: string;
  enabled: boolean;
  /** Sidebar icon. */
  icon: IconName;
  /** Loader for the tool's Svelte panel. Only required when enabled. */
  load?: () => Promise<{ default: Component }>;
}

export interface ToolGroup {
  category: string;
  tools: ToolDef[];
}

const TOOLS: ToolDef[] = [
  // Phase 1, offline tools
  {
    id: "subnet-calculator",
    icon: "network",
    name: "Subnet Calculator",
    category: "Utilities",
    enabled: true,
    load: () => import("./SubnetCalculator/SubnetCalculator.svelte"),
  },
  {
    id: "mtu-calculator",
    icon: "ruler",
    name: "MTU Calculator",
    category: "Utilities",
    enabled: true,
    load: () => import("./MtuCalculator/MtuCalculator.svelte"),
  },
  {
    id: "hash-calculator",
    icon: "hash",
    name: "Hash Calculator",
    category: "Utilities",
    enabled: true,
    load: () => import("./HashCalculator/HashCalculator.svelte"),
  },
  {
    id: "timestamp-converter",
    icon: "clock",
    name: "Timestamp Converter",
    category: "Utilities",
    enabled: true,
    load: () => import("./TimestampConverter/TimestampConverter.svelte"),
  },
  {
    id: "regex-builder",
    icon: "regex",
    name: "Regex Builder",
    category: "Utilities",
    enabled: true,
    load: () => import("./RegexBuilder/RegexBuilder.svelte"),
  },
  {
    id: "grep-builder",
    icon: "text-search",
    name: "Grep Builder",
    category: "Utilities",
    enabled: true,
    load: () => import("./GrepBuilder/GrepBuilder.svelte"),
  },
  {
    id: "filter-builder",
    icon: "filter",
    name: "Filter Builder",
    category: "Utilities",
    enabled: true,
    load: () => import("./FilterBuilder/FilterBuilder.svelte"),
  },
  {
    id: "mac-vendor",
    icon: "fingerprint",
    name: "MAC Vendor Lookup",
    category: "Utilities",
    enabled: true,
    load: () => import("./MacVendor/MacVendor.svelte"),
  },
  {
    id: "config-diff",
    icon: "git-compare",
    name: "Config Diff",
    category: "Analysis",
    enabled: true,
    load: () => import("./ConfigDiff/ConfigDiff.svelte"),
  },
  {
    id: "event-log",
    icon: "logs",
    name: "Windows Event Log",
    category: "Analysis",
    enabled: true,
    load: () => import("./EventLog/EventLog.svelte"),
  },
  {
    id: "pcap-inspector",
    icon: "file-search",
    name: "PCAP Inspector",
    category: "Analysis",
    enabled: true,
    load: () => import("./PcapInspector/PcapInspector.svelte"),
  },

  // Phase 2, network tools
  {
    id: "dig",
    icon: "globe",
    name: "Dig",
    category: "Troubleshooting",
    enabled: true,
    load: () => import("./Dig/Dig.svelte"),
  },
  {
    id: "dns-analyzer",
    icon: "shield-check",
    name: "DNS Analyzer",
    category: "Analysis",
    enabled: true,
    load: () => import("./DnsAnalyzer/DnsAnalyzer.svelte"),
  },
  {
    id: "ioc-extractor",
    icon: "scan-search",
    name: "IOC Extractor",
    category: "Analysis",
    enabled: true,
    load: () => import("./IocExtractor/IocExtractor.svelte"),
  },
  {
    id: "tls-inspector",
    icon: "lock",
    name: "TLS Inspector",
    category: "Analysis",
    enabled: true,
    load: () => import("./TlsInspector/TlsInspector.svelte"),
  },
  {
    id: "http-troubleshooter",
    icon: "send",
    name: "HTTP Troubleshooter",
    category: "Troubleshooting",
    enabled: true,
    load: () => import("./HttpTroubleshooter/HttpTroubleshooter.svelte"),
  },
  {
    id: "conn-monitor",
    icon: "activity",
    name: "Connectivity Monitor",
    category: "Troubleshooting",
    enabled: true,
    load: () => import("./ConnMonitor/ConnMonitor.svelte"),
  },
  {
    id: "socket-tools",
    icon: "plug",
    name: "Socket Tools",
    category: "Troubleshooting",
    enabled: true,
    load: () => import("./SocketTools/SocketTools.svelte"),
  },
  {
    id: "email-analyzer",
    icon: "mail-search",
    name: "Email Header Analyzer",
    category: "Analysis",
    enabled: true,
    load: () => import("./EmailAnalyzer/EmailAnalyzer.svelte"),
  },
  {
    id: "port-scanner",
    icon: "radar",
    name: "Port Scanner",
    category: "Troubleshooting",
    enabled: true,
    load: () => import("./PortScanner/PortScanner.svelte"),
  },
  {
    id: "syslog-server",
    icon: "scroll-text",
    name: "Syslog Server",
    category: "Servers",
    enabled: true,
    load: () => import("./SyslogServer/SyslogServer.svelte"),
  },
  {
    id: "tftp-server",
    icon: "server",
    name: "TFTP Server",
    category: "Servers",
    enabled: true,
    load: () => import("./TftpServer/TftpServer.svelte"),
  },
  {
    id: "wake-on-lan",
    icon: "power",
    name: "Wake-on-LAN",
    category: "Troubleshooting",
    enabled: true,
    load: () => import("./WakeOnLan/WakeOnLan.svelte"),
  },

  // Phase 3, SNMP
  {
    id: "snmp-walk",
    icon: "list-tree",
    name: "SNMP Walk",
    category: "Discovery and SNMP",
    enabled: true,
    load: () => import("./SnmpWalk/SnmpWalk.svelte"),
  },
  {
    id: "snmp-sweep",
    icon: "scan-search",
    name: "SNMP Sweep",
    category: "Discovery and SNMP",
    enabled: true,
    load: () => import("./SnmpSweep/SnmpSweep.svelte"),
  },
  {
    id: "port-mapper",
    icon: "ethernet-port",
    name: "Switch Port Mapper",
    category: "Discovery and SNMP",
    enabled: true,
    load: () => import("./PortMapper/PortMapper.svelte"),
  },

  // Phase 4, advanced
  {
    id: "dhcp-monitor",
    icon: "shield-alert",
    name: "DHCP Monitor",
    category: "Discovery and SNMP",
    enabled: true,
    load: () => import("./DhcpMonitor/DhcpMonitor.svelte"),
  },
  {
    id: "traceroute",
    icon: "route",
    name: "Visual Traceroute",
    category: "Troubleshooting",
    enabled: true,
    load: () => import("./Traceroute/Traceroute.svelte"),
  },

  // Fortinet
  {
    id: "forti-builder",
    icon: "square-terminal",
    name: "Fortinet Command Builder",
    category: "Fortinet",
    enabled: true,
    load: () => import("./FortinetBuilder/FortinetBuilder.svelte"),
  },
  {
    id: "forti-sniffer",
    icon: "file-down",
    name: "FortiGate Sniffer to PCAP",
    category: "Fortinet",
    enabled: true,
    load: () => import("./FgtSniffer/FgtSniffer.svelte"),
  },
  {
    id: "debug-flow",
    icon: "workflow",
    name: "Debug Flow Parser",
    category: "Fortinet",
    enabled: true,
    load: () => import("./DebugFlow/DebugFlow.svelte"),
  },

  // Decoders
  {
    id: "script-decoder",
    icon: "file-code",
    name: "Script Decoder",
    category: "Analysis",
    enabled: true,
    load: () => import("./ScriptDecoder/ScriptDecoder.svelte"),
  },
  {
    id: "encoder-workbench",
    icon: "binary",
    name: "Encoder Workbench",
    category: "Analysis",
    enabled: true,
    load: () => import("./EncoderWorkbench/EncoderWorkbench.svelte"),
  },

  // Remote access
  {
    id: "ssh",
    icon: "terminal",
    name: "SSH",
    category: "Remote",
    enabled: true,
    load: () => import("./Ssh/Ssh.svelte"),
  },

  // Workspace
  {
    id: "projects",
    icon: "folder-open",
    name: "Projects",
    category: "Workspace",
    enabled: true,
    load: () => import("./Projects/Projects.svelte"),
  },
];

/**
 * Sidebar order: groups by job, top to bottom, and tools within each group.
 * Each tool's `category` must match the group it is listed under here; a
 * tool missing from this list still shows, at the end of its group.
 */
const LAYOUT: { category: string; tools: string[] }[] = [
  { category: "Workspace", tools: ["projects"] },
  { category: "Analysis", tools: ["dns-analyzer", "email-analyzer", "tls-inspector", "event-log", "pcap-inspector", "ioc-extractor", "config-diff", "script-decoder", "encoder-workbench"] },
  { category: "Troubleshooting", tools: ["dig", "port-scanner", "traceroute", "http-troubleshooter", "socket-tools", "conn-monitor", "wake-on-lan"] },
  { category: "Discovery and SNMP", tools: ["snmp-walk", "snmp-sweep", "port-mapper", "dhcp-monitor"] },
  { category: "Servers", tools: ["syslog-server", "tftp-server"] },
  { category: "Remote", tools: ["ssh"] },
  { category: "Utilities", tools: ["subnet-calculator", "timestamp-converter", "hash-calculator", "mtu-calculator", "regex-builder", "grep-builder", "filter-builder", "mac-vendor"] },
  { category: "Fortinet", tools: ["forti-builder", "forti-sniffer", "debug-flow"] },
];

/** Tools grouped for the sidebar, in LAYOUT order. */
export function toolGroups(): ToolGroup[] {
  const groups: ToolGroup[] = LAYOUT.map((g) => ({ category: g.category, tools: [] }));
  const rank = (t: ToolDef) => {
    const g = LAYOUT.find((l) => l.category === t.category);
    const i = g ? g.tools.indexOf(t.id) : -1;
    return i < 0 ? Number.MAX_SAFE_INTEGER : i;
  };
  for (const tool of TOOLS) {
    let group = groups.find((g) => g.category === tool.category);
    if (!group) {
      group = { category: tool.category, tools: [] };
      groups.push(group);
    }
    group.tools.push(tool);
  }
  for (const g of groups) g.tools.sort((a, b) => rank(a) - rank(b));
  return groups.filter((g) => g.tools.length > 0);
}

export function findTool(id: string): ToolDef | undefined {
  return TOOLS.find((t) => t.id === id);
}

/** First enabled tool, used as the default selection. */
export function defaultToolId(): string {
  return TOOLS.find((t) => t.enabled)?.id ?? TOOLS[0].id;
}
