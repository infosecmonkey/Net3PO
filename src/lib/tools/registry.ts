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
    category: "Offline",
    enabled: true,
    load: () => import("./SubnetCalculator/SubnetCalculator.svelte"),
  },
  {
    id: "regex-builder",
    icon: "regex",
    name: "Regex Builder",
    category: "Offline",
    enabled: true,
    load: () => import("./RegexBuilder/RegexBuilder.svelte"),
  },
  {
    id: "grep-builder",
    icon: "text-search",
    name: "Grep Builder",
    category: "Offline",
    enabled: true,
    load: () => import("./GrepBuilder/GrepBuilder.svelte"),
  },
  {
    id: "mac-vendor",
    icon: "fingerprint",
    name: "MAC Vendor Lookup",
    category: "Offline",
    enabled: true,
    load: () => import("./MacVendor/MacVendor.svelte"),
  },
  {
    id: "config-diff",
    icon: "git-compare",
    name: "Config Diff",
    category: "Offline",
    enabled: true,
    load: () => import("./ConfigDiff/ConfigDiff.svelte"),
  },

  // Phase 2, network tools
  {
    id: "dig",
    icon: "globe",
    name: "Dig",
    category: "Network",
    enabled: true,
    load: () => import("./Dig/Dig.svelte"),
  },
  {
    id: "dns-analyzer",
    icon: "shield-check",
    name: "DNS Analyzer",
    category: "Network",
    enabled: true,
    load: () => import("./DnsAnalyzer/DnsAnalyzer.svelte"),
  },
  {
    id: "port-scanner",
    icon: "radar",
    name: "Port Scanner",
    category: "Network",
    enabled: true,
    load: () => import("./PortScanner/PortScanner.svelte"),
  },
  {
    id: "syslog-server",
    icon: "scroll-text",
    name: "Syslog Server",
    category: "Network",
    enabled: true,
    load: () => import("./SyslogServer/SyslogServer.svelte"),
  },
  {
    id: "tftp-server",
    icon: "server",
    name: "TFTP Server",
    category: "Network",
    enabled: true,
    load: () => import("./TftpServer/TftpServer.svelte"),
  },

  // Phase 3, SNMP
  {
    id: "snmp-walk",
    icon: "list-tree",
    name: "SNMP Walk",
    category: "SNMP",
    enabled: true,
    load: () => import("./SnmpWalk/SnmpWalk.svelte"),
  },
  {
    id: "snmp-sweep",
    icon: "scan-search",
    name: "SNMP Sweep",
    category: "SNMP",
    enabled: true,
    load: () => import("./SnmpSweep/SnmpSweep.svelte"),
  },
  {
    id: "port-mapper",
    icon: "ethernet-port",
    name: "Switch Port Mapper",
    category: "SNMP",
    enabled: true,
    load: () => import("./PortMapper/PortMapper.svelte"),
  },

  // Phase 4, advanced
  {
    id: "dhcp-monitor",
    icon: "shield-alert",
    name: "DHCP Monitor",
    category: "Advanced",
    enabled: true,
    load: () => import("./DhcpMonitor/DhcpMonitor.svelte"),
  },
  {
    id: "traceroute",
    icon: "route",
    name: "Visual Traceroute",
    category: "Advanced",
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
];

/** Tools grouped by category, preserving definition order. */
export function toolGroups(): ToolGroup[] {
  const groups: ToolGroup[] = [];
  for (const tool of TOOLS) {
    let group = groups.find((g) => g.category === tool.category);
    if (!group) {
      group = { category: tool.category, tools: [] };
      groups.push(group);
    }
    group.tools.push(tool);
  }
  return groups;
}

export function findTool(id: string): ToolDef | undefined {
  return TOOLS.find((t) => t.id === id);
}

/** First enabled tool, used as the default selection. */
export function defaultToolId(): string {
  return TOOLS.find((t) => t.enabled)?.id ?? TOOLS[0].id;
}
