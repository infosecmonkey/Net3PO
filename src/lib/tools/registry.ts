// Catalog of tools shown in the sidebar, grouped by category. Tools are enabled
// as they are built; the rest appear disabled so the sidebar reflects the full
// roadmap. The component is lazy-loaded by the shell when a tool is selected.

import type { Component } from "svelte";

export interface ToolDef {
  id: string;
  name: string;
  category: string;
  enabled: boolean;
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
    name: "Subnet Calculator",
    category: "Offline",
    enabled: true,
    load: () => import("./SubnetCalculator/SubnetCalculator.svelte"),
  },
  {
    id: "regex-builder",
    name: "Regex Builder",
    category: "Offline",
    enabled: true,
    load: () => import("./RegexBuilder/RegexBuilder.svelte"),
  },
  {
    id: "grep-builder",
    name: "Grep Builder",
    category: "Offline",
    enabled: true,
    load: () => import("./GrepBuilder/GrepBuilder.svelte"),
  },
  { id: "mac-vendor", name: "MAC Vendor Lookup", category: "Offline", enabled: false },
  { id: "forti-sniffer", name: "FortiGate Sniffer to PCAP", category: "Offline", enabled: false },

  // Phase 2, network tools
  { id: "dig", name: "Dig", category: "Network", enabled: false },
  { id: "dns-analyzer", name: "DNS Analyzer", category: "Network", enabled: false },
  { id: "port-scanner", name: "Port Scanner", category: "Network", enabled: false },
  { id: "syslog-server", name: "Syslog Server", category: "Network", enabled: false },
  { id: "tftp-server", name: "TFTP Server", category: "Network", enabled: false },

  // Phase 3, SNMP
  { id: "snmp-walk", name: "SNMP Walk", category: "SNMP", enabled: false },
  { id: "snmp-sweep", name: "SNMP Sweep", category: "SNMP", enabled: false },
  { id: "port-mapper", name: "Switch Port Mapper", category: "SNMP", enabled: false },

  // Phase 4, advanced
  { id: "dhcp-monitor", name: "DHCP Monitor", category: "Advanced", enabled: false },
  { id: "traceroute", name: "Visual Traceroute", category: "Advanced", enabled: false },

  // Phase 5, builders
  { id: "forti-builder", name: "Fortinet Command Builder", category: "Builders", enabled: false },
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
