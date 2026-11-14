// App-wide navigation state, so a tool can open another tool (for example the
// Fortinet sniffer builder linking to the sniffer-to-PCAP converter).

import { defaultToolId } from "$lib/tools/registry";
import type { GrepMode } from "$lib/tools/types";

export const nav = $state({ selected: defaultToolId() });

/** Switch the main area to another tool by id. */
export function openTool(id: string) {
  nav.selected = id;
}

/** A domain (and DKIM selectors) waiting for the DNS Analyzer to pick up. */
let pendingDns: { domain: string; selectors: string[] } | null = null;

/** Open the DNS Analyzer with a domain and selectors filled in and run it. */
export function openInDnsAnalyzer(domain: string, selectors: string[]) {
  pendingDns = { domain, selectors };
  openTool("dns-analyzer");
}

/** Take the pending DNS Analyzer request, if any, clearing it. */
export function takePendingDns(): { domain: string; selectors: string[] } | null {
  const p = pendingDns;
  pendingDns = null;
  return p;
}

/** A pattern waiting to be picked up by the Grep Builder when it mounts. */
let pendingGrep: { pattern: string; mode: GrepMode } | null = null;

/** Open the Grep Builder with `pattern` filled in. */
export function openInGrep(pattern: string, mode: GrepMode) {
  pendingGrep = { pattern, mode };
  openTool("grep-builder");
}

/** Take the pending Grep Builder pattern, if any, clearing it. */
export function takePendingGrep(): { pattern: string; mode: GrepMode } | null {
  const p = pendingGrep;
  pendingGrep = null;
  return p;
}
