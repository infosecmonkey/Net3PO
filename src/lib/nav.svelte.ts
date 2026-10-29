// App-wide navigation state, so a tool can open another tool (for example the
// Fortinet sniffer builder linking to the sniffer-to-PCAP converter).

import { defaultToolId } from "$lib/tools/registry";

export const nav = $state({ selected: defaultToolId() });

/** Switch the main area to another tool by id. */
export function openTool(id: string) {
  nav.selected = id;
}
