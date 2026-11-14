// Export report for the Subnet Calculator: the calculated network and, when
// one was made, the split into smaller subnets.

import type { Report, Section } from "$lib/report/types";
import type { SplitResult, SubnetReport } from "$lib/tools/types";

/** Label and value rows for the sipcalc-style grid, per address family. */
export function subnetRows(r: SubnetReport): [string, string][] {
  if (r.version === "ipv4") {
    return [
      ["Address", r.address],
      ["Network", r.cidr],
      ["Netmask", `${r.netmask}  (${r.netmaskHex})`],
      ["Wildcard", r.wildcard],
      ["Broadcast", r.broadcast],
      ["Host range", `${r.hostMin} - ${r.hostMax}`],
      ["Usable hosts", r.usableHosts.toLocaleString()],
      ["Total addresses", r.totalAddresses.toLocaleString()],
      ["Class", r.networkClass],
      ["Type", r.addressType],
      ["Address (bin)", r.addressBinary],
      ["Netmask (bin)", r.netmaskBinary],
      ["Network (bin)", r.networkBinary],
    ];
  }
  return [
    ["Address", r.addressCompressed],
    ["Expanded", r.addressExpanded],
    ["Network", r.cidr],
    ["Network (expanded)", r.networkExpanded],
    ["Host range", `${r.hostMin} - ${r.hostMax}`],
    ["Total addresses", r.totalAddresses],
    ["Type", r.addressType],
  ];
}

export function buildSubnetReport(r: SubnetReport | null, split: SplitResult | null): Report | null {
  if (!r && !split) return null;
  const sections: Section[] = [];
  if (r) {
    sections.push({
      title: r.cidr,
      blocks: [{ type: "keyValues", items: subnetRows(r).map(([key, value]) => ({ key, value })) }],
    });
  }
  if (split) {
    const total = Number(split.totalSubnets);
    sections.push({
      title: `${split.parentCidr} split into /${split.newPrefix}`,
      subtitle: `${total.toLocaleString()} subnets`,
      blocks: [
        {
          type: "table",
          headers: ["Network", "Broadcast", "Host range", "Usable hosts"],
          rows: split.subnets.map((s) => [s.cidr, s.broadcast, `${s.hostMin} - ${s.hostMax}`, s.usableHosts]),
        },
        ...(split.truncated
          ? [{ type: "paragraph" as const, text: `Only the first ${split.subnets.length.toLocaleString()} of ${total.toLocaleString()} subnets are listed.` }]
          : []),
      ],
    });
  }
  const cidr = r?.cidr ?? split?.parentCidr ?? "";
  return {
    title: `Subnet: ${cidr}`,
    subtitle: split ? `split into /${split.newPrefix}` : "",
    tool: "Subnet Calculator",
    sections,
  };
}
