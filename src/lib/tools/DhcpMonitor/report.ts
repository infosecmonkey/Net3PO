// Export report for the DHCP monitor: servers that answered, with what they
// offered and whether each is authorized.

import type { Report } from "$lib/report/types";
import type { DhcpServerRecord } from "$lib/tools/types";

const t = (ms: number) => new Date(ms).toLocaleString();

export function buildDhcpReport(iface: string, authorized: string, probes: number, servers: DhcpServerRecord[], warnings: string[]): Report {
  const rogue = servers.filter((s) => s.status === "rogue").length;
  return {
    title: `DHCP servers on ${iface || "the selected interface"}`,
    subtitle: `${servers.length} server${servers.length === 1 ? "" : "s"}${rogue ? `, ${rogue} not authorized` : ""}`,
    tool: "DHCP Monitor",
    sections: [
      {
        title: "Servers",
        blocks: [
          {
            type: "keyValues",
            items: [
              { key: "Interface", value: iface },
              { key: "Authorized servers", value: authorized.trim() || "(none listed; every server is unverified)" },
              { key: "Probes sent", value: String(probes) },
            ],
          },
          {
            type: "table",
            headers: ["Server", "Status", "Replies", "Offered", "Mask", "Router", "DNS", "Domain", "Lease", "Relay", "First seen", "Last seen"],
            rows: servers.map((s) => [
              s.server,
              s.status,
              String(s.replies),
              s.last.offeredIp ?? "",
              s.last.subnetMask ?? "",
              s.last.routers.join(", "),
              s.last.dns.join(", "),
              s.last.domain ?? "",
              s.last.leaseSecs === null ? "" : `${s.last.leaseSecs} s`,
              s.last.relay ?? "",
              t(s.firstSeenMs),
              t(s.lastSeenMs),
            ]),
          },
          { type: "paragraph", text: "Only servers that answered these probes are listed. A server that ignores unknown clients, or sits behind a filter, will not appear." },
          ...warnings.map((w) => ({ type: "paragraph" as const, text: w })),
        ],
      },
    ],
  };
}
