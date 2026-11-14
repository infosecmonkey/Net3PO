// Export report for the switch port mapper: ports and the MAC addresses
// learned on them. Credentials are never included.

import type { Report } from "$lib/report/types";
import type { PortMap } from "$lib/tools/types";

export function buildPortMapReport(host: string, m: PortMap): Report {
  return {
    title: `Port map: ${m.sysName || host}`,
    subtitle: `${m.ports.length} ports, ${m.macs.length} MAC addresses`,
    tool: "Switch Port Mapper",
    sections: [
      {
        title: "Switch",
        blocks: [
          { type: "keyValues", items: [{ key: "Host", value: host }, { key: "Name", value: m.sysName }, { key: "Description", value: m.sysDescr }, { key: "Data source", value: m.source }] },
          ...m.warnings.map((w) => ({ type: "paragraph" as const, text: w })),
          ...(m.truncated ? [{ type: "paragraph" as const, text: "The MAC table was truncated at the collection limit." }] : []),
        ],
      },
      {
        title: "MAC addresses by port",
        blocks: [
          {
            type: "table",
            headers: ["MAC", "Vendor", "VLAN", "Port", "IP addresses", "Uplink"],
            rows: m.macs.map((x) => [x.mac, x.vendor ?? "", x.vlan === null ? "" : String(x.vlan), x.port, x.ips.join(", "), x.onUplink ? "yes" : ""]),
          },
        ],
      },
      {
        title: "Ports",
        blocks: [
          {
            type: "table",
            headers: ["Port", "Alias", "Admin", "Oper", "Speed", "PVID", "VLANs", "MACs", "Uplink"],
            rows: m.ports.map((p) => [p.name || p.descr, p.alias, p.adminStatus, p.operStatus, p.speed, p.pvid === null ? "" : String(p.pvid), p.vlans.join(", "), String(p.macCount), p.uplink ? "yes" : ""]),
          },
          { type: "paragraph", text: "SNMP credentials are not included in this report." },
        ],
      },
    ],
  };
}
