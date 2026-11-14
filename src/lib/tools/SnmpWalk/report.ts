// Export report for SNMP walk. Credentials (community, v3 passwords) are
// never included.

import type { Report } from "$lib/report/types";

export interface WalkRow {
  oid: string;
  name: string;
  valueType: string;
  value: string;
}

export function buildWalkReport(host: string, port: number, version: string, startOid: string, rows: WalkRow[], doneMsg: string): Report {
  return {
    title: `SNMP walk: ${host}`,
    subtitle: `${rows.length.toLocaleString()} values from ${startOid}`,
    tool: "SNMP Walk",
    sections: [
      {
        title: "Walk",
        blocks: [
          {
            type: "keyValues",
            items: [
              { key: "Agent", value: `${host}:${port}` },
              { key: "Version", value: version },
              { key: "Start OID", value: startOid },
              ...(doneMsg ? [{ key: "Result", value: doneMsg }] : []),
            ],
          },
          { type: "table", headers: ["OID", "Name", "Type", "Value"], rows: rows.map((r) => [r.oid, r.name, r.valueType, r.value]) },
          { type: "paragraph", text: "Community strings and SNMPv3 credentials are not included in this report." },
        ],
      },
    ],
  };
}
