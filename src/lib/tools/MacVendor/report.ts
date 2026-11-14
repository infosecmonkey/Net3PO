// Export report for the MAC vendor lookup.

import type { Report } from "$lib/report/types";
import type { MacDbInfo, MacInfo } from "$lib/tools/types";

export function buildMacReport(i: MacInfo, db: MacDbInfo | null): Report {
  return {
    title: `MAC vendor: ${i.normalized}`,
    subtitle: i.vendor ?? "Unknown vendor",
    tool: "MAC Vendor Lookup",
    sections: [
      {
        title: "Lookup",
        blocks: [
          {
            type: "keyValues",
            items: [
              { key: "MAC", value: i.normalized },
              { key: "Vendor", value: i.vendor ?? "(not in the registry)" },
              { key: "Registry block", value: [i.block, i.prefix].filter(Boolean).join(" ") || i.oui },
              { key: "Locally administered", value: i.isLocallyAdministered ? "yes: set by software (randomized or virtual), so the vendor prefix does not apply" : "no" },
              { key: "Multicast", value: i.isMulticast ? "yes" : "no" },
              ...(db ? [{ key: "Database", value: `${db.source}, ${db.total.toLocaleString()} assignments` }] : []),
            ],
          },
        ],
      },
    ],
  };
}
