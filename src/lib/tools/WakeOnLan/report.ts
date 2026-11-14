// Build an export report from the Wake-on-LAN send log.

import type { Report } from "$lib/report/types";
import type { WolDelivery, WolSendResult } from "$lib/tools/types";

/** What the check found, kept separate from the send result. */
export type CheckOutcome =
  | { state: "none" }
  | { state: "running"; host: string }
  | { state: "up"; host: string; port: number; answer: "open" | "refused"; elapsedMs: number }
  | { state: "noAnswer"; host: string; elapsedMs: number }
  | { state: "cancelled"; host: string; elapsedMs: number }
  | { state: "error"; host: string; message: string };

export interface LogEntry {
  key: number;
  device: string;
  result: WolSendResult;
  check: CheckOutcome;
}

export const DELIVERY_LABEL: Record<WolDelivery, string> = {
  limitedBroadcast: "Limited broadcast",
  localBroadcast: "Local subnet broadcast",
  remoteBroadcast: "Remote subnet broadcast",
  unicast: "Unicast",
};

export const DELIVERY_NOTE: Record<WolDelivery, string> = {
  limitedBroadcast:
    "Limited broadcast (255.255.255.255): reaches only the segment of the sending interface. Routers never forward it.",
  localBroadcast:
    "Subnet broadcast of a local interface: reaches every host on that segment.",
  remoteBroadcast:
    "Looks like a remote subnet's broadcast address. It arrives only if the routers on the path forward directed broadcasts to that subnet (usually off by default).",
  unicast:
    "Unicast to one address. A sleeping host usually cannot answer ARP, so this works only with a static ARP entry or while the switch and router still remember the host.",
};

export function fmtSecs(ms: number): string {
  return `${(ms / 1000).toFixed(ms < 10_000 ? 1 : 0)}s`;
}

export function sentSummary(r: WolSendResult): string {
  const from = r.source ? ` from ${r.source}` : "";
  return `${r.packets} magic packet${r.packets === 1 ? "" : "s"} (${r.bytes} bytes) to ${r.destination}:${r.port}${from} via ${r.interface}`;
}

export function checkSummary(c: CheckOutcome): string {
  switch (c.state) {
    case "none":
      return "Not checked";
    case "running":
      return `Checking ${c.host}...`;
    case "up":
      return c.answer === "open"
        ? `${c.host} answered on TCP ${c.port} after ${fmtSecs(c.elapsedMs)}`
        : `${c.host} refused TCP ${c.port} after ${fmtSecs(c.elapsedMs)} (port closed, but the host is up)`;
    case "noAnswer":
      return `No answer from ${c.host} within ${fmtSecs(c.elapsedMs)}. Inconclusive: it may be awake with those ports filtered, still booting, or asleep.`;
    case "cancelled":
      return `Check of ${c.host} stopped after ${fmtSecs(c.elapsedMs)}`;
    case "error":
      return `Check of ${c.host} failed: ${c.message}`;
  }
}

export function buildWolReport(log: LogEntry[]): Report {
  const time = (ms: number) => new Date(ms).toLocaleString();
  return {
    title: "Wake-on-LAN log",
    subtitle: `${log.length} wake request${log.length === 1 ? "" : "s"}`,
    tool: "Wake-on-LAN",
    sections: [
      {
        title: "Requests",
        blocks: [
          {
            type: "table",
            headers: ["Time", "Device", "MAC", "Sent", "Reachability"],
            rows: log.map((e) => [
              time(e.result.sentAtMs),
              e.device || "(unsaved)",
              e.result.mac,
              sentSummary(e.result),
              checkSummary(e.check),
            ]),
          },
          {
            type: "paragraph",
            text:
              "A sent packet only means the OS accepted it for sending. Whether the target woke up is shown separately by the reachability check, when one was run.",
          },
        ],
      },
      {
        title: "Delivery notes",
        blocks: [
          {
            type: "findings",
            items: [...new Set(log.map((e) => e.result.delivery))].map((d) => ({
              severity: d === "remoteBroadcast" || d === "unicast" ? ("warn" as const) : ("info" as const),
              title: DELIVERY_LABEL[d],
              detail: DELIVERY_NOTE[d],
            })),
          },
          ...log
            .filter((e) => e.result.warnings.length > 0)
            .map((e) => ({
              type: "paragraph" as const,
              text: `${time(e.result.sentAtMs)}: ${e.result.warnings.join(" ")}`,
            })),
        ],
      },
    ],
  };
}
