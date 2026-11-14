// Export reports for the socket tools. Connection timing is labelled as
// socket connect time, not packet timing; UDP silence is called
// inconclusive.

import type { Report } from "$lib/report/types";
import { OUTCOME_LABEL, stamp, type LogLine, type SendEvent, type Stats, type TimingEvent } from "./types";

function fmt(n: number | null): string {
  return n === null ? "-" : `${n.toFixed(2)} ms`;
}

export function statsRows(s: Stats): { key: string; value: string }[] {
  return [
    { key: "Attempts", value: String(s.attempts) },
    { key: "Connected", value: `${s.connected}${s.attempts ? ` (${Math.round((100 * s.connected) / s.attempts)}%)` : ""}` },
    { key: "Refused", value: String(s.refused) },
    { key: "Timed out", value: String(s.timedOut) },
    { key: "Other errors", value: String(s.errors) },
    { key: "Connect time min / avg / max", value: `${fmt(s.minMs)} / ${fmt(s.avgMs)} / ${fmt(s.maxMs)}` },
    { key: "Std dev / p95", value: `${fmt(s.stddevMs)} / ${fmt(s.p95Ms)}` },
  ];
}

export function buildTimingReport(target: string, addr: string, log: LogLine<TimingEvent>[], stats: Stats | null): Report {
  const attempts = log.flatMap((l) => (l.ev.type === "attempt" ? [{ at: l.at, ev: l.ev }] : []));
  return {
    title: `TCP connect timing: ${target}`,
    subtitle: addr,
    tool: "Socket Tools",
    sections: [
      ...(stats ? [{ title: "Summary", blocks: [{ type: "keyValues" as const, items: statsRows(stats) }] }] : []),
      {
        title: "Attempts",
        blocks: [
          {
            type: "table",
            headers: ["#", "Time", "Result", "Connect time", "Detail"],
            rows: attempts.map(({ at, ev }) =>
              ev.type === "attempt" ? [String(ev.seq), stamp(at), OUTCOME_LABEL[ev.outcome], `${ev.ms.toFixed(2)} ms`, ev.detail] : [],
            ),
          },
          {
            type: "paragraph",
            text: "Connect time is measured around the operating system's connect call. It is not packet-level SYN/SYN-ACK timing. A timeout alone does not show where traffic was dropped or why.",
          },
        ],
      },
    ],
  };
}

export function buildSendReport(target: string, proto: string, log: LogLine<SendEvent>[]): Report {
  const rows = log.map((l) => {
    const e = l.ev;
    switch (e.type) {
      case "resolved":
        return [stamp(l.at), "Resolved", e.addr];
      case "connected":
        return [stamp(l.at), "Connected", `${e.ms.toFixed(2)} ms from ${e.local}`];
      case "sent":
        return [stamp(l.at), "Sent", `${e.bytes} bytes`];
      case "received":
        return [stamp(l.at), `Received +${e.atMs.toFixed(0)} ms`, `${e.chunk.bytes} bytes: ${e.chunk.text.slice(0, 500)}`];
      case "done":
        return [stamp(l.at), "Done", [e.reason, e.note].filter(Boolean).join(". ")];
    }
  });
  return {
    title: `${proto.toUpperCase()} send: ${target}`,
    subtitle: "",
    tool: "Socket Tools",
    sections: [{ title: "Exchange", blocks: [{ type: "table", headers: ["Time", "Event", "Detail"], rows }] }],
  };
}
