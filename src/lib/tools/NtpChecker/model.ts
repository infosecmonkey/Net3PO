// Types mirroring `tools::ntp_check`, and the export report.

import type { Report } from "$lib/report/types";

export interface Summary {
  samples: number;
  answered: number;
  bestOffsetMs: number | null;
  minOffsetMs: number | null;
  maxOffsetMs: number | null;
  meanOffsetMs: number | null;
  jitterMs: number | null;
  minDelayMs: number | null;
}

export interface Sample {
  seq: number;
  atMs: number;
  offsetMs: number | null;
  delayMs: number | null;
  stratum: number | null;
  refId: string;
  version: number | null;
  leap: number | null;
  precision: number | null;
  rootDelayMs: number | null;
  rootDispersionMs: number | null;
  error: string | null;
}

export type NtpEvent =
  | { type: "resolved"; server: string; addr: string }
  | ({ type: "sample"; server: string } & Sample)
  | { type: "done"; server: string; summary: Summary; error: string | null };

export interface ServerState {
  server: string;
  addr: string;
  samples: Sample[];
  summary: Summary | null;
  error: string | null;
}

export const fmt = (v: number | null, d = 2) => (v === null ? "-" : `${v.toFixed(d)} ms`);

export function buildNtpReport(list: ServerState[]): Report {
  return {
    title: "NTP check",
    subtitle: `${list.length} server${list.length === 1 ? "" : "s"}`,
    tool: "NTP Checker",
    sections: [
      {
        title: "Servers",
        blocks: [
          {
            type: "table",
            headers: ["Server", "Address", "Answered", "Stratum", "Reference", "Best offset", "Jitter", "Min delay"],
            rows: list.map((s) => {
              const last = [...s.samples].reverse().find((x) => x.stratum !== null);
              return [
                s.server,
                s.addr,
                s.summary ? `${s.summary.answered}/${s.summary.samples}` : "",
                last?.stratum !== undefined && last?.stratum !== null ? String(last.stratum) : "",
                last?.refId ?? "",
                fmt(s.summary?.bestOffsetMs ?? null),
                fmt(s.summary?.jitterMs ?? null),
                fmt(s.summary?.minDelayMs ?? null),
              ];
            }),
          },
          {
            type: "paragraph",
            text: "Offset is how far this computer's clock is from the server's: positive means this computer is behind. The best offset comes from the sample with the lowest round-trip delay. No reply is inconclusive: the server may be down, filtered or rate-limiting. The local clock was not changed.",
          },
        ],
      },
      ...list.map((s) => ({
        title: `${s.server} (${s.addr || "not resolved"})`,
        blocks: [
          s.error
            ? { type: "paragraph" as const, text: s.error }
            : {
                type: "table" as const,
                headers: ["#", "Time (UTC)", "Offset", "Delay", "Stratum", "Reference", "Result"],
                rows: s.samples.map((x) => [String(x.seq), new Date(x.atMs).toISOString().slice(11, 23), fmt(x.offsetMs), fmt(x.delayMs), x.stratum === null ? "" : String(x.stratum), x.refId, x.error ?? "ok"]),
              },
        ],
      })),
    ],
  };
}
