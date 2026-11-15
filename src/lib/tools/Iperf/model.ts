// Types mirroring the Rust iperf3 driver, formatting, and the export report.

import { generatedNow } from "$lib/report/export";
import type { Report, Section } from "$lib/report/types";

export interface Detected {
  path: string;
  version: string;
  jsonStream: boolean;
  bidir: boolean;
}

export type Protocol = "tcp" | "udp";
export type Direction = "upload" | "download" | "both";
export type Family = "auto" | "v4" | "v6";

export interface ClientOpts {
  host: string;
  port: number;
  protocol: Protocol;
  direction: Direction;
  duration: number;
  parallel: number;
  bitrate: string;
  omit: number;
  family: Family;
}

export interface Point {
  start: number;
  end: number;
  bitsPerSecond: number;
  bytes: number;
  retransmits: number | null;
  jitterMs: number | null;
  lostPackets: number | null;
  packets: number | null;
  omitted: boolean;
  localSends: boolean;
}

export interface DirResult {
  localSends: boolean;
  sentBps: number | null;
  receivedBps: number | null;
  sentBytes: number | null;
  receivedBytes: number | null;
  retransmits: number | null;
  jitterMs: number | null;
  lostPackets: number | null;
  packets: number | null;
  lostPercent: number | null;
}

export interface TestInfo {
  protocol: string;
  streams: number;
  duration: number;
  reverse: boolean;
  bidir: boolean;
  local: string;
  remote: string;
}

export interface Summary {
  directions: DirResult[];
  cpuLocal: number | null;
  cpuRemote: number | null;
}

export type IperfEvent =
  | { type: "started"; command: string; live: boolean }
  | { type: "testStart"; info: TestInfo }
  | { type: "interval"; points: Point[] }
  | { type: "result"; summary: Summary }
  | { type: "log"; line: string }
  | { type: "error"; message: string }
  | { type: "done"; cancelled: boolean; timedOut: boolean };

/** One test: a client run, or one client's test against our server. */
export interface TestRun {
  info: TestInfo | null;
  points: Point[];
  summary: Summary | null;
  errors: string[];
}

export function emptyRun(): TestRun {
  return { info: null, points: [], summary: null, errors: [] };
}

/** "941 Mbit/s" style rate. */
export function rate(bps: number | null | undefined): string {
  if (bps === null || bps === undefined || !isFinite(bps)) return "-";
  const units = ["bit/s", "Kbit/s", "Mbit/s", "Gbit/s", "Tbit/s"];
  let v = bps;
  let i = 0;
  while (v >= 1000 && i < units.length - 1) {
    v /= 1000;
    i++;
  }
  return `${v >= 100 ? v.toFixed(0) : v >= 10 ? v.toFixed(1) : v.toFixed(2)} ${units[i]}`;
}

export function bytes(n: number | null | undefined): string {
  if (n === null || n === undefined) return "-";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let v = n;
  let i = 0;
  while (v >= 1000 && i < units.length - 1) {
    v /= 1000;
    i++;
  }
  return `${i === 0 ? v : v.toFixed(1)} ${units[i]}`;
}

/** Direction label from this computer's point of view. */
export function dirLabel(localSends: boolean, server: boolean): string {
  if (server) return localSends ? "Server sends" : "Server receives";
  return localSends ? "Upload (this computer sends)" : "Download (server sends)";
}

export function shortDir(localSends: boolean): string {
  return localSends ? "send" : "receive";
}

const CAVEAT =
  "iperf3 measures what this computer and the iperf3 server can push through the path between them. Results depend on both end hosts (CPU, NIC, TCP buffers), the number of streams, and other traffic; a single TCP stream is often limited by latency and window size rather than the link. The received rate is the throughput that arrived.";

function testRows(t: TestRun, server: boolean): Section[] {
  const sections: Section[] = [];
  const s = t.summary;
  if (s) {
    sections.push({
      title: "Results",
      blocks: [
        {
          type: "table",
          headers: ["Direction", "Received", "Sent", "Data", "Retransmits", "Jitter", "Loss"],
          rows: s.directions.map((d) => [
            dirLabel(d.localSends, server),
            rate(d.receivedBps),
            rate(d.sentBps),
            bytes(d.receivedBytes ?? d.sentBytes),
            d.retransmits === null ? "-" : String(d.retransmits),
            d.jitterMs === null ? "-" : `${d.jitterMs.toFixed(3)} ms`,
            d.lostPercent === null ? "-" : `${d.lostPackets ?? 0}/${d.packets ?? 0} (${d.lostPercent.toFixed(2)}%)`,
          ]),
        },
        {
          type: "keyValues",
          items: [
            { key: "CPU (this computer)", value: s.cpuLocal === null ? "-" : `${s.cpuLocal.toFixed(1)}%` },
            { key: "CPU (remote)", value: s.cpuRemote === null ? "-" : `${s.cpuRemote.toFixed(1)}%` },
          ],
        },
      ],
    });
  }
  if (t.points.length) {
    sections.push({
      title: "Intervals",
      blocks: [
        {
          type: "table",
          headers: ["Time (s)", "Direction", "Rate", "Retransmits", "Jitter", "Lost / packets"],
          rows: t.points.map((p) => [
            `${p.start.toFixed(1)}-${p.end.toFixed(1)}${p.omitted ? " (omitted)" : ""}`,
            shortDir(p.localSends),
            rate(p.bitsPerSecond),
            p.retransmits === null ? "-" : String(p.retransmits),
            p.jitterMs === null ? "-" : `${p.jitterMs.toFixed(3)} ms`,
            p.packets === null ? "-" : `${p.lostPackets ?? 0}/${p.packets}`,
          ]),
        },
      ],
    });
  }
  if (t.errors.length) {
    sections.push({ title: "Errors", blocks: [{ type: "code", text: t.errors.join("\n") }] });
  }
  return sections;
}

function infoItems(t: TestRun, command: string) {
  const i = t.info;
  return [
    { key: "Command", value: command || "-" },
    { key: "Local", value: i?.local || "-" },
    { key: "Remote", value: i?.remote || "-" },
    { key: "Protocol", value: i?.protocol || "-" },
    { key: "Streams", value: i ? String(i.streams) : "-" },
    { key: "Duration", value: i ? `${i.duration} s` : "-" },
    { key: "Mode", value: i ? (i.bidir ? "bidirectional" : i.reverse ? "reverse (server sends)" : "normal (client sends)") : "-" },
  ];
}

export function buildClientReport(t: TestRun, command: string, version: string): Report {
  return {
    title: "Throughput test (iperf3)",
    subtitle: t.info?.remote || "",
    generated: generatedNow(),
    tool: "Throughput Tester",
    sections: [
      {
        title: "Test",
        blocks: [
          { type: "keyValues", items: [...infoItems(t, command), { key: "iperf3", value: version }] },
          { type: "paragraph", text: CAVEAT },
        ],
      },
      ...testRows(t, false),
    ],
  };
}

export function buildServerReport(tests: TestRun[], command: string, version: string): Report {
  const sections: Section[] = [
    {
      title: "Server",
      blocks: [
        {
          type: "keyValues",
          items: [
            { key: "Command", value: command || "-" },
            { key: "iperf3", value: version },
            { key: "Tests", value: String(tests.length) },
          ],
        },
        { type: "paragraph", text: CAVEAT },
      ],
    },
  ];
  tests.forEach((t, n) => {
    for (const s of testRows(t, true)) {
      sections.push({ ...s, title: `Test ${n + 1} (${t.info?.remote || "client"}): ${s.title}` });
    }
  });
  return { title: "iperf3 server results", generated: generatedNow(), tool: "Throughput Tester", sections };
}
