// Mirrors the Rust types in `tools::socket_tools`.

export type Proto = "tcp" | "udp";
export type PayloadKind = "text" | "hex";
export type Outcome = "connected" | "refused" | "timedOut" | "error";

export interface Chunk {
  bytes: number;
  text: string;
  hex: string;
  truncated: boolean;
}

export type SendEvent =
  | { type: "resolved"; addr: string }
  | { type: "connected"; ms: number; local: string }
  | { type: "sent"; bytes: number; ms: number }
  | { type: "received"; atMs: number; from: string; chunk: Chunk }
  | { type: "done"; received: number; reason: string; note: string };

export type ListenEvent =
  | { type: "started"; addr: string }
  | { type: "accepted"; conn: number; peer: string }
  | { type: "data"; conn: number | null; peer: string; chunk: Chunk }
  | { type: "closed"; conn: number; peer: string; bytes: number; reason: string }
  | { type: "rejected"; peer: string; reason: string }
  | { type: "stopped" };

export interface Stats {
  attempts: number;
  connected: number;
  refused: number;
  timedOut: number;
  errors: number;
  minMs: number | null;
  avgMs: number | null;
  maxMs: number | null;
  stddevMs: number | null;
  p95Ms: number | null;
}

export type TimingEvent =
  | { type: "resolved"; addr: string }
  | { type: "attempt"; seq: number; outcome: Outcome; ms: number; detail: string }
  | { type: "done"; stats: Stats; stopped: boolean };

/** One line in a log, stamped on arrival in the UI. */
export interface LogLine<E> {
  id: number;
  at: Date;
  ev: E;
}

export const OUTCOME_LABEL: Record<Outcome, string> = {
  connected: "connected",
  refused: "refused",
  timedOut: "timed out",
  error: "error",
};

export function stamp(d: Date): string {
  const p = (n: number, w = 2) => String(n).padStart(w, "0");
  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}.${p(d.getMilliseconds(), 3)}`;
}

export function newId(): number {
  return Math.floor(Math.random() * 0x7fffffff);
}
