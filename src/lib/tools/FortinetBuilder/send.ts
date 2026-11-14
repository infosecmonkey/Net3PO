// What "Send to SSH" types. Comment lines (`#`) are notes for the reader,
// not FortiOS commands, and the stop-debug block must not run right after the
// debug starts, so it is held back for a separate "Send stop" click.

/** Header line the builders put before the stop-debug block. */
const STOP_HEADER = "# When finished";

export interface SendPlan {
  /** Commands to type now. */
  now: string[];
  /** Stop-debug commands to type later, empty when there is no stop block. */
  stop: string[];
}

const runnable = (lines: string[]) =>
  lines.map((l) => l.trim()).filter((l) => l !== "" && !l.startsWith("#"));

export function planSend(command: string): SendPlan {
  const lines = command.split(/\r?\n/);
  const at = lines.findIndex((l) => l.trim().startsWith(STOP_HEADER));
  if (at < 0) return { now: runnable(lines), stop: [] };
  return { now: runnable(lines.slice(0, at)), stop: runnable(lines.slice(at + 1)) };
}
