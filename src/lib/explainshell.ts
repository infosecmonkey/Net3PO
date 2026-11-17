// Optional online lookup: open a shell command on explainshell.com in the
// user's browser. Only runs on an explicit click, after a confirm, because the
// command text leaves the machine.

import { ask } from "@tauri-apps/plugin-dialog";
import { openUrl } from "@tauri-apps/plugin-opener";

/** Longest command sent; explainshell is meant for one command line, and URLs have limits. */
export const EXPLAINSHELL_MAX = 4000;

/** The explainshell URL for `cmd`, or null if it is empty or too long. */
export function explainShellUrl(cmd: string): string | null {
  const c = cmd.trim();
  if (c.length === 0 || c.length > EXPLAINSHELL_MAX) return null;
  return `https://explainshell.com/explain?cmd=${encodeURIComponent(c)}`;
}

/** Why the button is unavailable for `cmd`, or null if it can be used. */
export function explainShellBlocked(cmd: string): string | null {
  const c = cmd.trim();
  if (c.length === 0) return "Nothing to explain";
  if (c.length > EXPLAINSHELL_MAX) return `Longer than ${EXPLAINSHELL_MAX} characters; copy one command instead`;
  return null;
}

/** Confirm, then open explainshell.com with `cmd`. */
export async function openExplainShell(cmd: string): Promise<void> {
  const url = explainShellUrl(cmd);
  if (!url) return;
  const ok = await ask(
    "This opens explainshell.com in your browser and sends the command text to that site. Do not use it for commands that contain secrets or internal names.",
    { title: "Open explainshell.com?", kind: "warning", okLabel: "Open", cancelLabel: "Cancel" },
  );
  if (ok) await openUrl(url);
}
