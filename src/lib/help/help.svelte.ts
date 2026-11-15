// App-wide state for the help panel: whether it is open, the page shown, and
// a back history.

import { notes, onNotesOpen, persistUi } from "$lib/notes.svelte";
import { HOME, toolPage } from "./manual";

const KEY = "net3po.help.ui";

function readWidth(): number {
  try {
    const w = Number(JSON.parse(localStorage.getItem(KEY) ?? "{}").width);
    return Number.isFinite(w) && w >= 320 ? w : 520;
  } catch {
    return 520;
  }
}

export const help = $state({
  open: false,
  page: HOME,
  anchor: "",
  history: [] as { page: string; anchor: string }[],
  width: readWidth(),
});

onNotesOpen(() => {
  help.open = false;
});

export function persistHelp() {
  try {
    localStorage.setItem(KEY, JSON.stringify({ width: help.width }));
  } catch {
    // Storage unavailable: the width resets next launch.
  }
}

/** Show a page, remembering the current one for Back. */
export function showPage(page: string, anchor = "") {
  if (help.open && (page !== help.page || anchor !== help.anchor)) {
    help.history = [...help.history.slice(-49), { page: help.page, anchor: help.anchor }];
  }
  help.page = page;
  help.anchor = anchor;
  openPanel();
}

/** Help and notes share the right edge; opening one hides the other (the
 * note draft is kept). */
function openPanel() {
  help.open = true;
  if (notes.open) {
    notes.open = false;
    persistUi();
  }
}

/** Open help for a tool, or the contents page when it has none. */
export function helpForTool(toolId: string) {
  showPage(toolPage(toolId) ?? HOME);
}

export function back() {
  const prev = help.history.at(-1);
  if (!prev) return;
  help.history = help.history.slice(0, -1);
  help.page = prev.page;
  help.anchor = prev.anchor;
}

/** Toggle: open on the current tool's page, or close. */
export function toggleHelp(toolId: string) {
  if (help.open) help.open = false;
  else {
    help.history = [];
    helpForTool(toolId);
  }
}
