// App updates. Nothing is checked unless the user clicks Check for updates
// or turns on the check at startup in Settings. The check reads latest.json
// from the latest published GitHub release; the download is verified
// against the public key built into the app before it is installed.

import { invoke } from "@tauri-apps/api/core";
import { check, type Update } from "@tauri-apps/plugin-updater";
import { relaunch } from "@tauri-apps/plugin-process";

export const RELEASES_URL = "https://github.com/infosecmonkey/Net3PO/releases/latest";

export type UpdateStatus = "idle" | "checking" | "current" | "available" | "installing" | "error";

export const updates = $state<{
  status: UpdateStatus;
  /** Dialog shown. */
  open: boolean;
  version: string;
  current: string;
  date: string;
  notes: string;
  error: string;
  downloaded: number;
  total: number;
  /** "package": a Linux .deb/.rpm install that cannot replace itself. */
  kind: "inPlace" | "package";
}>({
  status: "idle",
  open: false,
  version: "",
  current: "",
  date: "",
  notes: "",
  error: "",
  downloaded: 0,
  total: 0,
  kind: "inPlace",
});

let pending: Update | null = null;

/** Check for a newer release. `manual` shows the result even when there is none. */
export async function checkForUpdates(manual: boolean): Promise<void> {
  if (updates.status === "checking" || updates.status === "installing") return;
  updates.status = "checking";
  updates.error = "";
  if (manual) updates.open = true;
  try {
    updates.kind = await invoke<"inPlace" | "package">("update_kind").catch(() => "inPlace" as const);
    const u = await check({ timeout: 20_000 });
    pending = u;
    if (u) {
      updates.status = "available";
      updates.version = u.version;
      updates.current = u.currentVersion;
      updates.date = u.date ? u.date.slice(0, 10) : "";
      updates.notes = (u.body ?? "").slice(0, 20_000);
      updates.open = true;
    } else {
      updates.status = "current";
    }
  } catch (e) {
    updates.status = "error";
    updates.error = String(e);
    // A failed check at startup stays quiet; the user did not ask for it.
    if (!manual) updates.open = false;
  }
}

/** Download, verify and install the pending update, then restart. */
export async function installUpdate(): Promise<void> {
  if (!pending) return;
  updates.status = "installing";
  updates.downloaded = 0;
  updates.total = 0;
  try {
    await pending.downloadAndInstall((ev) => {
      if (ev.event === "Started") updates.total = ev.data.contentLength ?? 0;
      else if (ev.event === "Progress") updates.downloaded += ev.data.chunkLength;
    });
    await relaunch();
  } catch (e) {
    updates.status = "error";
    updates.error = String(e);
  }
}

export function closeUpdates() {
  if (updates.status === "installing") return;
  updates.open = false;
  if (updates.status !== "available") updates.status = "idle";
}
