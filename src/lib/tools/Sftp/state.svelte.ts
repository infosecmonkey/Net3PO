// SFTP session state, kept outside the panel so the connection, folder and
// transfers survive switching to another tool and back.

import { Channel, invoke } from "@tauri-apps/api/core";

export type Kind = "dir" | "file" | "link" | "other";

export interface Entry {
  name: string;
  kind: Kind;
  linkDir: boolean;
  size: number | null;
  mtime: number | null;
  perms: string;
}

export interface Listing {
  path: string;
  entries: Entry[];
  truncated: boolean;
}

export type TransferOutcome =
  | { type: "done"; bytes: number; path: string }
  | { type: "exists"; path: string }
  | { type: "cancelled" };

export interface Transfer {
  id: number;
  direction: "up" | "down";
  name: string;
  done: number;
  total: number | null;
  status: "running" | "done" | "failed" | "cancelled";
  message: string;
  started: number;
}

/** Transfers kept in the list. */
const MAX_TRANSFERS = 200;

export const sftp = $state<{
  session: number | null;
  title: string;
  listing: Listing | null;
  selected: string[];
  loading: boolean;
  error: string;
  transfers: Transfer[];
  /** Last local folder downloads went to. */
  downloadDir: string;
}>({
  session: null,
  title: "",
  listing: null,
  selected: [],
  loading: false,
  error: "",
  transfers: [],
  downloadDir: "",
});

/** Join a remote folder and a name. */
export function join(dir: string, name: string): string {
  return dir.endsWith("/") ? `${dir}${name}` : `${dir}/${name}`;
}

export async function list(path: string) {
  if (sftp.session === null) return;
  sftp.loading = true;
  sftp.error = "";
  try {
    sftp.listing = await invoke<Listing>("sftp_list", { session: sftp.session, path });
    sftp.selected = [];
  } catch (e) {
    sftp.error = String(e);
  } finally {
    sftp.loading = false;
  }
}

export async function disconnect() {
  const s = sftp.session;
  for (const t of sftp.transfers) if (t.status === "running") await cancel(t.id);
  sftp.session = null;
  sftp.listing = null;
  sftp.selected = [];
  sftp.title = "";
  if (s !== null) await invoke("sftp_close", { session: s }).catch(() => {});
}

export async function cancel(id: number) {
  await invoke("sftp_cancel", { transfer: id }).catch(() => {});
}

export function clearFinished() {
  sftp.transfers = sftp.transfers.filter((t) => t.status === "running");
}

let nextTransfer = 1;

/**
 * Run one transfer. `confirmOverwrite` is asked when the target exists.
 * Returns true when the file moved.
 */
export async function transfer(
  direction: "up" | "down",
  name: string,
  args: Record<string, unknown>,
  confirmOverwrite: (path: string) => Promise<boolean>,
): Promise<boolean> {
  if (sftp.session === null) return false;
  const id = nextTransfer++;
  const row: Transfer = {
    id,
    direction,
    name,
    done: 0,
    total: null,
    status: "running",
    message: "",
    started: Date.now(),
  };
  sftp.transfers = [row, ...sftp.transfers].slice(0, MAX_TRANSFERS);
  const live = () => sftp.transfers.find((t) => t.id === id);
  const command = direction === "up" ? "sftp_upload" : "sftp_download";
  let overwrite = false;
  for (;;) {
    const channel = new Channel<{ done: number; total: number | null }>();
    channel.onmessage = (p) => {
      const t = live();
      if (t) {
        t.done = p.done;
        t.total = p.total;
      }
    };
    try {
      const out = await invoke<TransferOutcome>(command, {
        session: sftp.session,
        transfer: id,
        overwrite,
        onProgress: channel,
        ...args,
      });
      const t = live();
      if (out.type === "exists") {
        if (!overwrite && (await confirmOverwrite(out.path))) {
          overwrite = true;
          continue;
        }
        if (t) {
          t.status = "cancelled";
          t.message = "Skipped: already exists";
        }
        return false;
      }
      if (t) {
        if (out.type === "done") {
          t.status = "done";
          t.done = out.bytes;
          t.total = out.bytes;
          t.message = out.path;
        } else {
          t.status = "cancelled";
          t.message = "Cancelled";
        }
      }
      return out.type === "done";
    } catch (e) {
      const t = live();
      if (t) {
        t.status = "failed";
        t.message = String(e);
      }
      return false;
    }
  }
}

export function formatSize(n: number | null): string {
  if (n === null) return "";
  if (n < 1024) return `${n} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v < 10 ? v.toFixed(1) : Math.round(v)} ${units[i]}`;
}

export function formatTime(secs: number | null): string {
  if (secs === null) return "";
  const d = new Date(secs * 1000);
  const pad = (x: number) => String(x).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}
