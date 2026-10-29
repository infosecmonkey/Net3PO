// App-wide SSH session manager. Sessions live here, not in the SSH panel, so
// they keep running (and keep their scrollback) while you switch tools, and
// other tools can send commands to the active session.

import { Channel, invoke } from "@tauri-apps/api/core";

export type AuthKind = "password" | "key";

export interface SshGroup {
  id: string;
  name: string;
}

export interface SshConnection {
  id: string;
  groupId: string | null;
  name: string;
  host: string;
  port: number;
  user: string;
  auth: AuthKind;
  keyPath: string;
  notes: string;
}

/** What Rust needs to connect. Secrets are optional; Rust falls back to the keychain. */
export interface ConnectParams {
  connectionId: string | null;
  host: string;
  port: number;
  user: string;
  auth: AuthKind;
  keyPath: string;
  secret?: string;
  saveSecret?: boolean;
  trustFingerprint?: string;
}

export type ConnectOutcome =
  | { type: "connected"; session: number; fingerprint: string }
  | {
      type: "hostKey";
      status: "new" | "changed";
      algorithm: string;
      fingerprint: string;
      previous: string | null;
    };

type SshEvent = { type: "data"; b64: string } | { type: "closed"; reason: string };

export interface SessionTab {
  /** Local tab id. */
  key: number;
  /** Backend session id. */
  session: number;
  title: string;
  connectionId: string | null;
  status: "open" | "closed";
  reason: string;
}

/** Scrollback kept per session for redrawing a terminal after a tool switch. */
const MAX_BUFFER = 2 * 1024 * 1024;

export const ssh = $state<{
  tabs: SessionTab[];
  active: number | null;
  /** Terminal drawer docked under other tools. */
  drawer: boolean;
  /** Drawer height in pixels. */
  drawerHeight: number;
}>({ tabs: [], active: null, drawer: false, drawerHeight: 300 });

let nextKey = 1;
const buffers = new Map<number, { chunks: Uint8Array[]; bytes: number }>();
const sinks = new Map<number, (data: Uint8Array) => void>();
const encoder = new TextEncoder();

function decodeB64(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function record(key: number, data: Uint8Array) {
  let b = buffers.get(key);
  if (!b) {
    b = { chunks: [], bytes: 0 };
    buffers.set(key, b);
  }
  b.chunks.push(data);
  b.bytes += data.length;
  while (b.bytes > MAX_BUFFER && b.chunks.length > 1) {
    b.bytes -= b.chunks.shift()!.length;
  }
  sinks.get(key)?.(data);
}

/**
 * Connect. On success a tab is opened and made active. A host key prompt is
 * returned to the caller to confirm, then connect again with
 * `trustFingerprint`.
 */
export async function connect(params: ConnectParams, title: string): Promise<ConnectOutcome> {
  const key = nextKey++;
  const channel = new Channel<SshEvent>();
  channel.onmessage = (ev) => {
    if (ev.type === "data") {
      record(key, decodeB64(ev.b64));
    } else {
      record(key, encoder.encode(`\r\n\x1b[2m[${ev.reason}]\x1b[0m\r\n`));
      const t = ssh.tabs.find((x) => x.key === key);
      if (t) {
        t.status = "closed";
        t.reason = ev.reason;
      }
    }
  };
  const outcome = await invoke<ConnectOutcome>("ssh_connect", {
    params,
    cols: 100,
    rows: 30,
    onEvent: channel,
  });
  if (outcome.type === "connected") {
    ssh.tabs.push({
      key,
      session: outcome.session,
      title,
      connectionId: params.connectionId,
      status: "open",
      reason: "",
    });
    ssh.active = key;
  }
  return outcome;
}

function tab(key: number): SessionTab | undefined {
  return ssh.tabs.find((t) => t.key === key);
}

/** Send keystrokes or text to a tab. */
export async function write(key: number, data: string) {
  const t = tab(key);
  if (!t || t.status !== "open") return;
  await invoke("ssh_write", { session: t.session, data });
}

export async function resize(key: number, cols: number, rows: number) {
  const t = tab(key);
  if (!t || t.status !== "open") return;
  await invoke("ssh_resize", { session: t.session, cols, rows });
}

/** Close a tab and its session. */
export async function closeTab(key: number) {
  const t = tab(key);
  if (t && t.status === "open") {
    await invoke("ssh_close", { session: t.session }).catch(() => {});
  }
  ssh.tabs = ssh.tabs.filter((x) => x.key !== key);
  buffers.delete(key);
  sinks.delete(key);
  if (ssh.active === key) ssh.active = ssh.tabs.at(-1)?.key ?? null;
  if (ssh.tabs.length === 0) ssh.drawer = false;
}

/** Attach a terminal: returns the scrollback to replay, then streams new data. */
export function attach(key: number, sink: (data: Uint8Array) => void): Uint8Array[] {
  sinks.set(key, sink);
  return buffers.get(key)?.chunks ?? [];
}

/** Detach a terminal. Only removes `sink` if it is still the current one, so a
 * terminal unmounting late does not cut off the one that replaced it. */
export function detach(key: number, sink: (data: Uint8Array) => void) {
  if (sinks.get(key) === sink) sinks.delete(key);
}

/** The active, open session, for tools that send commands to it. */
export function activeTab(): SessionTab | null {
  const t = ssh.tabs.find((x) => x.key === ssh.active);
  return t && t.status === "open" ? t : null;
}

/** Open sessions, the active one first, for tools that send commands. */
export function openTabs(): SessionTab[] {
  const open = ssh.tabs.filter((t) => t.status === "open");
  return [...open.filter((t) => t.key === ssh.active), ...open.filter((t) => t.key !== ssh.active)];
}

/** Type a command into a session, followed by Enter, and make it active. */
export async function sendTo(key: number, command: string): Promise<boolean> {
  const t = tab(key);
  if (!t || t.status !== "open") return false;
  ssh.active = key;
  // Send line by line so multi-line snippets arrive as separate commands.
  for (const line of command.split(/\r?\n/)) {
    await write(key, line + "\r");
  }
  return true;
}

/** Type a command into the active session, followed by Enter. */
export async function sendToActive(command: string): Promise<boolean> {
  const t = activeTab();
  return t ? sendTo(t.key, command) : false;
}
