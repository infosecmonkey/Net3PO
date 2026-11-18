// App settings, saved in the app data folder (collection "settings"). For
// now: which RDP and VNC clients the Remote tools open. The RDP and VNC
// tools show in the sidebar only when a client is available.

import { invoke } from "@tauri-apps/api/core";
import { loadCollection, saveCollection } from "$lib/store";

export type Protocol = "rdp" | "vnc";
export type ClientMode = "auto" | "custom" | "off";

export interface ClientSetting {
  mode: ClientMode;
  /** Detected client id in auto mode; empty picks the first found. */
  id: string;
  /** Custom program. */
  path: string;
  /** Custom argument template. */
  args: string;
}

export interface Settings {
  remote: Record<Protocol, ClientSetting>;
  updates: {
    /** Check GitHub for a newer release when the app starts. Off by default. */
    checkOnStart: boolean;
  };
}

export interface DetectedClient {
  id: string;
  name: string;
  path: string;
  style: string;
  note: string;
}

export interface Detected {
  rdp: DetectedClient[];
  vnc: DetectedClient[];
  rdpTemplate: string;
  vncTemplate: string;
  /** "macos", "windows", "linux", ... */
  os: string;
}

/** What the Rust launcher takes. */
export type Choice = { mode: "auto"; id: string } | { mode: "custom"; path: string; args: string };

const COLLECTION = "settings";

function defaults(): Settings {
  return {
    remote: {
      rdp: { mode: "auto", id: "", path: "", args: "{file}" },
      vnc: { mode: "auto", id: "", path: "", args: "{host}::{port}" },
    },
    updates: { checkOnStart: false },
  };
}

export const settings = $state<{ value: Settings; detected: Detected | null; loaded: boolean; error: string }>({
  value: defaults(),
  detected: null,
  loaded: false,
  error: "",
});

function merge(saved: unknown): Settings {
  const d = defaults();
  if (!saved || typeof saved !== "object") return d;
  const remote = (saved as { remote?: Partial<Record<Protocol, Partial<ClientSetting>>> }).remote ?? {};
  for (const p of ["rdp", "vnc"] as const) {
    const s = remote[p];
    if (!s) continue;
    const mode = s.mode === "custom" || s.mode === "off" ? s.mode : "auto";
    d.remote[p] = {
      mode,
      id: typeof s.id === "string" ? s.id : "",
      path: typeof s.path === "string" ? s.path : "",
      args: typeof s.args === "string" && s.args.trim() ? s.args : d.remote[p].args,
    };
  }
  const updates = (saved as { updates?: { checkOnStart?: unknown } }).updates;
  d.updates.checkOnStart = updates?.checkOnStart === true;
  return d;
}

export async function detectClients() {
  try {
    settings.detected = await invoke<Detected>("remote_clients");
  } catch (e) {
    settings.error = String(e);
  }
}

export async function loadSettings() {
  try {
    const l = await loadCollection<Settings>(COLLECTION);
    settings.value = merge(l.items[0]);
  } catch (e) {
    settings.error = String(e);
  }
  await detectClients();
  settings.loaded = true;
}

export async function saveSettings() {
  try {
    await saveCollection(COLLECTION, [$state.snapshot(settings.value)]);
    settings.error = "";
  } catch (e) {
    settings.error = String(e);
  }
}

/** The client a launch should use, or null when none is available. */
export function clientChoice(p: Protocol): Choice | null {
  const s = settings.value.remote[p];
  if (s.mode === "off") return null;
  if (s.mode === "custom") return s.path.trim() ? { mode: "custom", path: s.path.trim(), args: s.args } : null;
  const found = settings.detected?.[p] ?? [];
  if (!found.length) return null;
  const pick = found.find((c) => c.id === s.id) ?? found[0];
  return { mode: "auto", id: pick.id };
}

/** Display name of the client in use. */
export function clientName(p: Protocol): string {
  const c = clientChoice(p);
  if (!c) return "";
  if (c.mode === "custom") return c.path.split(/[\\/]/).pop() ?? c.path;
  return settings.detected?.[p].find((x) => x.id === c.id)?.name ?? c.id;
}

export function clientAvailable(p: Protocol): boolean {
  return clientChoice(p) !== null;
}
