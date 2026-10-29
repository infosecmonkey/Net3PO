// Typed access to the local store (JSON collections in the OS app data dir).
// The Rust side validates collection names, caps sizes, and writes atomically.

import { invoke } from "@tauri-apps/api/core";

/** Collections the app persists. Keep in sync with `store::core::COLLECTIONS`. */
export type Collection =
  | "fortinet_saved_commands"
  | "fortinet_interfaces"
  | "grep_saved_queries"
  | "ssh_groups"
  | "ssh_connections"
  | "ssh_known_hosts";

export interface Loaded<T> {
  items: T[];
  /** Set when the file was unreadable and was moved aside to this name. */
  recoveredTo: string | null;
}

export function loadCollection<T>(collection: Collection): Promise<Loaded<T>> {
  return invoke<Loaded<T>>("store_load", { collection });
}

export function saveCollection<T>(collection: Collection, items: T[]): Promise<void> {
  return invoke("store_save", { collection, items });
}
