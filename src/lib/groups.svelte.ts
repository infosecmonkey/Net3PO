// Connection groups shared by SSH, SFTP, RDP and VNC: one list, so a group
// such as a customer or site holds that site's SSH, RDP and VNC entries.
// Stored in the `ssh_groups` collection (its original name, kept so groups
// made before sharing still load).

import { loadCollection, saveCollection, type Collection } from "$lib/store";

export interface Group {
  id: string;
  name: string;
}

/** Pseudo group id for items without a (known) group. */
export const UNGROUPED = "__ungrouped";

export const groups = $state<{ list: Group[]; loaded: boolean; error: string }>({
  list: [],
  loaded: false,
  error: "",
});

/** Collapsed groups, per tool (`scope:groupId`), for this app session. */
export const collapsed = $state<Record<string, boolean>>({});

/** Collections whose items carry a `groupId`. */
const MEMBERS: Collection[] = ["ssh_connections", "rdp_hosts", "vnc_hosts"];

let loading: Promise<void> | null = null;

export function loadGroups(): Promise<void> {
  if (groups.loaded) return Promise.resolve();
  loading ??= (async () => {
    try {
      groups.list = (await loadCollection<Group>("ssh_groups")).items;
      groups.loaded = true;
      groups.error = "";
    } catch (e) {
      groups.error = String(e);
      loading = null;
    }
  })();
  return loading;
}

async function persist() {
  await saveCollection("ssh_groups", $state.snapshot(groups.list));
}

export function groupName(id: string | null | undefined): string {
  return groups.list.find((g) => g.id === id)?.name ?? "Ungrouped";
}

export function sortedGroups(): Group[] {
  return [...groups.list].sort((a, b) => a.name.localeCompare(b.name));
}

/** Add a group, or return the existing one with the same name. */
export async function addGroup(name: string): Promise<Group | null> {
  const n = name.trim();
  if (!n) return null;
  const same = groups.list.find((g) => g.name.toLowerCase() === n.toLowerCase());
  if (same) return same;
  const g = { id: crypto.randomUUID(), name: n };
  groups.list.push(g);
  await persist();
  return g;
}

export async function renameGroup(id: string, name: string) {
  const g = groups.list.find((x) => x.id === id);
  const n = name.trim();
  if (!g || !n) return;
  g.name = n;
  await persist();
}

/** How many saved SSH connections, RDP hosts and VNC hosts are in a group. */
export async function memberCounts(id: string): Promise<{ ssh: number; rdp: number; vnc: number }> {
  const count = async (c: Collection) =>
    (await loadCollection<{ groupId?: string | null }>(c)).items.filter((i) => i.groupId === id).length;
  const [ssh, rdp, vnc] = await Promise.all(MEMBERS.map(count));
  return { ssh, rdp, vnc };
}

/** Delete a group. Its members in every tool move to Ungrouped. */
export async function deleteGroup(id: string) {
  for (const c of MEMBERS) {
    const { items } = await loadCollection<{ groupId?: string | null }>(c);
    if (items.some((i) => i.groupId === id)) {
      await saveCollection(
        c,
        items.map((i) => (i.groupId === id ? { ...i, groupId: null } : i)),
      );
    }
  }
  groups.list = groups.list.filter((g) => g.id !== id);
  await persist();
}

export interface Branch<T> {
  id: string;
  name: string;
  items: T[];
}

/**
 * Items grouped by `groupId`, groups sorted by name, items by `name`.
 * Unknown or missing group ids go to Ungrouped. With `keepEmpty` every group
 * is listed even without items (unless searching).
 */
export function groupTree<T extends { groupId?: string | null; name: string }>(
  items: T[],
  match: (t: T) => boolean,
  opts: { searching: boolean; keepEmpty: boolean },
): Branch<T>[] {
  const byName = (a: T, b: T) => a.name.localeCompare(b.name);
  const known = new Set(groups.list.map((g) => g.id));
  const out: Branch<T>[] = sortedGroups().map((g) => ({
    id: g.id,
    name: g.name,
    items: items.filter((i) => i.groupId === g.id && match(i)).sort(byName),
  }));
  const loose = items.filter((i) => (!i.groupId || !known.has(i.groupId)) && match(i)).sort(byName);
  if (loose.length || !groups.list.length) out.push({ id: UNGROUPED, name: "Ungrouped", items: loose });
  const keep = opts.keepEmpty && !opts.searching;
  return out.filter((b) => b.items.length > 0 || (keep && b.id !== UNGROUPED) || (b.id === UNGROUPED && !opts.searching));
}
