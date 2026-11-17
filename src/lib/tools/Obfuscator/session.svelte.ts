// Obfuscator session: the key and the mapping from original values to their
// replacements. Kept in memory only, so it survives switching tools but not
// quitting the app, and is never written to disk.

import type { MappingEntry } from "$lib/report/redact";

export const session = $state<{ key: string; mapping: MappingEntry[] }>({ key: "", mapping: [] });

export function resetSession() {
  session.key = "";
  session.mapping = [];
}
