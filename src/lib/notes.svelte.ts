// App-wide state for the project notes pop-out: whether it is open, the
// active project, and the note being written. The draft is kept in local
// storage on every change, so closing the panel, switching tools or quitting
// the app does not lose it. Saving to the project is always explicit.

import { saveNote, stampNow, type ToolNote } from "$lib/projects";

export interface NoteDraft {
  /** Note id: generated when the draft starts, so repeated saves update it. */
  id: string;
  /** Project and tool are fixed when the draft starts. */
  projectId: string | null;
  projectName: string;
  toolId: string;
  toolName: string;
  text: string;
  created: number;
  createdLabel: string;
  timeZone: string;
  itemId: string | null;
  /** Text as last saved to the project; null when never saved. */
  savedText: string | null;
  savedItemId: string | null;
}

const KEY_UI = "net3po.notes.ui";
const KEY_DRAFT = "net3po.notes.draft";

function read<T>(key: string): T | null {
  try {
    const raw = localStorage.getItem(key);
    return raw ? (JSON.parse(raw) as T) : null;
  } catch {
    return null;
  }
}

function write(key: string, value: unknown) {
  try {
    if (value === null) localStorage.removeItem(key);
    else localStorage.setItem(key, JSON.stringify(value));
  } catch {
    // Storage unavailable: the draft lives only in memory this session.
  }
}

const ui = read<{ open: boolean; width: number; projectId: string | null; projectName: string }>(KEY_UI);

export const notes = $state({
  open: ui?.open ?? false,
  width: ui?.width ?? 380,
  /** Project new notes go to. */
  projectId: ui?.projectId ?? null,
  projectName: ui?.projectName ?? "",
  draft: read<NoteDraft>(KEY_DRAFT),
  saving: false,
  /** Bumped after a save or delete so open lists reload. */
  version: 0,
});

export function persistUi() {
  write(KEY_UI, {
    open: notes.open,
    width: notes.width,
    projectId: notes.projectId,
    projectName: notes.projectName,
  });
}

export function persistDraft() {
  write(KEY_DRAFT, notes.draft);
}

/** 32 lowercase hex characters, the id format the backend accepts. */
function newId(): string {
  const b = new Uint8Array(16);
  crypto.getRandomValues(b);
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}

export function setActiveProject(id: string | null, name: string) {
  notes.projectId = id;
  notes.projectName = name;
  persistUi();
}

/** Start a new draft for a tool, in the active project. */
export function startDraft(toolId: string, toolName: string) {
  notes.draft = {
    id: newId(),
    projectId: notes.projectId,
    projectName: notes.projectName,
    toolId,
    toolName,
    text: "",
    created: Date.now(),
    createdLabel: stampNow(),
    timeZone: Intl.DateTimeFormat().resolvedOptions().timeZone ?? "",
    itemId: null,
    savedText: null,
    savedItemId: null,
  };
  persistDraft();
}

/** Load a saved note into the editor. Its project, tool and times stay. */
export function editNote(note: ToolNote, projectId: string, projectName: string) {
  notes.draft = {
    id: note.id,
    projectId,
    projectName,
    toolId: note.toolId,
    toolName: note.tool,
    text: note.text,
    created: note.created,
    createdLabel: note.createdLabel,
    timeZone: note.timeZone,
    itemId: note.itemId,
    savedText: note.text,
    savedItemId: note.itemId,
  };
  notes.open = true;
  persistDraft();
  persistUi();
}

export function discardDraft() {
  notes.draft = null;
  persistDraft();
}

/** True when the draft has text that is not saved to its project. */
export function isDirty(d: NoteDraft | null): boolean {
  if (!d || d.text.trim() === "") return false;
  return d.text !== d.savedText || d.itemId !== d.savedItemId;
}

/** Save the draft to its project. A draft without a project must have one
 * chosen first; the caller passes it here. */
export async function saveDraft(projectId?: string, projectName?: string): Promise<ToolNote> {
  const d = notes.draft;
  if (!d) throw new Error("nothing to save");
  if (notes.saving) throw new Error("already saving");
  if (!d.projectId) {
    if (!projectId) throw new Error("choose a project for this note");
    d.projectId = projectId;
    d.projectName = projectName ?? "";
  }
  notes.saving = true;
  try {
    const saved = await saveNote(d.projectId, {
      id: d.id,
      tool: d.toolName,
      toolId: d.toolId,
      text: d.text,
      created: d.created,
      createdLabel: d.createdLabel,
      timeZone: d.timeZone,
      itemId: d.itemId,
    });
    // The backend may drop a link to a missing result.
    d.itemId = saved.itemId;
    d.savedText = saved.text;
    d.savedItemId = saved.itemId;
    persistDraft();
    notes.version += 1;
    return saved;
  } finally {
    notes.saving = false;
  }
}
