<script lang="ts">
  // Project notes pop-out, docked on the right of every tool. A new note is
  // tied to the active project and the current tool when you start typing,
  // and keeps that association if you switch tools before saving. Drafts are
  // kept locally on every keystroke; Save writes the note to the project.
  import { confirm as ask } from "@tauri-apps/plugin-dialog";
  import { tick } from "svelte";
  import { nav } from "$lib/nav.svelte";
  import { findTool } from "$lib/tools/registry";
  import ExportMenu from "$lib/components/ExportMenu.svelte";
  import { generatedNow } from "$lib/report/export";
  import type { NoteEntry, Report, Section } from "$lib/report/types";
  import {
    createProject,
    deleteNote,
    getProject,
    listProjects,
    type ProjectSummary,
    type ProjectView,
    type ToolNote,
  } from "$lib/projects";
  import {
    discardDraft,
    editNote,
    isDirty,
    notes,
    persistDraft,
    persistUi,
    saveDraft,
    setActiveProject,
    startDraft,
  } from "$lib/notes.svelte";

  const MIN_W = 280;

  let projects = $state<ProjectSummary[]>([]);
  let project = $state<ProjectView | null>(null);
  let draftProject = $state<ProjectView | null>(null);
  let scope = $state<"tool" | "all">("tool");
  // Inline "new project" form. The webview does not show window.prompt or
  // window.confirm, so names are typed here and questions use native dialogs.
  let creating = $state(false);
  let newName = $state("");
  let newInput = $state<HTMLInputElement | null>(null);
  let error = $state("");
  let status = $state("");
  let pickTarget = $state("");
  let dragging = $state(false);

  const tool = $derived(findTool(nav.selected));
  const draft = $derived(notes.draft);
  const dirty = $derived(isDirty(draft));
  const otherTool = $derived(draft && draft.toolId !== nav.selected);

  // Reload the project list and the active project after saves and deletes.
  $effect(() => {
    void notes.version;
    listProjects()
      .then((l) => {
        projects = l;
        if (notes.projectId && !l.some((p) => p.id === notes.projectId)) setActiveProject(null, "");
      })
      .catch((e) => (error = String(e)));
  });

  $effect(() => {
    void notes.version;
    const id = notes.projectId;
    if (!id) {
      project = null;
      return;
    }
    getProject(id)
      .then((p) => (project = p))
      .catch(() => (project = null));
  });

  // The draft's own project, for the result-link picker.
  $effect(() => {
    void notes.version;
    const id = draft?.projectId;
    if (!id) {
      draftProject = null;
      return;
    }
    if (project && project.id === id) {
      draftProject = project;
      return;
    }
    getProject(id)
      .then((p) => (draftProject = p))
      .catch(() => (draftProject = null));
  });

  const linkable = $derived(
    draftProject && draft ? draftProject.items.filter((i) => i.tool === draft.toolName) : [],
  );

  const shown = $derived.by(() => {
    if (!project) return [] as ToolNote[];
    const list = scope === "tool" ? project.toolNotes.filter((n) => n.toolId === nav.selected) : project.toolNotes;
    return [...list].sort((a, b) => b.created - a.created);
  });

  /** The notes on screen (this tool or all), plus an unsaved draft, as a
   * report: one section per tool, oldest first. */
  function buildNotesReport(): Report | null {
    const byTool = new Map<string, NoteEntry[]>();
    const add = (toolName: string, e: NoteEntry) => {
      if (!byTool.has(toolName)) byTool.set(toolName, []);
      byTool.get(toolName)!.push(e);
    };
    for (const n of [...shown].sort((a, b) => a.created - b.created)) {
      const about = itemTitle(n.itemId);
      const edited = n.edited ? `, edited ${n.editedLabel}` : "";
      add(n.tool, { heading: `${n.createdLabel}${edited}${about ? ` (about ${about})` : ""}`, text: n.text });
    }
    const d = notes.draft;
    if (d && dirty) add(d.toolName, { heading: `Draft, not saved (started ${d.createdLabel})`, text: d.text });
    if (byTool.size === 0) return null;
    const sections: Section[] = [...byTool.entries()].map(([t, items]) => ({ title: t, blocks: [{ type: "notes", items }] }));
    return {
      title: "Notes",
      subtitle: project ? project.name : "",
      generated: generatedNow(),
      tool: "Notes",
      sections,
    };
  }

  const exportName = $derived(
    `notes-${project ? project.name : "draft"}${scope === "tool" && tool ? `-${tool.name}` : ""}`,
  );

  function itemTitle(id: string | null): string {
    if (!id || !project) return "";
    const i = project.items.findIndex((x) => x.id === id);
    return i < 0 ? "" : `result ${i + 1}: ${project.items[i].title}`;
  }

  async function startCreate() {
    creating = true;
    newName = "";
    await tick();
    newInput?.focus();
  }

  async function createAndUse() {
    const name = newName.trim();
    if (!name) return;
    error = "";
    try {
      const p = await createProject(name);
      setActiveProject(p.id, p.name);
      pickTarget = "";
      creating = false;
      notes.version += 1;
    } catch (e) {
      error = String(e);
    }
  }

  function onNewKey(e: KeyboardEvent) {
    if (e.key === "Enter") void createAndUse();
    if (e.key === "Escape") {
      e.preventDefault();
      creating = false;
    }
  }

  async function chooseProject(value: string) {
    error = "";
    if (value === "__new") {
      await startCreate();
      return;
    }
    const p = projects.find((x) => x.id === value);
    setActiveProject(p ? p.id : null, p ? p.name : "");
  }

  function onInput(e: Event) {
    const text = (e.currentTarget as HTMLTextAreaElement).value;
    if (!notes.draft) {
      if (text === "") return;
      startDraft(nav.selected, tool?.name ?? "General");
    }
    notes.draft!.text = text;
    persistDraft();
    status = "";
  }

  async function newNote() {
    if (dirty && !(await ask("Discard the unsaved note?", { title: "Discard note", kind: "warning" }))) return;
    discardDraft();
    status = "";
    error = "";
  }

  async function save() {
    error = "";
    const d = notes.draft;
    if (!d || d.text.trim() === "" || notes.saving) return;
    let target: ProjectSummary | undefined;
    if (!d.projectId) {
      target = projects.find((p) => p.id === (pickTarget || notes.projectId));
      if (!target) {
        error = projects.length ? "Choose a project for this note first." : "Create a project for this note first (New project... above).";
        return;
      }
    }
    try {
      await saveDraft(target?.id, target?.name);
      if (target && !notes.projectId) setActiveProject(target.id, target.name);
      status = `Saved to ${notes.draft?.projectName || "project"}.`;
    } catch (e) {
      error = String(e);
    }
  }

  function onKey(e: KeyboardEvent) {
    if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "s") {
      e.preventDefault();
      void save();
    }
  }

  async function edit(n: ToolNote) {
    if (!project) return;
    if (dirty && draft?.id !== n.id && !(await ask("Discard the unsaved note and edit this one?", { title: "Discard note", kind: "warning" }))) return;
    editNote(n, project.id, project.name);
    status = "";
  }

  async function remove(n: ToolNote) {
    if (!project || !(await ask("Delete this note?", { title: "Delete note", kind: "warning" }))) return;
    try {
      await deleteNote(project.id, n.id);
      if (notes.draft?.id === n.id) discardDraft();
      notes.version += 1;
    } catch (e) {
      error = String(e);
    }
  }

  function setLink(value: string) {
    if (!notes.draft) return;
    notes.draft.itemId = value || null;
    persistDraft();
  }

  function close() {
    notes.open = false;
    persistUi();
  }

  function startDrag(e: PointerEvent) {
    dragging = true;
    (e.currentTarget as HTMLElement).setPointerCapture(e.pointerId);
  }

  function drag(e: PointerEvent) {
    if (!dragging) return;
    const max = Math.max(MIN_W, Math.min(760, window.innerWidth * 0.6));
    notes.width = Math.round(Math.min(max, Math.max(MIN_W, window.innerWidth - e.clientX)));
  }

  function stopDrag() {
    if (!dragging) return;
    dragging = false;
    persistUi();
  }
</script>

<svelte:window
  onkeydown={(e) => {
    // Esc hides the panel, unless a modal dialog is open (it owns Esc).
    if (e.key === "Escape" && !creating && !e.defaultPrevented && !document.querySelector('[aria-modal="true"]')) close();
  }}
/>

<aside class="notes" style:width="{notes.width}px">
  <div
    class="handle"
    class:dragging
    role="separator"
    aria-orientation="vertical"
    aria-label="Resize notes"
    onpointerdown={startDrag}
    onpointermove={drag}
    onpointerup={stopDrag}
    onpointercancel={stopDrag}
  ></div>

  <div class="head">
    <strong>Notes</strong>
    <button class="x" title="Hide notes (Esc; the draft is kept)" aria-label="Hide notes" onclick={close}>
      <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><path d="M18 6 6 18"/><path d="m6 6 12 12"/></svg>
    </button>
  </div>

  <label class="lbl" for="np-project">Active project</label>
  <select id="np-project" value={notes.projectId ?? ""} onchange={(e) => { const v = e.currentTarget.value; e.currentTarget.value = notes.projectId ?? ""; void chooseProject(v); }}>
    <option value="">No project</option>
    {#each projects as p (p.id)}
      <option value={p.id}>{p.name}</option>
    {/each}
    <option value="__new">New project...</option>
  </select>
  {#if creating}
    <div class="newproj">
      <input bind:this={newInput} bind:value={newName} onkeydown={onNewKey} placeholder="Project name" maxlength="200" spellcheck="false" />
      <button class="action" onclick={createAndUse} disabled={!newName.trim()}>Create</button>
      <button class="secondary" onclick={() => (creating = false)}>Cancel</button>
    </div>
  {/if}

  <div class="draft">
    {#if draft}
      <div class="assoc">
        <span class="tool">{draft.toolName}</span>
        <span class="dim">{draft.projectName || "No project yet"}</span>
        <span class="dim small">started {draft.createdLabel}</span>
      </div>
      {#if otherTool}
        <div class="hint">This note belongs to {draft.toolName}, where it was started.</div>
      {/if}
    {:else}
      <div class="assoc dim small">
        A new note will be for <strong>{tool?.name ?? "General"}</strong>{notes.projectName
          ? ` in ${notes.projectName}`
          : ""}.
      </div>
    {/if}
    <textarea
      value={draft?.text ?? ""}
      oninput={onInput}
      onkeydown={onKey}
      spellcheck="true"
      placeholder="Type a note. It is kept as a draft until you save it."
    ></textarea>

    {#if draft && !draft.projectId}
      <label class="lbl" for="np-target">Save to project</label>
      <select id="np-target" value={pickTarget} onchange={(e) => { const v = e.currentTarget.value; if (v === "__new") { e.currentTarget.value = pickTarget; void startCreate(); } else pickTarget = v; }}>
        <option value="">{notes.projectId ? `${notes.projectName} (active)` : "Choose a project"}</option>
        {#each projects.filter((p) => p.id !== notes.projectId) as p (p.id)}
          <option value={p.id}>{p.name}</option>
        {/each}
        <option value="__new">New project...</option>
      </select>
    {/if}

    {#if draft && linkable.length > 0}
      <label class="lbl" for="np-link">About a saved result (optional)</label>
      <select id="np-link" value={draft.itemId ?? ""} onchange={(e) => setLink(e.currentTarget.value)}>
        <option value="">No specific result</option>
        {#each linkable as i (i.id)}
          <option value={i.id}>{i.title} ({i.addedLabel})</option>
        {/each}
      </select>
    {/if}

    <div class="btns">
      <button class="action" onclick={save} disabled={!draft || draft.text.trim() === "" || notes.saving || !dirty}>
        {notes.saving ? "Saving..." : draft?.savedText !== null && draft?.savedText !== undefined ? "Save changes" : "Save"}
      </button>
      {#if draft}<button class="secondary" onclick={newNote}>New note</button>{/if}
      <span class="small dim state">
        {#if dirty}Draft kept locally, not saved{:else if draft?.savedText}Saved{/if}
      </span>
    </div>
    {#if status}<div class="small ok">{status}</div>{/if}
    {#if error}<div class="error small">{error}</div>{/if}
  </div>

  <div class="listhead">
    <strong class="small">{project ? project.name : "No active project"}</strong>
    <div class="tools">
      {#if project}
        <div class="seg">
          <button class:on={scope === "tool"} onclick={() => (scope = "tool")}>This tool</button>
          <button class:on={scope === "all"} onclick={() => (scope = "all")}>All</button>
        </div>
      {/if}
      <ExportMenu build={buildNotesReport} name={exportName} disabled={shown.length === 0 && !dirty} />
    </div>
  </div>
  <div class="list">
    {#if !project}
      <p class="dim small">Pick a project to see its notes.</p>
    {:else if shown.length === 0}
      <p class="dim small">No notes {scope === "tool" ? `for ${tool?.name ?? "this tool"} ` : ""}yet.</p>
    {:else}
      {#each shown as n (n.id)}
        <div class="note" class:current={draft?.id === n.id}>
          <div class="meta">
            {#if scope === "all"}<span class="tool">{n.tool}</span>{/if}
            <span class="dim small">{n.createdLabel}</span>
            {#if n.edited}<span class="dim small">edited {n.editedLabel}</span>{/if}
          </div>
          {#if n.itemId && itemTitle(n.itemId)}<div class="dim small">About {itemTitle(n.itemId)}</div>{/if}
          <div class="text">{n.text}</div>
          <div class="acts">
            <button class="mini" onclick={() => edit(n)}>Edit</button>
            <button class="mini" onclick={() => remove(n)}>Delete</button>
          </div>
        </div>
      {/each}
    {/if}
  </div>
</aside>

<style>
  .notes {
    position: relative;
    flex: 0 0 auto;
    height: 100vh;
    box-sizing: border-box;
    border-left: 1px solid var(--border);
    background: var(--sidebar-bg);
    display: flex;
    flex-direction: column;
    padding: 0.7rem 0.8rem;
    gap: 0.4rem;
    font-size: 0.82rem;
    min-width: 0;
  }

  .handle {
    position: absolute;
    top: 0;
    bottom: 0;
    left: -3px;
    width: 6px;
    cursor: ew-resize;
    z-index: 2;
  }

  .handle:hover,
  .handle.dragging {
    background: var(--accent);
    opacity: 0.5;
  }

  .head {
    display: flex;
    justify-content: space-between;
    align-items: center;
  }

  .x {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 28px;
    height: 28px;
    margin: -4px -6px -4px 0;
    background: none;
    border: none;
    border-radius: 6px;
    color: var(--muted);
    cursor: pointer;
  }

  .x:hover {
    color: var(--fg);
    background: var(--hover);
  }

  .lbl {
    font-size: 0.72rem;
    color: var(--muted);
    margin-top: 0.2rem;
  }

  select,
  textarea {
    width: 100%;
    box-sizing: border-box;
    background: var(--input-bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    color: var(--fg);
    font-size: 0.82rem;
    padding: 0.4rem 0.5rem;
  }

  select:focus,
  textarea:focus {
    outline: none;
    border-color: var(--accent);
  }

  .draft {
    display: flex;
    flex-direction: column;
    gap: 0.35rem;
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.5rem;
    background: var(--bg);
    margin-top: 0.3rem;
  }

  textarea {
    min-height: 8rem;
    resize: vertical;
    font-family: inherit;
    line-height: 1.45;
  }

  .assoc {
    display: flex;
    flex-wrap: wrap;
    gap: 0.4rem;
    align-items: baseline;
  }

  .tool {
    font-weight: 600;
  }

  .hint {
    font-size: 0.74rem;
    color: var(--accent);
  }

  .btns {
    display: flex;
    align-items: center;
    gap: 0.4rem;
    flex-wrap: wrap;
  }

  .state {
    margin-left: auto;
  }

  .action,
  .secondary,
  .mini,
  .seg button {
    border: 1px solid var(--border);
    border-radius: 6px;
    cursor: pointer;
    font-size: 0.78rem;
  }

  .action {
    background: var(--accent);
    border-color: var(--accent);
    color: var(--accent-fg);
    font-weight: 600;
    padding: 0.35rem 0.9rem;
  }

  .newproj {
    display: flex;
    gap: 0.35rem;
    margin: 0.35rem 0 0.2rem;
  }

  .newproj input {
    flex: 1;
    min-width: 0;
    box-sizing: border-box;
    background: var(--input-bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.3rem 0.45rem;
    color: var(--fg);
    font-size: 0.8rem;
  }

  .action:disabled {
    opacity: 0.5;
    cursor: default;
  }

  .secondary {
    background: var(--btn-bg);
    color: var(--fg);
    padding: 0.35rem 0.7rem;
  }

  .mini {
    background: var(--btn-bg);
    color: var(--fg);
    padding: 0.1rem 0.45rem;
    font-size: 0.72rem;
  }

  .listhead {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-top: 0.5rem;
  }

  .seg {
    display: flex;
  }

  .tools {
    display: flex;
    align-items: center;
    gap: 0.4rem;
  }

  .seg button {
    background: var(--btn-bg);
    color: var(--muted);
    padding: 0.1rem 0.5rem;
    font-size: 0.72rem;
    border-radius: 0;
  }

  .seg button:first-child {
    border-radius: 5px 0 0 5px;
  }

  .seg button:last-child {
    border-radius: 0 5px 5px 0;
    border-left: none;
  }

  .seg button.on {
    color: var(--fg);
    background: var(--active-bg);
    border-color: var(--accent);
  }

  .list {
    flex: 1 1 auto;
    min-height: 0;
    overflow-y: auto;
    display: flex;
    flex-direction: column;
    gap: 0.4rem;
  }

  .note {
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.4rem 0.55rem;
    background: var(--bg);
  }

  .note.current {
    border-color: var(--accent);
  }

  .meta {
    display: flex;
    flex-wrap: wrap;
    gap: 0.4rem;
    align-items: baseline;
  }

  .text {
    white-space: pre-wrap;
    overflow-wrap: anywhere;
    margin: 0.25rem 0;
    user-select: text;
  }

  .acts {
    display: flex;
    gap: 0.3rem;
    justify-content: flex-end;
  }

  .dim {
    color: var(--muted);
  }

  .small {
    font-size: 0.74rem;
  }

  .ok {
    color: #2ea043;
  }

  .error {
    color: var(--error-fg);
  }
</style>
