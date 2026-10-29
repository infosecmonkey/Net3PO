<script lang="ts">
  import { onMount } from "svelte";
  import { confirm, save } from "@tauri-apps/plugin-dialog";
  import {
    createProject,
    deleteProject,
    exportProject,
    getProject,
    listProjects,
    takePendingProject,
    updateProject,
    type ProjectItem,
    type ProjectSummary,
  } from "$lib/projects";
  import { FORMATS, safeName } from "$lib/report/export";
  import type { ReportFormat } from "$lib/report/types";

  let projects = $state<ProjectSummary[]>([]);
  let selectedId = $state<string | null>(null);

  // Editable copy of the selected project.
  let name = $state("");
  let notes = $state("");
  let items = $state<ProjectItem[]>([]);
  let updated = $state(0);

  let newName = $state("");
  let error = $state("");
  let message = $state("");
  let busy = $state(false);

  // Edits are saved after a short pause; structural changes save at once.
  let saveTimer: ReturnType<typeof setTimeout> | undefined;
  let dirty = false;

  onMount(async () => {
    await refreshList();
    const pending = takePendingProject();
    const first = pending ?? projects[0]?.id ?? null;
    if (first) await select(first);
  });

  async function refreshList() {
    try {
      projects = await listProjects();
    } catch (e) {
      error = String(e);
    }
  }

  async function select(id: string) {
    await flush();
    error = "";
    message = "";
    try {
      const v = await getProject(id);
      selectedId = v.id;
      name = v.name;
      notes = v.notes;
      items = v.items;
      updated = v.updated;
    } catch (e) {
      error = String(e);
    }
  }

  async function create() {
    try {
      const p = await createProject(newName);
      newName = "";
      await refreshList();
      await select(p.id);
    } catch (e) {
      error = String(e);
    }
  }

  function scheduleSave() {
    dirty = true;
    clearTimeout(saveTimer);
    saveTimer = setTimeout(flush, 600);
  }

  /** Save pending edits now. */
  async function flush() {
    clearTimeout(saveTimer);
    if (!dirty || !selectedId) return;
    dirty = false;
    try {
      const v = await updateProject(
        selectedId,
        name,
        notes,
        items.map((i) => ({ id: i.id, title: i.title, note: i.note })),
      );
      updated = v.updated;
      await refreshList();
    } catch (e) {
      error = String(e);
    }
  }

  function move(index: number, delta: number) {
    const to = index + delta;
    if (to < 0 || to >= items.length) return;
    const next = [...items];
    [next[index], next[to]] = [next[to], next[index]];
    items = next;
    dirty = true;
    void flush();
  }

  async function remove(item: ProjectItem) {
    const ok = await confirm(`Remove "${item.title}" from this project?`, {
      title: "Remove result",
      kind: "warning",
    });
    if (!ok) return;
    items = items.filter((i) => i.id !== item.id);
    dirty = true;
    await flush();
  }

  async function removeProject() {
    if (!selectedId) return;
    const ok = await confirm(
      `Delete project "${name}" and its ${items.length} saved result${items.length === 1 ? "" : "s"}? This cannot be undone.`,
      { title: "Delete project", kind: "warning" },
    );
    if (!ok) return;
    try {
      clearTimeout(saveTimer);
      dirty = false;
      await deleteProject(selectedId);
      selectedId = null;
      items = [];
      await refreshList();
      if (projects[0]) await select(projects[0].id);
    } catch (e) {
      error = String(e);
    }
  }

  async function exportAs(format: ReportFormat) {
    if (!selectedId) return;
    await flush();
    const f = FORMATS.find((x) => x.id === format)!;
    message = "";
    try {
      const path = await save({
        defaultPath: `${safeName(name)}.${f.ext}`,
        filters: [{ name: f.label, extensions: [f.ext] }],
      });
      if (!path) return;
      busy = true;
      await exportProject(selectedId, format, path);
      message = `Saved ${path.split(/[\\/]/).pop()}`;
    } catch (e) {
      error = String(e);
    } finally {
      busy = false;
    }
  }

  function when(secs: number): string {
    return new Date(secs * 1000).toLocaleString(undefined, {
      dateStyle: "medium",
      timeStyle: "short",
    });
  }
</script>

<div class="panel">
  <header>
    <h1>Projects</h1>
    <p class="sub">
      Collect results from several tools and export them together as one report. Add
      results from any tool with Export, Add to project.
    </p>
  </header>

  {#if error}
    <div class="error mono">{error}</div>
  {/if}

  <div class="layout">
    <aside>
      <div class="new">
        <input
          bind:value={newName}
          placeholder="New project name"
          maxlength="200"
          spellcheck="false"
          onkeydown={(e) => e.key === "Enter" && create()}
        />
        <button class="small primary" onclick={create}>Create</button>
      </div>
      {#if projects.length === 0}
        <p class="hint">No projects yet.</p>
      {/if}
      <ul class="list">
        {#each projects as p (p.id)}
          <li>
            <button class="proj" class:active={p.id === selectedId} onclick={() => select(p.id)}>
              <span class="pname">{p.name}</span>
              <span class="pmeta">{p.items} result{p.items === 1 ? "" : "s"} | {when(p.updated)}</span>
            </button>
          </li>
        {/each}
      </ul>
    </aside>

    <section class="detail">
      {#if selectedId}
        <div class="field">
          <label for="pname">Name</label>
          <input id="pname" bind:value={name} oninput={scheduleSave} onblur={flush} maxlength="200" />
        </div>
        <div class="field">
          <label for="pnotes">Notes</label>
          <textarea
            id="pnotes"
            bind:value={notes}
            oninput={scheduleSave}
            onblur={flush}
            placeholder="Scope, customer, ticket number. Printed in the report overview."
          ></textarea>
        </div>

        <div class="bar">
          <span class="label">Export all</span>
          {#each FORMATS as f (f.id)}
            <button class="small" onclick={() => exportAs(f.id)} disabled={busy || items.length === 0}>{f.label}</button>
          {/each}
          {#if message}<span class="muted">{message}</span>{/if}
          <div class="spacer"></div>
          <button class="small danger" onclick={removeProject}>Delete project</button>
        </div>

        <h2>Results <span class="muted">({items.length})</span></h2>
        {#if items.length === 0}
          <p class="hint">
            No results yet. Run a tool, then use Export, Add to project. Config Diff, DNS
            Analyzer, Port Scanner and SNMP Sweep support it today.
          </p>
        {/if}
        <ol class="items">
          {#each items as item, i (item.id)}
            <li class="item">
              <div class="item-head">
                <span class="num">{i + 1}.</span>
                <input
                  class="title"
                  bind:value={item.title}
                  oninput={scheduleSave}
                  onblur={flush}
                  maxlength="200"
                  aria-label="Result title"
                />
                <div class="item-actions">
                  <button class="icon" onclick={() => move(i, -1)} disabled={i === 0} title="Move up" aria-label="Move up">&#8593;</button>
                  <button class="icon" onclick={() => move(i, 1)} disabled={i === items.length - 1} title="Move down" aria-label="Move down">&#8595;</button>
                  <button class="icon" onclick={() => remove(item)} title="Remove" aria-label="Remove result">x</button>
                </div>
              </div>
              <div class="item-meta muted">
                {item.tool} | {item.addedLabel || when(item.added)} | {item.sections.join(", ")}
              </div>
              <textarea
                class="note"
                bind:value={item.note}
                oninput={scheduleSave}
                onblur={flush}
                placeholder="Note for this result (optional)"
                rows="1"
              ></textarea>
            </li>
          {/each}
        </ol>
        <p class="hint">Last saved {when(updated)}.</p>
      {:else if projects.length > 0}
        <p class="hint">Select a project.</p>
      {:else}
        <p class="hint">Create a project, then add results to it from any tool's Export menu.</p>
      {/if}
    </section>
  </div>
</div>

<style>
  .panel {
    padding: 1.5rem 2rem;
    max-width: 1100px;
  }

  header h1 {
    margin: 0 0 0.25rem;
    font-size: 1.3rem;
  }

  .sub {
    margin: 0 0 1.25rem;
    color: var(--muted);
    font-size: 0.85rem;
  }

  .layout {
    display: grid;
    grid-template-columns: 16rem 1fr;
    gap: 1.5rem;
    align-items: start;
  }

  input,
  textarea {
    box-sizing: border-box;
    width: 100%;
    background: var(--input-bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    color: var(--fg);
    font-size: 0.85rem;
    padding: 0.4rem 0.55rem;
    font-family: inherit;
  }

  input:focus,
  textarea:focus {
    outline: none;
    border-color: var(--accent);
  }

  textarea {
    resize: vertical;
    min-height: 3.5rem;
  }

  .new {
    display: flex;
    gap: 0.4rem;
    margin-bottom: 0.75rem;
  }

  .list {
    list-style: none;
    margin: 0;
    padding: 0;
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
  }

  .proj {
    width: 100%;
    display: flex;
    flex-direction: column;
    align-items: flex-start;
    gap: 0.1rem;
    background: none;
    border: 1px solid transparent;
    border-radius: 6px;
    padding: 0.45rem 0.6rem;
    color: var(--fg);
    cursor: pointer;
    text-align: left;
  }

  .proj:hover {
    background: var(--hover);
  }

  .proj.active {
    background: var(--active-bg);
    border-color: var(--accent);
  }

  .pname {
    font-size: 0.85rem;
    font-weight: 600;
    overflow: hidden;
    text-overflow: ellipsis;
    max-width: 100%;
    white-space: nowrap;
  }

  .pmeta {
    font-size: 0.72rem;
    color: var(--muted);
  }

  .field {
    margin-bottom: 0.8rem;
  }

  label,
  .label {
    display: block;
    font-size: 0.8rem;
    color: var(--muted);
    margin-bottom: 0.3rem;
  }

  .bar {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 0.4rem;
    margin: 0.4rem 0 1.25rem;
  }

  .bar .label {
    margin: 0 0.3rem 0 0;
  }

  .spacer {
    flex: 1 1 auto;
  }

  button.small,
  button.icon {
    background: var(--input-bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    color: var(--fg);
    font-size: 0.78rem;
    padding: 0.3rem 0.7rem;
    cursor: pointer;
    white-space: nowrap;
  }

  button.small:hover:not(:disabled),
  button.icon:hover:not(:disabled) {
    background: var(--hover);
  }

  button:disabled {
    opacity: 0.45;
    cursor: default;
  }

  button.primary {
    background: var(--accent);
    border-color: var(--accent);
    color: var(--accent-fg);
    font-weight: 600;
  }

  button.primary:hover:not(:disabled) {
    background: var(--accent);
  }

  button.danger {
    color: var(--error-fg);
    border-color: var(--error-border);
  }

  button.icon {
    width: 1.9rem;
    padding: 0.25rem 0;
  }

  h2 {
    font-size: 1rem;
    margin: 0 0 0.6rem;
  }

  .items {
    list-style: none;
    margin: 0;
    padding: 0;
    display: flex;
    flex-direction: column;
    gap: 0.6rem;
  }

  .item {
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.6rem 0.7rem;
  }

  .item-head {
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }

  .num {
    color: var(--muted);
    font-size: 0.85rem;
    min-width: 1.5rem;
  }

  .title {
    flex: 1 1 auto;
    font-weight: 600;
  }

  .item-actions {
    display: flex;
    gap: 0.25rem;
  }

  .item-meta {
    margin: 0.35rem 0 0.4rem 2rem;
    font-size: 0.74rem;
  }

  .note {
    margin-left: 2rem;
    width: calc(100% - 2rem);
    min-height: 2rem;
    font-size: 0.8rem;
  }

  .muted {
    color: var(--muted);
    font-size: 0.8rem;
  }

  .hint {
    font-size: 0.78rem;
    color: var(--muted);
  }

  .error {
    background: var(--error-bg);
    border: 1px solid var(--error-border);
    color: var(--error-fg);
    border-radius: 6px;
    padding: 0.6rem 0.8rem;
    font-size: 0.82rem;
    margin-bottom: 0.9rem;
    white-space: pre-wrap;
  }

  .mono {
    font-family: var(--mono);
  }
</style>
