<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import { save } from "@tauri-apps/plugin-dialog";
  import type { SavedCommand } from "$lib/tools/types";

  interface Props {
    items: SavedCommand[];
    onchange: (items: SavedCommand[]) => void;
  }
  let { items, onchange }: Props = $props();

  let search = $state("");
  let editing = $state<string | null>(null);
  let editTitle = $state("");
  let editNotes = $state("");
  let confirmAll = $state(false);
  let copiedId = $state<string | null>(null);
  let message = $state("");

  const shown = $derived.by(() => {
    const q = search.trim().toLowerCase();
    if (!q) return items;
    return items.filter((c) =>
      [c.title, c.notes, c.command, c.category].some((f) => f.toLowerCase().includes(q)),
    );
  });

  function fmtDate(iso: string): string {
    const d = new Date(iso);
    return Number.isNaN(d.getTime()) ? "" : d.toLocaleString();
  }

  async function copy(c: SavedCommand) {
    await navigator.clipboard.writeText(c.command);
    copiedId = c.id;
    setTimeout(() => (copiedId = null), 1500);
  }

  function startEdit(c: SavedCommand) {
    editing = c.id;
    editTitle = c.title;
    editNotes = c.notes;
  }

  function commitEdit() {
    if (!editing || editTitle.trim().length === 0) return;
    onchange(items.map((c) => (c.id === editing ? { ...c, title: editTitle.trim(), notes: editNotes.trim() } : c)));
    editing = null;
  }

  function remove(id: string) {
    onchange(items.filter((c) => c.id !== id));
  }

  function removeAll() {
    if (!confirmAll) {
      confirmAll = true;
      setTimeout(() => (confirmAll = false), 3000);
      return;
    }
    onchange([]);
    confirmAll = false;
  }

  /** Plain-text export: each command under a comment header. */
  function asText(list: SavedCommand[]): string {
    return list
      .map((c) => {
        const head = [`# ${c.title} (${c.category})`];
        if (c.notes) head.push(...c.notes.split("\n").map((l) => `# ${l}`));
        return `${head.join("\n")}\n${c.command}\n`;
      })
      .join("\n");
  }

  async function exportText(list: SavedCommand[], name: string) {
    try {
      const path = await save({ defaultPath: name, filters: [{ name: "Text", extensions: ["txt"] }] });
      if (typeof path !== "string") return;
      await invoke("fortinet_save_text", { path, contents: asText(list) });
      message = `Exported ${list.length} command${list.length === 1 ? "" : "s"}.`;
    } catch (e) {
      message = String(e);
    }
  }
</script>

<p class="help">Commands saved with Save for later. Stored on this machine only.</p>

<div class="row">
  <input class="search" bind:value={search} placeholder="Search title, notes, or command" spellcheck="false" />
  <button class="secondary" onclick={() => exportText(shown, "fortigate-commands.txt")} disabled={shown.length === 0}>Export shown</button>
  <button class="secondary danger" onclick={removeAll} disabled={items.length === 0}>{confirmAll ? "Click again to delete all" : "Delete all"}</button>
</div>
{#if message}<p class="muted note">{message}</p>{/if}

{#if items.length === 0}
  <p class="muted">Nothing saved yet. Build a command and click Save for later.</p>
{:else if shown.length === 0}
  <p class="muted">No saved commands match.</p>
{/if}

<div class="list">
  {#each shown as c (c.id)}
    <div class="item">
      {#if editing === c.id}
        <div class="field"><label for="e-title-{c.id}">Title</label><input id="e-title-{c.id}" bind:value={editTitle} /></div>
        <div class="field"><label for="e-notes-{c.id}">Notes</label><textarea id="e-notes-{c.id}" rows="2" bind:value={editNotes}></textarea></div>
        <div class="btns">
          <button class="action sm" onclick={commitEdit} disabled={editTitle.trim().length === 0}>Save</button>
          <button class="secondary sm" onclick={() => (editing = null)}>Cancel</button>
        </div>
      {:else}
        <div class="ihead">
          <div>
            <span class="ititle">{c.title}</span>
            <span class="tag">{c.category}</span>
            <span class="muted date">{fmtDate(c.createdAt)}</span>
          </div>
          <div class="btns">
            <button class="secondary sm" onclick={() => copy(c)}>{copiedId === c.id ? "Copied" : "Copy"}</button>
            <button class="secondary sm" onclick={() => exportText([c], `${c.category}.txt`)}>Export</button>
            <button class="secondary sm" onclick={() => startEdit(c)}>Edit</button>
            <button class="secondary sm danger" onclick={() => remove(c.id)}>Delete</button>
          </div>
        </div>
        {#if c.notes}<p class="notes">{c.notes}</p>{/if}
      {/if}
      <pre class="code mono">{c.command}</pre>
    </div>
  {/each}
</div>

<style>
  .row {
    display: flex;
    flex-wrap: wrap;
    gap: 0.6rem;
    align-items: center;
    margin-bottom: 0.8rem;
  }

  .search {
    flex: 1 1 240px;
    width: auto;
  }

  .list {
    display: flex;
    flex-direction: column;
    gap: 0.7rem;
  }

  .item {
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 0.7rem 0.8rem;
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }

  .ihead {
    display: flex;
    flex-wrap: wrap;
    justify-content: space-between;
    gap: 0.5rem;
    align-items: center;
  }

  .ititle {
    font-weight: 600;
    font-size: 0.88rem;
    word-break: break-word;
  }

  .tag {
    margin-left: 0.4rem;
    font-size: 0.7rem;
    color: var(--muted);
    border: 1px solid var(--border);
    border-radius: 3px;
    padding: 0 0.3rem;
  }

  .date {
    margin-left: 0.4rem;
    font-size: 0.74rem;
  }

  .btns {
    display: flex;
    flex-wrap: wrap;
    gap: 0.4rem;
  }

  .notes {
    margin: 0;
    font-size: 0.82rem;
    white-space: pre-wrap;
    color: var(--muted);
  }

  .code {
    margin: 0;
    padding: 0.55rem 0.7rem;
    background: var(--sidebar-bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    font-size: 0.8rem;
    white-space: pre-wrap;
    word-break: break-word;
  }

  .danger {
    color: var(--error-fg);
  }

  textarea {
    resize: vertical;
    font-family: inherit;
  }
</style>
