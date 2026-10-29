<script lang="ts">
  // Export button with a format menu and an "Add to project" list. The caller
  // supplies a function that builds the report from its current results.
  import { tick } from "svelte";
  import {
    addToProject,
    createProject,
    listProjects,
    openProject,
    type ProjectSummary,
  } from "$lib/projects";
  import { exportReport, FORMATS } from "$lib/report/export";
  import type { Report, ReportFormat } from "$lib/report/types";

  interface Props {
    build: () => Report | null;
    /** Default file name stem, such as the domain or target. */
    name: string;
    disabled?: boolean;
  }

  let { build, name, disabled = false }: Props = $props();

  // Projects shown in the menu, most recently updated first.
  const MENU_PROJECTS = 6;

  let open = $state(false);
  let busy = $state(false);
  let message = $state("");
  let failed = $state(false);
  let lastProject = $state<ProjectSummary | null>(null);
  let root = $state<HTMLDivElement | null>(null);
  let anchor = $state<HTMLSpanElement | null>(null);

  let projects = $state<ProjectSummary[]>([]);
  let creating = $state(false);
  let newName = $state("");
  let newInput = $state<HTMLInputElement | null>(null);

  // Open the menu toward whichever side has room.
  let alignRight = $state(false);
  const MENU_WIDTH_PX = 224;

  async function toggle() {
    open = !open;
    creating = false;
    if (open && anchor) {
      const r = anchor.getBoundingClientRect();
      alignRight = r.left + MENU_WIDTH_PX > window.innerWidth - 8;
    }
    if (open) {
      try {
        projects = (await listProjects()).slice(0, MENU_PROJECTS);
      } catch {
        projects = [];
      }
    }
  }

  function buildReport(): Report | null {
    message = "";
    lastProject = null;
    return build();
  }

  async function choose(format: ReportFormat) {
    open = false;
    const r = buildReport();
    if (!r) return;
    busy = true;
    try {
      const path = await exportReport(r, format, name);
      if (path) {
        failed = false;
        message = `Saved ${path.split(/[\\/]/).pop()}`;
      }
    } catch (e) {
      failed = true;
      message = String(e);
    } finally {
      busy = false;
    }
  }

  async function addTo(projectId: string) {
    open = false;
    const r = buildReport();
    if (!r) return;
    busy = true;
    try {
      lastProject = await addToProject(projectId, r);
      failed = false;
      message = `Added to ${lastProject.name} (${lastProject.items} result${lastProject.items === 1 ? "" : "s"})`;
    } catch (e) {
      failed = true;
      message = String(e);
    } finally {
      busy = false;
    }
  }

  async function startNew() {
    creating = true;
    newName = "";
    await tick();
    newInput?.focus();
  }

  async function createAndAdd() {
    try {
      const p = await createProject(newName);
      await addTo(p.id);
    } catch (e) {
      open = false;
      failed = true;
      message = String(e);
    }
  }

  function onNewKey(e: KeyboardEvent) {
    if (e.key === "Enter") void createAndAdd();
    if (e.key === "Escape") creating = false;
  }

  // Close the menu on an outside click or Escape. composedPath() is recorded
  // at dispatch, so a click on a menu item that the click itself removed (such
  // as "New project...") still counts as inside.
  function onWindowClick(e: MouseEvent) {
    if (open && root && !e.composedPath().includes(root)) open = false;
  }
  function onKeydown(e: KeyboardEvent) {
    if (open && !creating && e.key === "Escape") open = false;
  }
</script>

<svelte:window onclick={onWindowClick} onkeydown={onKeydown} />

<div class="export" bind:this={root}>
  <span class="anchor" bind:this={anchor}>
    <button
      class="trigger"
      onclick={toggle}
      disabled={disabled || busy}
      aria-haspopup="menu"
      aria-expanded={open}
    >
      {busy ? "Working..." : "Export"}
    </button>
    {#if open}
      <div class="menu" class:right={alignRight} role="menu">
        <span class="group">Save as</span>
        {#each FORMATS as f (f.id)}
          <button role="menuitem" onclick={() => choose(f.id)}>{f.label}</button>
        {/each}
        <hr />
        <span class="group">Add to project</span>
        {#each projects as p (p.id)}
          <button role="menuitem" class="project" onclick={() => addTo(p.id)} title={p.name}>
            <span class="pname">{p.name}</span>
            <span class="count">{p.items}</span>
          </button>
        {/each}
        {#if creating}
          <div class="new">
            <input
              bind:this={newInput}
              bind:value={newName}
              onkeydown={onNewKey}
              placeholder="Project name"
              maxlength="200"
              spellcheck="false"
            />
            <button class="go" onclick={createAndAdd}>Add</button>
          </div>
        {:else}
          <button role="menuitem" onclick={startNew}>New project...</button>
        {/if}
      </div>
    {/if}
  </span>
  {#if message}
    <span class="msg" class:failed>{message}</span>
    {#if lastProject && !failed}
      <button class="link" onclick={() => lastProject && openProject(lastProject.id)}>Open</button>
    {/if}
  {/if}
</div>

<style>
  .export {
    display: inline-flex;
    align-items: center;
    gap: 0.6rem;
  }

  /* The menu positions against the button, not the message beside it. */
  .anchor {
    position: relative;
    display: inline-flex;
  }

  .trigger {
    background: var(--input-bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    color: var(--fg);
    font-size: 0.78rem;
    padding: 0.3rem 0.8rem;
    cursor: pointer;
  }

  .trigger:hover:not(:disabled) {
    background: var(--hover);
  }

  .trigger:disabled {
    opacity: 0.5;
    cursor: default;
  }

  .menu {
    position: absolute;
    top: calc(100% + 4px);
    left: 0;
    z-index: 10;
    display: flex;
    flex-direction: column;
    width: 14rem;
    max-width: calc(100vw - 16px);
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    box-shadow: 0 4px 14px rgb(0 0 0 / 0.12);
    padding: 0.25rem;
  }

  .menu.right {
    left: auto;
    right: 0;
  }

  .group {
    font-size: 0.68rem;
    color: var(--muted);
    text-transform: uppercase;
    letter-spacing: 0.04em;
    padding: 0.35rem 0.6rem 0.15rem;
  }

  hr {
    border: none;
    border-top: 1px solid var(--border);
    margin: 0.25rem 0;
  }

  .menu button {
    background: none;
    border: none;
    border-radius: 4px;
    color: var(--fg);
    font-size: 0.8rem;
    text-align: left;
    padding: 0.35rem 0.6rem;
    cursor: pointer;
  }

  .menu button:hover {
    background: var(--hover);
  }

  .menu button.project {
    display: flex;
    justify-content: space-between;
    gap: 0.5rem;
  }

  .pname {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .count {
    color: var(--muted);
    font-size: 0.72rem;
  }

  .new {
    display: flex;
    gap: 0.3rem;
    padding: 0.2rem 0.3rem;
  }

  .new input {
    flex: 1 1 auto;
    min-width: 0;
    background: var(--input-bg);
    border: 1px solid var(--border);
    border-radius: 4px;
    color: var(--fg);
    font-size: 0.78rem;
    padding: 0.25rem 0.4rem;
  }

  .new input:focus {
    outline: none;
    border-color: var(--accent);
  }

  .menu .go {
    background: var(--accent);
    color: var(--accent-fg);
    font-weight: 600;
  }

  .menu .go:hover {
    background: var(--accent);
  }

  .msg {
    font-size: 0.75rem;
    color: var(--muted);
  }

  .msg.failed {
    color: var(--error-fg);
  }

  .link {
    background: none;
    border: none;
    padding: 0;
    color: var(--accent);
    font-size: 0.75rem;
    cursor: pointer;
    text-decoration: underline;
  }
</style>
