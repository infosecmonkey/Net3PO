<script lang="ts">
  import type { Component } from "svelte";
  import Sidebar from "$lib/components/Sidebar.svelte";
  import SessionBar from "$lib/components/SessionBar.svelte";
  import TerminalDrawer from "$lib/components/TerminalDrawer.svelte";
  import NotesPanel from "$lib/components/NotesPanel.svelte";
  import HelpPanel from "$lib/components/HelpPanel.svelte";
  import { help, toggleHelp } from "$lib/help/help.svelte";
  import { notes, setNotesOpen } from "$lib/notes.svelte";
  import { ssh } from "$lib/ssh/sessions.svelte";
  import { findTool } from "$lib/tools/registry";
  import { nav } from "$lib/nav.svelte";
  import { loadSettings } from "$lib/settings.svelte";
  // Settings decide which remote tools show; detection runs once at launch.
  void loadSettings();

  let ToolComponent = $state<Component | null>(null);
  let loading = $state(false);

  // The SSH tool shows its own tabs and terminal; elsewhere, open sessions get
  // a bar on top and an optional docked terminal.
  const onSsh = $derived(nav.selected === "ssh");
  const showBar = $derived(!onSsh && ssh.tabs.length > 0);
  const showDrawer = $derived(showBar && ssh.drawer && ssh.active !== null);

  // Cmd/Ctrl+Shift+N toggles the notes pop-out from any tool; F1 toggles
  // help for the open tool; Esc closes help when nothing else wants it.
  function onKey(e: KeyboardEvent) {
    if (e.key === "F1") {
      e.preventDefault();
      toggleHelp(nav.selected);
      return;
    }
    if (e.key === "Escape" && help.open && !e.defaultPrevented && !document.querySelector('[aria-modal="true"]')) {
      help.open = false;
      return;
    }
    if ((e.metaKey || e.ctrlKey) && e.shiftKey && e.key.toLowerCase() === "n") {
      e.preventDefault();
      setNotesOpen(!notes.open);
    }
  }

  // Load the selected tool's panel whenever the selection changes.
  $effect(() => {
    const tool = findTool(nav.selected);
    if (!tool?.load) {
      ToolComponent = null;
      return;
    }
    loading = true;
    tool
      .load()
      .then((m) => {
        ToolComponent = m.default;
      })
      .finally(() => {
        loading = false;
      });
  });
</script>

<svelte:window onkeydown={onKey} />

<div class="app">
  <Sidebar selected={nav.selected} onselect={(id) => (nav.selected = id)} />
  <div class="main-col">
    {#if showBar}<SessionBar />{/if}
    <main class="content">
      {#if loading}
        <div class="placeholder">Loading...</div>
      {:else if ToolComponent}
        <ToolComponent />
      {:else}
        <div class="placeholder">Select a tool.</div>
      {/if}
    </main>
    {#if showDrawer}<TerminalDrawer />{/if}
  </div>
  {#if help.open}<HelpPanel />{/if}
  {#if notes.open}<NotesPanel />{/if}
</div>

<style>
  :global(:root) {
    --mono: "SF Mono", "Cascadia Code", ui-monospace, "Menlo", monospace;

    /* Light theme */
    --bg: #ffffff;
    --fg: #1a1a1a;
    --muted: #6b7280;
    --border: #e2e5e9;
    --sidebar-bg: #f6f7f9;
    --hover: #eceef1;
    --active-bg: #ffedd5;
    /* Orange accent. Light: deep orange, white text on fills (5.2:1). */
    --accent: #c2410c;
    --accent-fg: #ffffff;
    --input-bg: #ffffff;
    --btn-bg: #f3f4f6;
    --error-bg: #fef2f2;
    --error-border: #fca5a5;
    --error-fg: #b91c1c;
    /* Diff rows: soft fill per line, stronger fill for changed words. */
    --diff-add-bg: #e9f7ee;
    --diff-add-strong: #b6e6c6;
    --diff-del-bg: #fdecec;
    --diff-del-strong: #f7c1c1;
    --diff-add-fg: #15803d;
    --diff-del-fg: #b91c1c;
  }

  @media (prefers-color-scheme: dark) {
    :global(:root) {
      --bg: #1b1d21;
      --fg: #e6e8eb;
      --muted: #8b9199;
      --border: #313540;
      --sidebar-bg: #16181c;
      --hover: #22252b;
      --active-bg: #3a2414;
      /* Dark: brighter orange for links on the dark surface (7.5:1); text on
         orange fills is dark (7.5:1), since no orange passes with white here. */
      --accent: #fb923c;
      --accent-fg: #1b1d21;
      --input-bg: #212429;
      --btn-bg: #2a2e35;
      --error-bg: #2a1718;
      --error-border: #7f3034;
      --error-fg: #f6a8a8;
      --diff-add-bg: #16291e;
      --diff-add-strong: #22573a;
      --diff-del-bg: #2e1819;
      --diff-del-strong: #6b2a2d;
      --diff-add-fg: #4ade80;
      --diff-del-fg: #f87171;
    }
  }

  /* Native controls (scrollbars, number spinners, date pickers) follow the
     app theme instead of the OS default. */
  :global(:root) {
    color-scheme: light dark;
  }

  /* WebKitGTK (Linux) draws <select> with the GTK theme and ignores the
     panel's background, so light text landed on a white box. Drop the native
     look everywhere and draw our own chevron. Panels set the background and
     padding shorthands, hence !important on the parts this rule owns. */
  :global(select) {
    appearance: none;
    -webkit-appearance: none;
    background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 12 12'%3E%3Cpath d='M2.5 4.5 6 8l3.5-3.5' fill='none' stroke='%23888' stroke-width='1.5' stroke-linecap='round' stroke-linejoin='round'/%3E%3C/svg%3E") !important;
    background-repeat: no-repeat !important;
    background-position: right 0.5rem center !important;
    background-size: 0.75rem !important;
    padding-right: 1.7rem !important;
  }

  :global(select[multiple]),
  :global(select[size]:not([size="1"])) {
    background-image: none !important;
    padding-right: 0.5rem !important;
  }

  :global(option),
  :global(optgroup) {
    background-color: var(--input-bg);
    color: var(--fg);
  }

  :global(body) {
    margin: 0;
    background: var(--bg);
    color: var(--fg);
    font-family: Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  }

  .app {
    display: flex;
    height: 100vh;
    overflow: hidden;
  }

  .main-col {
    flex: 1 1 auto;
    min-width: 0;
    display: flex;
    flex-direction: column;
    height: 100vh;
  }

  .content {
    flex: 1 1 auto;
    min-height: 0;
    overflow-y: auto;
  }

  .placeholder {
    padding: 2rem;
    color: var(--muted);
  }
</style>
