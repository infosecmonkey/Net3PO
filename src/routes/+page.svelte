<script lang="ts">
  import type { Component } from "svelte";
  import Sidebar from "$lib/components/Sidebar.svelte";
  import { findTool } from "$lib/tools/registry";
  import { nav } from "$lib/nav.svelte";
  let ToolComponent = $state<Component | null>(null);
  let loading = $state(false);

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

<div class="app">
  <Sidebar selected={nav.selected} onselect={(id) => (nav.selected = id)} />
  <main class="content">
    {#if loading}
      <div class="placeholder">Loading...</div>
    {:else if ToolComponent}
      <ToolComponent />
    {:else}
      <div class="placeholder">Select a tool.</div>
    {/if}
  </main>
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
    }
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

  .content {
    flex: 1 1 auto;
    min-width: 0;
    overflow-y: auto;
    height: 100vh;
  }

  .placeholder {
    padding: 2rem;
    color: var(--muted);
  }
</style>
