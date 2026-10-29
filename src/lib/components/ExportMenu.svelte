<script lang="ts">
  // Export button with a format menu. The caller supplies a function that
  // builds the report from its current results.
  import { exportReport, FORMATS } from "$lib/report/export";
  import type { Report, ReportFormat } from "$lib/report/types";

  interface Props {
    build: () => Report | null;
    /** Default file name stem, such as the domain or target. */
    name: string;
    disabled?: boolean;
  }

  let { build, name, disabled = false }: Props = $props();

  let open = $state(false);
  let busy = $state(false);
  let message = $state("");
  let failed = $state(false);
  let root = $state<HTMLDivElement | null>(null);

  async function choose(format: ReportFormat) {
    open = false;
    const report = build();
    if (!report) return;
    busy = true;
    message = "";
    try {
      const path = await exportReport(report, format, name);
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

  // Close the menu on an outside click or Escape.
  function onWindowClick(e: MouseEvent) {
    if (open && root && !root.contains(e.target as Node)) open = false;
  }
  function onKeydown(e: KeyboardEvent) {
    if (open && e.key === "Escape") open = false;
  }
</script>

<svelte:window onclick={onWindowClick} onkeydown={onKeydown} />

<div class="export" bind:this={root}>
  <button
    class="trigger"
    onclick={() => (open = !open)}
    disabled={disabled || busy}
    aria-haspopup="menu"
    aria-expanded={open}
  >
    {busy ? "Exporting..." : "Export"}
  </button>
  {#if open}
    <div class="menu" role="menu">
      {#each FORMATS as f (f.id)}
        <button role="menuitem" onclick={() => choose(f.id)}>{f.label}</button>
      {/each}
    </div>
  {/if}
  {#if message}
    <span class="msg" class:failed>{message}</span>
  {/if}
</div>

<style>
  .export {
    position: relative;
    display: inline-flex;
    align-items: center;
    gap: 0.6rem;
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
    min-width: 9rem;
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    box-shadow: 0 4px 14px rgb(0 0 0 / 0.12);
    padding: 0.25rem;
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

  .msg {
    font-size: 0.75rem;
    color: var(--muted);
  }

  .msg.failed {
    color: var(--error-fg);
  }
</style>
