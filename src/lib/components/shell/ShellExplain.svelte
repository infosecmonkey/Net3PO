<script lang="ts">
  // Explain a shell command line in place. Parsing happens in the backend;
  // the command is never run.
  import { invoke } from "@tauri-apps/api/core";
  import ExplainView from "./ExplainView.svelte";
  import type { Explanation } from "./types";

  let { text }: { text: string } = $props();
  let ex = $state<Explanation | null>(null);
  let error = $state("");
  let busy = $state(false);

  $effect(() => {
    const t = text;
    let stale = false;
    busy = true;
    error = "";
    invoke<Explanation>("shell_explain", { text: t })
      .then((r) => {
        if (!stale) ex = r;
      })
      .catch((e) => {
        if (!stale) error = String(e);
      })
      .finally(() => {
        if (!stale) busy = false;
      });
    return () => {
      stale = true;
    };
  });
</script>

<div class="shell-explain">
  <div class="cap">
    <strong>Explanation</strong>
    <span class="muted">Bash and POSIX shell syntax. Built-in descriptions first, then man pages on this computer. Nothing is run.</span>
  </div>
  {#if error}
    <p class="error">{error}</p>
  {:else if ex}
    <ExplainView {ex} />
  {:else if busy}
    <p class="muted">Explaining...</p>
  {/if}
</div>

<style>
  .shell-explain {
    margin-top: 0.6rem;
    padding: 0.6rem 0.7rem;
    border: 1px solid var(--border);
    border-radius: 6px;
  }

  .cap {
    display: flex;
    align-items: baseline;
    flex-wrap: wrap;
    gap: 0.5rem;
    font-size: 0.84rem;
    margin-bottom: 0.5rem;
  }

  .muted {
    color: var(--muted);
    font-size: 0.74rem;
  }

  .error {
    color: var(--error-fg);
    font-size: 0.8rem;
  }
</style>
