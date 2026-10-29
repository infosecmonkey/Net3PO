<script lang="ts">
  // About dialog: version, license, and the third-party notices that ship
  // with the app (static/third-party-notices.txt, from `pnpm notices`).
  import { onMount } from "svelte";
  import { getVersion } from "@tauri-apps/api/app";
  import { openUrl } from "@tauri-apps/plugin-opener";

  interface Props {
    onclose: () => void;
  }
  let { onclose }: Props = $props();

  const REPO = "https://github.com/infosecmonkey/Net3PO";

  let version = $state("");
  let notices = $state<string | null>(null);
  let noticesError = $state("");

  onMount(() => {
    getVersion()
      .then((v) => (version = v))
      .catch(() => {});
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onclose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  });

  async function showNotices() {
    try {
      const res = await fetch("/third-party-notices.txt");
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      notices = await res.text();
    } catch (e) {
      noticesError = `Could not load the notices: ${e}`;
    }
  }
</script>

<div class="backdrop" role="presentation" onclick={(e) => e.target === e.currentTarget && onclose()}>
  <div class="dialog" class:wide={notices !== null} role="dialog" aria-modal="true" aria-label="About Net3PO">
    {#if notices === null}
      <h2>Net3PO</h2>
      <p class="muted">{version ? `Version ${version}` : ""}</p>
      <p>Network and security engineering toolkit.</p>
      <p>
        Copyright 2026 InfoSecOps, Inc.<br />
        Licensed under the Apache License, Version 2.0. Provided "as is", without
        warranties or conditions of any kind.
      </p>
      <p>No telemetry. Settings and history stay on this computer.</p>
      {#if noticesError}<p class="error">{noticesError}</p>{/if}
      <div class="btns">
        <button class="secondary" onclick={() => void openUrl(REPO)}>Source code</button>
        <button class="secondary" onclick={showNotices}>Third-party notices</button>
        <button class="action" onclick={onclose}>Close</button>
      </div>
    {:else}
      <div class="head">
        <h2>Third-party notices</h2>
        <button class="secondary" onclick={() => (notices = null)}>Back</button>
      </div>
      <pre class="notices">{notices}</pre>
    {/if}
  </div>
</div>

<style>
  .backdrop {
    position: fixed;
    inset: 0;
    background: rgba(0, 0, 0, 0.45);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 100;
  }

  .dialog {
    background: var(--bg);
    color: var(--fg);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 1.2rem 1.4rem;
    width: min(28rem, calc(100vw - 2rem));
    max-height: calc(100vh - 2rem);
    box-sizing: border-box;
    display: flex;
    flex-direction: column;
    font-size: 0.85rem;
  }

  .dialog.wide {
    width: min(52rem, calc(100vw - 2rem));
    height: calc(100vh - 4rem);
  }

  h2 {
    margin: 0;
    font-size: 1.1rem;
  }

  p {
    margin: 0.5rem 0 0;
    line-height: 1.45;
  }

  .muted {
    color: var(--muted);
    margin-top: 0.15rem;
  }

  .error {
    color: var(--error-fg);
  }

  .btns {
    display: flex;
    justify-content: flex-end;
    gap: 0.5rem;
    margin-top: 1.1rem;
  }

  .head {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 0.6rem;
  }

  .notices {
    flex: 1 1 auto;
    min-height: 0;
    overflow: auto;
    margin: 0;
    padding: 0.7rem;
    background: var(--sidebar-bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    font-family: var(--mono);
    font-size: 0.72rem;
    white-space: pre-wrap;
    user-select: text;
  }

  button {
    font-size: 0.8rem;
    border-radius: 6px;
    padding: 0.35rem 0.8rem;
    cursor: pointer;
    border: 1px solid var(--border);
  }

  .secondary {
    background: var(--btn-bg);
    color: var(--fg);
  }

  .action {
    background: var(--accent);
    color: var(--accent-fg);
    border-color: var(--accent);
  }
</style>
