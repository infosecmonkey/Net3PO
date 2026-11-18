<script lang="ts">
  // Update dialog: result of a check, release notes, and install progress.
  import { onMount } from "svelte";
  import { openUrl } from "@tauri-apps/plugin-opener";
  import { checkForUpdates, closeUpdates, installUpdate, RELEASES_URL, updates } from "$lib/updater.svelte";

  onMount(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && closeUpdates();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  });

  const mb = (n: number) => `${(n / 1024 / 1024).toFixed(1)} MB`;
</script>

<div class="backdrop" role="presentation" onclick={(e) => e.target === e.currentTarget && closeUpdates()}>
  <div class="dialog" role="dialog" aria-modal="true" aria-label="Software update">
    <h2>Software update</h2>

    {#if updates.status === "checking"}
      <p class="muted">Checking GitHub for a newer release...</p>
    {:else if updates.status === "current"}
      <p>You have the latest version.</p>
      <div class="btns"><button class="action" onclick={closeUpdates}>Close</button></div>
    {:else if updates.status === "available"}
      <p>
        <strong>Net3PO {updates.version}</strong> is available{updates.date ? ` (released ${updates.date})` : ""}. You have
        {updates.current}.
      </p>
      {#if updates.notes}<pre class="notes">{updates.notes}</pre>{/if}
      {#if updates.kind === "package"}
        <p class="muted">
          This copy was installed from a .deb or .rpm package, so your package manager has to install the new version.
          Download it from the release page.
        </p>
        <div class="btns">
          <button class="secondary" onclick={closeUpdates}>Later</button>
          <button class="action" onclick={() => void openUrl(RELEASES_URL)}>Open release page</button>
        </div>
      {:else}
        <p class="muted">The download is checked against Net3PO's signing key before it is installed. The app restarts afterwards.</p>
        <div class="btns">
          <button class="secondary" onclick={closeUpdates}>Later</button>
          <button class="action" onclick={installUpdate}>Install and restart</button>
        </div>
      {/if}
    {:else if updates.status === "installing"}
      <p>Downloading Net3PO {updates.version}...</p>
      <div class="bar"><div class="fill" style="width: {updates.total ? Math.min(100, (100 * updates.downloaded) / updates.total) : 5}%"></div></div>
      <p class="muted">{mb(updates.downloaded)}{updates.total ? ` of ${mb(updates.total)}` : ""}. Keep the app open; it restarts when the update is installed.</p>
    {:else if updates.status === "error"}
      <p class="error">The update could not be completed: {updates.error}</p>
      <p class="muted">You can also download the latest version from the release page.</p>
      <div class="btns">
        <button class="secondary" onclick={() => void openUrl(RELEASES_URL)}>Open release page</button>
        <button class="secondary" onclick={() => void checkForUpdates(true)}>Try again</button>
        <button class="action" onclick={closeUpdates}>Close</button>
      </div>
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
    z-index: 110;
  }

  .dialog {
    background: var(--bg);
    color: var(--fg);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 1.2rem 1.4rem;
    width: min(34rem, calc(100vw - 2rem));
    max-height: calc(100vh - 2rem);
    overflow-y: auto;
    box-shadow: 0 10px 30px rgb(0 0 0 / 0.3);
    font-size: 0.88rem;
  }

  h2 {
    margin: 0 0 0.6rem;
    font-size: 1.05rem;
  }

  .muted {
    color: var(--muted);
    font-size: 0.8rem;
  }

  .error {
    color: var(--error-fg);
    overflow-wrap: anywhere;
  }

  .notes {
    background: var(--input-bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.5rem 0.6rem;
    font-family: inherit;
    font-size: 0.78rem;
    white-space: pre-wrap;
    overflow-wrap: anywhere;
    max-height: 14rem;
    overflow: auto;
  }

  .bar {
    height: 6px;
    background: var(--input-bg);
    border: 1px solid var(--border);
    border-radius: 3px;
    overflow: hidden;
  }

  .fill {
    height: 100%;
    background: var(--accent);
  }

  .btns {
    display: flex;
    justify-content: flex-end;
    gap: 0.5rem;
    margin-top: 0.9rem;
    flex-wrap: wrap;
  }

  button {
    border-radius: 6px;
    font-size: 0.82rem;
    padding: 0.4rem 0.9rem;
    cursor: pointer;
  }

  .secondary {
    background: var(--input-bg);
    border: 1px solid var(--border);
    color: var(--fg);
  }

  .action {
    background: var(--accent);
    border: 1px solid var(--accent);
    color: var(--accent-fg);
    font-weight: 600;
  }
</style>
