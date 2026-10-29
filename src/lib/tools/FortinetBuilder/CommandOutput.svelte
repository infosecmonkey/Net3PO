<script lang="ts">
  // Generated command with Copy, Save .txt, and Save for later. Shared by
  // every builder tab.
  import { invoke } from "@tauri-apps/api/core";
  import { save } from "@tauri-apps/plugin-dialog";
  import type { BuildError, FortinetCategory } from "$lib/tools/types";

  interface Props {
    category: FortinetCategory;
    defaultTitle: string;
    command: string;
    error: BuildError | null;
    onsave: (title: string, notes: string) => void;
  }
  let { category, defaultTitle, command, error, onsave }: Props = $props();

  let copied = $state(false);
  let saving = $state(false);
  let title = $state("");
  let notes = $state("");
  let message = $state("");

  async function copy() {
    try {
      await navigator.clipboard.writeText(command);
      copied = true;
      setTimeout(() => (copied = false), 1500);
    } catch (e) {
      message = `Copy failed: ${e}`;
    }
  }

  async function saveFile() {
    try {
      const path = await save({
        defaultPath: `fortigate-${category}.txt`,
        filters: [{ name: "Text", extensions: ["txt"] }],
      });
      if (typeof path !== "string") return;
      await invoke("fortinet_save_text", { path, contents: command + "\n" });
      message = "Saved.";
    } catch (e) {
      message = String(e);
    }
  }

  function startSave() {
    title = defaultTitle;
    notes = "";
    saving = true;
  }

  function commitSave() {
    if (title.trim().length === 0) return;
    onsave(title.trim(), notes.trim());
    saving = false;
    message = "Saved to Saved commands.";
    setTimeout(() => (message = ""), 2000);
  }
</script>

<div class="out">
  <div class="outhead">
    <span class="outtitle">Command</span>
    <div class="btns">
      <button class="secondary" onclick={copy} disabled={!command || !!error}>{copied ? "Copied" : "Copy"}</button>
      <button class="secondary" onclick={saveFile} disabled={!command || !!error}>Save .txt</button>
      <button class="secondary" onclick={startSave} disabled={!command || !!error}>Save for later</button>
    </div>
  </div>
  {#if error}
    <div class="error mono">{error.message}</div>
  {:else}
    <pre class="code mono">{command}</pre>
  {/if}
  {#if saving}
    <div class="savebox">
      <div class="field">
        <label for="sv-title">Title</label>
        <input id="sv-title" bind:value={title} onkeydown={(e) => e.key === "Enter" && commitSave()} />
      </div>
      <div class="field">
        <label for="sv-notes">Notes (optional)</label>
        <textarea id="sv-notes" rows="2" bind:value={notes}></textarea>
      </div>
      <div class="btns">
        <button class="action" onclick={commitSave} disabled={title.trim().length === 0}>Save</button>
        <button class="secondary" onclick={() => (saving = false)}>Cancel</button>
      </div>
    </div>
  {/if}
  {#if message}<p class="msg muted">{message}</p>{/if}
</div>

<style>
  .out {
    margin-top: 1rem;
  }

  .outhead {
    display: flex;
    flex-wrap: wrap;
    justify-content: space-between;
    align-items: center;
    gap: 0.6rem;
    margin-bottom: 0.4rem;
  }

  .outtitle {
    font-weight: 600;
    font-size: 0.9rem;
  }

  .btns {
    display: flex;
    flex-wrap: wrap;
    gap: 0.5rem;
  }

  .code {
    margin: 0;
    padding: 0.7rem 0.8rem;
    background: var(--sidebar-bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    font-size: 0.82rem;
    white-space: pre-wrap;
    word-break: break-word;
    user-select: text;
  }

  .savebox {
    margin-top: 0.7rem;
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.7rem;
    display: flex;
    flex-direction: column;
    gap: 0.6rem;
  }

  textarea {
    resize: vertical;
    font-family: inherit;
  }

  .msg {
    font-size: 0.8rem;
    margin: 0.4rem 0 0;
  }
</style>
