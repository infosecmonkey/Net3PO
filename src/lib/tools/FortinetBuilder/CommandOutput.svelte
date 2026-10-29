<script lang="ts">
  // Generated command with Copy, Save .txt, and Save for later. Shared by
  // every builder tab.
  import { invoke } from "@tauri-apps/api/core";
  import { save } from "@tauri-apps/plugin-dialog";
  import { openTabs, sendTo, type SessionTab } from "$lib/ssh/sessions.svelte";
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

  // Open SSH sessions, active first. With more than one, Send asks which.
  let targets = $derived(openTabs());
  let picking = $state(false);
  let pickerEl = $state<HTMLDivElement | null>(null);

  function onSendClick() {
    if (targets.length === 1) void send(targets[0]);
    else picking = !picking;
  }

  async function send(t: SessionTab) {
    picking = false;
    try {
      const ok = await sendTo(t.key, command);
      message = ok ? `Sent to ${t.title}.` : "That session is closed.";
      setTimeout(() => (message = ""), 2500);
    } catch (e) {
      message = `Send failed: ${e}`;
    }
  }

  // Close the session list on an outside click or Escape.
  $effect(() => {
    if (!picking) return;
    const onDown = (e: PointerEvent) => {
      if (pickerEl && !e.composedPath().includes(pickerEl)) picking = false;
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") picking = false;
    };
    window.addEventListener("pointerdown", onDown);
    window.addEventListener("keydown", onKey);
    return () => {
      window.removeEventListener("pointerdown", onDown);
      window.removeEventListener("keydown", onKey);
    };
  });

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
      <div class="send" bind:this={pickerEl}>
        <button
          class="secondary"
          onclick={onSendClick}
          disabled={!command || !!error || targets.length === 0}
          title={targets.length === 0
            ? "Open an SSH session in the SSH tool first"
            : targets.length === 1
              ? `Type into SSH tab: ${targets[0].title}`
              : "Choose an SSH session"}
        >Send to SSH{targets.length > 1 ? " ..." : ""}</button>
        {#if picking && targets.length > 1}
          <div class="picker" role="menu">
            <div class="picker-head">Send to</div>
            {#each targets as t, i (t.key)}
              <button class="pick" role="menuitem" onclick={() => send(t)}>
                <span class="mono">{t.title}</span>
                {#if i === 0}<span class="muted cur">active</span>{/if}
              </button>
            {/each}
          </div>
        {/if}
      </div>
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

  .send {
    position: relative;
  }

  .picker {
    position: absolute;
    right: 0;
    top: calc(100% + 4px);
    z-index: 20;
    min-width: 14rem;
    max-height: 18rem;
    overflow-y: auto;
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    box-shadow: 0 6px 20px rgba(0, 0, 0, 0.25);
    padding: 0.25rem;
  }

  .picker-head {
    font-size: 0.68rem;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: var(--muted);
    padding: 0.3rem 0.5rem;
  }

  .pick {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 0.8rem;
    width: 100%;
    text-align: left;
    background: none;
    border: none;
    border-radius: 4px;
    color: var(--fg);
    font-size: 0.8rem;
    padding: 0.35rem 0.5rem;
    cursor: pointer;
  }

  .pick:hover {
    background: var(--hover);
  }

  .cur {
    font-size: 0.7rem;
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
