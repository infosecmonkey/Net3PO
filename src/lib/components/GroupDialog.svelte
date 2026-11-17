<script lang="ts">
  // New or rename group dialog for the shared connection groups.
  import { untrack } from "svelte";
  import { addGroup, renameGroup, type Group } from "$lib/groups.svelte";

  interface Props {
    /** The group to rename, or null for a new group. */
    group: Group | null;
    onclose: (created?: Group) => void;
  }
  let { group, onclose }: Props = $props();

  // The dialog edits a copy of the name it opened with.
  let name = $state(untrack(() => group?.name ?? ""));
  let error = $state("");

  async function save() {
    if (!name.trim()) return;
    try {
      if (group) {
        await renameGroup(group.id, name);
        onclose();
      } else {
        onclose((await addGroup(name)) ?? undefined);
      }
    } catch (e) {
      error = String(e);
    }
  }
</script>

<div class="overlay" role="presentation" onclick={(e) => e.target === e.currentTarget && onclose()}>
  <div class="dialog" role="dialog" aria-modal="true" aria-label="Group">
    <h2>{group ? "Rename group" : "New group"}</h2>
    <!-- svelte-ignore a11y_autofocus -->
    <input bind:value={name} placeholder="customer or site" autofocus onkeydown={(e) => e.key === "Enter" && save()} />
    <p class="hint">Groups are shared by SSH, SFTP, RDP and VNC.</p>
    {#if error}<p class="error">{error}</p>{/if}
    <div class="actions">
      <button class="small" onclick={() => onclose()}>Cancel</button>
      <button class="primary" onclick={save} disabled={!name.trim()}>Save</button>
    </div>
  </div>
</div>

<style>
  .overlay {
    position: fixed;
    inset: 0;
    background: rgb(0 0 0 / 0.45);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 60;
  }

  .dialog {
    width: min(24rem, calc(100vw - 2rem));
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 1.1rem 1.2rem;
    box-shadow: 0 10px 30px rgb(0 0 0 / 0.3);
    font-size: 0.85rem;
  }

  h2 {
    margin: 0 0 0.7rem;
    font-size: 1rem;
  }

  input {
    box-sizing: border-box;
    width: 100%;
    background: var(--input-bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    color: var(--fg);
    font-size: 0.82rem;
    padding: 0.35rem 0.5rem;
  }

  input:focus {
    outline: none;
    border-color: var(--accent);
  }

  .hint {
    color: var(--muted);
    font-size: 0.75rem;
    margin: 0.4rem 0 0;
  }

  .error {
    color: var(--error-fg);
    font-size: 0.78rem;
  }

  .actions {
    display: flex;
    justify-content: flex-end;
    gap: 0.5rem;
    margin-top: 0.9rem;
  }

  button.small {
    background: var(--input-bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    color: var(--fg);
    font-size: 0.76rem;
    padding: 0.28rem 0.6rem;
    cursor: pointer;
  }

  button.primary {
    background: var(--accent);
    color: var(--accent-fg);
    border: none;
    border-radius: 6px;
    font-weight: 600;
    font-size: 0.82rem;
    padding: 0.4rem 0.9rem;
    cursor: pointer;
  }

  button:disabled {
    opacity: 0.5;
    cursor: default;
  }
</style>
