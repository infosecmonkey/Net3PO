<script lang="ts" generics="T extends { id: string }">
  // Collapsible list of saved connections or hosts under the shared groups.
  // Rows are rendered by the caller (`row` snippet) using the classes
  // .conn, .conn-main, .cname, .chost, .row-actions and button.icon.
  import type { Snippet } from "svelte";
  import { confirm } from "@tauri-apps/plugin-dialog";
  import GroupDialog from "./GroupDialog.svelte";
  import { collapsed, deleteGroup, memberCounts, UNGROUPED, type Branch, type Group } from "$lib/groups.svelte";

  interface Props {
    /** Tool name, for remembering collapsed groups. */
    scope: string;
    branches: Branch<T>[];
    row: Snippet<[T]>;
    /** Add an item to a group; omit to hide the + button. */
    onadd?: (groupId: string | null) => void;
    /** Group rename and delete buttons. */
    manage?: boolean;
    /** After a group is deleted, so the caller can update its items. */
    ondeleted?: (id: string) => void;
    emptyText?: string;
  }
  let { scope, branches, row, onadd, manage = true, ondeleted, emptyText = "Nothing saved." }: Props = $props();

  let renaming = $state<Group | null>(null);
  let error = $state("");

  const key = (id: string) => `${scope}:${id}`;

  async function remove(b: Branch<T>) {
    error = "";
    try {
      const n = await memberCounts(b.id);
      const parts = [
        n.ssh && `${n.ssh} SSH connection${n.ssh === 1 ? "" : "s"}`,
        n.rdp && `${n.rdp} RDP host${n.rdp === 1 ? "" : "s"}`,
        n.vnc && `${n.vnc} VNC host${n.vnc === 1 ? "" : "s"}`,
      ].filter(Boolean);
      const what = parts.length ? ` Its ${parts.join(", ")} move to Ungrouped.` : "";
      const ok = await confirm(`Delete group "${b.name}"? It is shared by SSH, SFTP, RDP and VNC.${what}`, {
        title: "Delete group",
        kind: "warning",
      });
      if (!ok) return;
      await deleteGroup(b.id);
      ondeleted?.(b.id);
    } catch (e) {
      error = String(e);
    }
  }
</script>

<div class="glist">
  {#if error}<p class="gerror">{error}</p>{/if}
  {#each branches as b (b.id)}
    <div class="group">
      <div class="group-head">
        <button class="twisty" onclick={() => (collapsed[key(b.id)] = !collapsed[key(b.id)])}>
          <span class="chev">{collapsed[key(b.id)] ? "+" : "-"}</span>
          <span class="gname">{b.name}</span>
          <span class="count">{b.items.length}</span>
        </button>
        {#if b.id !== UNGROUPED && (onadd || manage)}
          <div class="row-actions">
            {#if onadd}<button class="icon" title="Add to this group" onclick={() => onadd(b.id)}>+</button>{/if}
            {#if manage}
              <button class="icon" title="Rename group" onclick={() => (renaming = { id: b.id, name: b.name })}>e</button>
              <button class="icon" title="Delete group" onclick={() => remove(b)}>x</button>
            {/if}
          </div>
        {/if}
      </div>
      {#if !collapsed[key(b.id)]}
        {#each b.items as item (item.id)}
          {@render row(item)}
        {:else}
          <p class="ghint">{emptyText}</p>
        {/each}
      {/if}
    </div>
  {/each}
</div>

{#if renaming}
  <GroupDialog group={renaming} onclose={() => (renaming = null)} />
{/if}

<style>
  .glist {
    display: flex;
    flex-direction: column;
    gap: 0.2rem;
  }

  .gerror {
    color: var(--error-fg);
    font-size: 0.75rem;
    margin: 0;
  }

  .ghint {
    color: var(--muted);
    font-size: 0.75rem;
    margin: 0.1rem 0 0.3rem 1.4rem;
  }

  .group-head,
  .glist :global(.conn) {
    display: flex;
    align-items: center;
    gap: 0.2rem;
  }

  .row-actions,
  .glist :global(.row-actions) {
    display: none;
    gap: 0.15rem;
  }

  .group-head:hover .row-actions,
  .glist :global(.conn:hover .row-actions) {
    display: flex;
  }

  .twisty {
    flex: 1 1 auto;
    display: flex;
    align-items: center;
    gap: 0.35rem;
    background: none;
    border: none;
    color: var(--fg);
    padding: 0.3rem 0.2rem;
    cursor: pointer;
    font-size: 0.8rem;
    font-weight: 600;
    text-align: left;
  }

  .chev {
    width: 0.8rem;
    color: var(--muted);
  }

  .count {
    margin-left: auto;
    color: var(--muted);
    font-weight: 400;
    font-size: 0.72rem;
  }

  button.icon,
  .glist :global(button.icon) {
    background: var(--input-bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    color: var(--fg);
    padding: 0.05rem 0.4rem;
    font-size: 0.7rem;
    cursor: pointer;
    white-space: nowrap;
  }

  button.icon:hover,
  .glist :global(button.icon:hover) {
    background: var(--hover);
  }

  .glist :global(.conn-main) {
    flex: 1 1 auto;
    min-width: 0;
    display: flex;
    flex-direction: column;
    align-items: flex-start;
    background: none;
    border: 1px solid transparent;
    border-radius: 6px;
    padding: 0.3rem 0.5rem 0.3rem 1.4rem;
    color: var(--fg);
    cursor: pointer;
    text-align: left;
  }

  .glist :global(.conn-main:hover:not(:disabled)) {
    background: var(--hover);
  }

  .glist :global(.conn-main:disabled) {
    opacity: 0.5;
    cursor: default;
  }

  .glist :global(.cname) {
    font-size: 0.82rem;
  }

  .glist :global(.chost) {
    font-family: var(--mono);
    font-size: 0.7rem;
    color: var(--muted);
    max-width: 100%;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
</style>
