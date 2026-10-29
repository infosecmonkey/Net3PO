<script lang="ts">
  // Open SSH sessions shown above every other tool. Click a session to jump
  // back to it, or dock a terminal under the current tool.
  import Icon from "./icons/Icon.svelte";
  import { ssh } from "$lib/ssh/sessions.svelte";
  import { openTool } from "$lib/nav.svelte";

  function pick(key: number) {
    ssh.active = key;
    // With the drawer open, the bar switches the docked session instead.
    if (!ssh.drawer) openTool("ssh");
  }

  function toggleDrawer() {
    if (ssh.active === null) ssh.active = ssh.tabs.at(-1)?.key ?? null;
    ssh.drawer = !ssh.drawer;
  }
</script>

<div class="bar">
  <span class="label"><Icon name="terminal" size={14} /> SSH</span>
  <div class="sessions">
    {#each ssh.tabs as t (t.key)}
      <button
        class="session"
        class:active={ssh.active === t.key}
        title={ssh.drawer ? "Show in the docked terminal" : "Open in SSH"}
        onclick={() => pick(t.key)}
      >
        <span class="dot" class:closed={t.status === "closed"}></span>
        {t.title}
      </button>
    {/each}
  </div>
  <button class="dock" class:on={ssh.drawer} onclick={toggleDrawer}>
    <Icon name="square-terminal" size={14} />
    {ssh.drawer ? "Hide terminal" : "Dock terminal"}
  </button>
</div>

<style>
  .bar {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    padding: 0.3rem 0.6rem;
    border-bottom: 1px solid var(--border);
    background: var(--sidebar-bg);
    flex: 0 0 auto;
  }

  .label {
    display: flex;
    align-items: center;
    gap: 0.3rem;
    font-size: 0.7rem;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: var(--muted);
  }

  .sessions {
    display: flex;
    gap: 0.25rem;
    flex: 1 1 auto;
    min-width: 0;
    overflow-x: auto;
  }

  button {
    display: flex;
    align-items: center;
    gap: 0.4rem;
    font-size: 0.76rem;
    color: var(--fg);
    background: var(--btn-bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.2rem 0.6rem;
    cursor: pointer;
    white-space: nowrap;
  }

  button:hover {
    background: var(--hover);
  }

  .session.active,
  .dock.on {
    border-color: var(--accent);
    background: var(--active-bg);
  }

  .dot {
    width: 0.5rem;
    height: 0.5rem;
    border-radius: 50%;
    background: #16a34a;
  }

  .dot.closed {
    background: var(--muted);
  }
</style>
