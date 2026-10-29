<script lang="ts">
  import { toolGroups } from "$lib/tools/registry";
  import Icon from "./icons/Icon.svelte";
  import About from "./About.svelte";

  interface Props {
    selected: string;
    onselect: (id: string) => void;
  }

  let { selected, onselect }: Props = $props();
  const groups = toolGroups();
  let aboutOpen = $state(false);
</script>

<nav class="sidebar">
  <div class="brand">
    <span>OmniPacket</span>
    <button class="about" title="About OmniPacket" aria-label="About OmniPacket" onclick={() => (aboutOpen = true)}>
      <Icon name="info" size={15} />
    </button>
  </div>
  {#each groups as group (group.category)}
    <div class="group">
      <div class="group-label">{group.category}</div>
      <ul>
        {#each group.tools as tool (tool.id)}
          <li>
            <button
              class="tool"
              class:active={tool.id === selected}
              disabled={!tool.enabled}
              onclick={() => tool.enabled && onselect(tool.id)}
            >
              <span class="tool-icon"><Icon name={tool.icon} /></span>
              <span class="tool-name">{tool.name}</span>
              {#if !tool.enabled}
                <span class="soon">soon</span>
              {/if}
            </button>
          </li>
        {/each}
      </ul>
    </div>
  {/each}
</nav>

{#if aboutOpen}<About onclose={() => (aboutOpen = false)} />{/if}

<style>
  .sidebar {
    width: 240px;
    flex: 0 0 240px;
    height: 100vh;
    overflow-y: auto;
    background: var(--sidebar-bg);
    border-right: 1px solid var(--border);
    padding: 0 0 1rem;
    box-sizing: border-box;
  }

  .brand {
    font-weight: 700;
    font-size: 1rem;
    letter-spacing: 0.02em;
    padding: 1rem 1rem 0.75rem;
    position: sticky;
    top: 0;
    background: var(--sidebar-bg);
    border-bottom: 1px solid var(--border);
  }

  .brand {
    display: flex;
    align-items: center;
    justify-content: space-between;
  }

  .about {
    display: flex;
    background: none;
    border: none;
    padding: 0.15rem;
    border-radius: 4px;
    color: var(--muted);
    cursor: pointer;
  }

  .about:hover {
    color: var(--accent);
    background: var(--hover);
  }

  .group {
    margin-top: 0.75rem;
  }

  .group-label {
    font-size: 0.7rem;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: var(--muted);
    padding: 0 1rem 0.25rem;
  }

  ul {
    list-style: none;
    margin: 0;
    padding: 0;
  }

  .tool {
    width: 100%;
    display: flex;
    align-items: center;
    gap: 0.6rem;
    background: none;
    border: none;
    text-align: left;
    padding: 0.4rem 1rem;
    font-size: 0.85rem;
    color: var(--fg);
    cursor: pointer;
    border-left: 2px solid transparent;
  }

  .tool:hover:not(:disabled) {
    background: var(--hover);
  }

  .tool.active {
    background: var(--active-bg);
    border-left-color: var(--accent);
    font-weight: 600;
  }

  .tool:disabled {
    color: var(--muted);
    cursor: default;
  }

  .tool-icon {
    color: var(--muted);
    display: flex;
  }

  .tool:hover:not(:disabled) .tool-icon,
  .tool.active .tool-icon {
    color: var(--accent);
  }

  .tool:disabled .tool-icon {
    opacity: 0.6;
  }

  .tool-name {
    flex: 1 1 auto;
    min-width: 0;
  }

  .soon {
    font-size: 0.6rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    border: 1px solid var(--border);
    border-radius: 3px;
    padding: 0 0.25rem;
    color: var(--muted);
  }
</style>
