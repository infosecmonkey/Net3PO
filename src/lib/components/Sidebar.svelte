<script lang="ts">
  import { toolGroups } from "$lib/tools/registry";
  import Icon from "./icons/Icon.svelte";
  import logoLight from "$lib/assets/net3po-logo-light.png";
  import logoDark from "$lib/assets/net3po-logo-dark.png";
  import About from "./About.svelte";
  import { isDirty, notes, setNotesOpen } from "$lib/notes.svelte";
  import { help, toggleHelp } from "$lib/help/help.svelte";

  interface Props {
    selected: string;
    onselect: (id: string) => void;
  }

  let { selected, onselect }: Props = $props();
  const groups = toolGroups();
  let aboutOpen = $state(false);

  // Collapsed groups, remembered on this computer. Everything starts
  // expanded; the group holding the open tool always stays open.
  const COLLAPSED_KEY = "net3po.sidebar.collapsed";
  function loadCollapsed(): string[] {
    try {
      const v = JSON.parse(localStorage.getItem(COLLAPSED_KEY) ?? "[]");
      return Array.isArray(v) ? v.filter((x) => typeof x === "string") : [];
    } catch {
      return [];
    }
  }
  let collapsed = $state<string[]>(loadCollapsed());

  function persist() {
    try {
      localStorage.setItem(COLLAPSED_KEY, JSON.stringify(collapsed));
    } catch {
      // Storage unavailable: the choice lasts for this session only.
    }
  }

  function holdsSelected(category: string): boolean {
    return groups.some((g) => g.category === category && g.tools.some((t) => t.id === selected));
  }

  function isOpen(category: string): boolean {
    return !collapsed.includes(category) || holdsSelected(category);
  }

  function toggle(category: string) {
    collapsed = isOpen(category)
      ? [...collapsed.filter((c) => c !== category), category]
      : collapsed.filter((c) => c !== category);
    persist();
  }

  const anyCollapsed = $derived(groups.some((g) => !isOpen(g.category)));

  function toggleAll() {
    collapsed = anyCollapsed ? [] : groups.map((g) => g.category);
    persist();
  }
</script>

<nav class="sidebar">
  <div class="brand">
    <picture>
      <source srcset={logoDark} media="(prefers-color-scheme: dark)" />
      <img src={logoLight} alt="Net3PO" width="135" height="46" />
    </picture>
    <span class="brand-btns">
      <button
        class="about"
        class:on={notes.open}
        title="Project notes (Cmd/Ctrl+Shift+N)"
        aria-label="Project notes"
        onclick={() => setNotesOpen(!notes.open)}
      >
        <Icon name="notebook-pen" size={15} />
        {#if isDirty(notes.draft)}<span class="dot" aria-label="unsaved note"></span>{/if}
      </button>
      <button class="about" class:on={help.open} title="Help for this tool (F1)" aria-label="Help" onclick={() => toggleHelp(selected)}>
        <Icon name="circle-help" size={15} />
      </button>
      <button class="about" title="About Net3PO" aria-label="About Net3PO" onclick={() => (aboutOpen = true)}>
        <Icon name="info" size={15} />
      </button>
    </span>
  </div>
  <div class="all-row">
    <button class="all" onclick={toggleAll}>{anyCollapsed ? "Expand all" : "Collapse all"}</button>
  </div>
  {#each groups as group (group.category)}
    {@const open = isOpen(group.category)}
    <div class="group">
      <button
        class="group-label"
        aria-expanded={open}
        onclick={() => toggle(group.category)}
        title={holdsSelected(group.category) ? "Holds the open tool" : open ? "Collapse" : "Expand"}
      >
        <span class="chev" class:open>▸</span>
        <span>{group.category}</span>
        {#if !open}<span class="count">{group.tools.length}</span>{/if}
      </button>
      {#if open}
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
      {/if}
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

  .brand picture,
  .brand img {
    display: block;
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

  .brand-btns {
    display: flex;
    gap: 0.15rem;
  }

  .about {
    position: relative;
  }

  .about.on {
    color: var(--accent);
  }

  .dot {
    position: absolute;
    top: 0;
    right: 0;
    width: 6px;
    height: 6px;
    border-radius: 50%;
    background: var(--accent);
  }

  .about:hover {
    color: var(--accent);
    background: var(--hover);
  }

  .all-row {
    display: flex;
    justify-content: flex-end;
    padding: 0.4rem 0.75rem 0;
  }

  .all {
    background: none;
    border: none;
    color: var(--muted);
    font-size: 0.68rem;
    cursor: pointer;
    padding: 0.1rem 0.25rem;
    border-radius: 3px;
  }

  .all:hover {
    color: var(--accent);
    background: var(--hover);
  }

  .group {
    margin-top: 0.5rem;
  }

  .group-label {
    width: 100%;
    display: flex;
    align-items: center;
    gap: 0.35rem;
    background: none;
    border: none;
    text-align: left;
    font-size: 0.7rem;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: var(--muted);
    padding: 0.15rem 1rem 0.25rem;
    cursor: pointer;
  }

  .group-label:hover {
    color: var(--fg);
  }

  .chev {
    display: inline-block;
    font-size: 0.6rem;
    transition: transform 0.12s ease;
  }

  .chev.open {
    transform: rotate(90deg);
  }

  .count {
    margin-left: auto;
    font-size: 0.62rem;
    letter-spacing: 0;
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 0 0.35rem;
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
