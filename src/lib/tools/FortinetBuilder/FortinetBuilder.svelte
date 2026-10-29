<script lang="ts">
  // Fortinet command builder: FortiOS CLI builders (ported from FortiDebug
  // Builder) plus saved commands. Form styles live here and apply to the tab
  // components through :global under .fb.
  import { loadCollection, saveCollection } from "$lib/store";
  import type { FortinetCategory, SavedCommand } from "$lib/tools/types";
  import FlowForm from "./FlowForm.svelte";
  import HaForm from "./HaForm.svelte";
  import PingForm from "./PingForm.svelte";
  import SavedCommands from "./SavedCommands.svelte";
  import SessionForm from "./SessionForm.svelte";
  import SnifferForm from "./SnifferForm.svelte";
  import TracerouteForm from "./TracerouteForm.svelte";
  import VpnForm from "./VpnForm.svelte";

  type Tab = FortinetCategory | "saved";
  const TABS: { id: Tab; label: string }[] = [
    { id: "session", label: "Session" },
    { id: "flow", label: "Debug Flow" },
    { id: "sniffer", label: "Sniffer" },
    { id: "ping", label: "Ping" },
    { id: "traceroute", label: "Traceroute" },
    { id: "vpn", label: "VPN" },
    { id: "ha", label: "HA" },
    { id: "saved", label: "Saved" },
  ];

  let tab = $state<Tab>("session");
  let saved = $state<SavedCommand[]>([]);
  let storeError = $state("");

  $effect(() => {
    loadCollection<SavedCommand>("fortinet_saved_commands")
      .then((l) => {
        saved = l.items;
        if (l.recoveredTo) {
          storeError = `The saved commands file was unreadable and was moved aside as ${l.recoveredTo}.`;
        }
      })
      .catch((e) => (storeError = String(e)));
  });

  async function persist(next: SavedCommand[]) {
    try {
      await saveCollection("fortinet_saved_commands", next);
      saved = next;
      storeError = "";
    } catch (e) {
      storeError = `Could not save: ${e}`;
    }
  }

  function add(category: FortinetCategory, title: string, notes: string, command: string) {
    const item: SavedCommand = {
      id: crypto.randomUUID(),
      title,
      category,
      command,
      notes,
      createdAt: new Date().toISOString(),
    };
    persist([item, ...saved]);
  }
</script>

<div class="panel fb">
  <header>
    <h1>Fortinet Command Builder</h1>
    <p class="sub">Build FortiOS diagnose commands from validated inputs, then copy them to the FortiGate CLI.</p>
  </header>

  <div class="tabs" role="tablist">
    {#each TABS as t (t.id)}
      <button role="tab" aria-selected={tab === t.id} class:active={tab === t.id} onclick={() => (tab = t.id)}>
        {t.label}{#if t.id === "saved" && saved.length > 0}<span class="count">{saved.length}</span>{/if}
      </button>
    {/each}
  </div>

  {#if storeError}<div class="error">{storeError}</div>{/if}

  <!-- Keep every form mounted so switching tabs never loses input. -->
  <div hidden={tab !== "session"}><SessionForm onsave={(t, n, c) => add("session", t, n, c)} /></div>
  <div hidden={tab !== "flow"}><FlowForm onsave={(t, n, c) => add("flow", t, n, c)} /></div>
  <div hidden={tab !== "sniffer"}><SnifferForm onsave={(t, n, c) => add("sniffer", t, n, c)} /></div>
  <div hidden={tab !== "ping"}><PingForm onsave={(t, n, c) => add("ping", t, n, c)} /></div>
  <div hidden={tab !== "traceroute"}><TracerouteForm onsave={(t, n, c) => add("traceroute", t, n, c)} /></div>
  <div hidden={tab !== "vpn"}><VpnForm onsave={(t, n, c) => add("vpn", t, n, c)} /></div>
  <div hidden={tab !== "ha"}><HaForm onsave={(t, n, c) => add("ha", t, n, c)} /></div>
  <div hidden={tab !== "saved"}><SavedCommands items={saved} onchange={persist} /></div>
</div>

<style>
  .panel {
    padding: 1.5rem 2rem 2rem;
    box-sizing: border-box;
    width: 100%;
    max-width: 1100px;
  }

  header h1 {
    margin: 0 0 0.25rem;
    font-size: 1.3rem;
  }

  .sub {
    margin: 0 0 1rem;
    color: var(--muted);
    font-size: 0.85rem;
  }

  .tabs {
    display: flex;
    flex-wrap: wrap;
    gap: 0.25rem;
    border-bottom: 1px solid var(--border);
    margin-bottom: 1rem;
  }

  .tabs button {
    background: none;
    border: none;
    border-bottom: 2px solid transparent;
    color: var(--muted);
    padding: 0.45rem 0.9rem;
    font-size: 0.86rem;
    cursor: pointer;
  }

  .tabs button.active {
    color: var(--fg);
    border-bottom-color: var(--accent);
  }

  .count {
    margin-left: 0.35rem;
    font-size: 0.7rem;
    background: var(--accent);
    color: #fff;
    border-radius: 0.6rem;
    padding: 0 0.35rem;
  }

  /* Shared form styles for the tab components. */
  .fb :global(.help) {
    font-size: 0.84rem;
    margin: 0 0 0.9rem;
    color: var(--fg);
  }

  .fb :global(.grid) {
    display: flex;
    flex-wrap: wrap;
    gap: 0.75rem;
    margin-bottom: 0.75rem;
  }

  .fb :global(.field) {
    display: flex;
    flex-direction: column;
    flex: 2 1 200px;
    min-width: 0;
  }

  .fb :global(.field.small) {
    flex: 1 1 120px;
  }

  .fb :global(label) {
    font-size: 0.78rem;
    color: var(--muted);
    margin-bottom: 0.3rem;
  }

  .fb :global(input:not([type="checkbox"])),
  .fb :global(select),
  .fb :global(textarea) {
    width: 100%;
    box-sizing: border-box;
    background: var(--input-bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.45rem 0.55rem;
    color: var(--fg);
    font-size: 0.88rem;
  }

  .fb :global(input:focus),
  .fb :global(select:focus),
  .fb :global(textarea:focus) {
    outline: none;
    border-color: var(--accent);
  }

  .fb :global(input:disabled),
  .fb :global(select:disabled) {
    opacity: 0.5;
    cursor: not-allowed;
  }

  .fb :global(.bad) {
    border-color: var(--error-border) !important;
    background: var(--error-bg) !important;
  }

  .fb :global(input[type="checkbox"]) {
    margin: 0 0.3rem 0 0;
  }

  .fb :global(.checks) {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 0.6rem 1.1rem;
    margin: 0.2rem 0 0.6rem;
  }

  .fb :global(.check) {
    display: inline-flex;
    align-items: center;
    font-size: 0.82rem;
    margin: 0;
    color: var(--fg);
  }

  .fb :global(.mono) {
    font-family: var(--mono);
  }

  .fb :global(.muted) {
    color: var(--muted);
  }

  .fb :global(.note) {
    font-size: 0.78rem;
    margin: 0.2rem 0 0.4rem;
  }

  .fb :global(code) {
    font-family: var(--mono);
    font-size: 0.82em;
    background: var(--sidebar-bg);
    border: 1px solid var(--border);
    border-radius: 3px;
    padding: 0 0.25rem;
  }

  .fb :global(.warnline) {
    font-size: 0.8rem;
    border-left: 3px solid #c69026;
    padding: 0.2rem 0.6rem;
    margin: 0.2rem 0 0.6rem;
  }

  .fb :global(.action) {
    background: var(--accent);
    border: 1px solid var(--accent);
    border-radius: 6px;
    padding: 0.45rem 1.1rem;
    color: #fff;
    font-weight: 600;
    font-size: 0.84rem;
    cursor: pointer;
  }

  .fb :global(.secondary) {
    background: var(--btn-bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.4rem 0.85rem;
    color: var(--fg);
    font-size: 0.82rem;
    cursor: pointer;
    white-space: nowrap;
  }

  .fb :global(.sm) {
    padding: 0.25rem 0.6rem;
    font-size: 0.78rem;
  }

  .fb :global(button:disabled) {
    opacity: 0.5;
    cursor: default;
  }

  .fb :global(.link) {
    background: none;
    border: none;
    padding: 0;
    color: var(--accent);
    cursor: pointer;
    font-size: inherit;
    text-decoration: underline;
  }

  .fb :global(.error) {
    background: var(--error-bg);
    border: 1px solid var(--error-border);
    color: var(--error-fg);
    border-radius: 6px;
    padding: 0.55rem 0.8rem;
    font-size: 0.82rem;
    margin-bottom: 0.8rem;
    white-space: pre-wrap;
  }
</style>
