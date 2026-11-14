<script lang="ts">
  // TCP/UDP socket tools: sender, listener and connection timing. All three
  // stay mounted so a running listener keeps going while another tab is open.
  import Listener from "./Listener.svelte";
  import Sender from "./Sender.svelte";
  import Timing from "./Timing.svelte";

  type Tab = "send" | "listen" | "timing";
  let tab = $state<Tab>("send");

  const TABS: { id: Tab; label: string }[] = [
    { id: "send", label: "Send" },
    { id: "listen", label: "Listen" },
    { id: "timing", label: "Connection timing" },
  ];
</script>

<div class="panel sock">
  <header>
    <h1>Socket Tools</h1>
    <p class="sub">Send TCP or UDP payloads, listen on a port, and time repeated TCP connects.</p>
  </header>
  <div class="tabs" role="tablist">
    {#each TABS as t (t.id)}
      <button role="tab" aria-selected={tab === t.id} class:active={tab === t.id} onclick={() => (tab = t.id)}>{t.label}</button>
    {/each}
  </div>
  <div hidden={tab !== "send"}><Sender /></div>
  <div hidden={tab !== "listen"}><Listener /></div>
  <div hidden={tab !== "timing"}><Timing /></div>
</div>

<style>
  .panel {
    padding: 1.5rem 2rem;
    max-width: 980px;
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
    gap: 0.25rem;
    border-bottom: 1px solid var(--border);
    margin-bottom: 1rem;
  }

  .tabs button {
    background: none;
    border: none;
    border-bottom: 2px solid transparent;
    color: var(--muted);
    padding: 0.4rem 0.8rem;
    font-size: 0.85rem;
    cursor: pointer;
  }

  .tabs button.active {
    color: var(--fg);
    border-bottom-color: var(--accent);
  }

  /* Shared by the three panes. */
  .sock :global(.row) {
    display: flex;
    flex-wrap: wrap;
    align-items: flex-end;
    gap: 0.6rem 1rem;
    margin-bottom: 0.7rem;
  }

  .sock :global(.field) {
    display: flex;
    flex-direction: column;
    margin-bottom: 0.6rem;
  }

  .sock :global(.row .field) {
    margin-bottom: 0;
  }

  .sock :global(.field.grow) {
    flex: 1 1 240px;
  }

  .sock :global(.field.port) {
    flex: 0 0 6.5rem;
  }

  .sock :global(label),
  .sock :global(.lbl) {
    font-size: 0.8rem;
    color: var(--muted);
    margin-bottom: 0.3rem;
  }

  .sock :global(.lblrow) {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 0.3rem;
  }

  .sock :global(.lblrow label) {
    margin: 0;
  }

  .sock :global(input),
  .sock :global(textarea) {
    box-sizing: border-box;
    background: var(--input-bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.45rem 0.6rem;
    color: var(--fg);
    font-size: 0.86rem;
  }

  .sock :global(input[type="checkbox"]) {
    padding: 0;
  }

  .sock :global(textarea) {
    width: 100%;
    font-size: 0.8rem;
    resize: vertical;
  }

  .sock :global(input:focus),
  .sock :global(textarea:focus) {
    outline: none;
    border-color: var(--accent);
  }

  .sock :global(.mono) {
    font-family: var(--mono);
  }

  .sock :global(.inline) {
    display: inline-flex;
    align-items: center;
    gap: 0.4rem;
    margin: 0;
    font-size: 0.8rem;
  }

  .sock :global(.num) {
    width: 6rem;
  }

  .sock :global(.spacer) {
    flex: 1;
  }

  .sock :global(.seg) {
    display: inline-flex;
    border: 1px solid var(--border);
    border-radius: 6px;
    overflow: hidden;
  }

  .sock :global(.seg button) {
    background: var(--input-bg);
    border: none;
    color: var(--muted);
    padding: 0.42rem 0.8rem;
    font-size: 0.82rem;
    cursor: pointer;
  }

  .sock :global(.seg.small button) {
    padding: 0.15rem 0.55rem;
    font-size: 0.72rem;
  }

  .sock :global(.seg button.on) {
    background: var(--accent);
    color: var(--accent-fg);
  }

  .sock :global(.run) {
    background: var(--accent);
    border: 1px solid var(--accent);
    border-radius: 6px;
    padding: 0.45rem 1.1rem;
    color: var(--accent-fg);
    font-weight: 600;
    font-size: 0.85rem;
    cursor: pointer;
  }

  .sock :global(.second) {
    background: var(--input-bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.45rem 1rem;
    color: var(--fg);
    font-size: 0.85rem;
    cursor: pointer;
  }

  .sock :global(.error) {
    background: var(--error-bg);
    border: 1px solid var(--error-border);
    color: var(--error-fg);
    border-radius: 6px;
    padding: 0.6rem 0.8rem;
    font-size: 0.82rem;
    margin: 0.6rem 0;
    white-space: pre-wrap;
  }

  .sock :global(.hint) {
    font-size: 0.74rem;
    color: var(--muted);
    margin: 0.2rem 0 0.6rem;
  }

  .sock :global(.status),
  .sock :global(.note) {
    border-left: 3px solid var(--accent);
    padding: 0.3rem 0.7rem;
    font-size: 0.8rem;
    margin: 0.4rem 0;
  }

  .sock :global(.note) {
    border-left-color: #b7791f;
    margin-left: 6.2rem;
  }

  .sock :global(.adv) {
    margin: 0 0 0.8rem;
  }

  .sock :global(summary) {
    font-size: 0.78rem;
    color: var(--muted);
    cursor: pointer;
    margin-bottom: 0.4rem;
  }

  .sock :global(.bar) {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin: 0.8rem 0 0.4rem;
  }

  .sock :global(.muted) {
    color: var(--muted);
  }

  .sock :global(.small) {
    font-size: 0.75rem;
  }

  .sock :global(.warnc) {
    color: #b7791f;
  }

  .sock :global(.log) {
    display: flex;
    flex-direction: column;
    font-size: 0.82rem;
  }

  .sock :global(.line) {
    display: flex;
    gap: 0.6rem;
    align-items: baseline;
    padding: 0.12rem 0;
  }

  .sock :global(.line .t) {
    color: var(--muted);
    font-size: 0.74rem;
    flex: 0 0 5.6rem;
  }

  .sock :global(.line .n) {
    color: var(--muted);
    flex: 0 0 3rem;
  }

  .sock :global(.oc) {
    flex: 0 0 5.5rem;
    font-weight: 600;
  }

  .sock :global(.oc.connected) {
    color: #15935a;
  }

  .sock :global(.oc.refused) {
    color: #b7791f;
  }

  .sock :global(.oc.timedOut),
  .sock :global(.oc.error) {
    color: #c0392b;
  }

  .sock :global(.spark) {
    width: 100%;
    height: 48px;
    background: var(--input-bg);
    border: 1px solid var(--border);
    border-radius: 4px;
    margin-bottom: 0.6rem;
  }

  .sock :global(.spark rect.connected) {
    fill: #15935a;
  }

  .sock :global(.spark rect.refused) {
    fill: #b7791f;
  }

  .sock :global(.spark rect.timedOut),
  .sock :global(.spark rect.error) {
    fill: #c0392b;
  }

  .sock :global(.kv) {
    border-collapse: collapse;
    margin-bottom: 0.6rem;
  }

  .sock :global(.kv th) {
    text-align: left;
    font-weight: 500;
    color: var(--muted);
    font-size: 0.78rem;
    padding: 0.15rem 1rem 0.15rem 0;
  }

  .sock :global(.kv td) {
    font-size: 0.82rem;
  }
</style>
