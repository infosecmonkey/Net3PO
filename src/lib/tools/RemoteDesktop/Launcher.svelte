<script lang="ts">
  import { onMount } from "svelte";
  import { invoke } from "@tauri-apps/api/core";
  import { confirm } from "@tauri-apps/plugin-dialog";
  import { loadCollection, saveCollection, type Collection } from "$lib/store";
  import { selectOnFocus } from "$lib/actions/selectOnFocus";
  import { nav } from "$lib/nav.svelte";
  import { clientChoice, clientName, type Protocol } from "$lib/settings.svelte";

  interface Props {
    protocol: Protocol;
  }
  let { protocol }: Props = $props();

  interface Host {
    id: string;
    name: string;
    host: string;
    port: number;
    user: string;
    fullscreen: boolean;
    notes: string;
  }

  const TITLE = { rdp: "RDP", vnc: "VNC" } as const;
  const PORT = { rdp: 3389, vnc: 5900 } as const;
  const collection = $derived<Collection>(protocol === "rdp" ? "rdp_hosts" : "vnc_hosts");

  let hosts = $state<Host[]>([]);
  let search = $state("");
  let quick = $state("");
  let error = $state("");
  let status = $state("");
  let busy = $state(false);
  let form = $state<{ mode: "new" | "edit"; host: Host } | null>(null);

  onMount(async () => {
    try {
      hosts = (await loadCollection<Host>(collection)).items;
    } catch (e) {
      error = String(e);
    }
  });

  async function persist() {
    try {
      await saveCollection(collection, hosts);
    } catch (e) {
      error = String(e);
    }
  }

  const shown = $derived.by(() => {
    const q = search.trim().toLowerCase();
    return hosts
      .filter((h) => !q || `${h.name} ${h.host} ${h.user} ${h.notes}`.toLowerCase().includes(q))
      .sort((a, b) => a.name.localeCompare(b.name));
  });

  function blank(): Host {
    return { id: crypto.randomUUID(), name: "", host: "", port: PORT[protocol], user: "", fullscreen: false, notes: "" };
  }

  async function saveForm() {
    if (!form) return;
    const h = form.host;
    h.host = h.host.trim();
    h.user = h.user.trim();
    h.name = h.name.trim() || h.host;
    h.port = Number(h.port) || PORT[protocol];
    if (!h.host) {
      error = "Host is required.";
      return;
    }
    if (h.port < 1 || h.port > 65535) {
      error = "Port must be 1 to 65535.";
      return;
    }
    const i = hosts.findIndex((x) => x.id === h.id);
    if (i >= 0) hosts[i] = h;
    else hosts.push(h);
    form = null;
    error = "";
    await persist();
  }

  async function remove(h: Host) {
    const ok = await confirm(`Delete "${h.name}"?`, { title: "Delete host", kind: "warning" });
    if (!ok) return;
    hosts = hosts.filter((x) => x.id !== h.id);
    await persist();
  }

  async function launch(h: Pick<Host, "host" | "port" | "user" | "fullscreen">, label: string) {
    error = "";
    status = "";
    const choice = clientChoice(protocol);
    if (!choice) {
      error = `No ${TITLE[protocol]} client is set up. Choose one in Settings.`;
      return;
    }
    busy = true;
    try {
      const name = await invoke<string>("remote_launch", {
        protocol,
        choice,
        target: { host: h.host, port: h.port, user: h.user, fullscreen: h.fullscreen },
      });
      status = `Opened ${label} in ${name}. It will ask for the password if the server needs one.`;
    } catch (e) {
      error = String(e);
    } finally {
      busy = false;
    }
  }

  /** `[user@]host[:port]`, IPv6 in brackets. */
  async function quickConnect() {
    const m = quick.trim().match(/^(?:([^@\s]+)@)?(\[[^\]]+\]|[^:\s]+)(?::(\d+))?$/);
    if (!m) {
      error = "Quick connect takes host, host:port or user@host:port.";
      return;
    }
    const port = m[3] ? Number(m[3]) : PORT[protocol];
    await launch({ host: m[2], port, user: m[1] ?? "", fullscreen: false }, m[2]);
  }
</script>

<div class="panel">
  <aside>
    <div class="quick">
      <input
        bind:value={quick}
        placeholder={protocol === "rdp" ? "user@host:3389" : "host:5900"}
        spellcheck="false"
        autocapitalize="off"
        autocomplete="off"
        onkeydown={(e) => e.key === "Enter" && quickConnect()}
      />
      <button class="small" onclick={quickConnect} disabled={busy}>Go</button>
    </div>
    <input bind:value={search} placeholder="Search hosts" spellcheck="false" />
    <button class="small" onclick={() => { error = ""; form = { mode: "new", host: blank() }; }}>+ Host</button>
    <div class="list">
      {#each shown as h (h.id)}
        <div class="row">
          <button class="main-btn" onclick={() => launch(h, h.name)} disabled={busy} title={h.notes || `${h.host}:${h.port}`}>
            <span class="name">{h.name}</span>
            <span class="sub mono">{h.user ? `${h.user}@` : ""}{h.host}{h.port !== PORT[protocol] ? `:${h.port}` : ""}</span>
          </button>
          <div class="acts">
            <button class="icon" title="Edit" onclick={() => { error = ""; form = { mode: "edit", host: { ...h } }; }}>e</button>
            <button class="icon" title="Delete" onclick={() => remove(h)}>x</button>
          </div>
        </div>
      {:else}
        <p class="hint">{hosts.length ? "No matches." : "No saved hosts yet."}</p>
      {/each}
    </div>
  </aside>

  <section class="content">
    <h1>{TITLE[protocol]}</h1>
    <p class="lead">
      {#if protocol === "rdp"}
        Open Remote Desktop sessions to Windows hosts and jump servers in the RDP client installed on this computer.
      {:else}
        Open VNC sessions to servers, appliances and lab machines in the VNC viewer installed on this computer.
      {/if}
      Click a saved host, or type one in quick connect.
    </p>
    <p class="hint">
      Client: <strong>{clientName(protocol) || "none"}</strong>
      <button class="link" onclick={() => (nav.selected = "settings")}>Change in Settings</button>
    </p>
    <p class="hint">
      Passwords are not stored here and never passed to the client: it asks for them itself, and may offer to
      remember them in its own keychain.
    </p>
    {#if error}<div class="error mono">{error}</div>{/if}
    {#if status}<div class="okbox">{status}</div>{/if}
  </section>
</div>

{#if form}
  <div class="overlay" role="presentation" onclick={(e) => e.target === e.currentTarget && (form = null)}>
    <div class="dialog" role="dialog" aria-modal="true" aria-label="Host">
      <h2>{form.mode === "new" ? "New host" : "Edit host"}</h2>
      <div class="grid">
        <label class="wide">Name <input bind:value={form.host.name} placeholder={protocol === "rdp" ? "Jump server" : "Lab appliance"} /></label>
        <label class="wide">Host <input class="mono" bind:value={form.host.host} placeholder="192.0.2.10 or host.example.com" spellcheck="false" autocapitalize="off" /></label>
        <label>Port <input class="mono" type="number" min="1" max="65535" bind:value={form.host.port} use:selectOnFocus /></label>
        <label>User <input class="mono" bind:value={form.host.user} placeholder={protocol === "rdp" ? "CORP\\jane (optional)" : "optional"} spellcheck="false" autocapitalize="off" /></label>
        {#if protocol === "rdp"}
          <label class="check wide"><input type="checkbox" bind:checked={form.host.fullscreen} /> Full screen</label>
        {/if}
        <label class="wide">Notes <textarea bind:value={form.host.notes} rows="2" placeholder="Site, purpose, ticket"></textarea></label>
      </div>
      <div class="actions">
        <button class="small" onclick={() => (form = null)}>Cancel</button>
        <button class="primary" onclick={saveForm}>Save</button>
      </div>
    </div>
  </div>
{/if}

<style>
  .panel {
    display: grid;
    grid-template-columns: 17rem 1fr;
    height: 100vh;
    box-sizing: border-box;
  }

  aside {
    border-right: 1px solid var(--border);
    padding: 1rem 0.75rem;
    overflow-y: auto;
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }

  .content {
    padding: 1.5rem 2rem;
    max-width: 44rem;
  }

  h1 {
    margin: 0 0 0.25rem;
    font-size: 1.3rem;
  }

  .lead {
    color: var(--muted);
    font-size: 0.85rem;
  }

  input,
  textarea {
    box-sizing: border-box;
    width: 100%;
    background: var(--input-bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    color: var(--fg);
    font-size: 0.82rem;
    padding: 0.35rem 0.5rem;
    font-family: inherit;
  }

  input:focus,
  textarea:focus {
    outline: none;
    border-color: var(--accent);
  }

  .mono,
  input.mono {
    font-family: var(--mono);
  }

  .quick {
    display: flex;
    gap: 0.3rem;
  }

  .quick input {
    font-family: var(--mono);
  }

  button.small,
  button.icon {
    background: var(--input-bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    color: var(--fg);
    font-size: 0.76rem;
    padding: 0.28rem 0.6rem;
    cursor: pointer;
    white-space: nowrap;
  }

  button.small:hover:not(:disabled),
  button.icon:hover {
    background: var(--hover);
  }

  button.icon {
    padding: 0.05rem 0.4rem;
    font-size: 0.7rem;
  }

  button:disabled {
    opacity: 0.5;
    cursor: default;
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

  .link {
    background: none;
    border: none;
    color: var(--accent);
    cursor: pointer;
    font-size: inherit;
    text-decoration: underline;
    margin-left: 0.4rem;
  }

  .list {
    display: flex;
    flex-direction: column;
    gap: 0.15rem;
  }

  .row {
    display: flex;
    align-items: center;
    gap: 0.2rem;
  }

  .acts {
    display: none;
    gap: 0.15rem;
  }

  .row:hover .acts {
    display: flex;
  }

  .main-btn {
    flex: 1;
    min-width: 0;
    display: flex;
    flex-direction: column;
    align-items: flex-start;
    background: none;
    border: 1px solid transparent;
    border-radius: 6px;
    padding: 0.3rem 0.5rem;
    color: var(--fg);
    cursor: pointer;
    text-align: left;
  }

  .main-btn:hover:not(:disabled) {
    background: var(--hover);
  }

  .name {
    font-size: 0.82rem;
  }

  .sub {
    font-size: 0.7rem;
    color: var(--muted);
    max-width: 100%;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .hint {
    font-size: 0.8rem;
    color: var(--muted);
    margin: 0.4rem 0;
  }

  .error,
  .okbox {
    border-radius: 6px;
    padding: 0.5rem 0.7rem;
    font-size: 0.8rem;
    margin-top: 0.8rem;
    white-space: pre-wrap;
    user-select: text;
  }

  .error {
    background: var(--error-bg);
    border: 1px solid var(--error-border);
    color: var(--error-fg);
  }

  .okbox {
    border: 1px solid #16a34a;
  }

  .overlay {
    position: fixed;
    inset: 0;
    background: rgb(0 0 0 / 0.45);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 50;
  }

  .dialog {
    width: min(30rem, calc(100vw - 2rem));
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 1.1rem 1.2rem;
    box-shadow: 0 10px 30px rgb(0 0 0 / 0.3);
    font-size: 0.85rem;
  }

  .dialog h2 {
    margin: 0 0 0.7rem;
    font-size: 1rem;
  }

  .grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 0.6rem 0.8rem;
  }

  .grid label {
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
    font-size: 0.76rem;
    color: var(--muted);
  }

  .wide {
    grid-column: 1 / -1;
  }

  label.check {
    flex-direction: row;
    align-items: center;
    color: var(--fg);
    font-size: 0.8rem;
  }

  label.check input {
    width: auto;
  }

  .actions {
    display: flex;
    justify-content: flex-end;
    gap: 0.5rem;
    margin-top: 1rem;
  }
</style>
