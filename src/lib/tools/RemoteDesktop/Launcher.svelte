<script lang="ts">
  import { onMount } from "svelte";
  import { invoke } from "@tauri-apps/api/core";
  import { confirm } from "@tauri-apps/plugin-dialog";
  import { loadCollection, saveCollection, type Collection } from "$lib/store";
  import { selectOnFocus } from "$lib/actions/selectOnFocus";
  import { nav } from "$lib/nav.svelte";
  import { clientChoice, clientName, type Protocol } from "$lib/settings.svelte";
  import GroupDialog from "$lib/components/GroupDialog.svelte";
  import GroupedList from "$lib/components/GroupedList.svelte";
  import { groupName, groupTree, loadGroups, sortedGroups, UNGROUPED } from "$lib/groups.svelte";

  interface Props {
    protocol: Protocol;
  }
  let { protocol }: Props = $props();

  interface Host {
    id: string;
    /** Shared connection group; missing on hosts saved before groups. */
    groupId?: string | null;
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
  let newGroup = $state(false);

  interface Offer {
    version: string;
    types: { id: number; name: string }[];
    reason: string | null;
    advice: string[];
  }
  let check = $state<{ label: string; offer: Offer | null; error: string; busy: boolean } | null>(null);

  /** VNC only: read the login methods the server offers, without logging in. */
  async function checkServer(h: Pick<Host, "host" | "port">, label: string) {
    error = "";
    status = "";
    check = { label, offer: null, error: "", busy: true };
    try {
      const offer = await invoke<Offer>("vnc_check", { host: h.host, port: h.port });
      check = { label, offer, error: "", busy: false };
    } catch (e) {
      check = { label, offer: null, error: String(e), busy: false };
    }
  }

  onMount(async () => {
    try {
      await loadGroups();
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

  const tree = $derived.by(() => {
    const q = search.trim().toLowerCase();
    const match = (h: Host) =>
      !q || `${h.name} ${h.host} ${h.user} ${h.notes} ${groupName(h.groupId)}`.toLowerCase().includes(q);
    return groupTree(hosts, match, { searching: !!q, keepEmpty: false });
  });

  function groupDeleted(id: string) {
    for (const h of hosts) if (h.groupId === id) h.groupId = null;
  }

  function blank(groupId: string | null = null): Host {
    return { id: crypto.randomUUID(), groupId: groupId === UNGROUPED ? null : groupId, name: "", host: "", port: PORT[protocol], user: "", fullscreen: false, notes: "" };
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
  function parseQuick(): { host: string; port: number; user: string } | null {
    const m = quick.trim().match(/^(?:([^@\s]+)@)?(\[[^\]]+\]|[^:\s]+)(?::(\d+))?$/);
    if (!m) {
      error = "Quick connect takes host, host:port or user@host:port.";
      return null;
    }
    return { host: m[2], port: m[3] ? Number(m[3]) : PORT[protocol], user: m[1] ?? "" };
  }

  async function quickConnect() {
    const q = parseQuick();
    if (q) await launch({ ...q, fullscreen: false }, q.host);
  }

  async function quickCheck() {
    const q = parseQuick();
    if (q) await checkServer(q, q.host);
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
      {#if protocol === "vnc"}
        <button class="small" onclick={quickCheck} disabled={check?.busy} title="Show the login methods the server offers">Check</button>
      {/if}
    </div>
    <input bind:value={search} placeholder="Search hosts" spellcheck="false" />
    <div class="aside-actions">
      <button class="small" onclick={() => { error = ""; form = { mode: "new", host: blank() }; }}>+ Host</button>
      <button class="small" onclick={() => (newGroup = true)}>+ Group</button>
    </div>
    {#if hosts.length}
      <GroupedList scope={protocol} branches={tree} onadd={(id) => { error = ""; form = { mode: "new", host: blank(id) }; }} ondeleted={groupDeleted} emptyText="No matches.">
        {#snippet row(h: Host)}
          <div class="conn">
            <button class="conn-main" onclick={() => launch(h, h.name)} disabled={busy} title={h.notes || `${h.host}:${h.port}`}>
              <span class="cname">{h.name}</span>
              <span class="chost">{h.user ? `${h.user}@` : ""}{h.host}{h.port !== PORT[protocol] ? `:${h.port}` : ""}</span>
            </button>
            <div class="row-actions">
              {#if protocol === "vnc"}
                <button class="icon" title="Check server: show the login methods it offers" onclick={() => checkServer(h, h.name)} disabled={check?.busy}>?</button>
              {/if}
              <button class="icon" title="Edit" onclick={() => { error = ""; form = { mode: "edit", host: { ...h, groupId: h.groupId ?? null } }; }}>e</button>
              <button class="icon" title="Delete" onclick={() => remove(h)}>x</button>
            </div>
          </div>
        {/snippet}
      </GroupedList>
    {:else}
      <p class="hint">No saved hosts yet.</p>
    {/if}
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

    {#if check}
      <div class="check-box">
        <div class="check-head">
          <strong>Server check: {check.label}</strong>
          <span class="spacer"></span>
          <button class="icon" title="Close" onclick={() => (check = null)}>x</button>
        </div>
        {#if check.busy}
          <p class="hint">Connecting...</p>
        {:else if check.error}
          <div class="error mono">{check.error}</div>
        {:else if check.offer}
          <p class="hint">VNC protocol {check.offer.version}. Login methods offered:</p>
          {#if check.offer.types.length}
            <ul class="types">
              {#each check.offer.types as t, i (i)}
                <li><span class="mono">{t.id}</span> {t.name}</li>
              {/each}
            </ul>
          {:else}
            <p class="hint">None.</p>
          {/if}
          {#each check.offer.advice as a, i (i)}
            <p class="advice">{a}</p>
          {/each}
        {/if}
        <p class="hint">Only the server's greeting is read. Nothing is logged in and no password is sent.</p>
      </div>
    {/if}
  </section>
</div>

{#if newGroup}
  <GroupDialog group={null} onclose={() => (newGroup = false)} />
{/if}

{#if form}
  <div class="overlay" role="presentation" onclick={(e) => e.target === e.currentTarget && (form = null)}>
    <div class="dialog" role="dialog" aria-modal="true" aria-label="Host">
      <h2>{form.mode === "new" ? "New host" : "Edit host"}</h2>
      <div class="grid">
        <label>Name <input bind:value={form.host.name} placeholder={protocol === "rdp" ? "Jump server" : "Lab appliance"} /></label>
        <label>
          Group
          <select bind:value={form.host.groupId}>
            <option value={null}>Ungrouped</option>
            {#each sortedGroups() as g (g.id)}<option value={g.id}>{g.name}</option>{/each}
          </select>
        </label>
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
  select,
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
  select:focus,
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

  .aside-actions {
    display: flex;
    gap: 0.4rem;
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
  .check-box {
    margin-top: 0.9rem;
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 0.7rem 0.9rem;
    background: var(--sidebar-bg);
    font-size: 0.84rem;
    max-width: 44rem;
  }

  .check-head {
    display: flex;
    align-items: center;
  }

  .check-head .spacer {
    flex: 1;
  }

  .types {
    margin: 0.2rem 0 0.5rem;
    padding-left: 1.1rem;
  }

  .types .mono {
    display: inline-block;
    min-width: 2rem;
    color: var(--muted);
  }

  .advice {
    margin: 0.35rem 0;
    border-left: 3px solid var(--accent);
    padding-left: 0.6rem;
  }
</style>
