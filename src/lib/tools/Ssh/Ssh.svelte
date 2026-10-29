<script lang="ts">
  import { onMount } from "svelte";
  import { invoke } from "@tauri-apps/api/core";
  import { confirm, open } from "@tauri-apps/plugin-dialog";
  import { loadCollection, saveCollection } from "$lib/store";
  import { selectOnFocus } from "$lib/actions/selectOnFocus";
  import {
    closeTab,
    connect,
    ssh,
    type ConnectOutcome,
    type ConnectParams,
    type SshConnection,
    type SshGroup,
  } from "$lib/ssh/sessions.svelte";
  import TermView from "./TermView.svelte";

  let groups = $state<SshGroup[]>([]);
  let connections = $state<SshConnection[]>([]);
  let search = $state("");
  let collapsed = $state<Record<string, boolean>>({});
  let error = $state("");
  let busy = $state(false);
  let quick = $state("");

  // Connection editor.
  interface Form {
    mode: "new" | "edit";
    conn: SshConnection;
    secret: string;
    saveSecret: boolean;
    hasSecret: boolean;
  }
  let form = $state<Form | null>(null);

  // Group editor.
  let groupForm = $state<{ id: string | null; name: string } | null>(null);

  // Password or passphrase prompt before connecting.
  interface Prompt {
    conn: SshConnection;
    saved: boolean;
    message: string;
    secret: string;
    save: boolean;
  }
  let prompt = $state<Prompt | null>(null);

  // Host key confirmation.
  interface HostKey {
    outcome: Extract<ConnectOutcome, { type: "hostKey" }>;
    conn: SshConnection;
    saved: boolean;
    secret?: string;
    save?: boolean;
  }
  let hostKey = $state<HostKey | null>(null);

  const UNGROUPED = "__ungrouped";

  onMount(async () => {
    try {
      groups = (await loadCollection<SshGroup>("ssh_groups")).items;
      connections = (await loadCollection<SshConnection>("ssh_connections")).items;
    } catch (e) {
      error = String(e);
    }
  });

  async function persist() {
    try {
      await saveCollection("ssh_groups", groups);
      await saveCollection("ssh_connections", connections);
    } catch (e) {
      error = String(e);
    }
  }

  let tree = $derived.by(() => {
    const q = search.trim().toLowerCase();
    const match = (c: SshConnection) =>
      !q || `${c.name} ${c.host} ${c.user} ${c.notes}`.toLowerCase().includes(q);
    const sorted = [...groups].sort((a, b) => a.name.localeCompare(b.name));
    const out = sorted.map((g) => ({
      id: g.id,
      name: g.name,
      items: connections.filter((c) => c.groupId === g.id && match(c)).sort((a, b) => a.name.localeCompare(b.name)),
    }));
    const loose = connections
      .filter((c) => (!c.groupId || !groups.some((g) => g.id === c.groupId)) && match(c))
      .sort((a, b) => a.name.localeCompare(b.name));
    if (loose.length || !groups.length) out.push({ id: UNGROUPED, name: "Ungrouped", items: loose });
    return q ? out.filter((g) => g.items.length > 0) : out;
  });

  function blank(groupId: string | null): SshConnection {
    return { id: crypto.randomUUID(), groupId, name: "", host: "", port: 22, user: "", auth: "password", keyPath: "", notes: "" };
  }

  function newConnection(groupId: string | null = null) {
    error = "";
    form = { mode: "new", conn: blank(groupId === UNGROUPED ? null : groupId), secret: "", saveSecret: true, hasSecret: false };
  }

  async function editConnection(c: SshConnection) {
    error = "";
    const hasSecret = await invoke<boolean>("ssh_secret_has", { id: c.id }).catch(() => false);
    form = { mode: "edit", conn: { ...c }, secret: "", saveSecret: true, hasSecret };
  }

  async function saveForm() {
    if (!form) return;
    const c = form.conn;
    c.name = c.name.trim() || c.host.trim();
    c.host = c.host.trim();
    c.user = c.user.trim();
    c.port = Number(c.port) || 22;
    if (!c.host || !c.user) {
      error = "Host and user are required.";
      return;
    }
    if (c.port < 1 || c.port > 65535) {
      error = "Port must be 1 to 65535.";
      return;
    }
    try {
      if (form.secret && form.saveSecret) {
        await invoke("ssh_secret_set", { id: c.id, secret: form.secret });
      }
    } catch (e) {
      error = String(e);
      return;
    }
    const i = connections.findIndex((x) => x.id === c.id);
    if (i >= 0) connections[i] = c;
    else connections.push(c);
    form = null;
    error = "";
    await persist();
  }

  async function forgetSecret() {
    if (!form) return;
    await invoke("ssh_secret_delete", { id: form.conn.id }).catch((e) => (error = String(e)));
    form.hasSecret = false;
  }

  async function deleteConnection(c: SshConnection) {
    const ok = await confirm(`Delete connection "${c.name}"? Its saved password is removed from the keychain too.`, {
      title: "Delete connection",
      kind: "warning",
    });
    if (!ok) return;
    connections = connections.filter((x) => x.id !== c.id);
    await invoke("ssh_secret_delete", { id: c.id }).catch(() => {});
    await persist();
  }

  async function saveGroup() {
    if (!groupForm) return;
    const name = groupForm.name.trim();
    if (!name) return;
    if (groupForm.id) {
      const g = groups.find((x) => x.id === groupForm!.id);
      if (g) g.name = name;
    } else {
      groups.push({ id: crypto.randomUUID(), name });
    }
    groupForm = null;
    await persist();
  }

  async function deleteGroup(id: string) {
    const g = groups.find((x) => x.id === id);
    if (!g) return;
    const n = connections.filter((c) => c.groupId === id).length;
    const ok = await confirm(`Delete group "${g.name}"? Its ${n} connection${n === 1 ? "" : "s"} move to Ungrouped.`, {
      title: "Delete group",
      kind: "warning",
    });
    if (!ok) return;
    groups = groups.filter((x) => x.id !== id);
    for (const c of connections) if (c.groupId === id) c.groupId = null;
    await persist();
  }

  async function browseKey() {
    if (!form) return;
    const path = await open({ multiple: false });
    if (typeof path === "string") form.conn.keyPath = path;
  }

  function params(c: SshConnection, saved: boolean, secret?: string, save?: boolean, trust?: string): ConnectParams {
    return {
      connectionId: saved ? c.id : null,
      host: c.host,
      port: c.port,
      user: c.user,
      auth: c.auth,
      keyPath: c.keyPath,
      secret: secret || undefined,
      saveSecret: saved && !!save,
      trustFingerprint: trust,
    };
  }

  /** Start connecting: ask for a password first when none is saved. */
  async function start(c: SshConnection, saved = true) {
    error = "";
    if (c.auth === "password") {
      const has = saved ? await invoke<boolean>("ssh_secret_has", { id: c.id }).catch(() => false) : false;
      if (!has) {
        prompt = { conn: c, saved, message: "", secret: "", save: saved };
        return;
      }
    }
    await attempt(c, saved);
  }

  async function attempt(c: SshConnection, saved: boolean, secret?: string, save?: boolean, trust?: string) {
    busy = true;
    error = "";
    try {
      const out = await connect(params(c, saved, secret, save, trust), c.name || `${c.user}@${c.host}`);
      if (out.type === "hostKey") {
        hostKey = { outcome: out, conn: c, saved, secret, save };
      }
    } catch (e) {
      const msg = String(e);
      if (c.auth === "password" && /authentication failed|enter the password/i.test(msg)) {
        prompt = { conn: c, saved, message: msg, secret: "", save: !!save };
      } else if (c.auth === "key" && /passphrase|could not load the key/i.test(msg)) {
        prompt = { conn: c, saved, message: msg, secret: "", save: !!save };
      } else {
        error = msg;
      }
    } finally {
      busy = false;
    }
  }

  async function submitPrompt() {
    if (!prompt) return;
    const p = prompt;
    prompt = null;
    await attempt(p.conn, p.saved, p.secret, p.save);
  }

  async function trustHostKey() {
    if (!hostKey) return;
    const h = hostKey;
    hostKey = null;
    await attempt(h.conn, h.saved, h.secret, h.save, h.outcome.fingerprint);
  }

  /** `user@host[:port]` for a one-off, unsaved connection. */
  async function quickConnect() {
    const m = quick.trim().match(/^([^@\s]+)@(\[[^\]]+\]|[^:\s]+)(?::(\d+))?$/);
    if (!m) {
      error = "Quick connect takes user@host or user@host:port.";
      return;
    }
    const c: SshConnection = {
      id: crypto.randomUUID(),
      groupId: null,
      name: `${m[1]}@${m[2]}`,
      host: m[2],
      port: m[3] ? Number(m[3]) : 22,
      user: m[1],
      auth: "password",
      keyPath: "",
      notes: "",
    };
    await start(c, false);
  }

  function groupName(id: string | null): string {
    return groups.find((g) => g.id === id)?.name ?? "Ungrouped";
  }
</script>

<div class="panel">
  <aside>
    <div class="quick">
      <input
        bind:value={quick}
        placeholder="user@host:port"
        spellcheck="false"
        autocapitalize="off"
        autocomplete="off"
        onkeydown={(e) => e.key === "Enter" && quickConnect()}
      />
      <button class="small" onclick={quickConnect} disabled={busy}>Go</button>
    </div>
    <input class="search" bind:value={search} placeholder="Search connections" spellcheck="false" />
    <div class="aside-actions">
      <button class="small" onclick={() => newConnection(null)}>+ Connection</button>
      <button class="small" onclick={() => (groupForm = { id: null, name: "" })}>+ Group</button>
    </div>

    <div class="tree">
      {#each tree as g (g.id)}
        <div class="group">
          <div class="group-head">
            <button class="twisty" onclick={() => (collapsed[g.id] = !collapsed[g.id])}>
              <span class="chev">{collapsed[g.id] ? "+" : "-"}</span>
              <span class="gname">{g.name}</span>
              <span class="count">{g.items.length}</span>
            </button>
            {#if g.id !== UNGROUPED}
              <div class="row-actions">
                <button class="icon" title="Add connection" onclick={() => newConnection(g.id)}>+</button>
                <button class="icon" title="Rename group" onclick={() => (groupForm = { id: g.id, name: g.name })}>e</button>
                <button class="icon" title="Delete group" onclick={() => deleteGroup(g.id)}>x</button>
              </div>
            {/if}
          </div>
          {#if !collapsed[g.id]}
            {#each g.items as c (c.id)}
              <div class="conn">
                <button class="conn-main" onclick={() => start(c)} disabled={busy} title={c.notes || `${c.user}@${c.host}:${c.port}`}>
                  <span class="cname">{c.name}</span>
                  <span class="chost">{c.user}@{c.host}{c.port !== 22 ? `:${c.port}` : ""}</span>
                </button>
                <div class="row-actions">
                  <button class="icon" title="Edit" onclick={() => editConnection(c)}>e</button>
                  <button class="icon" title="Delete" onclick={() => deleteConnection(c)}>x</button>
                </div>
              </div>
            {:else}
              {#if !search}<p class="hint indent">No connections.</p>{/if}
            {/each}
          {/if}
        </div>
      {/each}
    </div>
  </aside>

  <section class="main">
    {#if error}
      <div class="error mono">{error}</div>
    {/if}
    {#if ssh.tabs.length > 0}
      <div class="tabs">
        {#each ssh.tabs as t (t.key)}
          <div class="tab" class:active={ssh.active === t.key}>
            <button class="tab-main" onclick={() => (ssh.active = t.key)}>
              <span class="dot" class:closed={t.status === "closed"}></span>
              {t.title}
            </button>
            <button class="tab-x" title="Close" onclick={() => closeTab(t.key)}>x</button>
          </div>
        {/each}
      </div>
      <div class="term-area">
        {#key ssh.active}
          {#if ssh.active !== null}
            <TermView tabKey={ssh.active} />
          {/if}
        {/key}
      </div>
    {:else}
      <div class="empty">
        <h1>SSH</h1>
        <p class="sub">
          Saved connections in groups, passwords in the OS keychain, host keys pinned on
          first connect. Click a connection to open it in a tab.
        </p>
        <p class="hint">
          Sessions keep running while you use other tools. The Fortinet Command Builder can
          send commands to the active session.
        </p>
      </div>
    {/if}
    {#if busy}<p class="hint busy">Connecting...</p>{/if}
  </section>
</div>

{#if form}
  <div class="overlay" role="presentation" onclick={(e) => e.target === e.currentTarget && (form = null)}>
    <div class="dialog" role="dialog" aria-modal="true" aria-label="Connection">
      <h2>{form.mode === "new" ? "New connection" : "Edit connection"}</h2>
      <div class="grid">
        <label>Name <input bind:value={form.conn.name} placeholder="Core switch" /></label>
        <label>
          Group
          <select bind:value={form.conn.groupId}>
            <option value={null}>Ungrouped</option>
            {#each groups as g (g.id)}<option value={g.id}>{g.name}</option>{/each}
          </select>
        </label>
        <label class="wide">Host <input class="mono" bind:value={form.conn.host} placeholder="10.0.0.1 or fw01.example.com" spellcheck="false" autocapitalize="off" /></label>
        <label>Port <input class="mono" type="number" min="1" max="65535" bind:value={form.conn.port} use:selectOnFocus /></label>
        <label>User <input class="mono" bind:value={form.conn.user} placeholder="admin" spellcheck="false" autocapitalize="off" /></label>
        <label>
          Authentication
          <select bind:value={form.conn.auth}>
            <option value="password">Password</option>
            <option value="key">Private key</option>
          </select>
        </label>
        {#if form.conn.auth === "key"}
          <label class="wide">
            Key file
            <span class="inline">
              <input class="mono" bind:value={form.conn.keyPath} placeholder="~/.ssh/id_ed25519" spellcheck="false" />
              <button class="small" onclick={browseKey}>Browse</button>
            </span>
          </label>
        {/if}
        <label class="wide">
          {form.conn.auth === "key" ? "Key passphrase" : "Password"}
          <input type="password" bind:value={form.secret} placeholder={form.hasSecret ? "Saved in keychain (type to replace)" : form.conn.auth === "key" ? "Leave empty if the key has none" : "Asked on connect if not saved"} autocomplete="off" />
        </label>
        <div class="wide row">
          <label class="check"><input type="checkbox" bind:checked={form.saveSecret} /> Save in OS keychain</label>
          {#if form.hasSecret}<button class="link" onclick={forgetSecret}>Remove saved secret</button>{/if}
        </div>
        <label class="wide">Notes <textarea bind:value={form.conn.notes} rows="2" placeholder="Site, rack, ticket"></textarea></label>
      </div>
      <div class="dialog-actions">
        <button class="small" onclick={() => (form = null)}>Cancel</button>
        <button class="primary" onclick={saveForm}>Save</button>
      </div>
    </div>
  </div>
{/if}

{#if groupForm}
  <div class="overlay" role="presentation" onclick={(e) => e.target === e.currentTarget && (groupForm = null)}>
    <div class="dialog small-dialog" role="dialog" aria-modal="true" aria-label="Group">
      <h2>{groupForm.id ? "Rename group" : "New group"}</h2>
      <!-- svelte-ignore a11y_autofocus -->
      <input bind:value={groupForm.name} placeholder="CustomerA" autofocus onkeydown={(e) => e.key === "Enter" && saveGroup()} />
      <div class="dialog-actions">
        <button class="small" onclick={() => (groupForm = null)}>Cancel</button>
        <button class="primary" onclick={saveGroup}>Save</button>
      </div>
    </div>
  </div>
{/if}

{#if prompt}
  <div class="overlay" role="presentation">
    <div class="dialog small-dialog" role="dialog" aria-modal="true" aria-label="Credentials">
      <h2>{prompt.conn.auth === "key" ? "Key passphrase" : "Password"}</h2>
      <p class="hint">{prompt.conn.user}@{prompt.conn.host}:{prompt.conn.port} ({groupName(prompt.conn.groupId)})</p>
      {#if prompt.message}<div class="error mono">{prompt.message}</div>{/if}
      <!-- svelte-ignore a11y_autofocus -->
      <input type="password" bind:value={prompt.secret} autofocus autocomplete="off" onkeydown={(e) => e.key === "Enter" && submitPrompt()} />
      {#if prompt.saved}
        <label class="check"><input type="checkbox" bind:checked={prompt.save} /> Save in OS keychain after a successful login</label>
      {/if}
      <div class="dialog-actions">
        <button class="small" onclick={() => (prompt = null)}>Cancel</button>
        <button class="primary" onclick={submitPrompt}>Connect</button>
      </div>
    </div>
  </div>
{/if}

{#if hostKey}
  <div class="overlay" role="presentation">
    <div class="dialog" role="dialog" aria-modal="true" aria-label="Host key">
      {#if hostKey.outcome.status === "new"}
        <h2>Verify host key</h2>
        <p>
          First connection to <span class="mono">{hostKey.conn.host}:{hostKey.conn.port}</span>. Check this
          fingerprint against the device (for example <span class="mono">get system status</span> or
          <span class="mono">ssh-keygen -lf</span> on the server) before trusting it.
        </p>
      {:else}
        <h2 class="danger-text">Host key changed</h2>
        <p>
          The key for <span class="mono">{hostKey.conn.host}:{hostKey.conn.port}</span> is different from the
          one pinned earlier. This happens after a rebuild or key regeneration, but it is also what an
          interception looks like. Confirm with the device owner before accepting.
        </p>
        <p class="hint">Previously pinned</p>
        <code class="fp mono">{hostKey.outcome.previous}</code>
      {/if}
      <p class="hint">{hostKey.outcome.status === "new" ? "Fingerprint" : "Presented now"} ({hostKey.outcome.algorithm})</p>
      <code class="fp mono">{hostKey.outcome.fingerprint}</code>
      <div class="dialog-actions">
        <button class="small" onclick={() => (hostKey = null)}>Cancel</button>
        <button class={hostKey.outcome.status === "new" ? "primary" : "danger"} onclick={trustHostKey}>
          {hostKey.outcome.status === "new" ? "Trust and connect" : "Accept new key and connect"}
        </button>
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

  .mono {
    font-family: var(--mono);
  }

  .quick {
    display: flex;
    gap: 0.3rem;
  }

  .quick input {
    font-family: var(--mono);
  }

  .aside-actions {
    display: flex;
    gap: 0.4rem;
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

  button.primary,
  button.danger {
    border: none;
    border-radius: 6px;
    font-weight: 600;
    font-size: 0.82rem;
    padding: 0.4rem 0.9rem;
    cursor: pointer;
  }

  button.primary {
    background: var(--accent);
    color: var(--accent-fg);
  }

  button.danger {
    background: #b91c1c;
    color: #fff;
  }

  .tree {
    display: flex;
    flex-direction: column;
    gap: 0.2rem;
  }

  .group-head,
  .conn {
    display: flex;
    align-items: center;
    gap: 0.2rem;
  }

  .row-actions {
    display: none;
    gap: 0.15rem;
  }

  .group-head:hover .row-actions,
  .conn:hover .row-actions {
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

  .conn-main {
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

  .conn-main:hover:not(:disabled) {
    background: var(--hover);
  }

  .cname {
    font-size: 0.82rem;
  }

  .chost {
    font-family: var(--mono);
    font-size: 0.7rem;
    color: var(--muted);
    max-width: 100%;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .main {
    display: flex;
    flex-direction: column;
    min-width: 0;
    min-height: 0;
  }

  .tabs {
    display: flex;
    gap: 0.2rem;
    padding: 0.4rem 0.5rem 0;
    border-bottom: 1px solid var(--border);
    overflow-x: auto;
  }

  .tab {
    display: flex;
    align-items: center;
    border: 1px solid var(--border);
    border-bottom: none;
    border-radius: 6px 6px 0 0;
    background: var(--sidebar-bg);
  }

  .tab.active {
    background: var(--input-bg);
    border-color: var(--accent);
  }

  .tab-main {
    display: flex;
    align-items: center;
    gap: 0.4rem;
    background: none;
    border: none;
    color: var(--fg);
    font-size: 0.78rem;
    padding: 0.35rem 0.5rem 0.35rem 0.7rem;
    cursor: pointer;
    white-space: nowrap;
  }

  .tab-x {
    background: none;
    border: none;
    color: var(--muted);
    cursor: pointer;
    font-size: 0.72rem;
    padding: 0 0.5rem;
  }

  .tab-x:hover {
    color: var(--fg);
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

  .term-area {
    flex: 1 1 auto;
    min-height: 0;
  }

  .empty {
    padding: 1.5rem 2rem;
    max-width: 640px;
  }

  .empty h1 {
    margin: 0 0 0.25rem;
    font-size: 1.3rem;
  }

  .sub {
    color: var(--muted);
    font-size: 0.85rem;
  }

  .hint {
    font-size: 0.76rem;
    color: var(--muted);
    margin: 0.3rem 0;
  }

  .indent {
    padding-left: 1.4rem;
  }

  .busy {
    padding: 0 1rem;
  }

  .error {
    margin: 0.6rem 0.8rem;
    background: var(--error-bg);
    border: 1px solid var(--error-border);
    color: var(--error-fg);
    border-radius: 6px;
    padding: 0.5rem 0.7rem;
    font-size: 0.8rem;
    white-space: pre-wrap;
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
    width: min(34rem, calc(100vw - 2rem));
    max-height: calc(100vh - 2rem);
    overflow-y: auto;
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 1.1rem 1.2rem;
    box-shadow: 0 10px 30px rgb(0 0 0 / 0.3);
    font-size: 0.85rem;
  }

  .small-dialog {
    width: min(24rem, calc(100vw - 2rem));
  }

  .dialog h2 {
    margin: 0 0 0.7rem;
    font-size: 1rem;
  }

  .danger-text {
    color: var(--error-fg);
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

  .inline {
    display: flex;
    gap: 0.3rem;
  }

  .row {
    display: flex;
    align-items: center;
    justify-content: space-between;
  }

  label.check {
    display: flex;
    flex-direction: row;
    align-items: center;
    gap: 0.35rem;
    color: var(--fg);
    font-size: 0.8rem;
    margin: 0.5rem 0;
  }

  label.check input {
    width: auto;
  }

  .link {
    background: none;
    border: none;
    color: var(--accent);
    cursor: pointer;
    font-size: 0.76rem;
    text-decoration: underline;
  }

  .fp {
    display: block;
    padding: 0.4rem 0.55rem;
    background: var(--input-bg);
    border: 1px solid var(--border);
    border-radius: 4px;
    font-size: 0.8rem;
    overflow-wrap: anywhere;
  }

  .dialog-actions {
    display: flex;
    justify-content: flex-end;
    gap: 0.5rem;
    margin-top: 1rem;
  }
</style>
