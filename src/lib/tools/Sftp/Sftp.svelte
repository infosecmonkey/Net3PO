<script lang="ts">
  import { onMount } from "svelte";
  import { invoke } from "@tauri-apps/api/core";
  import { confirm, open } from "@tauri-apps/plugin-dialog";
  import { loadCollection } from "$lib/store";
  import type { ConnectOutcome, ConnectParams, SshConnection } from "$lib/ssh/sessions.svelte";
  import GroupedList from "$lib/components/GroupedList.svelte";
  import { groupName, groups, groupTree, loadGroups } from "$lib/groups.svelte";
  import {
    cancel,
    clearFinished,
    disconnect,
    formatSize,
    formatTime,
    join,
    list,
    sftp,
    transfer,
    type Entry,
  } from "./state.svelte";

  let connections = $state<SshConnection[]>([]);
  let search = $state("");
  let quick = $state("");
  let busy = $state(false);
  let error = $state("");
  let pathInput = $state("");

  interface Prompt {
    conn: SshConnection;
    saved: boolean;
    message: string;
    secret: string;
    save: boolean;
  }
  let prompt = $state<Prompt | null>(null);

  interface HostKey {
    outcome: Extract<ConnectOutcome, { type: "hostKey" }>;
    conn: SshConnection;
    saved: boolean;
    secret?: string;
    save?: boolean;
  }
  let hostKey = $state<HostKey | null>(null);

  // New folder or rename.
  let nameForm = $state<{ mode: "mkdir" | "rename"; from: string; name: string } | null>(null);

  onMount(async () => {
    try {
      await loadGroups();
      connections = (await loadCollection<SshConnection>("ssh_connections")).items;
    } catch (e) {
      error = String(e);
    }
  });

  $effect(() => {
    pathInput = sftp.listing?.path ?? "";
  });

  let tree = $derived.by(() => {
    const q = search.trim().toLowerCase();
    const match = (c: SshConnection) =>
      !q || `${c.name} ${c.host} ${c.user} ${groupName(c.groupId)}`.toLowerCase().includes(q);
    return groupTree(connections, match, { searching: !!q, keepEmpty: false });
  });

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
      const out = await invoke<ConnectOutcome>("sftp_connect", { params: params(c, saved, secret, save, trust) });
      if (out.type === "hostKey") {
        hostKey = { outcome: out, conn: c, saved, secret, save };
        return;
      }
      if (sftp.session !== null) await disconnect();
      sftp.session = out.session;
      sftp.title = c.name || `${c.user}@${c.host}`;
      await list(".");
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

  async function quickConnect() {
    const m = quick.trim().match(/^([^@\s]+)@(\[[^\]]+\]|[^:\s]+)(?::(\d+))?$/);
    if (!m) {
      error = "Quick connect takes user@host or user@host:port.";
      return;
    }
    await start(
      {
        id: crypto.randomUUID(),
        groupId: null,
        name: `${m[1]}@${m[2]}`,
        host: m[2],
        port: m[3] ? Number(m[3]) : 22,
        user: m[1],
        auth: "password",
        keyPath: "",
        notes: "",
      },
      false,
    );
  }

  const cwd = $derived(sftp.listing?.path ?? ".");
  const isDir = (e: Entry) => e.kind === "dir" || e.linkDir;
  const selectedEntries = $derived(sftp.listing?.entries.filter((e) => sftp.selected.includes(e.name)) ?? []);
  const selectedFiles = $derived(selectedEntries.filter((e) => !isDir(e)));

  function select(e: Entry, ev: MouseEvent) {
    if (ev.metaKey || ev.ctrlKey) {
      sftp.selected = sftp.selected.includes(e.name)
        ? sftp.selected.filter((n) => n !== e.name)
        : [...sftp.selected, e.name];
    } else if (ev.shiftKey && sftp.selected.length && sftp.listing) {
      const names = sftp.listing.entries.map((x) => x.name);
      const a = names.indexOf(sftp.selected[sftp.selected.length - 1]);
      const b = names.indexOf(e.name);
      sftp.selected = names.slice(Math.min(a, b), Math.max(a, b) + 1);
    } else {
      sftp.selected = [e.name];
    }
  }

  async function activate(e: Entry) {
    if (isDir(e)) await list(join(cwd, e.name));
    else await download([e]);
  }

  async function up() {
    await list(join(cwd, ".."));
  }

  async function goTo() {
    const p = pathInput.trim();
    if (p) await list(p);
  }

  const askOverwrite = (path: string) =>
    confirm(`${path} already exists. Replace it?`, { title: "Replace file", kind: "warning" });

  async function download(entries: Entry[]) {
    const files = entries.filter((e) => !isDir(e));
    if (!files.length) return;
    const dir = await open({ directory: true, defaultPath: sftp.downloadDir || undefined, title: "Download to folder" });
    if (typeof dir !== "string") return;
    sftp.downloadDir = dir;
    for (const f of files) {
      if (sftp.session === null) break;
      await transfer("down", f.name, { remote: join(cwd, f.name), dir }, askOverwrite);
    }
  }

  async function upload() {
    const picked = await open({ multiple: true, title: "Upload files" });
    const paths = Array.isArray(picked) ? picked : typeof picked === "string" ? [picked] : [];
    if (!paths.length) return;
    const dir = cwd;
    let any = false;
    for (const p of paths) {
      if (sftp.session === null) break;
      const name = p.split(/[\\/]/).pop() ?? p;
      if (await transfer("up", name, { local: p, dir }, askOverwrite)) any = true;
    }
    if (any && sftp.listing?.path === dir) await list(dir);
  }

  async function submitName() {
    if (!nameForm || sftp.session === null) return;
    const f = nameForm;
    const name = f.name.trim();
    if (!name) return;
    try {
      if (f.mode === "mkdir") {
        await invoke("sftp_mkdir", { session: sftp.session, dir: cwd, name });
      } else if (name !== f.from) {
        await invoke("sftp_rename", { session: sftp.session, dir: cwd, from: f.from, to: name });
      }
      nameForm = null;
      await list(cwd);
    } catch (e) {
      sftp.error = String(e);
      nameForm = null;
    }
  }

  async function remove() {
    const items = selectedEntries;
    if (!items.length || sftp.session === null) return;
    const label = items.length === 1 ? `"${items[0].name}"` : `${items.length} items`;
    const ok = await confirm(`Delete ${label} from the server? This cannot be undone. Folders must be empty.`, {
      title: "Delete",
      kind: "warning",
    });
    if (!ok) return;
    for (const e of items) {
      try {
        await invoke("sftp_remove", { session: sftp.session, dir: cwd, name: e.name, folder: e.kind === "dir" });
      } catch (err) {
        sftp.error = String(err);
        break;
      }
    }
    await list(cwd);
    if (!sftp.error) sftp.selected = [];
  }

  function onKey(e: KeyboardEvent) {
    if (nameForm || prompt || hostKey || sftp.session === null) return;
    const t = e.target as HTMLElement;
    if (t.isContentEditable || t.tagName === "INPUT" || t.tagName === "TEXTAREA" || t.tagName === "SELECT") return;
    if (e.key === "Backspace" && (e.metaKey || e.ctrlKey)) {
      e.preventDefault();
      void remove();
    } else if (e.key === "Backspace" || (e.key === "ArrowUp" && e.altKey)) {
      e.preventDefault();
      void up();
    } else if (e.key === "Enter" && selectedEntries.length === 1) {
      e.preventDefault();
      void activate(selectedEntries[0]);
    } else if (e.key === "F2" && selectedEntries.length === 1) {
      e.preventDefault();
      nameForm = { mode: "rename", from: selectedEntries[0].name, name: selectedEntries[0].name };
    } else if (e.key === "F5") {
      e.preventDefault();
      void list(cwd);
    }
  }

  function pct(t: { done: number; total: number | null }): number {
    return t.total ? Math.min(100, (t.done / t.total) * 100) : 0;
  }

  function rate(t: { done: number; started: number }): string {
    const s = (Date.now() - t.started) / 1000;
    return s > 0.5 ? `${formatSize(Math.round(t.done / s))}/s` : "";
  }

  const hasFinished = $derived(sftp.transfers.some((t) => t.status !== "running"));
</script>

<svelte:window onkeydown={onKey} />

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
    {#if groups.list.length || connections.length}
      <GroupedList scope="sftp" branches={tree} manage={false} emptyText={search ? "No matches." : "No saved connections yet."}>
        {#snippet row(c: SshConnection)}
          <div class="conn">
            <button class="conn-main" onclick={() => start(c)} disabled={busy} title={c.notes || `${c.user}@${c.host}:${c.port}`}>
              <span class="cname">{c.name}</span>
              <span class="chost">{c.user}@{c.host}{c.port !== 22 ? `:${c.port}` : ""}</span>
            </button>
          </div>
        {/snippet}
      </GroupedList>
    {:else}
      <p class="hint">No saved connections yet.</p>
    {/if}
    <p class="hint">Saved connections, groups, passwords and pinned host keys are shared with the SSH tool. Add or edit them there.</p>
  </aside>

  <section class="main">
    {#if error}<div class="error mono">{error}</div>{/if}
    {#if sftp.session === null}
      <div class="empty">
        <h1>SFTP</h1>
        <p class="sub">
          Browse a server's files over SSH and move files both ways: configs, backups, firmware
          images, captures. Click a saved connection or use quick connect.
        </p>
        <p class="hint">
          The server must have the SFTP subsystem enabled (OpenSSH does by default; on network
          devices it is often a separate setting).
        </p>
        {#if busy}<p class="hint">Connecting...</p>{/if}
      </div>
    {:else}
      <div class="bar">
        <span class="dot"></span>
        <strong class="title">{sftp.title}</strong>
        <button class="small" onclick={disconnect}>Disconnect</button>
      </div>
      <div class="bar">
        <button class="small" onclick={up} title="Up one folder (Backspace)">Up</button>
        <input
          class="path mono"
          bind:value={pathInput}
          spellcheck="false"
          autocapitalize="off"
          onkeydown={(e) => e.key === "Enter" && goTo()}
        />
        <button class="small" onclick={() => list(cwd)} title="Refresh (F5)">Refresh</button>
      </div>
      <div class="bar">
        <button class="small" onclick={upload}>Upload...</button>
        <button class="small" onclick={() => download(selectedFiles)} disabled={!selectedFiles.length}>
          Download{selectedFiles.length > 1 ? ` (${selectedFiles.length})` : ""}
        </button>
        <button class="small" onclick={() => (nameForm = { mode: "mkdir", from: "", name: "" })}>New folder</button>
        <button
          class="small"
          disabled={selectedEntries.length !== 1}
          onclick={() => (nameForm = { mode: "rename", from: selectedEntries[0].name, name: selectedEntries[0].name })}
        >Rename</button>
        <button class="small" onclick={remove} disabled={!selectedEntries.length}>Delete</button>
        {#if sftp.loading}<span class="hint">Loading...</span>{/if}
      </div>
      {#if sftp.error}<div class="error mono">{sftp.error}</div>{/if}

      <div class="list">
        <table>
          <thead>
            <tr><th>Name</th><th class="num">Size</th><th>Modified</th><th>Permissions</th></tr>
          </thead>
          <tbody>
            {#each sftp.listing?.entries ?? [] as e (e.name)}
              <tr
                class:sel={sftp.selected.includes(e.name)}
                onclick={(ev) => select(e, ev)}
                ondblclick={() => activate(e)}
              >
                <td class="name">
                  <span class="kind" class:folder={isDir(e)}>{isDir(e) ? "▸" : ""}</span>{e.name}{e.kind === "link" ? " →" : ""}
                </td>
                <td class="num mono">{isDir(e) ? "" : formatSize(e.size)}</td>
                <td class="mono">{formatTime(e.mtime)}</td>
                <td class="mono">{e.perms}</td>
              </tr>
            {:else}
              <tr><td colspan="4" class="hint">Empty folder.</td></tr>
            {/each}
          </tbody>
        </table>
        {#if sftp.listing?.truncated}
          <p class="hint pad">Showing the first {sftp.listing.entries.length} entries only.</p>
        {/if}
      </div>
      <p class="hint pad">Double-click a folder to open it, or a file to download it. Ctrl or Cmd and Shift select several.</p>
    {/if}

    {#if sftp.transfers.length}
      <div class="transfers">
        <div class="thead">
          <strong>Transfers</strong>
          {#if hasFinished}<button class="link" onclick={clearFinished}>Clear finished</button>{/if}
        </div>
        {#each sftp.transfers as t (t.id)}
          <div class="trow">
            <span class="dir">{t.direction === "up" ? "↑" : "↓"}</span>
            <span class="tname" title={t.message || t.name}>{t.name}</span>
            {#if t.status === "running"}
              <span class="bar-wrap"><span class="fill" style:width={`${pct(t)}%`}></span></span>
              <span class="mono small">{formatSize(t.done)}{t.total !== null ? ` / ${formatSize(t.total)}` : ""} {rate(t)}</span>
              <button class="icon" onclick={() => cancel(t.id)}>Cancel</button>
            {:else}
              <span class="status {t.status}">
                {t.status === "done" ? `Done, ${formatSize(t.total)}` : t.status === "failed" ? "Failed" : "Stopped"}
              </span>
              {#if t.status !== "done" && t.message}<span class="small msg" title={t.message}>{t.message}</span>{/if}
            {/if}
          </div>
        {/each}
      </div>
    {/if}
  </section>
</div>

{#if nameForm}
  <div class="overlay" role="presentation" onclick={(e) => e.target === e.currentTarget && (nameForm = null)}>
    <div class="dialog small-dialog" role="dialog" aria-modal="true" aria-label="Name">
      <h2>{nameForm.mode === "mkdir" ? "New folder" : `Rename ${nameForm.from}`}</h2>
      <!-- svelte-ignore a11y_autofocus -->
      <input class="mono" bind:value={nameForm.name} placeholder="backups" autofocus spellcheck="false" onkeydown={(e) => e.key === "Enter" && submitName()} />
      <div class="dialog-actions">
        <button class="small" onclick={() => (nameForm = null)}>Cancel</button>
        <button class="primary" onclick={submitName}>{nameForm.mode === "mkdir" ? "Create" : "Rename"}</button>
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
          fingerprint against the device before trusting it.
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

  input {
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

  input:focus {
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
    padding: 0.05rem 0.45rem;
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

  .link {
    background: none;
    border: none;
    color: var(--accent);
    cursor: pointer;
    font-size: 0.76rem;
    text-decoration: underline;
  }






  .main {
    display: flex;
    flex-direction: column;
    min-width: 0;
    min-height: 0;
  }

  .bar {
    display: flex;
    align-items: center;
    gap: 0.4rem;
    padding: 0.45rem 0.8rem 0;
    flex-wrap: wrap;
  }

  .title {
    font-size: 0.9rem;
    margin-right: auto;
  }

  .dot {
    width: 0.5rem;
    height: 0.5rem;
    border-radius: 50%;
    background: #16a34a;
  }

  .path {
    flex: 1 1 12rem;
    width: auto;
  }

  .list {
    flex: 1 1 auto;
    min-height: 8rem;
    overflow: auto;
    margin: 0.6rem 0.8rem 0;
    border: 1px solid var(--border);
    border-radius: 6px;
  }

  table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.8rem;
  }

  th {
    position: sticky;
    top: 0;
    background: var(--sidebar-bg);
    text-align: left;
    font-weight: 600;
    color: var(--muted);
    font-size: 0.74rem;
    padding: 0.35rem 0.6rem;
    border-bottom: 1px solid var(--border);
  }

  td {
    padding: 0.28rem 0.6rem;
    white-space: nowrap;
    cursor: default;
    user-select: none;
  }

  td.name {
    white-space: normal;
    overflow-wrap: anywhere;
    width: 55%;
  }

  .num {
    text-align: right;
  }

  tr.sel td {
    background: color-mix(in srgb, var(--accent) 22%, transparent);
  }

  tbody tr:hover:not(.sel) td {
    background: var(--hover);
  }

  .kind {
    display: inline-block;
    width: 1rem;
    color: var(--muted);
  }

  .kind.folder {
    color: var(--accent);
  }

  .transfers {
    border-top: 1px solid var(--border);
    margin-top: 0.6rem;
    padding: 0.5rem 0.8rem;
    max-height: 30vh;
    overflow-y: auto;
    font-size: 0.78rem;
  }

  .thead {
    display: flex;
    justify-content: space-between;
    margin-bottom: 0.3rem;
  }

  .trow {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    padding: 0.15rem 0;
  }

  .tname {
    flex: 0 1 14rem;
    min-width: 4rem;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .bar-wrap {
    flex: 1 1 8rem;
    height: 0.4rem;
    background: var(--input-bg);
    border: 1px solid var(--border);
    border-radius: 3px;
    overflow: hidden;
  }

  .fill {
    display: block;
    height: 100%;
    background: var(--accent);
  }

  .status.done {
    color: #16a34a;
  }

  .status.failed {
    color: var(--error-fg);
  }

  .status.cancelled {
    color: var(--muted);
  }

  .msg {
    color: var(--muted);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    min-width: 0;
    flex: 1 1 auto;
  }

  .small {
    font-size: 0.74rem;
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

  .pad {
    padding: 0 0.8rem;
  }

  .error {
    margin: 0.6rem 0.8rem 0;
    background: var(--error-bg);
    border: 1px solid var(--error-border);
    color: var(--error-fg);
    border-radius: 6px;
    padding: 0.5rem 0.7rem;
    font-size: 0.8rem;
    white-space: pre-wrap;
    user-select: text;
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
    overflow-wrap: anywhere;
  }

  .danger-text {
    color: var(--error-fg);
  }

  label.check {
    display: flex;
    align-items: center;
    gap: 0.35rem;
    font-size: 0.8rem;
    margin: 0.5rem 0;
  }

  label.check input {
    width: auto;
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
