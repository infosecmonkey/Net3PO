<script lang="ts">
  import { invoke, Channel } from "@tauri-apps/api/core";
  import { open } from "@tauri-apps/plugin-dialog";
  import type { TftpEvent } from "$lib/tools/types";

  let port = $state(69);
  let root = $state("");
  let writable = $state(false);

  let running = $state(false);
  let error = $state("");
  let status = $state("");
  let serverId = 0;

  interface Transfer {
    id: number;
    file: string;
    client: string;
    direction: string;
    bytes: number;
    state: "active" | "done" | "failed";
    message: string;
  }

  let transfers = $state<Transfer[]>([]);

  function upsert(id: number, patch: Partial<Transfer>) {
    const i = transfers.findIndex((t) => t.id === id);
    if (i >= 0) {
      transfers[i] = { ...transfers[i], ...patch };
      transfers = [...transfers];
    }
  }

  async function chooseFolder() {
    try {
      const picked = await open({ directory: true, multiple: false });
      if (typeof picked === "string") root = picked;
    } catch (e) {
      error = String(e);
    }
  }

  async function start() {
    if (root.trim().length === 0) {
      error = "Choose a folder to serve first.";
      return;
    }
    error = "";
    transfers = [];
    running = true;
    serverId = Math.floor(Math.random() * 0x7fffffff);

    const channel = new Channel<TftpEvent>();
    channel.onmessage = (ev) => {
      switch (ev.type) {
        case "started":
          status = `Serving ${ev.root} on UDP ${ev.port} (${ev.writable ? "read + write" : "read-only"})`;
          break;
        case "transferStart":
          transfers = [
            {
              id: ev.id,
              file: ev.file,
              client: ev.client,
              direction: ev.direction,
              bytes: 0,
              state: "active",
              message: "",
            },
            ...transfers,
          ];
          break;
        case "transferProgress":
          upsert(ev.id, { bytes: ev.bytes });
          break;
        case "transferEnd":
          upsert(ev.id, {
            bytes: ev.bytes,
            state: ev.ok ? "done" : "failed",
            message: ev.message,
          });
          break;
        case "stopped":
          status = "Stopped.";
          break;
      }
    };

    try {
      await invoke("tftp_start", { serverId, port, root, writable, onEvent: channel });
    } catch (e) {
      error = String(e);
      status = "";
    } finally {
      running = false;
    }
  }

  async function stop() {
    try {
      await invoke("tftp_stop", { serverId });
    } catch {
      // ignore
    }
  }

  function fmtBytes(n: number): string {
    if (n < 1024) return `${n} B`;
    if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
    return `${(n / 1024 / 1024).toFixed(1)} MB`;
  }
</script>

<div class="panel">
  <header>
    <h1>TFTP Server</h1>
    <p class="sub">
      Serve files from a folder over TFTP (UDP 69). Read-only unless you enable
      writes. Access is confined to the chosen folder.
    </p>
  </header>

  <div class="folder">
    <button class="secondary" onclick={chooseFolder} disabled={running}>Choose folder</button>
    <span class="path mono">{root || "no folder chosen"}</span>
  </div>

  <div class="controls">
    <div class="field">
      <label for="port">Port</label>
      <input id="port" type="number" min="1" max="65535" bind:value={port} disabled={running} />
    </div>
    <label class="opt">
      <input type="checkbox" bind:checked={writable} disabled={running} /> Writable (accept uploads)
    </label>
    {#if running}
      <button class="action stop" onclick={stop}>Stop</button>
    {:else}
      <button class="action" onclick={start}>Start</button>
    {/if}
  </div>

  {#if error}
    <div class="error mono">{error}</div>
    {#if error.toLowerCase().includes("permission")}
      <button class="small fallback" onclick={() => { port = 6969; error = ""; }}>
        Use port 6969 (no admin needed)
      </button>
    {/if}
  {/if}
  {#if status}
    <div class="status" class:live={running}>
      {#if running}<span class="pulse"></span>{/if}{status}
    </div>
  {/if}

  {#if writable && !running}
    <p class="warn-note">
      Writable is on: any client that can reach this port can create or overwrite
      files in the chosen folder.
    </p>
  {/if}

  <div class="table-scroll">
    <table>
      <thead>
        <tr><th>Dir</th><th>File</th><th>Client</th><th>Size</th><th>Status</th></tr>
      </thead>
      <tbody>
        {#each transfers as t (t.id)}
          <tr>
            <td>{t.direction === "read" ? "GET" : "PUT"}</td>
            <td class="mono">{t.file}</td>
            <td class="mono dim">{t.client}</td>
            <td class="mono num">{fmtBytes(t.bytes)}</td>
            <td><span class="state {t.state}">{t.state === "failed" ? t.message || "failed" : t.state}</span></td>
          </tr>
        {/each}
      </tbody>
    </table>
    {#if transfers.length === 0}
      <p class="empty">
        {running ? "Waiting for transfers..." : "Choose a folder and Start, then point a device at this host."}
      </p>
    {/if}
  </div>
</div>

<style>
  .panel {
    padding: 1.5rem 2rem;
    max-width: 900px;
  }

  header h1 {
    margin: 0 0 0.25rem;
    font-size: 1.3rem;
  }

  .sub {
    margin: 0 0 1.25rem;
    color: var(--muted);
    font-size: 0.85rem;
  }

  .folder {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    margin-bottom: 0.9rem;
  }

  .path {
    font-size: 0.82rem;
    color: var(--muted);
    word-break: break-all;
  }

  .controls {
    display: flex;
    align-items: flex-end;
    gap: 1rem;
    margin-bottom: 0.9rem;
  }

  .field {
    display: flex;
    flex-direction: column;
  }

  label {
    font-size: 0.8rem;
    color: var(--muted);
    margin-bottom: 0.35rem;
  }

  .opt {
    display: flex;
    align-items: center;
    gap: 0.35rem;
    color: var(--fg);
    margin: 0 0 0.4rem;
    font-size: 0.85rem;
  }

  input[type="number"] {
    width: 6rem;
    background: var(--input-bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.5rem 0.6rem;
    color: var(--fg);
    font-size: 0.9rem;
  }

  .mono {
    font-family: var(--mono);
  }

  .secondary {
    background: var(--btn-bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.5rem 0.9rem;
    color: var(--fg);
    font-size: 0.85rem;
    cursor: pointer;
  }

  .secondary:disabled {
    opacity: 0.5;
    cursor: default;
  }

  .action {
    margin-left: auto;
    background: var(--accent);
    border: 1px solid var(--accent);
    border-radius: 6px;
    padding: 0.5rem 1.2rem;
    color: var(--accent-fg);
    font-weight: 600;
    font-size: 0.85rem;
    cursor: pointer;
  }

  .action.stop {
    background: var(--btn-bg);
    border-color: var(--error-border);
    color: var(--error-fg);
  }

  .small {
    background: var(--btn-bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.4rem 0.7rem;
    color: var(--fg);
    font-size: 0.8rem;
    cursor: pointer;
  }

  .fallback {
    margin: -0.4rem 0 0.9rem;
  }

  .error {
    background: var(--error-bg);
    border: 1px solid var(--error-border);
    color: var(--error-fg);
    border-radius: 6px;
    padding: 0.6rem 0.8rem;
    font-size: 0.82rem;
    margin-bottom: 0.9rem;
    white-space: pre-wrap;
  }

  .status {
    font-size: 0.82rem;
    color: var(--muted);
    margin-bottom: 0.9rem;
    display: flex;
    align-items: center;
    gap: 0.4rem;
  }

  .status.live {
    color: var(--fg);
  }

  .pulse {
    width: 0.5rem;
    height: 0.5rem;
    border-radius: 50%;
    background: #15935a;
    display: inline-block;
    animation: pulse 1.2s ease-in-out infinite;
  }

  @keyframes pulse {
    0%,
    100% {
      opacity: 1;
    }
    50% {
      opacity: 0.3;
    }
  }

  .warn-note {
    font-size: 0.78rem;
    color: var(--error-fg);
    margin: 0 0 0.9rem;
    max-width: 620px;
  }

  .table-scroll {
    border: 1px solid var(--border);
    border-radius: 6px;
    overflow: auto;
    max-height: 55vh;
  }

  table {
    border-collapse: collapse;
    width: 100%;
    font-size: 0.82rem;
  }

  th {
    text-align: left;
    color: var(--muted);
    font-weight: 500;
    padding: 0.4rem 0.75rem;
    border-bottom: 1px solid var(--border);
    white-space: nowrap;
  }

  td {
    padding: 0.35rem 0.75rem;
    border-bottom: 1px solid var(--border);
  }

  tr:last-child td {
    border-bottom: none;
  }

  .dim {
    color: var(--muted);
  }

  .num {
    text-align: right;
  }

  .state {
    font-size: 0.72rem;
    font-weight: 600;
    padding: 0.05rem 0.4rem;
    border-radius: 4px;
    color: #fff;
  }

  .state.active {
    background: #2563eb;
  }
  .state.done {
    background: #15935a;
  }
  .state.failed {
    background: #c0392b;
  }

  .empty {
    padding: 1.5rem;
    text-align: center;
    color: var(--muted);
    font-size: 0.85rem;
  }
</style>
