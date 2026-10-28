<script lang="ts">
  import { invoke, Channel } from "@tauri-apps/api/core";
  import { save } from "@tauri-apps/plugin-dialog";
  import type { SyslogEvent, SyslogMessageData } from "$lib/tools/types";

  const MAX_MESSAGES = 10000;

  let port = $state(5140);
  let udp = $state(true);
  let tcp = $state(true);

  let running = $state(false);
  let error = $state("");
  let status = $state("");

  interface Row {
    id: number;
    received: string;
    source: string;
    transport: string;
    data: SyslogMessageData;
  }

  let rows = $state<Row[]>([]);
  let nextId = 0;
  let listenerId = 0;

  // Filters.
  let filterText = $state("");
  // Minimum severity to show (0 = emerg .. 7 = debug); 8 = show all.
  let minSeverity = $state(8);

  const SEV_OPTIONS = [
    { value: 8, label: "All severities" },
    { value: 0, label: "emerg and worse" },
    { value: 1, label: "alert and worse" },
    { value: 2, label: "crit and worse" },
    { value: 3, label: "err and worse" },
    { value: 4, label: "warning and worse" },
    { value: 5, label: "notice and worse" },
    { value: 6, label: "info and worse" },
    { value: 7, label: "debug and worse" },
  ];

  const filtered = $derived(
    rows.filter((r) => {
      if (minSeverity < 8 && r.data.severity !== null && r.data.severity > minSeverity) {
        return false;
      }
      if (filterText.trim().length > 0) {
        return r.data.raw.toLowerCase().includes(filterText.toLowerCase());
      }
      return true;
    }),
  );

  function sevClass(sev: number | null): string {
    if (sev === null) return "none";
    if (sev <= 3) return "high"; // emerg/alert/crit/err
    if (sev === 4) return "warn";
    return "low"; // notice/info/debug
  }

  async function start() {
    error = "";
    rows = [];
    running = true;
    listenerId = Math.floor(Math.random() * 0x7fffffff);

    const channel = new Channel<SyslogEvent>();
    channel.onmessage = (ev) => {
      switch (ev.type) {
        case "started":
          status = `Listening on port ${ev.port} (${[ev.udp && "UDP", ev.tcp && "TCP"].filter(Boolean).join(" + ")})`;
          break;
        case "message": {
          const row: Row = {
            id: nextId++,
            received: new Date().toLocaleTimeString(),
            source: ev.source,
            transport: ev.transport,
            data: ev.data,
          };
          // Newest first, capped.
          rows = [row, ...rows].slice(0, MAX_MESSAGES);
          break;
        }
        case "stopped":
          status = "Stopped.";
          break;
      }
    };

    try {
      await invoke("syslog_start", { listenerId, port, udp, tcp, onEvent: channel });
    } catch (e) {
      error = String(e);
      status = "";
    } finally {
      running = false;
    }
  }

  async function stop() {
    try {
      await invoke("syslog_stop", { listenerId });
    } catch {
      // ignore
    }
  }

  async function saveLog() {
    try {
      const path = await save({
        defaultPath: "syslog.txt",
        filters: [{ name: "Text", extensions: ["txt", "log"] }],
      });
      if (typeof path !== "string") return;
      // Save in chronological order (oldest first).
      const contents = filtered
        .map((r) => r.data.raw)
        .reverse()
        .join("\n");
      await invoke("syslog_save", { path, contents });
    } catch (e) {
      error = String(e);
    }
  }

  function clearLog() {
    rows = [];
  }
</script>

<div class="panel">
  <header>
    <h1>Syslog Server</h1>
    <p class="sub">
      Collect syslog messages over UDP and TCP. Port 5140 avoids needing admin
      rights; set 514 if you can bind privileged ports.
    </p>
  </header>

  <div class="controls">
    <div class="field">
      <label for="port">Port</label>
      <input id="port" type="number" min="1" max="65535" bind:value={port} disabled={running} />
    </div>
    <label class="opt"><input type="checkbox" bind:checked={udp} disabled={running} /> UDP</label>
    <label class="opt"><input type="checkbox" bind:checked={tcp} disabled={running} /> TCP</label>
    {#if running}
      <button class="action stop" onclick={stop}>Stop</button>
    {:else}
      <button class="action" onclick={start}>Start</button>
    {/if}
  </div>

  {#if error}
    <div class="error mono">{error}</div>
  {/if}
  {#if status}
    <div class="status" class:live={running}>
      {#if running}<span class="pulse"></span>{/if}{status}
    </div>
  {/if}

  <div class="toolbar">
    <input
      class="filter"
      bind:value={filterText}
      placeholder="Filter text..."
      spellcheck="false"
    />
    <select bind:value={minSeverity}>
      {#each SEV_OPTIONS as o (o.value)}
        <option value={o.value}>{o.label}</option>
      {/each}
    </select>
    <span class="count muted">{filtered.length.toLocaleString()} shown</span>
    <button class="small" onclick={saveLog} disabled={filtered.length === 0}>Save</button>
    <button class="small" onclick={clearLog} disabled={rows.length === 0}>Clear</button>
  </div>

  <div class="table-scroll">
    <table>
      <thead>
        <tr>
          <th>Received</th>
          <th>Source</th>
          <th></th>
          <th>Severity</th>
          <th>Host</th>
          <th>Tag</th>
          <th>Message</th>
        </tr>
      </thead>
      <tbody>
        {#each filtered as r (r.id)}
          <tr>
            <td class="mono dim">{r.received}</td>
            <td class="mono">{r.source}</td>
            <td class="dim">{r.transport}</td>
            <td><span class="sev {sevClass(r.data.severity)}">{r.data.severityName ?? "-"}</span></td>
            <td class="mono">{r.data.host ?? ""}</td>
            <td class="mono">{r.data.tag ?? ""}</td>
            <td class="mono msg">{r.data.message}</td>
          </tr>
        {/each}
      </tbody>
    </table>
    {#if rows.length === 0}
      <p class="empty">
        {running ? "Waiting for messages..." : "Start the server, then point a device or app at this host."}
      </p>
    {/if}
  </div>
</div>

<style>
  .panel {
    padding: 1.5rem 2rem;
    max-width: 1100px;
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

  .action {
    margin-left: auto;
    background: var(--accent);
    border: 1px solid var(--accent);
    border-radius: 6px;
    padding: 0.5rem 1.2rem;
    color: #fff;
    font-weight: 600;
    font-size: 0.85rem;
    cursor: pointer;
  }

  .action.stop {
    background: var(--btn-bg);
    border-color: var(--error-border);
    color: var(--error-fg);
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

  .toolbar {
    display: flex;
    align-items: center;
    gap: 0.6rem;
    margin-bottom: 0.6rem;
  }

  .filter {
    flex: 1 1 auto;
    background: var(--input-bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.4rem 0.6rem;
    color: var(--fg);
    font-size: 0.85rem;
  }

  select {
    background: var(--input-bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.4rem 0.5rem;
    color: var(--fg);
    font-size: 0.82rem;
  }

  .count {
    font-size: 0.8rem;
    white-space: nowrap;
  }

  .muted {
    color: var(--muted);
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

  .small:disabled {
    opacity: 0.5;
    cursor: default;
  }

  .table-scroll {
    border: 1px solid var(--border);
    border-radius: 6px;
    overflow: auto;
    max-height: 60vh;
  }

  table {
    border-collapse: collapse;
    width: 100%;
    font-size: 0.8rem;
  }

  th {
    text-align: left;
    color: var(--muted);
    font-weight: 500;
    padding: 0.4rem 0.6rem;
    border-bottom: 1px solid var(--border);
    position: sticky;
    top: 0;
    background: var(--sidebar-bg);
    white-space: nowrap;
  }

  td {
    padding: 0.3rem 0.6rem;
    border-bottom: 1px solid var(--border);
    vertical-align: top;
  }

  tr:last-child td {
    border-bottom: none;
  }

  .dim {
    color: var(--muted);
    white-space: nowrap;
  }

  .msg {
    word-break: break-word;
  }

  .sev {
    font-size: 0.68rem;
    font-weight: 700;
    padding: 0.05rem 0.4rem;
    border-radius: 4px;
    color: #fff;
    white-space: nowrap;
  }

  .sev.high {
    background: #c0392b;
  }
  .sev.warn {
    background: #b7791f;
  }
  .sev.low {
    background: #2563eb;
  }
  .sev.none {
    background: var(--muted);
  }

  .empty {
    padding: 1.5rem;
    text-align: center;
    color: var(--muted);
    font-size: 0.85rem;
  }
</style>
