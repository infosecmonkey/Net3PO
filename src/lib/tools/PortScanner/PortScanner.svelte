<script lang="ts">
  import { invoke, Channel } from "@tauri-apps/api/core";
  import ExportMenu from "$lib/components/ExportMenu.svelte";
  import type { ScanEvent } from "$lib/tools/types";
  import { buildScanReport } from "./report";
  import { selectOnFocus } from "$lib/actions/selectOnFocus";

  const PRESETS = ["polite", "normal", "aggressive"];

  let target = $state("");
  let ports = $state("common");
  let preset = $state("normal");

  interface OpenPort {
    host: string;
    port: number;
    service: string | null;
  }

  // Numeric-aware sort so 10.0.0.2 comes before 10.0.0.10, then by port.
  function ipKey(ip: string): number {
    const parts = ip.split(".");
    if (parts.length !== 4) return Number.MAX_SAFE_INTEGER;
    return parts.reduce((acc, p) => acc * 256 + (Number(p) || 0), 0);
  }
  function compareOpen(a: OpenPort, b: OpenPort): number {
    return ipKey(a.host) - ipKey(b.host) || a.port - b.port;
  }

  let scanning = $state(false);
  let openPorts = $state<OpenPort[]>([]);
  let progress = $state<{ done: number; total: number; open: number } | null>(null);
  let summary = $state<Extract<ScanEvent, { type: "done" }> | null>(null);
  let error = $state("");
  let currentScanId = 0;

  async function startScan() {
    if (target.trim().length === 0) {
      error = "Enter a host or IP to scan.";
      return;
    }
    openPorts = [];
    progress = null;
    summary = null;
    error = "";
    scanning = true;
    currentScanId = Math.floor(Math.random() * 0x7fffffff);

    const channel = new Channel<ScanEvent>();
    channel.onmessage = (ev) => {
      switch (ev.type) {
        case "open":
          // Keep the list sorted by host then port as results arrive.
          openPorts = [...openPorts, { host: ev.host, port: ev.port, service: ev.service }].sort(
            compareOpen,
          );
          break;
        case "progress":
          progress = { done: ev.done, total: ev.total, open: ev.open };
          break;
        case "done":
          summary = ev;
          scanning = false;
          break;
        case "error":
          error = ev.message;
          scanning = false;
          break;
      }
    };

    try {
      await invoke("port_scan", {
        scanId: currentScanId,
        target,
        ports,
        preset,
        onEvent: channel,
      });
    } catch (e) {
      error = String(e);
      scanning = false;
    }
  }

  async function cancelScan() {
    try {
      await invoke("port_scan_cancel", { scanId: currentScanId });
    } catch {
      // ignore; the scan will finish on its own shortly
    }
  }

  function onKeydown(e: KeyboardEvent) {
    if (e.key === "Enter" && !scanning) startScan();
  }

  const pct = $derived(
    progress && progress.total > 0 ? Math.round((progress.done / progress.total) * 100) : 0,
  );
</script>

<div class="panel">
  <header>
    <h1>Port Scanner</h1>
    <p class="sub">
      TCP connect scan of a single host. Only scan hosts you are authorized to
      test.
    </p>
  </header>

  <div class="fields">
    <div class="field grow">
      <label for="target">Host, IP, or subnet</label>
      <input
        id="target"
        class="mono"
        bind:value={target}
        onkeydown={onKeydown}
        spellcheck="false"
        autocapitalize="off"
        autocomplete="off"
        placeholder="10.0.0.1, host.example.com, or 10.0.0.0/24"
      />
    </div>
    <div class="field grow">
      <label for="ports">Ports</label>
      <input
        id="ports"
        class="mono"
        bind:value={ports}
        onkeydown={onKeydown}
        spellcheck="false"
        use:selectOnFocus
        placeholder="common, all, or 22,80,443,8000-8100"
      />
    </div>
  </div>

  <div class="row">
    <div class="presets">
      {#each PRESETS as p (p)}
        <button
          class="preset"
          class:active={preset === p}
          disabled={scanning}
          onclick={() => (preset = p)}
        >
          {p}
        </button>
      {/each}
    </div>
    {#if scanning}
      <button class="action cancel" onclick={cancelScan}>Cancel</button>
    {:else}
      <button class="action" onclick={startScan}>Scan</button>
    {/if}
  </div>

  {#if error}
    <div class="error mono">{error}</div>
  {/if}

  {#if progress}
    <div class="progress">
      <div class="bar"><div class="fill" style="width: {pct}%"></div></div>
      <div class="pline muted">
        {progress.done.toLocaleString()} / {progress.total.toLocaleString()} checks
        · {openPorts.length} open
        {#if scanning}· scanning...{/if}
      </div>
    </div>
  {/if}

  {#if openPorts.length > 0}
    <div class="table-scroll">
      <table>
        <thead>
          <tr><th>Host</th><th>Port</th><th>State</th><th>Service</th></tr>
        </thead>
        <tbody>
          {#each openPorts as p (p.host + ":" + p.port)}
            <tr>
              <td class="mono">{p.host}</td>
              <td class="mono">{p.port}</td>
              <td><span class="open-badge">open</span></td>
              <td class="mono">{p.service ?? ""}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}

  {#if summary}
    <p class="summary">
      {summary.cancelled ? "Cancelled" : "Done"}:
      {summary.open} open across {summary.hostsWithOpen} of {summary.hosts}
      host{summary.hosts === 1 ? "" : "s"}
      ({summary.total.toLocaleString()} host-port checks in {(summary.elapsedMs / 1000).toFixed(1)}s).
    </p>
    <ExportMenu
      build={() => buildScanReport({ target, ports, preset, open: openPorts, summary })}
      name={`scan-${target}`}
      disabled={scanning}
    />
  {/if}
</div>

<style>
  .panel {
    padding: 1.5rem 2rem;
    max-width: 820px;
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

  .fields {
    display: flex;
    flex-wrap: wrap;
    gap: 0.9rem;
    margin-bottom: 0.9rem;
  }

  .field {
    display: flex;
    flex-direction: column;
  }

  .field.grow {
    flex: 1 1 240px;
  }

  label {
    font-size: 0.8rem;
    color: var(--muted);
    margin-bottom: 0.35rem;
  }

  input {
    width: 100%;
    box-sizing: border-box;
    background: var(--input-bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.5rem 0.6rem;
    color: var(--fg);
    font-size: 0.9rem;
  }

  input:focus {
    outline: none;
    border-color: var(--accent);
  }

  .mono {
    font-family: var(--mono);
  }

  .row {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    margin-bottom: 1rem;
  }

  .presets {
    display: flex;
    gap: 0.4rem;
  }

  .preset {
    background: var(--input-bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.4rem 0.8rem;
    color: var(--fg);
    font-size: 0.8rem;
    text-transform: capitalize;
    cursor: pointer;
  }

  .preset.active {
    background: var(--accent);
    border-color: var(--accent);
    color: var(--accent-fg);
    font-weight: 600;
  }

  .preset:disabled {
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

  .action.cancel {
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

  .progress {
    margin-bottom: 1rem;
  }

  .bar {
    height: 6px;
    background: var(--hover);
    border-radius: 3px;
    overflow: hidden;
  }

  .fill {
    height: 100%;
    background: var(--accent);
    transition: width 0.2s ease;
  }

  .pline {
    font-size: 0.8rem;
    margin-top: 0.3rem;
  }

  .muted {
    color: var(--muted);
  }

  .table-scroll {
    border: 1px solid var(--border);
    border-radius: 6px;
    overflow: hidden;
  }

  table {
    border-collapse: collapse;
    width: 100%;
    font-size: 0.85rem;
  }

  th {
    text-align: left;
    color: var(--muted);
    font-weight: 500;
    padding: 0.4rem 0.75rem;
    border-bottom: 1px solid var(--border);
  }

  td {
    padding: 0.35rem 0.75rem;
    border-bottom: 1px solid var(--border);
  }

  tr:last-child td {
    border-bottom: none;
  }

  .open-badge {
    font-size: 0.7rem;
    font-weight: 700;
    color: #fff;
    background: #15935a;
    border-radius: 4px;
    padding: 0.05rem 0.4rem;
  }

  .summary {
    margin-top: 1rem;
    font-size: 0.85rem;
  }
</style>
