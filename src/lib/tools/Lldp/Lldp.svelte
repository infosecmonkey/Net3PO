<script lang="ts">
  import { invoke, Channel } from "@tauri-apps/api/core";
  import { open } from "@tauri-apps/plugin-dialog";
  import ExportMenu from "$lib/components/ExportMenu.svelte";
  import {
    buildLldpReport,
    headline,
    key,
    rows,
    type FileResult,
    type LldpEvent,
    type Seen,
    type Status,
  } from "./model";

  let status = $state<Status | null>(null);
  let device = $state("");
  let seconds = $state(65);
  let running = $state(false);
  let reading = $state(false);
  let error = $state("");
  let warnings = $state<string[]>([]);
  let neighbors = $state<Seen[]>([]);
  let line = $state("");
  let source = $state("");
  let finished = $state(false);
  let started = 0;
  let elapsed = $state(0);
  let timer: ReturnType<typeof setInterval> | undefined;
  let runId = 0;

  async function loadStatus() {
    try {
      status = await invoke<Status>("lldp_status");
      if (!device && status.devices.length) {
        const pick = status.devices.find((d) => d.up) ?? status.devices[0];
        device = pick.name;
      }
    } catch (e) {
      error = String(e);
    }
  }

  $effect(() => {
    void loadStatus();
    return () => clearInterval(timer);
  });

  function label(d: { name: string; description: string }): string {
    // Windows names are \Device\NPF_{GUID}; the description is the readable part.
    if (d.name.startsWith("\\Device\\")) return d.description || d.name;
    return d.description ? `${d.name} (${d.description})` : d.name;
  }

  function upsert(s: Seen) {
    const k = key(s.neighbor);
    const i = neighbors.findIndex((x) => key(x.neighbor) === k);
    if (i >= 0) neighbors[i] = s;
    else neighbors = [...neighbors, s];
  }

  function reset() {
    error = "";
    warnings = [];
    neighbors = [];
    finished = false;
  }

  async function listen() {
    if (!device) {
      error = "Choose an interface.";
      return;
    }
    reset();
    running = true;
    const d = status?.devices.find((x) => x.name === device);
    source = d ? label(d) : device;
    line = `Opening ${source}`;
    runId = Math.floor(Math.random() * 0x7fffffff);
    started = Date.now();
    elapsed = 0;
    timer = setInterval(() => (elapsed = Math.floor((Date.now() - started) / 1000)), 1000);

    const channel = new Channel<LldpEvent>();
    channel.onmessage = (ev) => {
      switch (ev.type) {
        case "started":
          line = `Listening on ${source}`;
          break;
        case "neighbor":
          upsert(ev.seen);
          break;
        case "warning":
          if (warnings.length < 20) warnings = [...warnings, ev.message];
          break;
        case "done":
          line = `${ev.cancelled ? "Stopped" : "Finished"} after ${elapsed} s: ${ev.frames} discovery frame${ev.frames === 1 ? "" : "s"}, ${neighbors.length} neighbor${neighbors.length === 1 ? "" : "s"}.`;
          finished = true;
          break;
      }
    };
    try {
      await invoke("lldp_listen", { runId, device, seconds, onEvent: channel });
    } catch (e) {
      error = String(e);
      line = "";
    } finally {
      running = false;
      clearInterval(timer);
    }
  }

  async function stop() {
    await invoke("lldp_stop", { runId });
  }

  async function openFile() {
    const path = await open({
      multiple: false,
      filters: [{ name: "Capture", extensions: ["pcap", "pcapng", "cap", "dmp"] }],
    });
    if (typeof path !== "string") return;
    reset();
    reading = true;
    source = path.split(/[\\/]/).pop() ?? path;
    line = `Reading ${source}`;
    try {
      const r = await invoke<FileResult>("lldp_read_file", { path });
      neighbors = r.neighbors;
      warnings = r.warnings;
      line = `${r.format}: ${r.packets} packets, ${r.frames} discovery frame${r.frames === 1 ? "" : "s"}, ${r.neighbors.length} neighbor${r.neighbors.length === 1 ? "" : "s"}.`;
      finished = true;
    } catch (e) {
      error = String(e);
      line = "";
    } finally {
      reading = false;
    }
  }

  const remaining = $derived(seconds > 0 ? Math.max(0, seconds - elapsed) : null);
</script>

<div class="panel">
  <header>
    <h1>LLDP / CDP Neighbors</h1>
    <p class="sub">
      See which switch and port this computer is plugged into, from the LLDP or CDP
      announcements the switch sends: port, VLANs, voice VLAN, PoE, management address.
      Listen live (needs libpcap or Npcap) or open a capture file.
    </p>
  </header>

  {#if status && !status.available}
    <div class="warn">
      <strong>Live capture is not available.</strong>
      <div class="pre">{status.error}</div>
      <div class="small">You can still open a capture file. <button class="link" onclick={loadStatus}>Check again</button></div>
    </div>
  {/if}

  <div class="grid">
    <div class="field grow">
      <label for="lldp-dev">Interface</label>
      <select id="lldp-dev" bind:value={device} disabled={running || !status?.available}>
        {#if !status?.devices.length}<option value="">No interfaces</option>{/if}
        {#each status?.devices ?? [] as d (d.name)}
          <option value={d.name}>{label(d)}{d.up ? "" : " (down)"}</option>
        {/each}
      </select>
    </div>
    <div class="field">
      <label for="lldp-secs">Listen for</label>
      <select id="lldp-secs" bind:value={seconds} disabled={running}>
        <option value={35}>35 s (LLDP)</option>
        <option value={65}>65 s (LLDP and CDP)</option>
        <option value={0}>Until stopped</option>
      </select>
    </div>
  </div>

  <div class="row">
    {#if running}
      <button class="action stop" onclick={stop}>Stop</button>
    {:else}
      <button class="action" onclick={listen} disabled={!status?.available || !device || reading}>Listen</button>
    {/if}
    <button class="secondary" onclick={openFile} disabled={running || reading}>Open capture file...</button>
    {#if line}
      <span class="muted small mono">
        {line}{running ? `... ${remaining !== null ? `${remaining} s left` : `${elapsed} s`}` : ""}
      </span>
    {/if}
    {#if status?.version}<span class="muted small spacer">{status.version}</span>{/if}
  </div>

  {#if error}<div class="error mono">{error}</div>{/if}
  {#each warnings as w (w)}<div class="warn">{w}</div>{/each}

  {#if finished && neighbors.length === 0 && !error}
    <div class="verdict">
      No LLDP or CDP announcements. The switch port may have discovery turned off, the
      link may go through an unmanaged switch or media converter, or the interval is
      longer than the listen time (CDP sends every 60 s by default, LLDP every 30 s).
    </div>
  {/if}

  {#if neighbors.length > 0}
    <div class="export-row">
      <h2>Neighbors</h2>
      <ExportMenu build={() => buildLldpReport(neighbors, source, status?.version ?? "")} name="lldp-neighbors" />
    </div>
    {#each neighbors as s (key(s.neighbor))}
      {@const h = headline(s.neighbor)}
      <div class="card">
        <div class="title">
          <span class="badge">{s.neighbor.protocol}</span>
          <strong>{h.device}</strong>
          <span class="muted">port</span>
          <strong class="mono">{h.port}</strong>
        </div>
        <dl>
          {#each rows(s) as r (r.key)}
            <dt>{r.key}</dt>
            <dd class:mono={/address|MAC|ID|Port$/.test(r.key)}>{r.value}</dd>
          {/each}
        </dl>
      </div>
    {/each}
  {/if}
</div>

<style>
  .panel {
    padding: 1.5rem 2rem 2rem;
    box-sizing: border-box;
    width: 100%;
  }

  header h1 {
    margin: 0 0 0.25rem;
    font-size: 1.3rem;
  }

  h2 {
    font-size: 0.95rem;
    font-weight: 600;
    margin: 1.2rem 0 0.5rem;
  }

  .sub {
    margin: 0 0 1.25rem;
    color: var(--muted);
    font-size: 0.85rem;
  }

  .grid {
    display: flex;
    flex-wrap: wrap;
    gap: 0.75rem;
    margin-bottom: 0.75rem;
  }

  .field {
    display: flex;
    flex-direction: column;
    flex: 1 1 160px;
  }

  .field.grow {
    flex: 3 1 280px;
  }

  label {
    font-size: 0.78rem;
    color: var(--muted);
    margin-bottom: 0.3rem;
  }

  select {
    width: 100%;
    box-sizing: border-box;
    background: var(--input-bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.45rem 0.55rem;
    color: var(--fg);
    font-size: 0.88rem;
  }

  select:focus {
    outline: none;
    border-color: var(--accent);
  }

  select:disabled {
    opacity: 0.55;
  }

  .row {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 0.75rem;
    margin: 0.3rem 0 1rem;
  }

  .spacer {
    margin-left: auto;
  }

  .action {
    background: var(--accent);
    border: 1px solid var(--accent);
    border-radius: 6px;
    padding: 0.5rem 1.3rem;
    color: var(--accent-fg);
    font-weight: 600;
    font-size: 0.85rem;
    cursor: pointer;
  }

  .action:disabled,
  .secondary:disabled {
    opacity: 0.5;
    cursor: default;
  }

  .action.stop {
    background: var(--btn-bg);
    border-color: var(--error-border);
    color: var(--error-fg);
  }

  .secondary {
    background: var(--btn-bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.5rem 1.1rem;
    color: var(--fg);
    font-size: 0.85rem;
    cursor: pointer;
  }

  .link {
    background: none;
    border: none;
    padding: 0;
    color: var(--accent);
    cursor: pointer;
    font-size: inherit;
  }

  .mono {
    font-family: var(--mono);
  }

  .muted {
    color: var(--muted);
  }

  .small {
    font-size: 0.8rem;
  }

  .pre {
    white-space: pre-wrap;
    font-family: var(--mono);
    font-size: 0.78rem;
    margin: 0.35rem 0;
    user-select: text;
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
    user-select: text;
  }

  .warn {
    border: 1px solid #c69026;
    border-left-width: 3px;
    border-radius: 6px;
    padding: 0.5rem 0.75rem;
    font-size: 0.82rem;
    margin-bottom: 0.75rem;
  }

  .verdict {
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.6rem 0.8rem;
    font-size: 0.85rem;
    color: var(--muted);
  }

  .export-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
  }

  .card {
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 0.8rem 1rem;
    margin-bottom: 0.8rem;
    background: var(--sidebar-bg);
  }

  .title {
    display: flex;
    align-items: baseline;
    flex-wrap: wrap;
    gap: 0.45rem;
    font-size: 1rem;
    margin-bottom: 0.6rem;
  }

  .badge {
    font-size: 0.7rem;
    font-weight: 700;
    letter-spacing: 0.04em;
    border: 1px solid var(--accent);
    color: var(--accent);
    border-radius: 4px;
    padding: 0.05rem 0.35rem;
  }

  dl {
    display: grid;
    grid-template-columns: minmax(9rem, max-content) minmax(0, 1fr);
    gap: 0.25rem 1rem;
    margin: 0;
    font-size: 0.84rem;
  }

  dt {
    color: var(--muted);
  }

  dd {
    margin: 0;
    overflow-wrap: anywhere;
    white-space: pre-wrap;
    user-select: text;
  }
</style>
