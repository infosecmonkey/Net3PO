<script lang="ts">
  // Continuous connectivity monitor: several targets, TCP/HTTP/ICMP probes
  // on an interval, latency graphs and outage windows. Stopping keeps the
  // history; starting again resumes into it.
  import { Channel, invoke } from "@tauri-apps/api/core";
  import { save } from "@tauri-apps/plugin-dialog";
  import ExportMenu from "$lib/components/ExportMenu.svelte";
  import { selectOnFocus } from "$lib/actions/selectOnFocus";
  import { buildMonitorReport } from "./report";
  import {
    clock,
    duration,
    KIND_LABEL,
    stats,
    targetLabel,
    toCsv,
    type Kind,
    type MonitorEvent,
    type Sample,
    type TargetDef,
  } from "./model";

  /** Samples kept per target; older ones are dropped. */
  const MAX_SAMPLES = 10_000;
  /** Samples drawn in each graph. */
  const GRAPH_POINTS = 300;
  const MAX_TARGETS = 20;

  let nextTarget = 1;
  let targets = $state<TargetDef[]>([{ id: nextTarget++, kind: "tcp", address: "", port: null }]);
  let intervalS = $state(5);
  let timeoutMs = $state(2000);

  let history = $state(new Map<number, Sample[]>());
  let dropped = $state(0);
  let overruns = $state(0);
  let icmpMethod = $state("");
  let running = $state(false);
  let error = $state("");
  let message = $state("");
  let runId = 0;
  let startedTargets = $state<TargetDef[]>([]);

  function addTarget() {
    if (targets.length < MAX_TARGETS) targets = [...targets, { id: nextTarget++, kind: "tcp", address: "", port: null }];
  }

  function removeTarget(id: number) {
    targets = targets.filter((t) => t.id !== id);
  }

  function setKind(t: TargetDef, k: Kind) {
    t.kind = k;
    targets = [...targets];
  }

  async function start() {
    const active = targets.filter((t) => t.address.trim());
    if (!active.length) {
      error = "Add at least one target.";
      return;
    }
    error = "";
    message = "";
    startedTargets = active.map((t) => ({ ...t, address: t.address.trim() }));
    runId = Math.floor(Math.random() * 0x7fffffff);
    running = true;
    const ch = new Channel<MonitorEvent>();
    ch.onmessage = (ev) => {
      if (ev.type === "started") icmpMethod = ev.icmpMethod;
      if (ev.type === "overrun") overruns++;
      if (ev.type === "sample") {
        const s = ev.sample;
        const list = history.get(s.target) ?? [];
        list.push(s);
        if (list.length > MAX_SAMPLES) {
          list.splice(0, list.length - MAX_SAMPLES);
          dropped++;
        }
        history.set(s.target, list);
        history = new Map(history);
      }
    };
    try {
      await invoke("mon_start", {
        id: runId,
        req: {
          targets: startedTargets.map((t) => ({ id: t.id, kind: t.kind, address: t.address, port: t.port ?? 0 })),
          intervalMs: Math.max(1, intervalS) * 1000,
          timeoutMs,
        },
        onEvent: ch,
      });
    } catch (e) {
      error = String(e);
    } finally {
      running = false;
    }
  }

  function stop() {
    void invoke("mon_stop", { id: runId });
  }

  function clear() {
    history = new Map();
    dropped = 0;
    overruns = 0;
  }

  async function exportCsv() {
    message = "";
    const path = await save({ defaultPath: "connectivity-samples.csv", filters: [{ name: "CSV", extensions: ["csv"] }] });
    if (!path) return;
    try {
      await invoke("mon_save", { path, contents: toCsv(shown, history) });
      message = `Saved ${path.split(/[\\/]/).pop()}`;
    } catch (e) {
      error = String(e);
    }
  }

  /** Targets with history, in the order they were configured. */
  const shown = $derived(
    [...startedTargets, ...targets].filter((t, i, all) => history.has(t.id) && all.findIndex((x) => x.id === t.id) === i),
  );

  function graph(samples: Sample[]): { points: string; fails: number[]; max: number; n: number } {
    const tail = samples.slice(-GRAPH_POINTS);
    const max = Math.max(1, ...tail.filter((s) => s.ok && s.ms !== null).map((s) => s.ms as number));
    const pts: string[] = [];
    const fails: number[] = [];
    tail.forEach((s, i) => {
      if (s.ok && s.ms !== null) pts.push(`${i},${(40 - (s.ms / max) * 36).toFixed(1)}`);
      else fails.push(i);
    });
    return { points: pts.join(" "), fails, max, n: Math.max(tail.length, 2) };
  }

  const fmt = (n: number | null) => (n === null ? "-" : `${n.toFixed(1)} ms`);
</script>

<div class="panel">
  <header>
    <h1>Connectivity Monitor</h1>
    <p class="sub">Probe several targets on an interval with TCP, HTTP or ICMP; graph latency and record outages.</p>
  </header>

  <div class="targets">
    {#each targets as t (t.id)}
      <div class="trow">
        <select value={t.kind} onchange={(e) => setKind(t, e.currentTarget.value as Kind)} disabled={running} aria-label="Probe type">
          <option value="tcp">TCP</option>
          <option value="http">HTTP</option>
          <option value="icmp">ICMP</option>
        </select>
        <input class="mono" bind:value={t.address} spellcheck="false" autocapitalize="off" disabled={running}
          placeholder={t.kind === "http" ? "https://host/health" : "hostname or IP"} aria-label="Address" />
        {#if t.kind === "tcp"}
          <input class="mono port" type="number" min="1" max="65535" bind:value={t.port} disabled={running} placeholder="port" aria-label="Port" />
        {:else}
          <span class="port"></span>
        {/if}
        <button class="mini" onclick={() => removeTarget(t.id)} disabled={running || targets.length === 1} aria-label="Remove target">×</button>
      </div>
    {/each}
    {#if targets.length < MAX_TARGETS && !running}
      <button class="link" onclick={addTarget}>+ Add target</button>
    {/if}
  </div>

  <div class="row">
    <label class="inline">Every (s) <input class="num mono" type="number" min="1" max="3600" bind:value={intervalS} use:selectOnFocus disabled={running} /></label>
    <label class="inline">Timeout (ms) <input class="num mono" type="number" min="200" max="30000" bind:value={timeoutMs} use:selectOnFocus disabled={running} /></label>
    <span class="spacer"></span>
    {#if running}
      <button class="second" onclick={stop}>Stop</button>
    {:else}
      <button class="run" onclick={start}>{history.size ? "Resume" : "Start"}</button>
      {#if history.size}<button class="second" onclick={clear}>Clear</button>{/if}
    {/if}
  </div>
  <p class="hint">
    TCP times the connect call; HTTP times the whole request and counts status below 400 as up;
    ICMP measures echo round trip{icmpMethod ? ` (${icmpMethod})` : ""}. A failed ICMP probe does
    not mean the service is down. Each target's probes never overlap; a slow probe delays the next.
  </p>

  {#if error}<div class="error mono">{error}</div>{/if}

  {#if shown.length}
    <div class="bar">
      <span class="muted small">
        {running ? "Running" : "Stopped"}{dropped ? ` · oldest samples dropped past ${MAX_SAMPLES} per target` : ""}{overruns ? ` · ${overruns} probes ran past the interval` : ""}
      </span>
      <span class="actions">
        {#if message}<span class="muted small">{message}</span>{/if}
        <button class="second small" onclick={exportCsv}>Export samples (CSV)</button>
        <ExportMenu build={() => buildMonitorReport(shown, history, intervalS)} name="connectivity" />
      </span>
    </div>

    {#each shown as t (t.id)}
      {@const samples = history.get(t.id) ?? []}
      {@const st = stats(samples)}
      {@const g = graph(samples)}
      {@const last = samples[samples.length - 1]}
      <div class="card">
        <div class="head">
          <span class="dot" class:up={last?.ok} class:down={last && !last.ok}></span>
          <span class="mono name">{targetLabel(t)}</span>
          <span class="muted small">{KIND_LABEL[t.kind]}</span>
          <span class="spacer"></span>
          <span class="small">{last ? (last.ok ? "up" : "down") : ""}{last ? ` · ${last.status}` : ""}</span>
        </div>
        <svg class="graph" viewBox="0 0 {g.n - 1} 40" preserveAspectRatio="none" role="img" aria-label="Latency">
          {#each g.fails as x (x)}<rect x={x - 0.4} y="0" width="0.8" height="40" class="fail" />{/each}
          {#if g.points}<polyline points={g.points} class="line" vector-effect="non-scaling-stroke" />{/if}
        </svg>
        <div class="stats small">
          <span>Success {st.samples ? ((100 * st.ok) / st.samples).toFixed(1) : "-"}% of {st.samples}</span>
          <span>Last {fmt(st.lastMs)}</span>
          <span>Min / avg / max {fmt(st.minMs)} / {fmt(st.avgMs)} / {fmt(st.maxMs)}</span>
          <span class="muted">graph peak {g.max.toFixed(1)} ms</span>
        </div>
        {#if last && !last.ok && last.detail}<div class="detail small">{last.detail}</div>{/if}
        {#if st.outages.length}
          <details>
            <summary>{st.outages.length} outage{st.outages.length === 1 ? "" : "s"}</summary>
            <table>
              <thead><tr><th>Start</th><th>End</th><th>Duration</th><th>Failed</th><th>First failure</th></tr></thead>
              <tbody>
                {#each st.outages as o (o.startMs)}
                  <tr>
                    <td>{clock(o.startMs)}</td>
                    <td>{o.endMs === null ? "ongoing" : clock(o.endMs)}</td>
                    <td>{o.endMs === null ? "-" : duration(o.endMs - o.startMs)}</td>
                    <td>{o.failures}</td>
                    <td>{o.firstStatus}</td>
                  </tr>
                {/each}
              </tbody>
            </table>
          </details>
        {/if}
      </div>
    {/each}
  {/if}
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

  input,
  select {
    box-sizing: border-box;
    background: var(--input-bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.42rem 0.6rem;
    color: var(--fg);
    font-size: 0.86rem;
  }

  input:focus,
  select:focus {
    outline: none;
    border-color: var(--accent);
  }

  .mono {
    font-family: var(--mono);
  }

  .targets {
    display: flex;
    flex-direction: column;
    gap: 0.35rem;
    margin-bottom: 0.7rem;
  }

  .trow {
    display: grid;
    grid-template-columns: 6rem 1fr 6.5rem auto;
    gap: 0.4rem;
  }

  .mini {
    background: var(--input-bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    color: var(--muted);
    padding: 0 0.6rem;
    cursor: pointer;
  }

  .link {
    align-self: flex-start;
    background: none;
    border: none;
    color: var(--accent);
    font-size: 0.8rem;
    padding: 0.2rem 0;
    cursor: pointer;
  }

  .row {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 0.6rem 1rem;
  }

  .inline {
    display: inline-flex;
    align-items: center;
    gap: 0.4rem;
    font-size: 0.8rem;
    color: var(--muted);
  }

  .num {
    width: 6rem;
  }

  .spacer {
    flex: 1;
  }

  .run {
    background: var(--accent);
    border: 1px solid var(--accent);
    border-radius: 6px;
    padding: 0.45rem 1.1rem;
    color: var(--accent-fg);
    font-weight: 600;
    font-size: 0.85rem;
    cursor: pointer;
  }

  .second {
    background: var(--input-bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.45rem 1rem;
    color: var(--fg);
    font-size: 0.85rem;
    cursor: pointer;
  }

  .second.small {
    padding: 0.3rem 0.7rem;
    font-size: 0.78rem;
  }

  .hint {
    font-size: 0.74rem;
    color: var(--muted);
    margin: 0.5rem 0 0.8rem;
  }

  .error {
    background: var(--error-bg);
    border: 1px solid var(--error-border);
    color: var(--error-fg);
    border-radius: 6px;
    padding: 0.6rem 0.8rem;
    font-size: 0.82rem;
    margin: 0.6rem 0;
    white-space: pre-wrap;
  }

  .bar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin: 0.6rem 0;
  }

  .actions {
    display: inline-flex;
    align-items: center;
    gap: 0.6rem;
  }

  .muted {
    color: var(--muted);
  }

  .small {
    font-size: 0.76rem;
  }

  .card {
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 0.6rem 0.8rem;
    margin-bottom: 0.6rem;
  }

  .head {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    margin-bottom: 0.35rem;
  }

  .name {
    font-weight: 600;
    font-size: 0.86rem;
  }

  .dot {
    width: 0.6rem;
    height: 0.6rem;
    border-radius: 50%;
    background: var(--border);
  }

  .dot.up {
    background: #15935a;
  }

  .dot.down {
    background: #c0392b;
  }

  .graph {
    width: 100%;
    height: 56px;
    background: var(--input-bg);
    border-radius: 4px;
  }

  .graph .line {
    fill: none;
    stroke: var(--accent);
    stroke-width: 1.5;
  }

  .graph .fail {
    fill: #c0392b;
    opacity: 0.55;
  }

  .stats {
    display: flex;
    flex-wrap: wrap;
    gap: 0.3rem 1.2rem;
    margin-top: 0.35rem;
  }

  .detail {
    margin-top: 0.3rem;
    color: #b7791f;
  }

  details {
    margin-top: 0.4rem;
  }

  summary {
    font-size: 0.78rem;
    color: var(--muted);
    cursor: pointer;
  }

  table {
    border-collapse: collapse;
    margin-top: 0.3rem;
    font-size: 0.78rem;
  }

  th,
  td {
    text-align: left;
    padding: 0.15rem 1rem 0.15rem 0;
  }

  th {
    color: var(--muted);
    font-weight: 500;
  }
</style>
