<script lang="ts">
  import { invoke, Channel } from "@tauri-apps/api/core";
  import { tick } from "svelte";
  import type { HopView, MtuResult, PathSummary, TraceEvent, TraceFinding } from "$lib/tools/types";
  import LatencyChart from "./LatencyChart.svelte";
  import RttHistory from "./RttHistory.svelte";
  import { fmtMs, hopLabel } from "./format";

  let target = $state("");
  let continuous = $state(false);
  let cycles = $state(5);
  let intervalMs = $state(1000);
  let maxHops = $state(30);
  let packetSize = $state(60);
  let measureMtu = $state(true);
  let resolveNames = $state(true);

  let method = $state("");
  let running = $state(false);
  let error = $state("");
  let resolved = $state("");
  let hops = $state<HopView[]>([]);
  let summary = $state<PathSummary | null>(null);
  let mtu = $state<MtuResult | null>(null);
  let mtuRunning = $state(false);
  let finished = $state("");
  let selected = $state<number | null>(null);
  let detailEl = $state<HTMLElement | null>(null);
  let traceId = 0;

  $effect(() => {
    invoke<string>("trace_method")
      .then((m) => (method = m))
      .catch(() => {});
  });

  const selectedHop = $derived(selected !== null ? (hops.find((h) => h.ttl === selected) ?? null) : null);
  /** Shared y-scale for the per-hop charts so hops compare honestly. */
  const sharedTop = $derived(Math.max(1, ...hops.flatMap((h) => h.history.filter((v): v is number => v !== null))));
  const destHop = $derived(summary?.reached ? (hops[hops.length - 1] ?? null) : null);

  const SEVERITY: Record<TraceFinding["kind"], { label: string; cls: string }> = {
    loss: { label: "Critical", cls: "critical" },
    unreachable: { label: "Serious", cls: "serious" },
    noReply: { label: "Serious", cls: "serious" },
    latency: { label: "Warning", cls: "warning" },
    rateLimit: { label: "Info", cls: "info" },
  };

  async function select(ttl: number) {
    selected = ttl;
    await tick();
    detailEl?.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }

  async function run() {
    if (target.trim().length === 0) {
      error = "Enter a host or IPv4 address.";
      return;
    }
    error = "";
    resolved = "";
    hops = [];
    summary = null;
    mtu = null;
    mtuRunning = false;
    finished = "";
    selected = null;
    running = true;
    traceId = Math.floor(Math.random() * 0x7fffffff);

    const channel = new Channel<TraceEvent>();
    channel.onmessage = (ev) => {
      switch (ev.type) {
        case "started":
          resolved = ev.ip;
          method = ev.method;
          break;
        case "cycle":
          hops = ev.hops;
          summary = ev.summary;
          break;
        case "mtuStarted":
          mtuRunning = true;
          break;
        case "mtu":
          mtu = ev.result;
          mtuRunning = false;
          break;
        case "error":
          error = ev.message;
          break;
        case "done":
          mtuRunning = false;
          running = false;
          finished = `${ev.cancelled ? "Stopped" : "Done"} after ${ev.cycles} cycle${ev.cycles === 1 ? "" : "s"}.`;
          break;
      }
    };

    const config = {
      target,
      maxHops,
      cycles: continuous ? 0 : cycles,
      intervalMs,
      timeoutMs: 2000,
      packetSize,
      measureMtu,
      resolveNames,
    };
    try {
      await invoke("trace_run", { traceId, config, onEvent: channel });
    } catch (e) {
      error = String(e);
      running = false;
    }
  }

  async function stop() {
    try {
      await invoke("trace_stop", { traceId });
    } catch {
      // ignore
    }
  }
</script>

<div class="panel">
  <header>
    <h1>Visual Traceroute</h1>
    <p class="sub">
      Per-hop latency, loss, and Path MTU over repeated cycles. No admin rights needed.
      {#if method}<span class="method">Method: {method}.</span>{/if}
    </p>
  </header>

  <div class="grid">
    <div class="field grow">
      <label for="target">Host or IPv4</label>
      <input
        id="target"
        class="mono"
        bind:value={target}
        disabled={running}
        spellcheck="false"
        placeholder="1.1.1.1"
        onkeydown={(e) => e.key === "Enter" && !running && run()}
      />
    </div>
    <div class="field">
      <label for="mode">Mode</label>
      <select id="mode" bind:value={continuous} disabled={running}>
        <option value={false}>Fixed cycles</option>
        <option value={true}>Continuous</option>
      </select>
    </div>
    {#if !continuous}
      <div class="field small">
        <label for="cycles">Cycles</label>
        <input id="cycles" type="number" min="1" max="1000" bind:value={cycles} disabled={running} />
      </div>
    {/if}
    <div class="field small">
      <label for="interval">Interval (ms)</label>
      <input id="interval" type="number" min="200" step="100" bind:value={intervalMs} disabled={running} />
    </div>
    <div class="field small">
      <label for="maxhops">Max hops</label>
      <input id="maxhops" type="number" min="1" max="64" bind:value={maxHops} disabled={running} />
    </div>
    <div class="field small">
      <label for="psize">Packet (bytes)</label>
      <input id="psize" type="number" min="28" max="1500" bind:value={packetSize} disabled={running} />
    </div>
  </div>

  <div class="row">
    {#if running}
      <button class="action stop" onclick={stop}>Stop</button>
    {:else}
      <button class="action" onclick={run}>Trace</button>
    {/if}
    <label class="check"><input type="checkbox" bind:checked={measureMtu} disabled={running} /> Path MTU</label>
    <label class="check"><input type="checkbox" bind:checked={resolveNames} disabled={running} /> Reverse DNS</label>
    {#if running}
      <span class="muted status">Tracing{summary ? `, cycle ${summary.cycles}` : ""}...</span>
    {:else if finished}
      <span class="muted status">{finished}</span>
    {/if}
  </div>

  {#if error}
    <div class="error mono">{error}</div>
  {/if}

  {#if summary}
    <!-- Path Summary -->
    <section>
      <h2>Path Summary</h2>
      <div class="tiles">
        <div class="tile wide">
          <div class="tlabel">Destination</div>
          <div class="tvalue mono">{target.trim()}</div>
          {#if resolved && resolved !== target.trim()}<div class="tsub mono">{resolved}</div>{/if}
        </div>
        <div class="tile">
          <div class="tlabel">Reached</div>
          <div class="tvalue">{summary.reached ? "Yes" : "No"}</div>
        </div>
        <div class="tile">
          <div class="tlabel">Hops</div>
          <div class="tvalue">{summary.hops}</div>
        </div>
        <div class="tile">
          <div class="tlabel">Latency</div>
          <div class="tvalue">{summary.destAvgMs !== null ? `${fmtMs(summary.destAvgMs)} ms` : "n/a"}</div>
          {#if destHop?.jitterMs != null}<div class="tsub">jitter {fmtMs(destHop.jitterMs)} ms</div>{/if}
        </div>
        <div class="tile">
          <div class="tlabel">Loss</div>
          <div class="tvalue">{summary.destLossPct !== null ? `${summary.destLossPct.toFixed(0)}%` : "n/a"}</div>
        </div>
        <div class="tile">
          <div class="tlabel">Path MTU</div>
          <div class="tvalue">
            {#if mtu?.mtu}{mtu.mtu}{:else if mtuRunning}...{:else}n/a{/if}
          </div>
        </div>
        <div class="tile">
          <div class="tlabel">Cycles</div>
          <div class="tvalue">{summary.cycles}</div>
        </div>
      </div>

      {#if summary.findings.length > 0}
        <ul class="findings">
          {#each summary.findings as f, i (i)}
            <li class="finding {SEVERITY[f.kind].cls}">
              <span class="sev"><i class="sevdot"></i>{SEVERITY[f.kind].label}</span>
              <span>{f.message}</span>
              {#if f.ttl !== null}
                <button class="link" onclick={() => select(f.ttl!)}>hop {f.ttl}</button>
              {/if}
            </li>
          {/each}
        </ul>
      {:else if summary.reached && summary.cycles >= 5}
        <p class="muted ok">No loss or latency problems found on this path.</p>
      {/if}
    </section>

    <!-- Hop Table -->
    <section>
      <h2>Hop Table</h2>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th class="num">Hop</th><th>Host</th><th class="num">Loss</th><th class="num">Sent</th>
              <th class="num">Last</th><th class="num">Avg</th><th class="num">Best</th>
              <th class="num">Worst</th><th class="num">StDev</th><th class="num">Jitter</th>
            </tr>
          </thead>
          <tbody>
            {#each hops as h (h.ttl)}
              <tr class:sel={selected === h.ttl} onclick={() => select(h.ttl)}>
                <td class="num">{h.ttl}</td>
                <td class="host">
                  {#if h.ip}
                    <button class="link hostbtn" onclick={(e) => { e.stopPropagation(); select(h.ttl); }}>
                      {h.hostname ?? h.ip}
                    </button>
                    {#if h.hostname}<span class="mono dim ipsub">{h.ip}</span>{/if}
                    {#if h.responders.length > 1}
                      <span class="tag">+{h.responders.length - 1} more</span>
                    {/if}
                  {:else}
                    <span class="dim">* no reply</span>
                  {/if}
                </td>
                <td class="num">{#if h.lossPct > 0}<i class="lossdot"></i>{/if}{h.lossPct.toFixed(0)}%</td>
                <td class="num dim">{h.sent}</td>
                <td class="num">{fmtMs(h.lastMs)}</td>
                <td class="num strong">{fmtMs(h.avgMs)}</td>
                <td class="num">{fmtMs(h.bestMs)}</td>
                <td class="num">{fmtMs(h.worstMs)}</td>
                <td class="num dim">{fmtMs(h.stdevMs)}</td>
                <td class="num dim">{fmtMs(h.jitterMs)}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
      <p class="note muted">Times in ms. A hop with loss but a clean destination is usually a router rate-limiting ICMP, not real loss.</p>
    </section>

    <!-- Path Latency -->
    <section>
      <h2>Path Latency</h2>
      <p class="note muted">Average RTT per hop; the shaded band spans best to worst. Click a hop for detail.</p>
      <div class="card">
        <LatencyChart {hops} {selected} onselect={select} />
      </div>
    </section>

    <!-- Path MTU -->
    <section>
      <h2>Path MTU</h2>
      <div class="card">
        {#if !measureMtu}
          <p class="muted">Disabled for this run.</p>
        {:else if mtuRunning}
          <p class="muted">Measuring with don't-fragment probes...</p>
        {:else if mtu}
          <div class="mtu">
            <div class="mtuv">{mtu.mtu !== null ? `${mtu.mtu} bytes` : "Unknown"}</div>
            <div>
              <div>{mtu.note}.</div>
              {#if mtu.limitedBy}<div class="muted">Limited by <span class="mono">{mtu.limitedBy}</span></div>{/if}
              {#if mtu.blackHole}
                <div class="finding serious inline"><span class="sev"><i class="sevdot"></i>Serious</span> PMTUD black hole: oversized packets are dropped silently. Expect stalls on large transfers; check MSS clamping or ICMP filtering.</div>
              {/if}
            </div>
          </div>
          <table class="steps">
            <thead><tr><th class="num">Size</th><th>Result</th></tr></thead>
            <tbody>
              {#each mtu.steps as s, i (i)}
                <tr><td class="num mono">{s.size}</td><td>{s.result}</td></tr>
              {/each}
            </tbody>
          </table>
        {:else if !summary.reached}
          <p class="muted">Path MTU is measured once the destination answers.</p>
        {:else}
          <p class="muted">Waiting for the first cycle.</p>
        {/if}
      </div>
    </section>

    <!-- Per-Hop Charts -->
    <section>
      <h2>Per-Hop Charts</h2>
      <p class="note muted legend">
        <span><i class="lkey line"></i>RTT per cycle</span>
        <span><i class="lkey lost"></i>lost probe</span>
        <span>Shared scale, 0 to {fmtMs(sharedTop)} ms.</span>
      </p>
      <div class="multiples">
        {#each hops as h (h.ttl)}
          <button class="mini" class:sel={selected === h.ttl} onclick={() => select(h.ttl)}>
            <div class="minihead">
              <span class="strong">{h.ttl}</span>
              <span class="mono minihost">{hopLabel(h)}</span>
            </div>
            <div class="ministats muted">
              {h.avgMs !== null ? `${fmtMs(h.avgMs)} ms` : "no reply"} · {h.lossPct.toFixed(0)}% loss
            </div>
            <RttHistory history={h.history} top={sharedTop} label="Hop {h.ttl} RTT" />
          </button>
        {/each}
      </div>
    </section>

    <!-- Hop Detail -->
    <section bind:this={detailEl}>
      <h2>Hop Detail</h2>
      {#if selectedHop}
        <div class="card">
          <div class="detailhead">
            <div>
              <div class="strong">Hop {selectedHop.ttl} · {hopLabel(selectedHop)}</div>
              {#if selectedHop.hostname && selectedHop.ip}<div class="mono dim">{selectedHop.ip}</div>{/if}
            </div>
            <button class="secondary" onclick={() => (selected = null)}>Close</button>
          </div>
          <div class="tiles">
            <div class="tile"><div class="tlabel">Avg</div><div class="tvalue">{fmtMs(selectedHop.avgMs) || "n/a"}</div></div>
            <div class="tile"><div class="tlabel">Best</div><div class="tvalue">{fmtMs(selectedHop.bestMs) || "n/a"}</div></div>
            <div class="tile"><div class="tlabel">Worst</div><div class="tvalue">{fmtMs(selectedHop.worstMs) || "n/a"}</div></div>
            <div class="tile"><div class="tlabel">StDev</div><div class="tvalue">{fmtMs(selectedHop.stdevMs) || "n/a"}</div></div>
            <div class="tile"><div class="tlabel">Jitter</div><div class="tvalue">{fmtMs(selectedHop.jitterMs) || "n/a"}</div></div>
            <div class="tile"><div class="tlabel">Loss</div><div class="tvalue">{selectedHop.lossPct.toFixed(0)}%</div><div class="tsub">{selectedHop.received} of {selectedHop.sent}</div></div>
          </div>
          {#if selectedHop.unreachable !== null}
            <div class="finding serious inline"><span class="sev"><i class="sevdot"></i>Serious</span> ICMP unreachable code {selectedHop.unreachable} reported at this hop.</div>
          {/if}
          <h3>RTT history</h3>
          <RttHistory history={selectedHop.history} top={Math.max(1, selectedHop.worstMs ?? 1)} height={180} axis label="Hop {selectedHop.ttl} RTT history" />
          <h3>Responders</h3>
          {#if selectedHop.responders.length === 0}
            <p class="muted">No router answered at this TTL. It may not send ICMP Time Exceeded, which is common and harmless if later hops answer.</p>
          {:else}
            <table class="steps">
              <thead><tr><th>IP</th><th>Hostname</th><th class="num">Replies</th><th class="num">Share</th></tr></thead>
              <tbody>
                {#each selectedHop.responders as r (r.ip)}
                  <tr>
                    <td class="mono">{r.ip}</td>
                    <td>{r.hostname ?? ""}</td>
                    <td class="num">{r.count}</td>
                    <td class="num">{selectedHop.received ? Math.round((r.count * 100) / selectedHop.received) : 0}%</td>
                  </tr>
                {/each}
              </tbody>
            </table>
            {#if selectedHop.responders.length > 1}
              <p class="note muted">Several routers answer at this hop: the path is load-balanced (ECMP).</p>
            {/if}
          {/if}
        </div>
      {:else}
        <p class="muted">Click a hop in the table or charts to see its detail.</p>
      {/if}
    </section>
  {:else if running}
    <p class="muted">Probing {resolved || target.trim()}...</p>
  {/if}
</div>

<style>
  .panel {
    /* Chart series and status colors, validated against the app surfaces. */
    --viz-series: #2a78d6;
    --viz-critical: #d03b3b;
    --viz-serious: #ec835a;
    --viz-warning: #fab219;
    padding: 1.5rem 2rem 2rem;
    box-sizing: border-box;
    width: 100%;
  }

  @media (prefers-color-scheme: dark) {
    .panel {
      --viz-series: #3987e5;
    }
  }

  header h1 {
    margin: 0 0 0.25rem;
    font-size: 1.3rem;
  }

  h2 {
    font-size: 0.95rem;
    font-weight: 600;
    margin: 1.6rem 0 0.5rem;
  }

  h3 {
    font-size: 0.82rem;
    font-weight: 600;
    margin: 1rem 0 0.4rem;
    color: var(--muted);
  }

  .sub {
    margin: 0 0 1.25rem;
    color: var(--muted);
    font-size: 0.85rem;
  }

  .method {
    display: block;
    margin-top: 0.2rem;
    font-size: 0.78rem;
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
    flex: 1 1 130px;
  }

  .field.grow {
    flex: 3 1 220px;
  }

  .field.small {
    flex: 1 1 90px;
  }

  label {
    font-size: 0.78rem;
    color: var(--muted);
    margin-bottom: 0.3rem;
  }

  input,
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

  input:focus,
  select:focus {
    outline: none;
    border-color: var(--accent);
  }

  input:disabled,
  select:disabled {
    opacity: 0.55;
  }

  input[type="checkbox"] {
    width: auto;
    margin: 0 0.3rem 0 0;
  }

  .check {
    display: inline-flex;
    align-items: center;
    font-size: 0.82rem;
    margin: 0;
    color: var(--fg);
  }

  .mono {
    font-family: var(--mono);
  }

  .strong {
    font-weight: 600;
  }

  .row {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 1rem;
    margin: 0.3rem 0 1rem;
  }

  .status {
    font-size: 0.82rem;
  }

  .action {
    background: var(--accent);
    border: 1px solid var(--accent);
    border-radius: 6px;
    padding: 0.5rem 1.3rem;
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

  .secondary {
    background: var(--btn-bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.35rem 0.8rem;
    color: var(--fg);
    font-size: 0.8rem;
    cursor: pointer;
  }

  .muted,
  .dim {
    color: var(--muted);
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

  .note {
    font-size: 0.78rem;
    margin: 0.4rem 0;
  }

  .card {
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 0.8rem 0.9rem;
  }

  .tiles {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(120px, 1fr));
    gap: 0.6rem;
  }

  .tile {
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 0.55rem 0.7rem;
    min-width: 0;
  }

  .tile.wide {
    grid-column: span 2;
  }

  .tlabel {
    font-size: 0.72rem;
    color: var(--muted);
  }

  .tvalue {
    font-size: 1.15rem;
    font-weight: 600;
    margin-top: 0.15rem;
    overflow-wrap: anywhere;
  }

  .tsub {
    font-size: 0.72rem;
    color: var(--muted);
    overflow-wrap: anywhere;
  }

  .findings {
    list-style: none;
    padding: 0;
    margin: 0.7rem 0 0;
    display: flex;
    flex-direction: column;
    gap: 0.4rem;
  }

  .finding {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 0.6rem;
    font-size: 0.84rem;
    border: 1px solid var(--border);
    border-left: 3px solid var(--sevc, var(--border));
    border-radius: 6px;
    padding: 0.4rem 0.6rem;
  }

  .finding.inline {
    margin-top: 0.6rem;
  }

  .finding.critical {
    --sevc: var(--viz-critical);
  }

  .finding.serious {
    --sevc: var(--viz-serious);
  }

  .finding.warning {
    --sevc: var(--viz-warning);
  }

  .finding.info {
    --sevc: var(--muted);
  }

  .sev {
    font-size: 0.72rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.03em;
    white-space: nowrap;
  }

  .sevdot {
    display: inline-block;
    width: 0.55rem;
    height: 0.55rem;
    border-radius: 50%;
    background: var(--sevc);
    margin-right: 0.35rem;
  }

  .ok {
    font-size: 0.82rem;
    margin: 0.6rem 0 0;
  }

  .table-wrap {
    border: 1px solid var(--border);
    border-radius: 6px;
    overflow: clip;
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
    z-index: 1;
    background: var(--sidebar-bg);
    white-space: nowrap;
  }

  td {
    padding: 0.3rem 0.6rem;
    border-bottom: 1px solid var(--border);
    vertical-align: top;
  }

  tbody tr {
    cursor: pointer;
  }

  tbody tr:hover td {
    background: var(--hover);
  }

  tr.sel td {
    background: var(--active-bg);
  }

  tr:last-child td {
    border-bottom: none;
  }

  .num {
    text-align: right;
    font-variant-numeric: tabular-nums;
    white-space: nowrap;
  }

  .host {
    word-break: break-word;
  }

  .ipsub {
    margin-left: 0.4rem;
    font-size: 0.74rem;
  }

  .link {
    background: none;
    border: none;
    padding: 0;
    color: var(--accent);
    cursor: pointer;
    font-size: inherit;
    text-align: left;
  }

  .hostbtn {
    word-break: break-word;
  }

  .tag {
    margin-left: 0.4rem;
    font-size: 0.68rem;
    color: var(--muted);
    border: 1px solid var(--border);
    border-radius: 3px;
    padding: 0 0.25rem;
  }

  .lossdot {
    display: inline-block;
    width: 0.45rem;
    height: 0.45rem;
    border-radius: 50%;
    background: var(--viz-critical);
    margin-right: 0.35rem;
    vertical-align: 0.05rem;
  }

  .mtu {
    display: flex;
    flex-wrap: wrap;
    gap: 1.2rem;
    align-items: center;
    margin-bottom: 0.8rem;
    font-size: 0.85rem;
  }

  .mtuv {
    font-size: 1.6rem;
    font-weight: 600;
  }

  table.steps {
    width: auto;
    min-width: 50%;
  }

  table.steps tbody tr {
    cursor: default;
  }

  .legend {
    display: flex;
    flex-wrap: wrap;
    gap: 1rem;
    align-items: center;
  }

  .lkey {
    display: inline-block;
    margin-right: 0.35rem;
    vertical-align: middle;
  }

  .lkey.line {
    width: 14px;
    height: 2px;
    background: var(--viz-series);
  }

  .lkey.lost {
    width: 2px;
    height: 9px;
    background: var(--viz-critical);
  }

  .multiples {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(220px, 1fr));
    gap: 0.6rem;
  }

  .mini {
    text-align: left;
    background: none;
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 0.5rem 0.6rem 0.4rem;
    color: var(--fg);
    cursor: pointer;
    min-width: 0;
    font: inherit;
  }

  .mini:hover {
    background: var(--hover);
  }

  .mini.sel {
    border-color: var(--accent);
  }

  .minihead {
    display: flex;
    gap: 0.5rem;
    font-size: 0.8rem;
    min-width: 0;
  }

  .minihost {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    color: var(--muted);
  }

  .ministats {
    font-size: 0.74rem;
    margin: 0.1rem 0 0.2rem;
  }

  .detailhead {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    gap: 1rem;
    margin-bottom: 0.8rem;
    word-break: break-word;
  }
</style>
