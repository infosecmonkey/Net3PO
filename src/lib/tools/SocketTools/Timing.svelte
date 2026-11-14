<script lang="ts">
  // Repeated TCP connects to one port, timing each and keeping statistics.
  import { Channel, invoke } from "@tauri-apps/api/core";
  import ExportMenu from "$lib/components/ExportMenu.svelte";
  import { selectOnFocus } from "$lib/actions/selectOnFocus";
  import { buildTimingReport, statsRows } from "./report";
  import { newId, OUTCOME_LABEL, stamp, type LogLine, type Stats, type TimingEvent } from "./types";

  let host = $state("");
  let port = $state<number | null>(null);
  let count = $state(20);
  let intervalMs = $state(1000);
  let timeoutMs = $state(3000);

  let log = $state<LogLine<TimingEvent>[]>([]);
  let stats = $state<Stats | null>(null);
  let addr = $state("");
  let running = $state(false);
  let error = $state("");
  let id = 0;
  let seq = 0;

  const attempts = $derived(log.flatMap((l) => (l.ev.type === "attempt" ? [{ at: l.at, ...l.ev }] : [])));
  const maxMs = $derived(Math.max(1, ...attempts.map((a) => a.ms)));

  async function start() {
    if (!host.trim() || !port) {
      error = "Enter a host and port.";
      return;
    }
    error = "";
    log = [];
    stats = null;
    addr = "";
    id = newId();
    running = true;
    const ch = new Channel<TimingEvent>();
    ch.onmessage = (ev) => {
      if (ev.type === "resolved") addr = ev.addr;
      if (ev.type === "done") stats = ev.stats;
      log = [...log, { id: seq++, at: new Date(), ev }];
    };
    try {
      await invoke("sock_timing", { id, req: { host: host.trim(), port, count, intervalMs, timeoutMs }, onEvent: ch });
    } catch (e) {
      error = String(e);
    } finally {
      running = false;
    }
  }

  function stop() {
    void invoke("sock_stop", { id });
  }
</script>

<div class="row">
  <div class="field grow">
    <label for="t-host">Host</label>
    <input id="t-host" class="mono" bind:value={host} spellcheck="false" autocapitalize="off" placeholder="hostname or IP" disabled={running} />
  </div>
  <div class="field port">
    <label for="t-port">Port</label>
    <input id="t-port" class="mono" type="number" min="1" max="65535" bind:value={port} placeholder="port" disabled={running} />
  </div>
</div>
<div class="row">
  <label class="inline">Count <input class="num mono" type="number" min="1" max="10000" bind:value={count} use:selectOnFocus disabled={running} /></label>
  <label class="inline">Interval (ms) <input class="num mono" type="number" min="100" bind:value={intervalMs} use:selectOnFocus disabled={running} /></label>
  <label class="inline">Timeout (ms) <input class="num mono" type="number" min="100" max="60000" bind:value={timeoutMs} use:selectOnFocus disabled={running} /></label>
  <span class="spacer"></span>
  {#if running}
    <button class="second" onclick={stop}>Stop</button>
  {:else}
    <button class="run" onclick={start}>Start</button>
  {/if}
</div>
<p class="hint">
  Times the operating system's TCP connect call: socket connect time, not packet-level SYN/SYN-ACK
  timing. Refused means a reset came back; a timeout alone does not show where or why traffic was
  dropped.
</p>

{#if error}<div class="error mono">{error}</div>{/if}

{#if attempts.length}
  <div class="bar">
    <span class="muted small">{addr} · {attempts.length} attempt{attempts.length === 1 ? "" : "s"}</span>
    <ExportMenu build={() => buildTimingReport(`${host}:${port}`, addr, log, stats)} name="tcp-timing" disabled={running} />
  </div>
  <svg class="spark" viewBox="0 0 {Math.max(attempts.length, 1) * 6} 40" preserveAspectRatio="none" role="img" aria-label="Connect times">
    {#each attempts as a, i (a.seq)}
      {@const h = a.outcome === "connected" ? Math.max(2, (a.ms / maxMs) * 38) : 38}
      <rect x={i * 6} y={40 - h} width="5" height={h} class={a.outcome} />
    {/each}
  </svg>
  {#if stats}
    <table class="kv">
      <tbody>{#each statsRows(stats) as r (r.key)}<tr><th>{r.key}</th><td>{r.value}</td></tr>{/each}</tbody>
    </table>
  {/if}
  <div class="log">
    {#each attempts as a (a.seq)}
      <div class="line">
        <span class="t mono">{stamp(a.at)}</span>
        <span class="mono n">#{a.seq}</span>
        <span class="oc {a.outcome}">{OUTCOME_LABEL[a.outcome]}</span>
        <span class="mono">{a.ms.toFixed(2)} ms</span>
        {#if a.detail}<span class="muted small">{a.detail}</span>{/if}
      </div>
    {/each}
  </div>
{/if}
