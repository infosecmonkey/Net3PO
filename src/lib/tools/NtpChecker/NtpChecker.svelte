<script lang="ts">
  // NTP checker: query servers several times and compare their time with
  // this computer's. Read-only; the system clock is never changed.
  import { Channel, invoke } from "@tauri-apps/api/core";
  import ExportMenu from "$lib/components/ExportMenu.svelte";
  import { selectOnFocus } from "$lib/actions/selectOnFocus";
  import { buildNtpReport, fmt, type NtpEvent, type ServerState } from "./model";

  let serversText = $state("");
  let samples = $state(4);
  let intervalMs = $state(1000);
  let timeoutMs = $state(2000);
  let running = $state(false);
  let error = $state("");
  let results = $state<ServerState[]>([]);

  async function run() {
    const servers = serversText.split(/[\s,]+/).map((s) => s.trim()).filter(Boolean);
    if (!servers.length) {
      error = "Enter at least one NTP server.";
      return;
    }
    error = "";
    running = true;
    results = servers.map((s) => ({ server: s, addr: "", samples: [], summary: null, error: null }));
    const ch = new Channel<NtpEvent>();
    ch.onmessage = (e) => {
      const r = results.find((x) => x.server === e.server);
      if (!r) return;
      if (e.type === "resolved") r.addr = e.addr;
      else if (e.type === "sample") r.samples.push(e);
      else {
        r.summary = e.summary;
        r.error = e.error;
      }
    };
    try {
      await invoke("ntp_check", { req: { servers, samples, intervalMs, timeoutMs }, onEvent: ch });
    } catch (e) {
      error = String(e);
    } finally {
      running = false;
    }
  }

  function verdict(r: ServerState): { cls: string; text: string } {
    const s = r.summary;
    if (r.error) return { cls: "bad", text: r.error };
    if (!s) return { cls: "", text: running ? "querying..." : "" };
    if (!s.answered) return { cls: "warn", text: "no replies (inconclusive)" };
    const off = Math.abs(s.bestOffsetMs ?? 0);
    if (off > 1000) return { cls: "bad", text: `this computer is ${(off / 1000).toFixed(1)} s off this server` };
    if (off > 100) return { cls: "warn", text: `offset ${off.toFixed(0)} ms` };
    return { cls: "ok", text: `within ${off < 1 ? "1" : off.toFixed(0)} ms` };
  }
</script>

<div class="panel">
  <header>
    <h1>NTP Checker</h1>
    <p class="sub">Query NTP servers and compare their time with this computer's: offset, round-trip delay, stratum and reference. Sends UDP 123 from this computer when you click. The local clock is never changed.</p>
  </header>

  <label class="lbl" for="ntp-servers">Servers</label>
  <textarea id="ntp-servers" class="mono" rows="3" bind:value={serversText} spellcheck="false" placeholder="one per line: hostname, IP, or host:port"></textarea>
  <div class="row">
    <label class="inline">Samples <input class="mono num" type="number" min="1" max="10" bind:value={samples} use:selectOnFocus disabled={running} /></label>
    <label class="inline">Interval (ms) <input class="mono num" type="number" min="200" max="10000" bind:value={intervalMs} use:selectOnFocus disabled={running} /></label>
    <label class="inline">Timeout (ms) <input class="mono num" type="number" min="200" max="10000" bind:value={timeoutMs} use:selectOnFocus disabled={running} /></label>
    <span class="spacer"></span>
    <button class="primary" onclick={run} disabled={running}>{running ? "Checking..." : "Check"}</button>
  </div>
  {#if error}<div class="error">{error}</div>{/if}

  {#if results.length}
    <div class="bar">
      <span class="muted">Positive offset: this computer is behind the server.</span>
      {#if !running}<ExportMenu build={() => buildNtpReport(results)} name="ntp" />{/if}
    </div>
    {#each results as r (r.server)}
      {@const v = verdict(r)}
      {@const last = [...r.samples].reverse().find((x) => x.stratum !== null)}
      <div class="card">
        <div class="head">
          <span class="mono name">{r.server}</span>
          {#if r.addr}<span class="muted">{r.addr}</span>{/if}
          {#if last}<span class="muted">stratum {last.stratum}, ref {last.refId}{last.leap ? `, leap ${last.leap}` : ""}</span>{/if}
          <span class="spacer"></span>
          <span class="v {v.cls}">{v.text}</span>
        </div>
        {#if r.summary && r.summary.answered}
          <div class="stats">
            <span>Best offset <strong>{fmt(r.summary.bestOffsetMs)}</strong></span>
            <span>Range {fmt(r.summary.minOffsetMs)} to {fmt(r.summary.maxOffsetMs)}</span>
            <span>Jitter {fmt(r.summary.jitterMs)}</span>
            <span>Min delay {fmt(r.summary.minDelayMs)}</span>
            <span class="muted">{r.summary.answered}/{r.summary.samples} answered</span>
          </div>
        {/if}
        {#if r.samples.length}
          <table>
            <thead><tr><th>#</th><th>Time (UTC)</th><th class="n">Offset</th><th class="n">Delay</th><th>Result</th></tr></thead>
            <tbody>
              {#each r.samples as s (s.seq)}
                <tr><td>{s.seq}</td><td class="mono">{new Date(s.atMs).toISOString().slice(11, 23)}</td><td class="n mono">{fmt(s.offsetMs)}</td><td class="n mono">{fmt(s.delayMs)}</td><td class:err={s.error}>{s.error ?? "ok"}</td></tr>
              {/each}
            </tbody>
          </table>
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

  .lbl {
    font-size: 0.78rem;
    color: var(--muted);
  }

  textarea,
  input {
    box-sizing: border-box;
    background: var(--input-bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.4rem 0.55rem;
    color: var(--fg);
    font-size: 0.82rem;
  }

  textarea {
    width: 100%;
    margin-top: 0.3rem;
    resize: vertical;
  }

  textarea:focus,
  input:focus {
    outline: none;
    border-color: var(--accent);
  }

  .mono {
    font-family: var(--mono);
  }

  .row,
  .bar {
    display: flex;
    align-items: center;
    gap: 1rem;
    margin: 0.6rem 0;
    flex-wrap: wrap;
  }

  .bar {
    justify-content: space-between;
  }

  .inline {
    display: inline-flex;
    align-items: center;
    gap: 0.4rem;
    font-size: 0.8rem;
    color: var(--muted);
  }

  .num {
    width: 5.5rem;
  }

  .spacer {
    flex: 1;
  }

  .primary {
    background: var(--accent);
    color: var(--accent-fg);
    border: 1px solid var(--accent);
    border-radius: 6px;
    padding: 0.45rem 1.1rem;
    font-weight: 600;
    cursor: pointer;
  }

  .primary:disabled {
    opacity: 0.6;
  }

  .error {
    color: var(--error-fg);
    font-size: 0.84rem;
  }

  .muted {
    color: var(--muted);
    font-size: 0.78rem;
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
    gap: 0.7rem;
    flex-wrap: wrap;
  }

  .name {
    font-weight: 600;
    font-size: 0.88rem;
  }

  .v {
    font-size: 0.82rem;
    font-weight: 600;
  }

  .v.ok {
    color: #15935a;
  }

  .v.warn {
    color: #b7791f;
  }

  .v.bad {
    color: #c0392b;
  }

  .stats {
    display: flex;
    flex-wrap: wrap;
    gap: 0.4rem 1.2rem;
    font-size: 0.82rem;
    margin: 0.4rem 0;
  }

  table {
    border-collapse: collapse;
    width: 100%;
    font-size: 0.78rem;
  }

  th,
  td {
    text-align: left;
    padding: 0.18rem 0.8rem 0.18rem 0;
    border-bottom: 1px solid var(--border);
  }

  th {
    color: var(--muted);
    font-weight: 500;
  }

  .n {
    text-align: right;
  }

  td.err {
    color: #b7791f;
  }
</style>
