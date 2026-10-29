<script lang="ts">
  import { invoke, Channel } from "@tauri-apps/api/core";
  import ExportMenu from "$lib/components/ExportMenu.svelte";
  import type { SnmpSweepEvent } from "$lib/tools/types";
  import { buildSweepReport } from "./report";

  let targets = $state("");
  let port = $state(161);
  let version = $state("v2c");
  let community = $state("public");

  let sweeping = $state(false);
  let error = $state("");
  let rows = $state<{ ip: string; name: string; descr: string; objid: string }[]>([]);
  let progress = $state<{ done: number; total: number; found: number } | null>(null);
  let summary = $state("");
  let sweepId = 0;

  function ipKey(ip: string): number {
    const p = ip.split(".");
    if (p.length !== 4) return Number.MAX_SAFE_INTEGER;
    return p.reduce((a, x) => a * 256 + (Number(x) || 0), 0);
  }

  async function sweep() {
    if (targets.trim().length === 0) {
      error = "Enter a subnet (e.g. 10.0.0.0/24) or host list.";
      return;
    }
    error = "";
    summary = "";
    rows = [];
    progress = null;
    sweeping = true;
    sweepId = Math.floor(Math.random() * 0x7fffffff);

    const channel = new Channel<SnmpSweepEvent>();
    channel.onmessage = (ev) => {
      switch (ev.type) {
        case "responder":
          rows = [
            ...rows,
            { ip: ev.ip, name: ev.sysName, descr: ev.sysDescr, objid: ev.sysObjectId },
          ].sort((a, b) => ipKey(a.ip) - ipKey(b.ip));
          break;
        case "progress":
          progress = { done: ev.done, total: ev.total, found: ev.found };
          break;
        case "done":
          summary = `${ev.cancelled ? "Cancelled" : "Done"}: ${ev.found} SNMP responder${ev.found === 1 ? "" : "s"} of ${ev.total} host${ev.total === 1 ? "" : "s"}.`;
          sweeping = false;
          break;
      }
    };

    const config = { targets, port, version, community, timeoutMs: 1000, concurrency: 64 };
    try {
      await invoke("snmp_sweep", { sweepId, config, onEvent: channel });
    } catch (e) {
      error = String(e);
      sweeping = false;
    }
  }

  async function cancel() {
    try {
      await invoke("snmp_sweep_cancel", { sweepId });
    } catch {
      // ignore
    }
  }

  const pct = $derived(
    progress && progress.total > 0 ? Math.round((progress.done / progress.total) * 100) : 0,
  );
</script>

<div class="panel">
  <header>
    <h1>SNMP Sweep</h1>
    <p class="sub">
      Find SNMP responders across a subnet and read their system identity. Only
      sweep networks you are authorized to query.
    </p>
  </header>

  <div class="grid">
    <div class="field grow">
      <label for="targets">Subnet or hosts</label>
      <input
        id="targets"
        class="mono"
        bind:value={targets}
        disabled={sweeping}
        spellcheck="false"
        placeholder="10.0.0.0/24"
      />
    </div>
    <div class="field">
      <label for="port">Port</label>
      <input id="port" type="number" min="1" max="65535" bind:value={port} disabled={sweeping} />
    </div>
    <div class="field">
      <label for="ver">Version</label>
      <select id="ver" bind:value={version} disabled={sweeping}>
        <option value="v1">v1</option>
        <option value="v2c">v2c</option>
      </select>
    </div>
    <div class="field grow">
      <label for="comm">Community</label>
      <input id="comm" class="mono" bind:value={community} disabled={sweeping} spellcheck="false" />
    </div>
  </div>

  <div class="row">
    {#if sweeping}
      <button class="action stop" onclick={cancel}>Cancel</button>
    {:else}
      <button class="action" onclick={sweep}>Sweep</button>
    {/if}
    {#if summary}<span class="done muted">{summary}</span>{/if}
    {#if summary && !sweeping}
      <ExportMenu
        build={() => buildSweepReport({ targets, port, version, summary, rows })}
        name={`snmp-sweep-${targets}`}
      />
    {/if}
  </div>

  {#if error}
    <div class="error mono">{error}</div>
  {/if}

  {#if progress}
    <div class="progress">
      <div class="bar"><div class="fill" style="width: {pct}%"></div></div>
      <div class="pline muted">
        {progress.done.toLocaleString()} / {progress.total.toLocaleString()} hosts
        · {rows.length} responding
      </div>
    </div>
  {/if}

  {#if rows.length > 0}
    <div class="table-scroll">
      <table>
        <thead>
          <tr><th>Host</th><th>sysName</th><th>sysDescr</th><th>sysObjectID</th></tr>
        </thead>
        <tbody>
          {#each rows as r (r.ip)}
            <tr>
              <td class="mono">{r.ip}</td>
              <td class="mono">{r.name}</td>
              <td class="descr">{r.descr}</td>
              <td class="mono dim">{r.objid}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
</div>

<style>
  .panel {
    padding: 1.5rem 2rem;
    max-width: 1000px;
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

  .grid {
    display: flex;
    flex-wrap: wrap;
    gap: 0.75rem;
    margin-bottom: 0.9rem;
  }

  .field {
    display: flex;
    flex-direction: column;
    flex: 1 1 120px;
  }

  .field.grow {
    flex: 2 1 220px;
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

  .mono {
    font-family: var(--mono);
  }

  .row {
    display: flex;
    align-items: center;
    gap: 0.9rem;
    margin-bottom: 1rem;
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

  .action.stop {
    background: var(--btn-bg);
    border-color: var(--error-border);
    color: var(--error-fg);
  }

  .done {
    font-size: 0.82rem;
  }

  .muted {
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
  }

  .descr {
    font-size: 0.8rem;
    max-width: 420px;
  }
</style>
