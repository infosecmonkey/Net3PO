<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import ExportMenu from "$lib/components/ExportMenu.svelte";
  import type { SubnetReport, SplitResult } from "$lib/tools/types";
  import { buildSubnetReport, subnetRows } from "./report";
  import CidrSets from "./CidrSets.svelte";

  type Tab = "calculate" | "aggregate" | "compare";
  let tab = $state<Tab>("calculate");
  const TABS: { id: Tab; label: string }[] = [
    { id: "calculate", label: "Calculate and split" },
    { id: "aggregate", label: "Aggregate and overlap" },
    { id: "compare", label: "Compare sets" },
  ];

  let input = $state("");
  let splitPrefix = $state(28);

  let report = $state<SubnetReport | null>(null);
  let split = $state<SplitResult | null>(null);
  let error = $state("");

  async function calculate() {
    error = "";
    split = null;
    try {
      report = await invoke<SubnetReport>("subnet_calculate", { input });
    } catch (e) {
      report = null;
      error = String(e);
    }
  }

  async function doSplit() {
    error = "";
    try {
      split = await invoke<SplitResult>("subnet_split", {
        input,
        newPrefix: splitPrefix,
      });
    } catch (e) {
      split = null;
      error = String(e);
    }
  }

  function onKeydown(e: KeyboardEvent) {
    if (e.key === "Enter") calculate();
  }

  // Rows for the sipcalc-style grid, built per address family.
  const rows = $derived(report ? subnetRows(report) : []);
</script>

<div class="panel">
  <header>
    <h1>Subnet Calculator</h1>
    <p class="sub">IPv4 and IPv6: calculate and split a network, aggregate an address list and find overlaps, or compare two lists.</p>
  </header>

  <div class="tabs" role="tablist">
    {#each TABS as t (t.id)}
      <button role="tab" aria-selected={tab === t.id} class:active={tab === t.id} onclick={() => (tab = t.id)}>{t.label}</button>
    {/each}
  </div>

  <div hidden={tab !== "calculate"}>
  <div class="controls">
    <input
      class="addr"
      bind:value={input}
      onkeydown={onKeydown}
      placeholder="10.1.1.0/24"
      spellcheck="false"
      autocapitalize="off"
      autocomplete="off"
    />
    <button class="primary" onclick={calculate}>Calculate</button>
    <div class="split-control">
      <span>Split into /</span>
      <input class="prefix" type="number" min="1" max="128" bind:value={splitPrefix} />
      <button onclick={doSplit}>Split</button>
    </div>
  </div>

  {#if error}
    <div class="error">{error}</div>
  {/if}

  {#if report || split}
    <div class="export-row">
      <ExportMenu
        build={() => buildSubnetReport(report, split)}
        name={`subnet-${(report?.cidr ?? split?.parentCidr ?? "").replace(/[/:]/g, "_")}`}
      />
    </div>
  {/if}

  {#if report}
    <section class="results">
      <table>
        <tbody>
          {#each rows as [label, value] (label)}
            <tr>
              <th>{label}</th>
              <td class="mono">{value}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    </section>
  {/if}

  {#if split}
    <section class="split">
      <h2>
        {split.parentCidr} into /{split.newPrefix}
        <span class="count">{Number(split.totalSubnets).toLocaleString()} subnets</span>
      </h2>
      {#if split.truncated}
        <p class="note">Showing the first {split.subnets.length.toLocaleString()} subnets.</p>
      {/if}
      <div class="table-scroll">
        <table class="split-table">
          <thead>
            <tr>
              <th>Network</th>
              <th>Broadcast</th>
              <th>Host range</th>
              <th>Hosts</th>
            </tr>
          </thead>
          <tbody>
            {#each split.subnets as s (s.cidr)}
              <tr>
                <td class="mono">{s.cidr}</td>
                <td class="mono">{s.broadcast}</td>
                <td class="mono">{s.hostMin} - {s.hostMax}</td>
                <td class="mono num">{s.usableHosts}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    </section>
  {/if}
  </div>
  <div hidden={tab !== "aggregate"}><CidrSets mode="aggregate" /></div>
  <div hidden={tab !== "compare"}><CidrSets mode="compare" /></div>
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

  .tabs {
    display: flex;
    gap: 0.25rem;
    border-bottom: 1px solid var(--border);
    margin-bottom: 1rem;
  }

  .tabs button {
    background: none;
    border: none;
    border-bottom: 2px solid transparent;
    color: var(--muted);
    padding: 0.4rem 0.8rem;
    font-size: 0.85rem;
    cursor: pointer;
  }

  .tabs button.active {
    color: var(--fg);
    border-bottom-color: var(--accent);
  }

  .export-row {
    display: flex;
    justify-content: flex-end;
    margin-bottom: 0.5rem;
  }

  .controls {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 0.75rem;
    margin-bottom: 1rem;
  }

  input {
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

  .addr {
    flex: 1 1 260px;
    font-family: var(--mono);
  }

  .prefix {
    width: 4.5rem;
  }

  button {
    background: var(--btn-bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.5rem 0.9rem;
    color: var(--fg);
    font-size: 0.85rem;
    cursor: pointer;
  }

  button:hover {
    border-color: var(--accent);
  }

  button.primary {
    background: var(--accent);
    border-color: var(--accent);
    color: var(--accent-fg);
    font-weight: 600;
  }

  .split-control {
    display: flex;
    align-items: center;
    gap: 0.4rem;
    font-size: 0.85rem;
    color: var(--muted);
  }

  .error {
    background: var(--error-bg);
    border: 1px solid var(--error-border);
    color: var(--error-fg);
    border-radius: 6px;
    padding: 0.6rem 0.8rem;
    font-size: 0.85rem;
    margin-bottom: 1rem;
  }

  .results table {
    border-collapse: collapse;
    width: 100%;
  }

  .results th {
    text-align: left;
    width: 180px;
    color: var(--muted);
    font-weight: 500;
    font-size: 0.8rem;
    padding: 0.3rem 0.75rem 0.3rem 0;
    vertical-align: top;
  }

  .results td {
    padding: 0.3rem 0;
    font-size: 0.85rem;
  }

  .mono {
    font-family: var(--mono);
  }

  .split {
    margin-top: 1.75rem;
  }

  .split h2 {
    font-size: 1rem;
    display: flex;
    align-items: baseline;
    gap: 0.6rem;
  }

  .count {
    font-size: 0.8rem;
    color: var(--muted);
    font-weight: 400;
  }

  .note {
    font-size: 0.8rem;
    color: var(--muted);
    margin: 0 0 0.5rem;
  }

  .table-scroll {
    overflow-x: auto;
    border: 1px solid var(--border);
    border-radius: 6px;
  }

  .split-table {
    border-collapse: collapse;
    width: 100%;
    font-size: 0.82rem;
  }

  .split-table th {
    text-align: left;
    color: var(--muted);
    font-weight: 500;
    padding: 0.4rem 0.75rem;
    border-bottom: 1px solid var(--border);
    position: sticky;
    top: 0;
    background: var(--sidebar-bg);
  }

  .split-table td {
    padding: 0.35rem 0.75rem;
    border-bottom: 1px solid var(--border);
  }

  .split-table tr:last-child td {
    border-bottom: none;
  }

  .num {
    text-align: right;
  }
</style>
