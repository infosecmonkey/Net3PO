<script lang="ts">
  // Aggregate an address list (with overlap checks), or compare two lists.
  import { invoke } from "@tauri-apps/api/core";
  import ExportMenu from "$lib/components/ExportMenu.svelte";
  import {
    addressText,
    buildAggregateReport,
    buildCompareReport,
    OVERLAP_LABEL,
    type AggregateResult,
    type CompareResult,
    type FamilySet,
    type Invalid,
  } from "./cidr";

  let { mode }: { mode: "aggregate" | "compare" } = $props();

  let textA = $state("");
  let textB = $state("");
  let agg = $state<AggregateResult | null>(null);
  let cmp = $state<CompareResult | null>(null);
  let copied = $state("");

  async function run() {
    if (mode === "aggregate") {
      agg = await invoke<AggregateResult>("cidr_aggregate", { text: textA });
    } else {
      cmp = await invoke<CompareResult>("cidr_compare", { a: textA, b: textB });
    }
  }

  async function copy(label: string, list: string[]) {
    try {
      await navigator.clipboard.writeText(list.join("\n"));
      copied = label;
      setTimeout(() => (copied = ""), 1500);
    } catch {
      copied = "";
    }
  }

  const PLACEHOLDER = "one per line, or separated by commas\nprefixes, addresses, netmasks or ranges (a - b)\n# comments are ignored";
</script>

{#snippet setView(title: string, s: FamilySet, key: string)}
  {#if s.prefixes.length}
    <div class="set">
      <div class="set-head">
        <strong>{title}</strong>
        <span class="muted">{s.prefixes.length} prefix{s.prefixes.length === 1 ? "" : "es"} · {addressText(s.addresses)} addresses</span>
        <button class="mini" onclick={() => copy(key, s.prefixes)}>{copied === key ? "Copied" : "Copy"}</button>
      </div>
      <pre class="mono list">{s.prefixes.join("\n")}</pre>
      {#if s.truncated}<div class="note">List truncated at 50,000 prefixes.</div>{/if}
    </div>
  {/if}
{/snippet}

{#snippet invalidView(label: string, inv: Invalid[])}
  {#if inv.length}
    <div class="problems">
      <strong>{label}: {inv.length} entr{inv.length === 1 ? "y" : "ies"} skipped</strong>
      <ul>{#each inv.slice(0, 200) as i, n (n)}<li><span class="mono">line {i.line}: {i.text}</span> <span class="muted">{i.reason}</span></li>{/each}</ul>
    </div>
  {/if}
{/snippet}

<div class="inputs" class:two={mode === "compare"}>
  <label>
    <span>{mode === "compare" ? "Set A" : "Addresses"}</span>
    <textarea class="mono" rows="10" bind:value={textA} spellcheck="false" placeholder={PLACEHOLDER}></textarea>
  </label>
  {#if mode === "compare"}
    <label>
      <span>Set B</span>
      <textarea class="mono" rows="10" bind:value={textB} spellcheck="false" placeholder={PLACEHOLDER}></textarea>
    </label>
  {/if}
</div>
<div class="actions">
  <button class="primary" onclick={run}>{mode === "aggregate" ? "Aggregate" : "Compare"}</button>
  <span class="hint">IPv4 and IPv6 are handled separately. Results cover exactly the input addresses, nothing more.</span>
  <span class="spacer"></span>
  {#if mode === "aggregate" && agg}
    <ExportMenu build={() => (agg ? buildAggregateReport(agg) : null)} name="cidr-aggregate" />
  {:else if mode === "compare" && cmp}
    <ExportMenu build={() => (cmp ? buildCompareReport(cmp) : null)} name="cidr-compare" />
  {/if}
</div>

{#if mode === "aggregate" && agg}
  {#if agg.inputTruncated}<div class="note">Only the first 20,000 entries were read.</div>{/if}
  <div class="summary">{agg.v4.entries + agg.v6.entries} entries in, {agg.v4.prefixes.length + agg.v6.prefixes.length} prefixes out.</div>
  <div class="sets">
    {@render setView("IPv4", agg.v4, "v4")}
    {@render setView("IPv6", agg.v6, "v6")}
  </div>
  {#if agg.overlaps.length}
    <div class="problems">
      <strong>{agg.overlaps.length}{agg.overlapsTruncated ? "+" : ""} overlap{agg.overlaps.length === 1 ? "" : "s"} in the input</strong>
      <ul>
        {#each agg.overlaps as o, n (n)}
          <li><span class="mono">line {o.aLine}: {o.a}</span> {OVERLAP_LABEL[o.kind]} <span class="mono">line {o.bLine}: {o.b}</span></li>
        {/each}
      </ul>
    </div>
  {/if}
  {#if agg.notes.length}
    <div class="problems">
      <strong>Normalized</strong>
      <ul>{#each agg.notes as nt, n (n)}<li><span class="mono">line {nt.line}: {nt.text}</span> <span class="muted">{nt.note}</span></li>{/each}</ul>
    </div>
  {/if}
  {@render invalidView("Input", agg.invalid)}
{/if}

{#if mode === "compare" && cmp}
  <div class="summary" class:same={cmp.identical}>
    {cmp.identical ? "A and B cover exactly the same addresses." : "A and B differ."}
  </div>
  {#each [["IPv4", cmp.v4], ["IPv6", cmp.v6]] as const as [fam, f] (fam)}
    {#if f.onlyA.prefixes.length || f.onlyB.prefixes.length || f.both.prefixes.length}
      <h3>{fam}</h3>
      <div class="sets three">
        {@render setView("Only in A", f.onlyA, `${fam}a`)}
        {@render setView("Only in B", f.onlyB, `${fam}b`)}
        {@render setView("In both", f.both, `${fam}c`)}
      </div>
    {/if}
  {/each}
  {@render invalidView("Set A", cmp.invalidA)}
  {@render invalidView("Set B", cmp.invalidB)}
{/if}

<style>
  .inputs {
    display: grid;
    gap: 0.8rem;
  }

  .inputs.two {
    grid-template-columns: 1fr 1fr;
  }

  label {
    display: flex;
    flex-direction: column;
    gap: 0.3rem;
    font-size: 0.8rem;
    color: var(--muted);
  }

  textarea {
    box-sizing: border-box;
    width: 100%;
    background: var(--input-bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.5rem 0.6rem;
    color: var(--fg);
    font-size: 0.8rem;
    resize: vertical;
  }

  textarea:focus {
    outline: none;
    border-color: var(--accent);
  }

  .mono {
    font-family: var(--mono);
  }

  .actions {
    display: flex;
    align-items: center;
    gap: 0.8rem;
    margin: 0.7rem 0 1rem;
  }

  .spacer {
    flex: 1;
  }

  .primary {
    background: var(--accent);
    color: var(--accent-fg);
    border: 1px solid var(--accent);
    border-radius: 6px;
    padding: 0.45rem 1rem;
    font-weight: 600;
    cursor: pointer;
  }

  .hint,
  .muted {
    color: var(--muted);
    font-size: 0.76rem;
  }

  .summary {
    font-size: 0.86rem;
    margin-bottom: 0.6rem;
  }

  .summary.same {
    color: #15935a;
  }

  h3 {
    font-size: 0.9rem;
    margin: 0.8rem 0 0.4rem;
  }

  .sets {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 0.8rem;
  }

  .sets.three {
    grid-template-columns: repeat(3, 1fr);
  }

  .set {
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 0.5rem 0.7rem;
    min-width: 0;
  }

  .set-head {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    font-size: 0.82rem;
    margin-bottom: 0.35rem;
  }

  .set-head .mini {
    margin-left: auto;
  }

  .mini {
    background: var(--input-bg);
    border: 1px solid var(--border);
    border-radius: 4px;
    color: var(--fg);
    font-size: 0.72rem;
    padding: 0.1rem 0.5rem;
    cursor: pointer;
  }

  .list {
    margin: 0;
    font-size: 0.78rem;
    max-height: 18rem;
    overflow: auto;
    white-space: pre;
  }

  .problems {
    margin-top: 0.8rem;
    font-size: 0.8rem;
  }

  .problems ul {
    margin: 0.3rem 0 0;
    padding-left: 1.1rem;
    max-height: 14rem;
    overflow: auto;
  }

  .note {
    font-size: 0.76rem;
    color: #b7791f;
    margin: 0.3rem 0;
  }
</style>
