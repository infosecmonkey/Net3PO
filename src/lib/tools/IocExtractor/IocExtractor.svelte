<script lang="ts">
  // IOC extractor and defanger. Paste text (logs, reports, emails, even
  // defanged indicators) and get grouped, deduplicated indicators.
  // Nothing is resolved, fetched or opened.
  import { invoke } from "@tauri-apps/api/core";
  import ExportMenu from "$lib/components/ExportMenu.svelte";
  import { buildIocReport, isInternal, KIND_LABEL, KIND_ORDER, toCsv, type Extraction, type Ioc } from "./report";

  let text = $state("");
  let result = $state<Extraction | null>(null);
  let showDefanged = $state(true);
  let hideInternal = $state(false);
  let copied = $state("");
  let error = $state("");

  const shown = $derived((result?.iocs ?? []).filter((i) => !(hideInternal && isInternal(i))));
  const groups = $derived(
    KIND_ORDER.map((k) => ({ kind: k, items: shown.filter((i) => i.kind === k) })).filter((g) => g.items.length),
  );

  async function extract() {
    error = "";
    result = await invoke<Extraction>("ioc_extract", { text });
    if (result.error) error = result.error;
  }

  async function transform(defang: boolean) {
    error = "";
    try {
      text = await invoke<string>("ioc_transform", { text, defang });
    } catch (e) {
      error = String(e);
    }
  }

  async function copy(key: string, value: string) {
    try {
      await navigator.clipboard.writeText(value);
      copied = key;
      setTimeout(() => (copied = ""), 1200);
    } catch {
      copied = "";
    }
  }

  const val = (i: Ioc) => (showDefanged ? i.defanged : i.value);
</script>

<div class="panel">
  <header>
    <h1>IOC Extractor</h1>
    <p class="sub">
      Pull IPs, domains, URLs, email addresses and hash candidates out of text, including defanged
      input. Offline: nothing is resolved, fetched or opened.
    </p>
  </header>

  <textarea class="mono" rows="9" bind:value={text} spellcheck="false" placeholder="paste logs, an alert, a threat report or an email"></textarea>
  <div class="row">
    <button class="primary" onclick={extract}>Extract</button>
    <button class="second" onclick={() => transform(true)} title="Rewrite the text with indicators defanged">Defang text</button>
    <button class="second" onclick={() => transform(false)} title="Rewrite the text with indicators refanged; nothing is opened">Refang text</button>
  </div>
  {#if error}<div class="error">{error}</div>{/if}

  {#if result && !result.error}
    <div class="bar">
      <span class="muted">{shown.length} distinct indicator{shown.length === 1 ? "" : "s"}{result.truncated ? " (stopped at 50,000)" : ""}</span>
      <label class="check"><input type="checkbox" bind:checked={showDefanged} /> Show defanged</label>
      <label class="check"><input type="checkbox" bind:checked={hideInternal} /> Hide private and documentation addresses</label>
      <span class="spacer"></span>
      {#if shown.length}
        <button class="mini" onclick={() => copy("csv", toCsv(shown, showDefanged))}>{copied === "csv" ? "Copied" : "Copy all as CSV"}</button>
        <ExportMenu build={() => buildIocReport(shown)} name="iocs" />
      {/if}
    </div>
    {#if !shown.length}<p class="muted">No indicators found.</p>{/if}
    {#each groups as g (g.kind)}
      <section>
        <div class="ghead">
          <h2>{KIND_LABEL[g.kind]} <span class="muted">{g.items.length}</span></h2>
          <button class="mini" onclick={() => copy(g.kind, g.items.map(val).join("\n"))}>{copied === g.kind ? "Copied" : "Copy"}</button>
        </div>
        <table>
          <tbody>
            {#each g.items as i (i.value)}
              <tr>
                <td class="mono v">{val(i)}</td>
                <td class="muted n">{i.count > 1 ? `×${i.count}` : ""}</td>
                <td class="muted n" title={`first seen as: ${i.original}`}>line {i.line}</td>
                <td class="flags">{#each i.flags as f (f)}<span class="flag">{f}</span>{/each}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </section>
    {/each}
    {#if groups.some((g) => g.kind.startsWith("sha") || g.kind === "md5")}
      <p class="muted small">Hash entries are candidates by length (32, 40, 64 or 128 hex digits), not confirmed hashes.</p>
    {/if}
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
    margin: 0 0 1rem;
    color: var(--muted);
    font-size: 0.85rem;
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

  .row,
  .bar {
    display: flex;
    align-items: center;
    gap: 0.7rem;
    margin: 0.7rem 0;
    flex-wrap: wrap;
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

  .second {
    background: var(--input-bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.45rem 0.9rem;
    color: var(--fg);
    cursor: pointer;
    font-size: 0.84rem;
  }

  .mini {
    background: var(--input-bg);
    border: 1px solid var(--border);
    border-radius: 4px;
    color: var(--fg);
    font-size: 0.72rem;
    padding: 0.12rem 0.5rem;
    cursor: pointer;
  }

  .check {
    display: inline-flex;
    align-items: center;
    gap: 0.35rem;
    font-size: 0.8rem;
  }

  .muted {
    color: var(--muted);
    font-size: 0.8rem;
    font-weight: normal;
  }

  .small {
    font-size: 0.74rem;
  }

  .error {
    color: var(--error-fg);
    font-size: 0.82rem;
  }

  section {
    margin: 0.8rem 0;
  }

  .ghead {
    display: flex;
    align-items: center;
    gap: 0.6rem;
  }

  h2 {
    font-size: 0.92rem;
    margin: 0 0 0.3rem;
  }

  table {
    border-collapse: collapse;
    width: 100%;
  }

  td {
    padding: 0.18rem 0.6rem 0.18rem 0;
    font-size: 0.8rem;
    border-bottom: 1px solid var(--border);
    vertical-align: top;
  }

  td.v {
    overflow-wrap: anywhere;
  }

  td.n {
    white-space: nowrap;
    width: 1%;
  }

  .flag {
    display: inline-block;
    font-size: 0.68rem;
    border: 1px solid var(--border);
    border-radius: 3px;
    padding: 0 0.3rem;
    margin: 0 0.25rem 0.15rem 0;
    color: var(--muted);
  }
</style>
