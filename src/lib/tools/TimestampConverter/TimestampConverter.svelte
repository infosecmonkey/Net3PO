<script lang="ts">
  // Timestamp converter: paste any common timestamp, see every reading of it
  // in UTC and a chosen zone. Inferred units, years and zones are stated.
  import { invoke } from "@tauri-apps/api/core";
  import ExportMenu from "$lib/components/ExportMenu.svelte";
  import { buildTimestampReport } from "./report";
  import { FORMAT_ROWS, type TsConversion } from "./types";

  const localZone = Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC";
  const zones: string[] = (() => {
    try {
      const list = (Intl as unknown as { supportedValuesOf?: (k: string) => string[] }).supportedValuesOf?.("timeZone") ?? [];
      return Array.from(new Set(["UTC", localZone, ...list]));
    } catch {
      return ["UTC", localZone];
    }
  })();

  let input = $state("");
  let zone = $state(localZone);
  let result = $state<TsConversion | null>(null);
  let copied = $state("");
  let timer: ReturnType<typeof setTimeout> | undefined;

  async function convert() {
    if (!input.trim()) {
      result = null;
      return;
    }
    result = await invoke<TsConversion>("ts_convert", { input, zone });
  }

  function changed() {
    clearTimeout(timer);
    timer = setTimeout(() => void convert(), 200);
  }

  async function now() {
    result = await invoke<TsConversion>("ts_now", { zone });
    input = result.readings[0]?.formats.unixSeconds ?? "";
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
</script>

<div class="panel">
  <header>
    <h1>Timestamp Converter</h1>
    <p class="sub">
      Unix seconds, milliseconds, microseconds or nanoseconds, Windows FILETIME and AD timestamps,
      LDAP generalized time, ISO 8601, RFC 2822 and syslog dates. Offline.
    </p>
  </header>

  <div class="row">
    <input class="mono grow" bind:value={input} oninput={changed} spellcheck="false" autocapitalize="off" placeholder="paste a timestamp" aria-label="Timestamp" />
    <button class="second" onclick={now}>Now</button>
  </div>
  <div class="row">
    <label class="zone">Show in
      <input class="mono" list="tz-list" bind:value={zone} onchange={convert} spellcheck="false" aria-label="Time zone" />
      <datalist id="tz-list">{#each zones as z (z)}<option value={z}></option>{/each}</datalist>
    </label>
    <button class="link" onclick={() => { zone = localZone; void convert(); }}>This computer ({localZone})</button>
    <button class="link" onclick={() => { zone = "UTC"; void convert(); }}>UTC</button>
    <span class="spacer"></span>
    {#if result?.readings.length}
      <ExportMenu build={() => (result ? buildTimestampReport(input, zone, result) : null)} name="timestamp" />
    {/if}
  </div>

  {#if result?.error}<div class="error">{result.error}</div>{/if}

  {#if result?.readings.length}
    {@const likely = result.readings.filter((r) => r.plausible)}
    {@const unlikely = result.readings.filter((r) => !r.plausible)}
    {#each likely as r, i (i)}
      <div class="card">
        <div class="head">Read as <strong>{r.label}</strong></div>
        {#each r.notes as n (n)}<div class="note">{n}</div>{/each}
        <table>
          <tbody>
            {#each FORMAT_ROWS as f (f.key)}
              <tr>
                <th>{f.label}</th>
                <td class="mono">{r.formats[f.key]}</td>
                <td><button class="mini" onclick={() => copy(`${i}${f.key}`, r.formats[f.key])}>{copied === `${i}${f.key}` ? "Copied" : "Copy"}</button></td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/each}
    {#if unlikely.length}
      <details open={likely.length === 0}>
        <summary>{unlikely.length} other reading{unlikely.length === 1 ? "" : "s"} outside 1990 to 2100</summary>
        <table class="others">
          <tbody>
            {#each unlikely as r, i (i)}
              <tr><th>{r.label}</th><td class="mono">{r.formats.isoUtc}</td></tr>
            {/each}
          </tbody>
        </table>
      </details>
    {/if}
  {/if}
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
    margin: 0 0 1rem;
    color: var(--muted);
    font-size: 0.85rem;
  }

  .row {
    display: flex;
    align-items: center;
    gap: 0.6rem;
    margin-bottom: 0.7rem;
    flex-wrap: wrap;
  }

  input {
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

  .grow {
    flex: 1;
    min-width: 0;
  }

  .mono {
    font-family: var(--mono);
  }

  .zone {
    display: inline-flex;
    align-items: center;
    gap: 0.5rem;
    font-size: 0.82rem;
    color: var(--muted);
  }

  .zone input {
    width: 16rem;
    font-size: 0.82rem;
    padding: 0.35rem 0.5rem;
  }

  .spacer {
    flex: 1;
  }

  .second {
    background: var(--input-bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.5rem 1rem;
    color: var(--fg);
    font-size: 0.85rem;
    cursor: pointer;
  }

  .link {
    background: none;
    border: none;
    color: var(--accent);
    font-size: 0.78rem;
    cursor: pointer;
    padding: 0;
  }

  .error {
    background: var(--error-bg);
    border: 1px solid var(--error-border);
    color: var(--error-fg);
    border-radius: 6px;
    padding: 0.6rem 0.8rem;
    font-size: 0.82rem;
  }

  .card {
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 0.7rem 0.9rem;
    margin-bottom: 0.7rem;
  }

  .head {
    font-size: 0.86rem;
    margin-bottom: 0.4rem;
  }

  .note {
    border-left: 3px solid #b7791f;
    padding: 0.2rem 0.6rem;
    font-size: 0.8rem;
    margin: 0.3rem 0;
  }

  table {
    border-collapse: collapse;
    width: 100%;
  }

  th {
    text-align: left;
    font-weight: 500;
    color: var(--muted);
    font-size: 0.8rem;
    padding: 0.22rem 1rem 0.22rem 0;
    white-space: nowrap;
    width: 1%;
  }

  td {
    font-size: 0.84rem;
    padding: 0.22rem 0;
  }

  td:last-child {
    text-align: right;
    width: 1%;
    white-space: nowrap;
    padding-left: 0.6rem;
  }

  .mini {
    white-space: nowrap;
    background: var(--input-bg);
    border: 1px solid var(--border);
    border-radius: 4px;
    color: var(--fg);
    font-size: 0.7rem;
    padding: 0.08rem 0.45rem;
    cursor: pointer;
  }

  summary {
    font-size: 0.8rem;
    color: var(--muted);
    cursor: pointer;
  }

  .others td {
    color: var(--muted);
  }
</style>
