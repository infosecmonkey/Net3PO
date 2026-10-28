<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import type { DigResponse, DnsRecord } from "$lib/tools/types";

  const TYPES = ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA", "PTR", "SRV", "CAA"];

  let name = $state("example.com");
  let server = $state("");
  let rtype = $state("A");

  let result = $state<DigResponse | null>(null);
  let error = $state("");
  let loading = $state(false);

  async function run(type: string) {
    rtype = type;
    if (name.trim().length === 0) {
      error = "Enter a name or IP to look up.";
      return;
    }
    loading = true;
    error = "";
    try {
      result = await invoke<DigResponse>("dig_query", {
        name,
        recordType: type,
        server,
      });
    } catch (e) {
      result = null;
      error = String(e);
    } finally {
      loading = false;
    }
  }

  function onKeydown(e: KeyboardEvent) {
    if (e.key === "Enter") run(rtype);
  }

  const sections = $derived<[string, DnsRecord[]][]>(
    result
      ? [
          ["Answer", result.answers],
          ["Authority", result.authority],
          ["Additional", result.additional],
        ]
      : [],
  );
</script>

<div class="panel">
  <header>
    <h1>Dig</h1>
    <p class="sub">
      DNS lookups against your system resolver, or a server you name. Pick a
      record type to run the query.
    </p>
  </header>

  <div class="fields">
    <div class="field grow">
      <label for="name">Name or IP</label>
      <input
        id="name"
        class="mono"
        bind:value={name}
        onkeydown={onKeydown}
        spellcheck="false"
        autocapitalize="off"
        autocomplete="off"
        placeholder="example.com"
      />
    </div>
    <div class="field">
      <label for="server">Server (optional)</label>
      <input
        id="server"
        class="mono"
        bind:value={server}
        onkeydown={onKeydown}
        spellcheck="false"
        autocapitalize="off"
        autocomplete="off"
        placeholder="system resolver"
      />
    </div>
  </div>

  <div class="types">
    {#each TYPES as t (t)}
      <button class="type" class:active={rtype === t} disabled={loading} onclick={() => run(t)}>
        {t}
      </button>
    {/each}
  </div>

  {#if loading}
    <div class="status muted">Querying...</div>
  {/if}

  {#if error}
    <div class="error mono">{error}</div>
  {/if}

  {#if result && !loading}
    <div class="meta">
      <span>{result.rcode}</span>
      <span class="muted">{result.server} · {result.protocol} · {result.queryTimeMs} ms</span>
      {#if result.flags.length > 0}
        <span class="flags mono">flags: {result.flags.join(" ")}</span>
      {/if}
    </div>
    <div class="question mono">;; {result.question}</div>

    {#each sections as [title, records] (title)}
      {#if records.length > 0}
        <section>
          <h2>{title}</h2>
          <div class="table-scroll">
            <table>
              <thead>
                <tr><th>Name</th><th>TTL</th><th>Type</th><th>Data</th></tr>
              </thead>
              <tbody>
                {#each records as r, i (i)}
                  <tr>
                    <td class="mono">{r.name}</td>
                    <td class="mono num">{r.ttl}</td>
                    <td class="mono">{r.rtype}</td>
                    <td class="mono data">{r.data}</td>
                  </tr>
                {/each}
              </tbody>
            </table>
          </div>
        </section>
      {/if}
    {/each}

    {#if result.answers.length === 0}
      <p class="note">No answer records. Response code: {result.rcode}.</p>
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
    margin: 0 0 1.25rem;
    color: var(--muted);
    font-size: 0.85rem;
  }

  .fields {
    display: flex;
    flex-wrap: wrap;
    gap: 0.9rem;
    margin-bottom: 0.9rem;
  }

  .field {
    display: flex;
    flex-direction: column;
    flex: 0 0 auto;
  }

  .field.grow {
    flex: 1 1 260px;
  }

  label {
    font-size: 0.8rem;
    color: var(--muted);
    margin-bottom: 0.35rem;
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

  .field.grow input {
    width: 100%;
  }

  input:focus {
    outline: none;
    border-color: var(--accent);
  }

  .mono {
    font-family: var(--mono);
  }

  .types {
    display: flex;
    flex-wrap: wrap;
    gap: 0.4rem;
    margin-bottom: 1.1rem;
  }

  .type {
    background: var(--input-bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.4rem 0.7rem;
    color: var(--fg);
    font-size: 0.8rem;
    font-family: var(--mono);
    cursor: pointer;
  }

  .type:hover:not(:disabled):not(.active) {
    background: var(--hover);
  }

  .type.active {
    background: var(--accent);
    border-color: var(--accent);
    color: #fff;
    font-weight: 600;
  }

  .type:disabled {
    opacity: 0.5;
    cursor: default;
  }

  .status {
    font-size: 0.85rem;
    margin-bottom: 0.6rem;
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

  .meta {
    display: flex;
    flex-wrap: wrap;
    align-items: baseline;
    gap: 0.75rem;
    font-size: 0.85rem;
    margin-bottom: 0.25rem;
  }

  .meta span:first-child {
    font-weight: 600;
  }

  .flags {
    font-size: 0.78rem;
  }

  .question {
    font-size: 0.8rem;
    color: var(--muted);
    margin-bottom: 1rem;
  }

  section {
    margin-bottom: 1.25rem;
  }

  h2 {
    font-size: 0.95rem;
    margin: 0 0 0.5rem;
  }

  .table-scroll {
    overflow-x: auto;
    border: 1px solid var(--border);
    border-radius: 6px;
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
    padding: 0.4rem 0.75rem;
    border-bottom: 1px solid var(--border);
    white-space: nowrap;
  }

  td {
    padding: 0.35rem 0.75rem;
    border-bottom: 1px solid var(--border);
    vertical-align: top;
  }

  tr:last-child td {
    border-bottom: none;
  }

  .num {
    text-align: right;
  }

  .data {
    word-break: break-all;
  }

  .note {
    font-size: 0.82rem;
    color: var(--muted);
  }
</style>
