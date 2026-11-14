<script lang="ts">
  // Redacted export: pick what to replace, add rules and exclusions, review
  // every replacement, then save. The mapping shown here is never written
  // into the exported report. Settings are remembered locally.
  import { onMount } from "svelte";
  import { FORMATS } from "$lib/report/export";
  import {
    DEFAULT_SETTINGS,
    KIND_LABEL,
    loadRedactSettings,
    saveRedactSettings,
    toOptions,
    type RedactOptions,
    type RedactPreview,
    type RedactSettings,
  } from "$lib/report/redact";
  import type { ReportFormat } from "$lib/report/types";

  interface Props {
    /** What the export covers, for the heading ("Port Scanner", "Project"). */
    subject: string;
    preview: (opts: RedactOptions) => Promise<RedactPreview>;
    /** Save in `format`; resolves to the saved file name or null if cancelled. */
    onexport: (opts: RedactOptions, format: ReportFormat) => Promise<string | null>;
    onclose: () => void;
  }

  let { subject, preview, onexport, onclose }: Props = $props();

  let settings = $state<RedactSettings>({ ...DEFAULT_SETTINGS });
  let loaded = $state(false);
  let result = $state<RedactPreview | null>(null);
  let error = $state("");
  let message = $state("");
  let busy = $state(false);
  let filter = $state("");

  const CATEGORIES: { key: "ips" | "hostnames" | "emails" | "usernames" | "secrets"; label: string }[] = [
    { key: "ips", label: "IP addresses" },
    { key: "hostnames", label: "Hostnames and domains" },
    { key: "emails", label: "Email addresses" },
    { key: "usernames", label: "Usernames" },
    { key: "secrets", label: "Passwords, keys, tokens" },
  ];

  let timer: ReturnType<typeof setTimeout> | undefined;
  let seq = 0;

  async function refresh() {
    const mine = ++seq;
    try {
      const r = await preview(toOptions(settings));
      if (mine !== seq) return;
      result = r;
      error = "";
    } catch (e) {
      if (mine !== seq) return;
      error = String(e);
    }
  }

  function changed() {
    message = "";
    clearTimeout(timer);
    timer = setTimeout(() => {
      void refresh();
      void saveRedactSettings($state.snapshot(settings)).catch(() => {});
    }, 350);
  }

  function keep(original: string) {
    const lines = settings.exclusionsText.split(/\r?\n/).map((l) => l.trim());
    if (!lines.some((l) => l.toLowerCase() === original.toLowerCase())) {
      settings.exclusionsText = [...lines.filter(Boolean), original].join("\n");
      changed();
    }
  }

  async function save(format: ReportFormat) {
    clearTimeout(timer);
    busy = true;
    message = "";
    try {
      const opts = toOptions(settings);
      await saveRedactSettings($state.snapshot(settings)).catch(() => {});
      const saved = await onexport(opts, format);
      if (saved) message = `Saved ${saved}`;
    } catch (e) {
      error = String(e);
    } finally {
      busy = false;
    }
  }

  const shown = $derived.by(() => {
    const q = filter.trim().toLowerCase();
    const all = result?.mapping ?? [];
    return q ? all.filter((m) => m.original.toLowerCase().includes(q) || m.token.toLowerCase().includes(q)) : all;
  });

  function onKeydown(e: KeyboardEvent) {
    if (e.key === "Escape") onclose();
  }

  onMount(() => {
    void (async () => {
      settings = await loadRedactSettings();
      loaded = true;
      await refresh();
    })();
    return () => clearTimeout(timer);
  });
</script>

<svelte:window onkeydown={onKeydown} />

<div class="backdrop" role="presentation" onclick={(e) => e.target === e.currentTarget && onclose()}>
  <div class="dialog" role="dialog" aria-modal="true" aria-label="Redacted export">
    <div class="head">
      <h2>Redacted export <span class="muted">{subject}</span></h2>
      <button class="x" onclick={onclose} aria-label="Close">×</button>
    </div>

    <div class="body">
      <div class="left">
        <div class="group">Replace</div>
        {#each CATEGORIES as c (c.key)}
          <label class="check">
            <input type="checkbox" bind:checked={settings[c.key]} onchange={changed} disabled={!loaded} />
            {c.label}
          </label>
        {/each}

        <label class="group" for="rrules">Rules</label>
        <textarea
          id="rrules"
          bind:value={settings.rulesText}
          oninput={changed}
          spellcheck="false"
          rows="5"
          placeholder={"one per line\nfind\nfind => replacement\nre:regex => replacement"}
        ></textarea>
        <div class="hint">Add customer and site names here; automatic detection cannot know them.</div>

        <label class="group" for="rexcl">Keep (never replace)</label>
        <textarea
          id="rexcl"
          bind:value={settings.exclusionsText}
          oninput={changed}
          spellcheck="false"
          rows="4"
          placeholder={"one per line\ndomain (covers subdomains)\nIPv4 or CIDR"}
        ></textarea>
      </div>

      <div class="right">
        <div class="summary">
          {#if result}
            <strong>{result.replacements}</strong> replacement{result.replacements === 1 ? "" : "s"},
            {result.mapping.length} distinct value{result.mapping.length === 1 ? "" : "s"}{result.privateKeys ? `, ${result.privateKeys} private key${result.privateKeys === 1 ? "" : "s"} removed` : ""}.
            <span class="muted">Title: {result.title}</span>
          {:else if !error}
            <span class="muted">Scanning...</span>
          {/if}
        </div>
        {#if error}<div class="error">{error}</div>{/if}
        <input class="filter" bind:value={filter} placeholder="Filter" spellcheck="false" />
        <div class="table-wrap">
          <table>
            <thead><tr><th>Type</th><th>Original</th><th>Becomes</th><th>Uses</th><th></th></tr></thead>
            <tbody>
              {#each shown as m (m.kind + m.token + m.original)}
                <tr>
                  <td class="kind {m.kind}">{KIND_LABEL[m.kind]}</td>
                  <td class="mono orig" title={m.kind === "secret" ? "" : m.original}>{m.kind === "secret" ? "••••••" : m.original}</td>
                  <td class="mono">{m.token}</td>
                  <td>{m.count}</td>
                  <td>
                    {#if m.kind !== "secret" && m.kind !== "custom"}
                      <button class="mini" onclick={() => keep(m.original)} title="Add to Keep">Keep</button>
                    {/if}
                  </td>
                </tr>
              {/each}
              {#if result && shown.length === 0}
                <tr><td colspan="5" class="muted">Nothing to replace.</td></tr>
              {/if}
            </tbody>
          </table>
        </div>
        {#if result?.mappingTruncated}<div class="hint">Showing the first 5000 values.</div>{/if}
      </div>
    </div>

    <div class="warn">
      Automatic detection is a best effort and can miss secrets, names and identifiers. Read the
      export before you send it. This table stays here; it is not written to the file. Saved
      projects are not changed.
    </div>

    <div class="foot">
      <span class="group inline">Save as</span>
      {#each FORMATS as f (f.id)}
        <button onclick={() => save(f.id)} disabled={busy || !!error || !result}>{f.label}</button>
      {/each}
      {#if message}<span class="muted">{message}</span>{/if}
    </div>
  </div>
</div>

<style>
  .backdrop {
    position: fixed;
    inset: 0;
    background: rgba(0, 0, 0, 0.45);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 100;
  }

  .dialog {
    background: var(--bg);
    color: var(--fg);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 1rem 1.2rem;
    width: min(60rem, calc(100vw - 2rem));
    height: min(44rem, calc(100vh - 2rem));
    box-sizing: border-box;
    display: flex;
    flex-direction: column;
    gap: 0.6rem;
    font-size: 0.82rem;
  }

  .head {
    display: flex;
    align-items: center;
    justify-content: space-between;
  }

  h2 {
    margin: 0;
    font-size: 1.05rem;
  }

  h2 .muted {
    font-weight: normal;
    font-size: 0.85rem;
    margin-left: 0.4rem;
  }

  .x {
    background: none;
    border: none;
    color: var(--muted);
    font-size: 1.3rem;
    cursor: pointer;
  }

  .body {
    flex: 1 1 auto;
    min-height: 0;
    display: grid;
    grid-template-columns: 17rem 1fr;
    gap: 1rem;
  }

  .left {
    display: flex;
    flex-direction: column;
    gap: 0.3rem;
    overflow-y: auto;
  }

  .right {
    display: flex;
    flex-direction: column;
    gap: 0.4rem;
    min-width: 0;
    min-height: 0;
  }

  .group {
    font-size: 0.68rem;
    color: var(--muted);
    text-transform: uppercase;
    letter-spacing: 0.04em;
    margin-top: 0.5rem;
  }

  .group.inline {
    margin: 0 0.3rem 0 0;
  }

  .check {
    display: flex;
    align-items: center;
    gap: 0.4rem;
  }

  textarea,
  .filter {
    background: var(--input-bg);
    border: 1px solid var(--border);
    border-radius: 4px;
    color: var(--fg);
    font-family: var(--mono, monospace);
    font-size: 0.76rem;
    padding: 0.35rem 0.45rem;
    resize: vertical;
  }

  textarea:focus,
  .filter:focus {
    outline: none;
    border-color: var(--accent);
  }

  .hint {
    font-size: 0.72rem;
    color: var(--muted);
  }

  .summary {
    min-height: 1.2rem;
  }

  .summary .muted {
    margin-left: 0.4rem;
  }

  .table-wrap {
    flex: 1 1 auto;
    min-height: 0;
    overflow: auto;
    border: 1px solid var(--border);
    border-radius: 4px;
  }

  table {
    width: 100%;
    border-collapse: collapse;
  }

  th,
  td {
    text-align: left;
    padding: 0.25rem 0.5rem;
    border-bottom: 1px solid var(--border);
    white-space: nowrap;
  }

  th {
    position: sticky;
    top: 0;
    background: var(--bg);
    font-size: 0.7rem;
    color: var(--muted);
    font-weight: 600;
  }

  .orig {
    max-width: 22rem;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .mono {
    font-family: var(--mono, monospace);
  }

  .kind {
    font-size: 0.72rem;
  }

  .kind.secret {
    color: var(--error-fg);
  }

  .mini {
    background: var(--input-bg);
    border: 1px solid var(--border);
    border-radius: 4px;
    color: var(--fg);
    font-size: 0.7rem;
    padding: 0.1rem 0.45rem;
    cursor: pointer;
  }

  .warn {
    font-size: 0.74rem;
    color: var(--muted);
    border-left: 3px solid var(--warn-fg, #c90);
    padding-left: 0.6rem;
  }

  .foot {
    display: flex;
    align-items: center;
    gap: 0.4rem;
  }

  .foot button {
    background: var(--input-bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    color: var(--fg);
    font-size: 0.78rem;
    padding: 0.3rem 0.8rem;
    cursor: pointer;
  }

  .foot button:hover:not(:disabled) {
    background: var(--hover);
  }

  .foot button:disabled {
    opacity: 0.5;
    cursor: default;
  }

  .muted {
    color: var(--muted);
  }

  .error {
    color: var(--error-fg);
  }

  @media (max-width: 700px) {
    .body {
      grid-template-columns: 1fr;
    }
  }
</style>
