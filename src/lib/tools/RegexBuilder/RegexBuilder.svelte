<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import type { RegexEngine, RegexFlags, RegexResult } from "$lib/tools/types";

  let pattern = $state(String.raw`(?<user>\w+)@(?<host>[\w.]+)`);
  let text = $state("Contact alice@example.com or bob@mail.test for access.");
  let engine = $state<RegexEngine>("standard");
  let flags = $state<RegexFlags>({
    caseInsensitive: false,
    multiline: false,
    dotAll: false,
    ignoreWhitespace: false,
  });

  // What each engine supports, shown under the toggle.
  const ENGINES: { id: RegexEngine; label: string; features: string }[] = [
    {
      id: "standard",
      label: "Standard (grep -E, linear time)",
      features:
        "Character classes, groups, alternation, anchors, Unicode. No backreferences or lookaround. Cannot ReDoS.",
    },
    {
      id: "pcre",
      label: "PCRE-style (grep -P)",
      features:
        "Adds lookahead, lookbehind, and backreferences. Backtracks, so it runs under a backtrack limit and errors if the limit is hit.",
    },
  ];

  let replaceOn = $state(false);
  let replacement = $state("$1 [at] $2");

  let result = $state<RegexResult | null>(null);
  let replaced = $state("");
  let error = $state("");

  // Code points of the current text, so highlight slicing is Unicode-safe and
  // matches the char offsets the backend returns.
  let codePoints = $derived([...text]);

  interface Segment {
    text: string;
    match: boolean;
  }

  // Build highlight segments from match ranges (matches never overlap).
  let segments = $derived.by<Segment[]>(() => {
    if (!result || result.matches.length === 0) {
      return [{ text, match: false }];
    }
    const segs: Segment[] = [];
    let cursor = 0;
    for (const m of result.matches) {
      if (m.start > cursor) {
        segs.push({ text: codePoints.slice(cursor, m.start).join(""), match: false });
      }
      segs.push({ text: codePoints.slice(m.start, m.end).join(""), match: true });
      cursor = m.end;
    }
    if (cursor < codePoints.length) {
      segs.push({ text: codePoints.slice(cursor).join(""), match: false });
    }
    return segs;
  });

  let debounce: ReturnType<typeof setTimeout> | undefined;

  // Re-run whenever any input changes, debounced so typing stays responsive.
  $effect(() => {
    // Touch the reactive inputs so the effect tracks them.
    void pattern;
    void text;
    void engine;
    void flags.caseInsensitive;
    void flags.multiline;
    void flags.dotAll;
    void flags.ignoreWhitespace;
    void replaceOn;
    void replacement;

    clearTimeout(debounce);
    debounce = setTimeout(run, 150);
    return () => clearTimeout(debounce);
  });

  async function run() {
    if (pattern.length === 0) {
      result = null;
      replaced = "";
      error = "";
      return;
    }
    try {
      result = await invoke<RegexResult>("regex_test", { pattern, text, flags, engine });
      error = "";
      if (replaceOn) {
        replaced = await invoke<string>("regex_replace", {
          pattern,
          text,
          flags,
          replacement,
          engine,
        });
      } else {
        replaced = "";
      }
    } catch (e) {
      result = null;
      replaced = "";
      error = String(e);
    }
  }

  function groupHeader(i: number): string {
    const name = result?.groupNames[i] ?? null;
    return name ? `${i + 1} ${name}` : `${i + 1}`;
  }

  // Keep the highlight layer aligned when the textarea scrolls internally.
  let highlightEl = $state<HTMLPreElement | null>(null);
  function syncScroll(e: Event) {
    const ta = e.currentTarget as HTMLTextAreaElement;
    if (highlightEl) {
      highlightEl.scrollTop = ta.scrollTop;
      highlightEl.scrollLeft = ta.scrollLeft;
    }
  }
</script>

<div class="panel">
  <header>
    <h1>Regex Builder</h1>
    <p class="sub">Paste sample data and build the expression live.</p>
  </header>

  <div class="field">
    <span class="label">Engine</span>
    <div class="engine">
      {#each ENGINES as e (e.id)}
        <button
          class="engine-btn"
          class:active={engine === e.id}
          onclick={() => (engine = e.id)}
        >
          {e.label}
        </button>
      {/each}
    </div>
    <p class="features">{ENGINES.find((e) => e.id === engine)?.features}</p>
  </div>

  <div class="field">
    <label for="pattern">Pattern</label>
    <input
      id="pattern"
      class="mono"
      bind:value={pattern}
      spellcheck="false"
      autocapitalize="off"
      autocomplete="off"
      placeholder="\d+"
    />
  </div>

  <div class="flags">
    <label><input type="checkbox" bind:checked={flags.caseInsensitive} /> ignore case (i)</label>
    <label><input type="checkbox" bind:checked={flags.multiline} /> multiline (m)</label>
    <label><input type="checkbox" bind:checked={flags.dotAll} /> dot matches newline (s)</label>
    <label><input type="checkbox" bind:checked={flags.ignoreWhitespace} /> verbose (x)</label>
  </div>

  {#if error}
    <div class="error mono">{error}</div>
  {:else if result}
    <div class="status">
      {result.total === 0 ? "No matches" : `${result.total.toLocaleString()} match${result.total === 1 ? "" : "es"}`}
      {#if result.truncated}
        <span class="muted">(showing first {result.matches.length.toLocaleString()})</span>
      {/if}
    </div>
  {/if}

  <div class="field">
    <label for="sample">Sample text</label>
    <div class="editor">
      <pre class="highlight mono" aria-hidden="true" bind:this={highlightEl}>{#each segments as seg (seg)}{#if seg.match}<mark>{seg.text}</mark>{:else}{seg.text}{/if}{/each}<br /></pre>
      <textarea
        id="sample"
        class="mono"
        bind:value={text}
        onscroll={syncScroll}
        spellcheck="false"
        autocapitalize="off"
        autocomplete="off"
      ></textarea>
    </div>
  </div>

  {#if result && result.matches.length > 0 && result.groupNames.length > 0}
    <section>
      <h2>Capture groups</h2>
      <div class="table-scroll">
        <table>
          <thead>
            <tr>
              <th>#</th>
              <th>Match</th>
              {#each result.groupNames as _, i (i)}
                <th>{groupHeader(i)}</th>
              {/each}
            </tr>
          </thead>
          <tbody>
            {#each result.matches as m, i (i)}
              <tr>
                <td class="muted">{i + 1}</td>
                <td class="mono">{m.value}</td>
                {#each m.groups as g (g.index)}
                  <td class="mono">{g.value ?? ""}{#if g.value === null}<span class="muted">-</span>{/if}</td>
                {/each}
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    </section>
  {/if}

  <section>
    <label class="replace-toggle">
      <input type="checkbox" bind:checked={replaceOn} /> Replacement preview
    </label>
    {#if replaceOn}
      <input
        class="mono"
        bind:value={replacement}
        spellcheck="false"
        autocapitalize="off"
        autocomplete="off"
        placeholder="$1"
      />
      <pre class="replaced mono">{replaced}</pre>
    {/if}
  </section>
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

  .field {
    margin-bottom: 0.9rem;
  }

  label,
  .label {
    display: block;
    font-size: 0.8rem;
    color: var(--muted);
    margin-bottom: 0.35rem;
  }

  .engine {
    display: flex;
    flex-wrap: wrap;
    gap: 0;
    border: 1px solid var(--border);
    border-radius: 6px;
    overflow: hidden;
    width: fit-content;
  }

  .engine-btn {
    background: var(--input-bg);
    border: none;
    border-right: 1px solid var(--border);
    padding: 0.45rem 0.9rem;
    color: var(--fg);
    font-size: 0.82rem;
    cursor: pointer;
  }

  .engine-btn:last-child {
    border-right: none;
  }

  .engine-btn:hover:not(.active) {
    background: var(--hover);
  }

  .engine-btn.active {
    background: var(--accent);
    color: #fff;
    font-weight: 600;
  }

  .features {
    margin: 0.4rem 0 0;
    font-size: 0.78rem;
    color: var(--muted);
    max-width: 640px;
  }

  input,
  textarea {
    width: 100%;
    box-sizing: border-box;
    background: var(--input-bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.5rem 0.6rem;
    color: var(--fg);
    font-size: 0.9rem;
  }

  input:focus,
  textarea:focus {
    outline: none;
    border-color: var(--accent);
  }

  .mono {
    font-family: var(--mono);
  }

  .flags {
    display: flex;
    flex-wrap: wrap;
    gap: 1rem;
    margin-bottom: 1rem;
  }

  .flags label {
    display: flex;
    align-items: center;
    gap: 0.35rem;
    color: var(--fg);
    margin: 0;
    font-size: 0.82rem;
  }

  .flags input {
    width: auto;
  }

  .status {
    font-size: 0.85rem;
    margin-bottom: 0.9rem;
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

  /* Overlay the highlight layer exactly behind the transparent textarea so
     highlighted matches line up with the typed text. */
  .editor {
    position: relative;
  }

  .highlight,
  .editor textarea {
    margin: 0;
    padding: 0.5rem 0.6rem;
    font-size: 0.9rem;
    line-height: 1.45;
    border: 1px solid var(--border);
    border-radius: 6px;
    white-space: pre-wrap;
    overflow-wrap: break-word;
    min-height: 9rem;
  }

  .highlight {
    position: absolute;
    inset: 0;
    color: var(--fg);
    background: var(--input-bg);
    pointer-events: none;
    overflow: hidden;
  }

  .editor textarea {
    position: relative;
    background: transparent;
    color: transparent;
    caret-color: var(--fg);
    resize: vertical;
    width: 100%;
    box-sizing: border-box;
  }

  mark {
    background: var(--accent);
    color: #fff;
    border-radius: 2px;
  }

  section {
    margin-top: 1.5rem;
  }

  h2 {
    font-size: 1rem;
    margin: 0 0 0.6rem;
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

  .replace-toggle {
    display: flex;
    align-items: center;
    gap: 0.35rem;
    color: var(--fg);
    margin-bottom: 0.6rem;
    font-size: 0.85rem;
  }

  .replace-toggle input {
    width: auto;
  }

  .replaced {
    margin: 0.6rem 0 0;
    padding: 0.6rem;
    background: var(--input-bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    white-space: pre-wrap;
    overflow-wrap: break-word;
    font-size: 0.85rem;
    min-height: 3rem;
  }
</style>
