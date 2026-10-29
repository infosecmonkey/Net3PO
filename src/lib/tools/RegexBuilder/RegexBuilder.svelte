<script lang="ts">
  import { onMount, tick } from "svelte";
  import { invoke } from "@tauri-apps/api/core";
  import { openInGrep } from "$lib/nav.svelte";
  import type { RegexEngine, RegexFlags, RegexRecipe, RegexResult } from "$lib/tools/types";
  import { PALETTE, type PaletteToken } from "./palette";
  import { SAMPLES } from "./samples";

  let pattern = $state("");
  let text = $state("");
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

  // Recipe library, loaded once from the backend where it is tested.
  let recipes = $state<RegexRecipe[]>([]);
  let recipeFilter = $state("");
  let lastRecipe = $state<RegexRecipe | null>(null);
  let patternEl = $state<HTMLInputElement | null>(null);

  onMount(async () => {
    try {
      recipes = await invoke<RegexRecipe[]>("regex_recipes");
    } catch (e) {
      error = String(e);
    }
  });

  // Recipes grouped in library order, narrowed by the filter box.
  let recipeGroups = $derived.by(() => {
    const q = recipeFilter.trim().toLowerCase();
    const groups: { name: string; items: RegexRecipe[] }[] = [];
    for (const r of recipes) {
      if (q && !`${r.label} ${r.help} ${r.group}`.toLowerCase().includes(q)) continue;
      let g = groups.find((x) => x.name === r.group);
      if (!g) {
        g = { name: r.group, items: [] };
        groups.push(g);
      }
      g.items.push(r);
    }
    return groups;
  });

  /** Insert `snippet` at the caret (replacing any selection), then place the
      caret `caret` characters into it. */
  async function insertAtCaret(snippet: string, caret?: number) {
    const start = patternEl?.selectionStart ?? pattern.length;
    const end = patternEl?.selectionEnd ?? pattern.length;
    pattern = pattern.slice(0, start) + snippet + pattern.slice(end);
    await tick();
    const pos = start + (caret ?? snippet.length);
    patternEl?.focus();
    patternEl?.setSelectionRange(pos, pos);
  }

  /** Recipes replace the pattern; Shift-click inserts at the caret instead. */
  function useRecipe(r: RegexRecipe, e: MouseEvent) {
    lastRecipe = r;
    if (e.shiftKey) {
      void insertAtCaret(r.pattern);
    } else {
      pattern = r.pattern;
    }
  }

  function useToken(t: PaletteToken) {
    if (t.pcreOnly) engine = "pcre";
    void insertAtCaret(t.insert, t.caret);
  }

  function loadSample(e: Event) {
    const sel = e.currentTarget as HTMLSelectElement;
    const doc = SAMPLES.find((s) => s.name === sel.value);
    if (doc) text = doc.text;
    sel.value = "";
  }

  function sendToGrep() {
    openInGrep(pattern, engine === "pcre" ? "perl" : "extended");
  }

  let replaceOn = $state(false);
  let replacement = $state("");

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
      bind:this={patternEl}
      bind:value={pattern}
      spellcheck="false"
      autocapitalize="off"
      autocomplete="off"
      placeholder="(?<user>\w+)@(?<host>[\w.]+), or pick a recipe below"
    />
    <div class="pattern-actions">
      <button class="small" onclick={() => (pattern = "")} disabled={pattern.length === 0}>Clear</button>
      <button class="small" onclick={sendToGrep} disabled={pattern.length === 0}>Open in Grep Builder</button>
    </div>
  </div>

  <details class="library" open>
    <summary>Recipes <span class="muted">({recipes.length})</span></summary>
    <div class="library-body">
      <input
        class="filter"
        bind:value={recipeFilter}
        placeholder="Filter: mask, mac, syslog..."
        spellcheck="false"
        autocapitalize="off"
        autocomplete="off"
      />
      <p class="hint">Click to replace the pattern. Shift-click to insert at the caret.</p>
      {#each recipeGroups as g (g.name)}
        <div class="chip-group">
          <span class="group-name">{g.name}</span>
          <div class="chips">
            {#each g.items as r (r.id)}
              <button
                class="chip"
                class:active={lastRecipe?.id === r.id && pattern === r.pattern}
                title={`${r.help}\ne.g. ${r.examples[0]}`}
                onclick={(e) => useRecipe(r, e)}
              >
                {r.label}
              </button>
            {/each}
          </div>
        </div>
      {:else}
        <p class="hint">No recipes match.</p>
      {/each}
      {#if lastRecipe}
        <p class="recipe-info">
          <strong>{lastRecipe.label}:</strong>
          {lastRecipe.help}. e.g. <code>{lastRecipe.examples.join("  ")}</code>
        </p>
      {/if}
    </div>
  </details>

  <details class="library">
    <summary>Tokens</summary>
    <div class="library-body">
      <p class="hint">Inserts at the caret. PCRE-only tokens switch the engine.</p>
      {#each PALETTE as g (g.name)}
        <div class="chip-group">
          <span class="group-name">{g.name}</span>
          <div class="chips">
            {#each g.tokens as t (t.label)}
              <button class="chip mono" class:pcre={t.pcreOnly} title={t.help} onclick={() => useToken(t)}>
                {t.label}
              </button>
            {/each}
          </div>
        </div>
      {/each}
    </div>
  </details>

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
    <div class="sample-head">
      <label for="sample">Sample text</label>
      <select class="sample-select" onchange={loadSample} aria-label="Load sample">
        <option value="">Load sample...</option>
        {#each SAMPLES as doc (doc.name)}
          <option value={doc.name}>{doc.name}</option>
        {/each}
      </select>
    </div>
    <div class="editor">
      <pre class="highlight mono" aria-hidden="true" bind:this={highlightEl}>{#each segments as seg (seg)}{#if seg.match}<mark>{seg.text}</mark>{:else}{seg.text}{/if}{/each}<br /></pre>
      <textarea
        id="sample"
        class="mono"
        bind:value={text}
        onscroll={syncScroll}
        placeholder="Paste sample text, or use Load sample"
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
    color: var(--accent-fg);
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
  /* The textarea text is transparent over the highlight layer; keep the
     placeholder visible. */
  .editor textarea::placeholder {
    color: var(--muted);
  }

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
    color: var(--accent-fg);
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

  .pattern-actions {
    display: flex;
    gap: 0.5rem;
    margin-top: 0.45rem;
  }

  button.small,
  .sample-select {
    background: var(--input-bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    color: var(--fg);
    font-size: 0.78rem;
    padding: 0.3rem 0.7rem;
    cursor: pointer;
  }

  button.small:hover:not(:disabled) {
    background: var(--hover);
  }

  button.small:disabled {
    opacity: 0.5;
    cursor: default;
  }

  .library {
    border: 1px solid var(--border);
    border-radius: 6px;
    margin-bottom: 0.9rem;
  }

  .library summary {
    cursor: pointer;
    padding: 0.5rem 0.75rem;
    font-size: 0.85rem;
    user-select: none;
  }

  .library-body {
    padding: 0 0.75rem 0.75rem;
  }

  .library .filter {
    max-width: 320px;
    font-size: 0.82rem;
    padding: 0.35rem 0.55rem;
  }

  .hint {
    margin: 0.4rem 0 0.6rem;
    font-size: 0.75rem;
    color: var(--muted);
  }

  .chip-group {
    display: flex;
    gap: 0.6rem;
    margin-bottom: 0.5rem;
    align-items: baseline;
  }

  .group-name {
    flex: 0 0 7.5rem;
    font-size: 0.75rem;
    color: var(--muted);
  }

  .chips {
    display: flex;
    flex-wrap: wrap;
    gap: 0.3rem;
  }

  .chip {
    background: var(--input-bg);
    border: 1px solid var(--border);
    border-radius: 4px;
    color: var(--fg);
    font-size: 0.76rem;
    padding: 0.2rem 0.5rem;
    cursor: pointer;
  }

  .chip:hover {
    background: var(--hover);
  }

  .chip.active {
    background: var(--accent);
    border-color: var(--accent);
    color: var(--accent-fg);
  }

  .chip.pcre {
    border-style: dashed;
  }

  .recipe-info {
    margin: 0.6rem 0 0;
    font-size: 0.78rem;
  }

  .recipe-info code {
    font-family: var(--mono);
    color: var(--muted);
  }

  .sample-head {
    display: flex;
    justify-content: space-between;
    align-items: flex-end;
    margin-bottom: 0.35rem;
  }

  .sample-head label {
    margin: 0;
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
