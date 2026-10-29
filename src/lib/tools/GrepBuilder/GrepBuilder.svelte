<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import MatchHighlighter from "$lib/components/MatchHighlighter.svelte";
  import { takePendingGrep } from "$lib/nav.svelte";
  import type {
    BuiltCommand,
    FilenameDisplay,
    GrepCombine,
    GrepMode,
    GrepOptions,
    GrepPreview,
    GrepTarget,
  } from "$lib/tools/types";

  interface Row {
    id: number;
    pattern: string;
    exclude: boolean;
  }

  let nextId = 1;
  function row(pattern = "", exclude = false): Row {
    return { id: nextId++, pattern, exclude };
  }

  // A pattern sent from the Regex Builder replaces the default.
  const handoff = takePendingGrep();
  let rows = $state<Row[]>([row(handoff?.pattern ?? String.raw`\berror\b`)]);
  let combine = $state<GrepCombine>("all");
  let mode = $state<GrepMode>(handoff?.mode ?? "extended");
  let target = $state<GrepTarget>("gnu");
  let pathsStr = $state("/var/log/app.log");
  let text = $state(
    "INFO starting up\nerror: disk full\nWARN error-rate high\nerror: timeout\nDEBUG error retry 3",
  );

  let ignoreCase = $state(false);
  let word = $state(false);
  let lineMatch = $state(false);
  let onlyMatching = $state(false);
  let lineNumber = $state(true);
  let count = $state(false);
  let filesWithMatches = $state(false);
  let recursive = $state(false);
  let color = $state(false);
  let skipBinary = $state(false);
  let filename = $state<FilenameDisplay>("auto");

  let before = $state(0);
  let after = $state(0);
  let context = $state(0);

  let include = $state("");
  let exclude = $state("");
  let excludeDir = $state("");

  let built = $state<BuiltCommand>({ command: "grep", stages: 0, warnings: [] });
  let result = $state<GrepPreview | null>(null);
  let error = $state("");
  let copied = $state(false);

  const MODES: { id: GrepMode; label: string; note: string }[] = [
    { id: "basic", label: "Basic (-G)", note: "BRE, grep default" },
    { id: "extended", label: "Extended (-E)", note: "ERE" },
    { id: "perl", label: "Perl (-P)", note: "PCRE, lookaround and backrefs" },
    { id: "fixed", label: "Fixed (-F)", note: "literal, no regex" },
  ];

  const TARGETS: { id: GrepTarget; label: string }[] = [
    { id: "gnu", label: "GNU grep (Linux)" },
    { id: "bsd", label: "BSD grep (macOS)" },
  ];

  let matchRows = $derived(rows.filter((r) => !r.exclude && r.pattern.length > 0).length);
  let hasPattern = $derived(rows.some((r) => r.pattern.length > 0));

  // Assemble the options object sent to the backend. Paths split on whitespace;
  // each token is quoted independently in the command.
  let options = $derived<GrepOptions>({
    conditions: rows.map((r) => ({ pattern: r.pattern, exclude: r.exclude })),
    combine,
    mode,
    target,
    ignoreCase,
    word,
    lineMatch,
    onlyMatching,
    lineNumber,
    count,
    filesWithMatches,
    recursive,
    color,
    skipBinary,
    filename,
    before: Number(before) || 0,
    after: Number(after) || 0,
    context: Number(context) || 0,
    include,
    exclude,
    excludeDir,
    paths: pathsStr.split(/\s+/).filter((p) => p.length > 0),
  });

  function addRow(excludeRow: boolean) {
    rows.push(row("", excludeRow));
  }

  function removeRow(id: number) {
    rows = rows.filter((r) => r.id !== id);
    if (rows.length === 0) rows = [row()];
  }

  let debounce: ReturnType<typeof setTimeout> | undefined;

  $effect(() => {
    // Track the serialized options and the sample text.
    void JSON.stringify(options);
    void text;
    clearTimeout(debounce);
    debounce = setTimeout(run, 150);
    return () => clearTimeout(debounce);
  });

  async function run() {
    try {
      built = await invoke<BuiltCommand>("grep_build", { options });
    } catch (e) {
      built = { command: "grep", stages: 0, warnings: [] };
      error = String(e);
      return;
    }
    if (!hasPattern) {
      result = null;
      error = "";
      return;
    }
    try {
      result = await invoke<GrepPreview>("grep_preview", { options, text });
      error = "";
    } catch (e) {
      result = null;
      error = String(e);
    }
  }

  async function copy() {
    try {
      await navigator.clipboard.writeText(built.command);
      copied = true;
      setTimeout(() => (copied = false), 1200);
    } catch {
      // Clipboard can be unavailable; ignore and leave the text selectable.
    }
  }
</script>

<div class="panel">
  <header>
    <h1>Grep Builder</h1>
    <p class="sub">
      Build a grep command or pipeline and check it against sample data live, using
      the same engines as the Regex Builder.
    </p>
  </header>

  <div class="field">
    <span class="label">Mode</span>
    <div class="modes">
      {#each MODES as m (m.id)}
        <button class="mode-btn" class:active={mode === m.id} onclick={() => (mode = m.id)}>
          <span class="mode-label">{m.label}</span>
          <span class="mode-note">{m.note}</span>
        </button>
      {/each}
    </div>
  </div>

  <div class="field">
    <span class="label">Target</span>
    <div class="segmented">
      {#each TARGETS as t (t.id)}
        <button class:active={target === t.id} onclick={() => (target = t.id)}>{t.label}</button>
      {/each}
    </div>
  </div>

  <div class="field">
    <div class="patterns-head">
      <span class="label">Patterns</span>
      {#if matchRows > 1}
        <div class="segmented small">
          <button class:active={combine === "all"} onclick={() => (combine = "all")}>All (AND)</button>
          <button class:active={combine === "any"} onclick={() => (combine = "any")}>Any (OR)</button>
        </div>
      {/if}
    </div>
    {#each rows as r, i (r.id)}
      <div class="pattern-row">
        <select bind:value={r.exclude} aria-label="Pattern {i + 1} role">
          <option value={false}>Match</option>
          <option value={true}>Exclude</option>
        </select>
        <input
          class="mono"
          class:excluded={r.exclude}
          bind:value={r.pattern}
          aria-label="Pattern {i + 1}"
          spellcheck="false"
          autocapitalize="off"
          autocomplete="off"
          placeholder={r.exclude ? "drop lines matching this" : "error"}
        />
        <button class="icon" onclick={() => removeRow(r.id)} title="Remove pattern" aria-label="Remove pattern {i + 1}">x</button>
      </div>
    {/each}
    <div class="row-actions">
      <button class="small" onclick={() => addRow(false)}>+ Match</button>
      <button class="small" onclick={() => addRow(true)}>+ Exclude</button>
    </div>
  </div>

  <div class="field">
    <label for="paths">Files or paths</label>
    <input
      id="paths"
      class="mono"
      bind:value={pathsStr}
      spellcheck="false"
      autocapitalize="off"
      autocomplete="off"
      placeholder="/var/log/app.log"
    />
  </div>

  <div class="flags">
    <label><input type="checkbox" bind:checked={ignoreCase} /> ignore case (-i)</label>
    <label><input type="checkbox" bind:checked={word} /> word match (-w)</label>
    <label><input type="checkbox" bind:checked={lineMatch} /> whole line (-x)</label>
    <label><input type="checkbox" bind:checked={onlyMatching} /> only matching (-o)</label>
    <label><input type="checkbox" bind:checked={lineNumber} /> line numbers (-n)</label>
    <label><input type="checkbox" bind:checked={count} /> count (-c)</label>
    <label><input type="checkbox" bind:checked={filesWithMatches} /> files only (-l)</label>
    <label><input type="checkbox" bind:checked={recursive} /> recursive (-r)</label>
    <label><input type="checkbox" bind:checked={skipBinary} /> skip binary (-I)</label>
    <label><input type="checkbox" bind:checked={color} /> color</label>
    <label>
      file names
      <select bind:value={filename}>
        <option value="auto">auto</option>
        <option value="always">always (-H)</option>
        <option value="never">never (-h)</option>
      </select>
    </label>
  </div>

  <div class="context">
    <label>before (-B) <input type="number" min="0" bind:value={before} /></label>
    <label>after (-A) <input type="number" min="0" bind:value={after} /></label>
    <label>context (-C) <input type="number" min="0" bind:value={context} /></label>
  </div>

  <div class="globs">
    <label>
      --include
      <input class="mono" bind:value={include} placeholder="*.log, *.conf" spellcheck="false" autocapitalize="off" autocomplete="off" />
    </label>
    <label>
      --exclude
      <input class="mono" bind:value={exclude} placeholder="*.gz" spellcheck="false" autocapitalize="off" autocomplete="off" />
    </label>
    <label>
      --exclude-dir
      <input class="mono" bind:value={excludeDir} placeholder=".git node_modules" spellcheck="false" autocapitalize="off" autocomplete="off" />
    </label>
  </div>

  <div class="command-box">
    <code class="mono">{built.command}</code>
    <button class="copy" onclick={copy}>{copied ? "Copied" : "Copy"}</button>
  </div>

  {#if built.warnings.length > 0}
    <ul class="warnings">
      {#each built.warnings as w (w)}
        <li>{w}</li>
      {/each}
    </ul>
  {/if}

  <section>
    <div class="preview-head">
      <h2>Preview</h2>
      {#if result}
        <span class="muted">
          {result.linesKept.toLocaleString()} of {result.linesTotal.toLocaleString()} line{result.linesTotal === 1 ? "" : "s"} kept
        </span>
      {/if}
    </div>
    <p class="hint">
      Runs the patterns line by line, as grep does. Highlights show match patterns
      in kept lines. -o, -c, -l and context are not simulated.
    </p>
    {#if error}
      <div class="error mono">{error}</div>
    {/if}
    <MatchHighlighter bind:text matches={result?.matches ?? []} />
    {#if result && result.output.length > 0}
      <h3>Output</h3>
      <pre class="output mono">{#each result.output as l (l.number)}{#if lineNumber}<span class="ln">{l.number}:</span>{/if}{l.text}
{/each}</pre>
      {#if result.truncated}
        <p class="hint">Showing the first {result.output.length.toLocaleString()} lines.</p>
      {/if}
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

  input:not([type="checkbox"]) {
    width: 100%;
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

  .mono {
    font-family: var(--mono);
  }

  .modes {
    display: flex;
    flex-wrap: wrap;
    gap: 0.5rem;
  }

  .mode-btn {
    display: flex;
    flex-direction: column;
    align-items: flex-start;
    gap: 0.1rem;
    background: var(--input-bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.4rem 0.7rem;
    color: var(--fg);
    cursor: pointer;
    text-align: left;
  }

  .mode-btn:hover:not(.active) {
    background: var(--hover);
  }

  .mode-btn.active {
    background: var(--accent);
    border-color: var(--accent);
    color: var(--accent-fg);
  }

  .mode-label {
    font-size: 0.82rem;
    font-weight: 600;
  }

  .mode-note {
    font-size: 0.68rem;
    opacity: 0.8;
  }

  .flags {
    display: flex;
    flex-wrap: wrap;
    gap: 0.5rem 1rem;
    margin-bottom: 1rem;
  }

  .flags label {
    display: flex;
    align-items: center;
    gap: 0.35rem;
    color: var(--fg);
    margin: 0;
    font-size: 0.8rem;
  }

  .context {
    display: flex;
    flex-wrap: wrap;
    gap: 1rem;
    margin-bottom: 1.25rem;
  }

  .context label {
    display: flex;
    align-items: center;
    gap: 0.4rem;
    color: var(--fg);
    font-size: 0.8rem;
    margin: 0;
  }

  .context input {
    width: 4.5rem;
  }

  .command-box {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    background: var(--input-bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.6rem 0.75rem;
    margin-bottom: 1.5rem;
  }

  .command-box code {
    flex: 1 1 auto;
    overflow-x: auto;
    white-space: pre;
    font-size: 0.88rem;
  }

  .copy {
    flex: 0 0 auto;
    background: var(--btn-bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.35rem 0.8rem;
    color: var(--fg);
    font-size: 0.8rem;
    cursor: pointer;
  }

  .copy:hover {
    border-color: var(--accent);
  }

  section {
    margin-top: 0.5rem;
  }

  .preview-head {
    display: flex;
    align-items: baseline;
    gap: 0.6rem;
  }

  h2 {
    font-size: 1rem;
    margin: 0 0 0.3rem;
  }

  .muted {
    color: var(--muted);
    font-size: 0.8rem;
  }

  .hint {
    margin: 0 0 0.6rem;
    font-size: 0.76rem;
    color: var(--muted);
    max-width: 640px;
  }

  .error {
    background: var(--error-bg);
    border: 1px solid var(--error-border);
    color: var(--error-fg);
    border-radius: 6px;
    padding: 0.6rem 0.8rem;
    font-size: 0.82rem;
    margin-bottom: 0.6rem;
    white-space: pre-wrap;
  }
  select {
    background: var(--input-bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    color: var(--fg);
    font-size: 0.8rem;
    padding: 0.3rem 0.4rem;
  }

  .segmented {
    display: inline-flex;
    border: 1px solid var(--border);
    border-radius: 6px;
    overflow: hidden;
  }

  .segmented button {
    background: var(--input-bg);
    border: none;
    border-right: 1px solid var(--border);
    color: var(--fg);
    font-size: 0.8rem;
    padding: 0.35rem 0.8rem;
    cursor: pointer;
  }

  .segmented.small button {
    font-size: 0.74rem;
    padding: 0.2rem 0.6rem;
  }

  .segmented button:last-child {
    border-right: none;
  }

  .segmented button:hover:not(.active) {
    background: var(--hover);
  }

  .segmented button.active {
    background: var(--accent);
    color: var(--accent-fg);
    font-weight: 600;
  }

  .patterns-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 0.35rem;
  }

  .patterns-head .label {
    margin: 0;
  }

  .pattern-row {
    display: flex;
    gap: 0.4rem;
    align-items: center;
    margin-bottom: 0.4rem;
  }

  .pattern-row select {
    flex: 0 0 6rem;
    padding: 0.45rem 0.4rem;
  }

  .pattern-row input.excluded {
    text-decoration: line-through;
    text-decoration-color: var(--muted);
  }

  button.icon,
  button.small {
    background: var(--input-bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    color: var(--fg);
    cursor: pointer;
  }

  button.icon {
    flex: 0 0 auto;
    width: 2rem;
    height: 2rem;
    font-size: 0.8rem;
  }

  button.small {
    font-size: 0.78rem;
    padding: 0.3rem 0.7rem;
  }

  button.icon:hover,
  button.small:hover {
    background: var(--hover);
  }

  .row-actions {
    display: flex;
    gap: 0.5rem;
  }

  .globs {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(12rem, 1fr));
    gap: 0.75rem;
    margin-bottom: 1.25rem;
  }

  .globs label {
    margin: 0;
  }

  .globs input {
    margin-top: 0.25rem;
    font-size: 0.82rem;
    padding: 0.4rem 0.55rem;
  }

  .flags select {
    font-size: 0.78rem;
    padding: 0.15rem 0.3rem;
  }

  .warnings {
    margin: -0.75rem 0 1.5rem;
    padding: 0.5rem 0.75rem 0.5rem 1.75rem;
    border-left: 3px solid var(--accent);
    background: var(--input-bg);
    border-radius: 0 6px 6px 0;
    font-size: 0.8rem;
  }

  .warnings li + li {
    margin-top: 0.25rem;
  }

  h3 {
    font-size: 0.85rem;
    margin: 1rem 0 0.4rem;
  }

  .output {
    margin: 0;
    padding: 0.5rem 0.6rem;
    background: var(--input-bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    font-size: 0.82rem;
    white-space: pre-wrap;
    overflow-wrap: break-word;
    max-height: 18rem;
    overflow-y: auto;
  }

  .ln {
    color: var(--muted);
    margin-right: 0.25rem;
  }
</style>