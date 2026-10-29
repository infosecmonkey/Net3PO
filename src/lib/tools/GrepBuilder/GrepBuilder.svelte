<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import MatchHighlighter from "$lib/components/MatchHighlighter.svelte";
  import { takePendingGrep } from "$lib/nav.svelte";
  import type { GrepMode, GrepOptions, RegexResult } from "$lib/tools/types";

  // A pattern sent from the Regex Builder replaces the default.
  const handoff = takePendingGrep();
  let pattern = $state(handoff?.pattern ?? String.raw`\berror\b`);
  let mode = $state<GrepMode>(handoff?.mode ?? "extended");
  let pathsStr = $state("/var/log/app.log");
  let text = $state("INFO starting up\nerror: disk full\nWARN error-rate high\nerror: timeout");

  let ignoreCase = $state(false);
  let invert = $state(false);
  let word = $state(false);
  let lineMatch = $state(false);
  let onlyMatching = $state(false);
  let lineNumber = $state(true);
  let count = $state(false);
  let filesWithMatches = $state(false);
  let recursive = $state(false);
  let color = $state(false);

  let before = $state(0);
  let after = $state(0);
  let context = $state(0);

  let command = $state("grep");
  let result = $state<RegexResult | null>(null);
  let error = $state("");
  let copied = $state(false);

  const MODES: { id: GrepMode; label: string; note: string }[] = [
    { id: "basic", label: "Basic (-G)", note: "BRE, grep default" },
    { id: "extended", label: "Extended (-E)", note: "ERE" },
    { id: "perl", label: "Perl (-P)", note: "PCRE, lookaround and backrefs" },
    { id: "fixed", label: "Fixed (-F)", note: "literal, no regex" },
  ];

  // Assemble the options object sent to the backend. Paths split on whitespace;
  // each token is quoted independently in the command.
  let options = $derived<GrepOptions>({
    pattern,
    mode,
    ignoreCase,
    invert,
    word,
    lineMatch,
    onlyMatching,
    lineNumber,
    count,
    filesWithMatches,
    recursive,
    color,
    before: Number(before) || 0,
    after: Number(after) || 0,
    context: Number(context) || 0,
    paths: pathsStr.split(/\s+/).filter((p) => p.length > 0),
  });

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
      command = await invoke<string>("grep_build", { options });
    } catch (e) {
      command = "grep";
      error = String(e);
      return;
    }
    if (pattern.length === 0) {
      result = null;
      error = "";
      return;
    }
    try {
      result = await invoke<RegexResult>("grep_preview", { options, text });
      error = "";
    } catch (e) {
      result = null;
      error = String(e);
    }
  }

  async function copy() {
    try {
      await navigator.clipboard.writeText(command);
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
      Build a grep command and check the pattern against sample data live, using
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
    <label for="pattern">Pattern</label>
    <input
      id="pattern"
      class="mono"
      bind:value={pattern}
      spellcheck="false"
      autocapitalize="off"
      autocomplete="off"
      placeholder="error"
    />
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
    <label><input type="checkbox" bind:checked={invert} /> invert (-v)</label>
    <label><input type="checkbox" bind:checked={onlyMatching} /> only matching (-o)</label>
    <label><input type="checkbox" bind:checked={lineNumber} /> line numbers (-n)</label>
    <label><input type="checkbox" bind:checked={count} /> count (-c)</label>
    <label><input type="checkbox" bind:checked={filesWithMatches} /> files only (-l)</label>
    <label><input type="checkbox" bind:checked={recursive} /> recursive (-r)</label>
    <label><input type="checkbox" bind:checked={color} /> color</label>
  </div>

  <div class="context">
    <label>before (-B) <input type="number" min="0" bind:value={before} /></label>
    <label>after (-A) <input type="number" min="0" bind:value={after} /></label>
    <label>context (-C) <input type="number" min="0" bind:value={context} /></label>
  </div>

  <div class="command-box">
    <code class="mono">{command}</code>
    <button class="copy" onclick={copy}>{copied ? "Copied" : "Copy"}</button>
  </div>

  <section>
    <div class="preview-head">
      <h2>Pattern preview</h2>
      {#if result}
        <span class="muted">
          {result.total === 0 ? "no matches" : `${result.total.toLocaleString()} match${result.total === 1 ? "" : "es"}`}
        </span>
      {/if}
    </div>
    <p class="hint">
      Highlights what the pattern matches. Output flags like -v, -c, -n, -o,
      context, and -r change grep's output, not what is matched.
    </p>
    {#if error}
      <div class="error mono">{error}</div>
    {/if}
    <MatchHighlighter bind:text matches={result?.matches ?? []} />
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
</style>
