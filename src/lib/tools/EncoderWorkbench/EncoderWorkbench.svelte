<script lang="ts">
  // Encoder/decoder workbench: build a chain of explicit steps and see each
  // intermediate result as text or hex. Output is never executed.
  import { invoke } from "@tauri-apps/api/core";
  import ExportMenu from "$lib/components/ExportMenu.svelte";
  import { explainShellBlocked, openExplainShell } from "$lib/explainshell";
  import { buildCodecReport, OP_GROUPS, OP_LABEL, type Op, type Run, type View } from "./model";

  let input = $state("");
  let inputHex = $state(false);
  let ops = $state<Op[]>([]);
  let result = $state<Run | null>(null);
  let hexView = $state<Record<number, boolean>>({});
  let copied = $state(false);
  let timer: ReturnType<typeof setTimeout> | undefined;

  $effect(() => {
    void input;
    void inputHex;
    JSON.stringify(ops);
    clearTimeout(timer);
    timer = setTimeout(async () => {
      result = input ? await invoke<Run>("codec_run", { input, inputIsHex: inputHex, ops: $state.snapshot(ops) }) : null;
    }, 200);
  });

  function add(op: Op) {
    ops.push(op);
  }

  function move(i: number, d: number) {
    const j = i + d;
    if (j < 0 || j >= ops.length) return;
    [ops[i], ops[j]] = [ops[j], ops[i]];
  }

  const finalView = $derived.by<View | null>(() => {
    if (!result) return null;
    const okSteps = result.steps.filter((s) => s.ok);
    return okSteps.length ? okSteps[okSteps.length - 1].view : result.input;
  });
  const failed = $derived(result?.steps.some((s) => !s.ok) ?? false);

  async function copyFinal() {
    const v = finalView;
    if (!v) return;
    try {
      await navigator.clipboard.writeText(v.text ?? v.hex);
      copied = true;
      setTimeout(() => (copied = false), 1200);
    } catch {
      copied = false;
    }
  }
</script>

{#snippet viewBox(v: View, key: number)}
  <div class="vhead">
    <span class="muted">{v.bytes.toLocaleString()} bytes</span>
    {#if v.text !== null}
      <button class="mini" onclick={() => (hexView[key] = !hexView[key])}>{hexView[key] ? "Text" : "Hex"}</button>
    {/if}
  </div>
  {#if v.text !== null && !hexView[key]}
    <pre class="mono out">{v.text}{v.textTruncated ? "\n... (first 256 KB shown)" : ""}</pre>
  {:else}
    {#if v.text === null}<div class="muted small">Binary content, shown as hex.</div>{/if}
    <pre class="mono out">{v.hex}{v.hexTruncated ? "\n... (first 4 KB shown)" : ""}</pre>
  {/if}
  {#if v.hint}<div class="hint">{v.hint}</div>{/if}
{/snippet}

<div class="panel">
  <header>
    <h1>Encoder Workbench</h1>
    <p class="sub">Chain Base64, Base32, hex, URL, HTML entity, ROT13 and compression steps. Each step shows its result. Offline; nothing is executed.</p>
  </header>

  <div class="ihead">
    <span class="lbl">Input</span>
    <label class="chk"><input type="checkbox" bind:checked={inputHex} /> input is hex bytes</label>
  </div>
  <textarea class="mono" rows="6" bind:value={input} spellcheck="false" placeholder={inputHex ? "hex bytes, spaces allowed" : "text to encode or decode"}></textarea>

  <div class="recipe">
    <span class="lbl">Steps</span>
    {#each ops as op, i (i)}
      <span class="chip">
        {i + 1}. {OP_LABEL[op]}
        <button onclick={() => move(i, -1)} disabled={i === 0} aria-label="Move up">↑</button>
        <button onclick={() => move(i, 1)} disabled={i === ops.length - 1} aria-label="Move down">↓</button>
        <button onclick={() => ops.splice(i, 1)} aria-label="Remove step">×</button>
      </span>
    {/each}
    <select onchange={(e) => { if (e.currentTarget.value) add(e.currentTarget.value as Op); e.currentTarget.value = ""; }}>
      <option value="">+ add step...</option>
      {#each OP_GROUPS as g (g.group)}
        <optgroup label={g.group}>{#each g.ops as [op, label] (op)}<option value={op}>{label}</option>{/each}</optgroup>
      {/each}
    </select>
    {#if ops.length}<button class="link" onclick={() => (ops = [])}>Clear</button>{/if}
  </div>

  {#if result?.error}<div class="error">{result.error}</div>{/if}

  {#if result && !result.error}
    {#each result.steps as s, i (i)}
      <div class="step" class:bad={!s.ok}>
        <div class="shead"><strong>{i + 1}. {s.label}</strong>{#if s.note}<span class="note">{s.note}</span>{/if}</div>
        {#if s.error}
          <div class="err">Stopped here: {s.error}</div>
        {:else if s.view}
          {@render viewBox(s.view, i + 1)}
        {/if}
      </div>
    {/each}
    {#if !ops.length}
      <div class="step">{@render viewBox(result.input, 0)}</div>
    {/if}

    {#if finalView && !failed}
      <div class="bar">
        {#if finalView.suggestions.length}
          <span class="muted">Looks like it could be:</span>
          {#each finalView.suggestions as sg (sg)}<button class="sugg" onclick={() => add(sg)}>+ {OP_LABEL[sg]}</button>{/each}
        {/if}
        <span class="spacer"></span>
        {#if finalView.text !== null}
          <button
            class="mini"
            onclick={() => finalView?.text && void openExplainShell(finalView.text)}
            disabled={finalView.textTruncated || explainShellBlocked(finalView.text) !== null}
            title={finalView.textTruncated ? "Result is shortened; copy one command instead" : explainShellBlocked(finalView.text) ?? "Open the result as a shell command on explainshell.com (online)"}
          >explainshell.com</button>
        {/if}
        <button class="mini" onclick={copyFinal}>{copied ? "Copied" : "Copy result"}</button>
        <ExportMenu build={() => (result ? buildCodecReport(result) : null)} name="encoder" />
      </div>
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

  textarea,
  select {
    box-sizing: border-box;
    background: var(--input-bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.45rem 0.55rem;
    color: var(--fg);
    font-size: 0.82rem;
  }

  textarea {
    width: 100%;
    resize: vertical;
  }

  textarea:focus,
  select:focus {
    outline: none;
    border-color: var(--accent);
  }

  .mono {
    font-family: var(--mono);
  }

  .ihead {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 0.3rem;
  }

  .lbl {
    font-size: 0.78rem;
    color: var(--muted);
  }

  .chk {
    display: inline-flex;
    gap: 0.3rem;
    align-items: center;
    font-size: 0.78rem;
  }

  .recipe {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 0.4rem;
    margin: 0.7rem 0 0.9rem;
  }

  .chip {
    display: inline-flex;
    align-items: center;
    gap: 0.15rem;
    background: var(--hover);
    border: 1px solid var(--border);
    border-radius: 14px;
    padding: 0.15rem 0.35rem 0.15rem 0.6rem;
    font-size: 0.78rem;
  }

  .chip button {
    background: none;
    border: none;
    color: var(--muted);
    cursor: pointer;
    font-size: 0.8rem;
    padding: 0 0.15rem;
  }

  .chip button:disabled {
    opacity: 0.3;
  }

  .link {
    background: none;
    border: none;
    color: var(--accent);
    font-size: 0.78rem;
    cursor: pointer;
  }

  .error,
  .err {
    color: var(--error-fg);
    font-size: 0.82rem;
  }

  .step {
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 0.5rem 0.7rem;
    margin-bottom: 0.5rem;
  }

  .step.bad {
    border-color: var(--error-border);
  }

  .shead {
    display: flex;
    gap: 0.7rem;
    align-items: baseline;
    font-size: 0.84rem;
    margin-bottom: 0.3rem;
  }

  .note {
    font-size: 0.74rem;
    color: #b7791f;
  }

  .vhead {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 0.25rem;
  }

  .muted {
    color: var(--muted);
    font-size: 0.76rem;
  }

  .small {
    font-size: 0.72rem;
  }

  .out {
    margin: 0;
    padding: 0.4rem 0.55rem;
    background: var(--input-bg);
    border-radius: 4px;
    font-size: 0.78rem;
    white-space: pre-wrap;
    overflow-wrap: anywhere;
    max-height: 16rem;
    overflow: auto;
  }

  .hint {
    font-size: 0.76rem;
    border-left: 3px solid var(--accent);
    padding: 0.2rem 0.6rem;
    margin-top: 0.35rem;
  }

  .bar {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    flex-wrap: wrap;
    margin-top: 0.6rem;
  }

  .spacer {
    flex: 1;
  }

  .sugg {
    background: none;
    border: 1px dashed var(--accent);
    color: var(--accent);
    border-radius: 12px;
    padding: 0.1rem 0.55rem;
    font-size: 0.76rem;
    cursor: pointer;
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
</style>
