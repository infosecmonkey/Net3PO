<script lang="ts">
  // Hash text or a file with SHA-256, SHA-512, SHA-1 and MD5, and check an
  // expected digest. Files are streamed and can be stopped.
  import { Channel, invoke } from "@tauri-apps/api/core";
  import { open } from "@tauri-apps/plugin-dialog";
  import ExportMenu from "$lib/components/ExportMenu.svelte";
  import { ALGOS, buildHashReport, type Comparison, type Digests } from "./report";

  type Mode = "text" | "file";
  let mode = $state<Mode>("text");
  let text = $state("");
  let filePath = $state("");
  let digests = $state<Digests | null>(null);
  let expected = $state("");
  let cmp = $state<Comparison | null>(null);
  let busy = $state(false);
  let size = $state(0);
  let done = $state(0);
  let error = $state("");
  let copied = $state("");
  let id = 0;
  let timer: ReturnType<typeof setTimeout> | undefined;

  const fileName = $derived(filePath.split(/[\\/]/).pop() ?? "");

  async function compareNow() {
    cmp = digests && expected.trim() ? await invoke<Comparison>("hash_compare", { expected, digests }) : null;
  }

  function textChanged() {
    clearTimeout(timer);
    timer = setTimeout(async () => {
      digests = await invoke<Digests>("hash_text", { text });
      await compareNow();
    }, 150);
  }

  async function pickFile() {
    const p = await open({ multiple: false });
    if (typeof p !== "string") return;
    filePath = p;
    error = "";
    digests = null;
    cmp = null;
    busy = true;
    size = 0;
    done = 0;
    id = Math.floor(Math.random() * 0x7fffffff);
    const ch = new Channel<{ type: "started"; size: number } | { type: "progress"; bytes: number }>();
    ch.onmessage = (e) => {
      if (e.type === "started") size = e.size;
      else done = e.bytes;
    };
    try {
      const d = await invoke<Digests | null>("hash_file", { id, path: p, onEvent: ch });
      if (d) {
        digests = d;
        await compareNow();
      } else {
        error = "Stopped.";
      }
    } catch (e) {
      error = String(e);
    } finally {
      busy = false;
    }
  }

  function setMode(m: Mode) {
    mode = m;
    digests = null;
    cmp = null;
    error = "";
    if (m === "text" && text) textChanged();
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
    <h1>Hash Calculator</h1>
    <p class="sub">SHA-256, SHA-512, SHA-1 and MD5 for text or files, with a check against an expected digest. Offline.</p>
  </header>

  <div class="tabs" role="tablist">
    <button role="tab" aria-selected={mode === "text"} class:active={mode === "text"} onclick={() => setMode("text")}>Text</button>
    <button role="tab" aria-selected={mode === "file"} class:active={mode === "file"} onclick={() => setMode("file")}>File</button>
  </div>

  {#if mode === "text"}
    <textarea class="mono" rows="5" bind:value={text} oninput={textChanged} spellcheck="false" placeholder="text to hash"></textarea>
    <p class="hint">Hashed as UTF-8 exactly as typed. A trailing newline or different line endings change every digest.</p>
  {:else}
    <div class="row">
      <button class="primary" onclick={pickFile} disabled={busy}>Choose file...</button>
      {#if busy}<button class="second" onclick={() => invoke("hash_stop", { id })}>Stop</button>{/if}
      {#if fileName}<span class="mono name" title={filePath}>{fileName}</span>{/if}
    </div>
    {#if busy}
      <div class="bar"><div class="fill" style="width: {size ? Math.min(100, (100 * done) / size) : 0}%"></div></div>
      <div class="hint">{(done / 1048576).toFixed(1)} of {(size / 1048576).toFixed(1)} MB</div>
    {/if}
    <p class="hint">The file is read, never modified.</p>
  {/if}

  <label class="exp">Expected digest (optional)
    <input class="mono" bind:value={expected} oninput={compareNow} spellcheck="false" placeholder="paste a digest or a sha256sum line" />
  </label>

  {#if error}<div class="error">{error}</div>{/if}

  {#if cmp && cmp.message}
    <div class="verdict" class:ok={cmp.matched} class:bad={!cmp.matched}>{cmp.message}</div>
  {/if}

  {#if digests}
    <div class="bar-row">
      <span class="muted small">{digests.bytes.toLocaleString()} bytes</span>
      <ExportMenu build={() => (digests ? buildHashReport(mode === "file" ? fileName : "text input", digests, cmp) : null)} name="hashes" />
    </div>
    <table>
      <tbody>
        {#each ALGOS as a (a.key)}
          <tr class:hit={cmp?.matched === a.label}>
            <th>{a.label}{#if a.legacy}<span class="legacy">legacy</span>{/if}</th>
            <td class="mono">{digests[a.key]}</td>
            <td><button class="mini" onclick={() => copy(a.key, digests ? digests[a.key] : "")}>{copied === a.key ? "Copied" : "Copy"}</button></td>
          </tr>
        {/each}
      </tbody>
    </table>
    <p class="hint">MD5 and SHA-1 are legacy integrity formats: good for spotting corruption, not for proving a file was not tampered with.</p>
  {/if}
</div>

<style>
  .panel {
    padding: 1.5rem 2rem;
    max-width: 980px;
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

  .tabs {
    display: flex;
    gap: 0.25rem;
    border-bottom: 1px solid var(--border);
    margin-bottom: 0.9rem;
  }

  .tabs button {
    background: none;
    border: none;
    border-bottom: 2px solid transparent;
    color: var(--muted);
    padding: 0.4rem 0.8rem;
    font-size: 0.85rem;
    cursor: pointer;
  }

  .tabs button.active {
    color: var(--fg);
    border-bottom-color: var(--accent);
  }

  textarea,
  input {
    box-sizing: border-box;
    width: 100%;
    background: var(--input-bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.5rem 0.6rem;
    color: var(--fg);
    font-size: 0.84rem;
  }

  textarea {
    resize: vertical;
  }

  textarea:focus,
  input:focus {
    outline: none;
    border-color: var(--accent);
  }

  .mono {
    font-family: var(--mono);
  }

  .hint,
  .muted {
    color: var(--muted);
    font-size: 0.75rem;
  }

  .hint {
    margin: 0.35rem 0 0.8rem;
  }

  .small {
    font-size: 0.75rem;
  }

  .row {
    display: flex;
    align-items: center;
    gap: 0.7rem;
  }

  .name {
    font-size: 0.84rem;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
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
    padding: 0.45rem 1rem;
    color: var(--fg);
    cursor: pointer;
  }

  .bar {
    height: 6px;
    background: var(--hover);
    border-radius: 3px;
    margin-top: 0.6rem;
    overflow: hidden;
  }

  .fill {
    height: 100%;
    background: var(--accent);
  }

  .exp {
    display: flex;
    flex-direction: column;
    gap: 0.3rem;
    font-size: 0.8rem;
    color: var(--muted);
    margin-bottom: 0.8rem;
  }

  .error {
    color: var(--error-fg);
    font-size: 0.82rem;
    margin-bottom: 0.6rem;
  }

  .verdict {
    border-left: 3px solid var(--border);
    padding: 0.4rem 0.7rem;
    font-size: 0.84rem;
    margin-bottom: 0.8rem;
  }

  .verdict.ok {
    border-color: #15935a;
  }

  .verdict.bad {
    border-color: #c0392b;
  }

  .bar-row {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 0.3rem;
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
    padding: 0.3rem 1rem 0.3rem 0;
    white-space: nowrap;
    width: 1%;
    vertical-align: top;
  }

  td {
    font-size: 0.8rem;
    padding: 0.3rem 0;
    overflow-wrap: anywhere;
  }

  td:last-child {
    width: 1%;
    padding-left: 0.6rem;
    vertical-align: top;
  }

  tr.hit td,
  tr.hit th {
    color: #15935a;
    font-weight: 600;
  }

  .legacy {
    margin-left: 0.4rem;
    font-size: 0.62rem;
    border: 1px solid var(--border);
    border-radius: 3px;
    padding: 0 0.25rem;
  }

  .mini {
    background: var(--input-bg);
    border: 1px solid var(--border);
    border-radius: 4px;
    color: var(--fg);
    font-size: 0.7rem;
    padding: 0.08rem 0.45rem;
    cursor: pointer;
  }
</style>
