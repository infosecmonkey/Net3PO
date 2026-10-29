<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import { open } from "@tauri-apps/plugin-dialog";
  import ExportMenu from "$lib/components/ExportMenu.svelte";
  import type { DecodeResult, DecodedLayer, IocKind } from "$lib/tools/types";
  import { buildDecodeReport } from "./report";

  let text = $state("");
  let sourceName = $state("");
  let result = $state<DecodeResult | null>(null);
  let error = $state("");
  let busy = $state(false);
  let defanged = $state(true);
  let copied = $state("");

  const LEVEL: Record<string, string> = { fail: "FAIL", warn: "WARN", info: "INFO" };
  const KIND: Record<DecodedLayer["kind"], string> = {
    source: "input",
    text: "text",
    binary: "binary",
    marshal: "marshal",
  };
  const LANG: Record<string, string> = {
    python: "Python",
    bash: "Bash",
    powershell: "PowerShell",
    javascript: "JavaScript",
    unknown: "text",
  };
  const IOC_LABEL: Record<IocKind, string> = {
    url: "URL",
    domain: "Domain",
    ipv4: "IPv4",
    email: "Email",
    md5: "MD5",
    sha1: "SHA1",
    sha256: "SHA256",
    path: "Path",
  };

  async function decode() {
    if (text.trim().length === 0) {
      error = "Paste a script or open a file.";
      return;
    }
    busy = true;
    error = "";
    try {
      result = await invoke<DecodeResult>("script_decode", { text });
    } catch (e) {
      result = null;
      error = String(e);
    } finally {
      busy = false;
    }
  }

  async function openFile() {
    try {
      const path = await open({
        multiple: false,
        filters: [
          { name: "Scripts", extensions: ["py", "pyw", "sh", "bash", "zsh", "ps1", "psm1", "psd1", "js", "mjs", "cjs", "jse", "hta", "txt"] },
          { name: "All files", extensions: ["*"] },
        ],
      });
      if (typeof path !== "string") return; // cancelled
      text = await invoke<string>("script_read_file", { path });
      sourceName = path.split(/[\\/]/).pop() ?? path;
      result = null;
      await decode();
    } catch (e) {
      error = String(e);
    }
  }

  function clearAll() {
    text = "";
    sourceName = "";
    result = null;
    error = "";
  }

  function onKeydown(e: KeyboardEvent) {
    if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) {
      e.preventDefault();
      void decode();
    }
  }

  async function copy(what: string, label: string) {
    try {
      await navigator.clipboard.writeText(what);
      copied = label;
      setTimeout(() => (copied = ""), 1200);
    } catch {
      // Clipboard can be unavailable; the text stays selectable.
    }
  }

  function copyIocs() {
    if (!result) return;
    void copy(result.iocs.map((i) => (defanged ? i.defanged : i.value)).join("\n"), "iocs");
  }

  function fmtSize(n: number): string {
    if (n < 1024) return `${n} B`;
    if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
    return `${(n / 1024 / 1024).toFixed(1)} MB`;
  }

  let decodedCount = $derived(result ? result.layers.length - 1 : 0);
</script>

<div class="panel">
  <header>
    <h1>Script Decoder</h1>
    <p class="sub">
      Unwrap obfuscated Python, Bash, PowerShell and JavaScript layer by layer, pull out
      indicators, and flag suspicious behavior. The script is parsed, never run.
    </p>
  </header>

  <div class="field">
    <div class="input-head">
      <label for="src">Script <span class="muted">(Python, Bash, PowerShell, JavaScript; detected per layer)</span></label>
      {#if sourceName}<span class="name mono">{sourceName}</span>{/if}
    </div>
    <textarea
      id="src"
      class="mono"
      bind:value={text}
      onkeydown={onKeydown}
      oninput={() => (sourceName = "")}
      spellcheck="false"
      autocapitalize="off"
      autocomplete="off"
      placeholder="Paste a script, e.g. echo ... | base64 -d | bash, powershell -enc ..., eval(atob('...'))"
    ></textarea>
  </div>

  <div class="actions">
    <button class="primary" onclick={decode} disabled={busy}>{busy ? "Decoding..." : "Decode"}</button>
    <button class="small" onclick={openFile} disabled={busy}>Open file</button>
    <button class="small" onclick={clearAll} disabled={busy || (!text && !result)}>Clear</button>
    <span class="hint">Cmd/Ctrl+Enter to decode</span>
  </div>

  {#if error}
    <div class="error mono">{error}</div>
  {/if}

  {#if result}
    <div class="summary">
      <strong>{decodedCount === 0 ? "No encoded layers found" : `${decodedCount} decoded layer${decodedCount === 1 ? "" : "s"}`}</strong>
      <span class="muted">
        {result.iocs.length} indicator{result.iocs.length === 1 ? "" : "s"} | {result.flags.length}
        flag{result.flags.length === 1 ? "" : "s"}
      </span>
      <div class="spacer"></div>
      <ExportMenu
        build={() => (result ? buildDecodeReport(result, sourceName) : null)}
        name={`decode-${sourceName || "script"}`}
      />
    </div>

    {#if result.notes.length > 0}
      <ul class="notes">
        {#each result.notes as n (n)}<li>{n}</li>{/each}
      </ul>
    {/if}

    {#if result.flags.length > 0}
      <section>
        <h2>Flags <span class="muted">heuristic, pattern matches only</span></h2>
        <ul class="flags">
          {#each result.flags as f, fi (fi)}
            <li class="flag {f.level}">
              <div class="flag-head">
                <span class="badge {f.level}">{LEVEL[f.level]}</span>
                <strong>{f.title}</strong>
                <span class="muted">layer {f.layer}{f.line ? `, line ${f.line}` : ""}</span>
              </div>
              <p class="detail">{f.detail}</p>
              {#if f.snippet}<code class="snippet mono">{f.snippet}</code>{/if}
            </li>
          {/each}
        </ul>
      </section>
    {/if}

    {#if result.iocs.length > 0}
      <section>
        <div class="section-head">
          <h2>Indicators</h2>
          <label class="check"><input type="checkbox" bind:checked={defanged} /> defanged</label>
          <button class="small" onclick={copyIocs}>{copied === "iocs" ? "Copied" : "Copy all"}</button>
        </div>
        <div class="table-scroll">
          <table>
            <thead><tr><th>Type</th><th>Indicator</th><th>Layer</th></tr></thead>
            <tbody>
              {#each result.iocs as i (i.kind + i.value)}
                <tr>
                  <td class="muted">{IOC_LABEL[i.kind]}</td>
                  <td class="mono value">
                    {defanged ? i.defanged : i.value}
                    {#if i.private}<span class="tag">private</span>{/if}
                  </td>
                  <td class="muted">{i.layer}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      </section>
    {/if}

    <section>
      <h2>Layers</h2>
      {#each result.layers as l (l.index)}
        <details class="layer" open={l.index > 0 || result.layers.length === 1}>
          <summary>
            <span class="lnum">Layer {l.index}</span>
            <span class="kind {l.kind}">{l.language ? LANG[l.language] ?? l.language : KIND[l.kind]}</span>
            <span class="method mono">{l.method}</span>
            {#if l.parent !== null}
              <span class="muted">from layer {l.parent}{l.line ? `, line ${l.line}` : ""}</span>
            {/if}
            <span class="muted size">{fmtSize(l.size)}</span>
          </summary>
          <div class="layer-body">
            <button class="small copy" onclick={() => copy(l.text, `layer-${l.index}`)}>
              {copied === `layer-${l.index}` ? "Copied" : "Copy"}
            </button>
            <pre class="code mono">{l.text}</pre>
            {#if l.truncated}<p class="hint">Shown text is shortened; export or copy for the displayed part only.</p>{/if}
            {#if l.strings.length > 0}
              <h3>Strings <span class="muted">({l.strings.length})</span></h3>
              <pre class="code mono strings">{l.strings.join("\n")}</pre>
            {/if}
          </div>
        </details>
      {/each}
    </section>
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
    margin: 0 0 1.25rem;
    color: var(--muted);
    font-size: 0.85rem;
  }

  .mono {
    font-family: var(--mono);
  }

  .muted {
    color: var(--muted);
    font-size: 0.8rem;
    font-weight: 400;
  }

  .field {
    margin-bottom: 0.6rem;
  }

  .input-head {
    display: flex;
    align-items: baseline;
    gap: 0.6rem;
    margin-bottom: 0.35rem;
  }

  label {
    font-size: 0.8rem;
    color: var(--muted);
  }

  .name {
    font-size: 0.75rem;
    color: var(--muted);
  }

  textarea {
    width: 100%;
    box-sizing: border-box;
    min-height: 12rem;
    resize: vertical;
    background: var(--input-bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    color: var(--fg);
    padding: 0.5rem 0.6rem;
    font-size: 0.8rem;
    line-height: 1.4;
    white-space: pre;
  }

  textarea:focus {
    outline: none;
    border-color: var(--accent);
  }

  .actions {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    margin-bottom: 1rem;
  }

  button.primary {
    background: var(--accent);
    color: var(--accent-fg);
    border: none;
    border-radius: 6px;
    font-weight: 600;
    font-size: 0.85rem;
    padding: 0.45rem 1.1rem;
    cursor: pointer;
  }

  button.small {
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

  button:disabled {
    opacity: 0.5;
    cursor: default;
  }

  .hint {
    font-size: 0.75rem;
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

  .summary {
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    gap: 0.5rem 0.9rem;
    font-size: 0.9rem;
  }

  .spacer {
    flex: 1 1 auto;
  }

  .notes {
    margin: 0.6rem 0 0;
    padding-left: 1.2rem;
    font-size: 0.78rem;
    color: var(--muted);
  }

  section {
    margin-top: 1.4rem;
  }

  h2 {
    font-size: 1rem;
    margin: 0 0 0.6rem;
  }

  h3 {
    font-size: 0.85rem;
    margin: 0.8rem 0 0.4rem;
  }

  .section-head {
    display: flex;
    align-items: center;
    gap: 0.8rem;
    margin-bottom: 0.6rem;
  }

  .section-head h2 {
    margin: 0;
  }

  .check {
    display: flex;
    align-items: center;
    gap: 0.3rem;
    color: var(--fg);
  }

  .flags {
    list-style: none;
    margin: 0;
    padding: 0;
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }

  .flag {
    border: 1px solid var(--border);
    border-left: 4px solid var(--muted);
    border-radius: 6px;
    padding: 0.5rem 0.75rem;
  }

  .flag.fail {
    border-left-color: var(--diff-del-fg);
  }

  .flag.warn {
    border-left-color: #d97706;
  }

  .flag.info {
    border-left-color: #2563eb;
  }

  .flag-head {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    font-size: 0.85rem;
  }

  .badge {
    font-size: 0.65rem;
    font-weight: 700;
    padding: 0.1rem 0.4rem;
    border-radius: 3px;
    color: #fff;
  }

  .badge.fail {
    background: #b91c1c;
  }

  .badge.warn {
    background: #b45309;
  }

  .badge.info {
    background: #2563eb;
  }

  .detail {
    margin: 0.3rem 0;
    font-size: 0.8rem;
  }

  .snippet {
    display: block;
    font-size: 0.75rem;
    background: var(--input-bg);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 0.25rem 0.45rem;
    overflow-x: auto;
    white-space: pre;
  }

  .table-scroll {
    border: 1px solid var(--border);
    border-radius: 6px;
    overflow: auto;
    max-height: 22rem;
  }

  table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.8rem;
  }

  th {
    text-align: left;
    color: var(--muted);
    font-weight: 500;
    padding: 0.4rem 0.7rem;
    border-bottom: 1px solid var(--border);
    position: sticky;
    top: 0;
    background: var(--bg);
  }

  td {
    padding: 0.3rem 0.7rem;
    border-bottom: 1px solid var(--border);
    vertical-align: top;
  }

  td.value {
    overflow-wrap: anywhere;
  }

  .tag {
    margin-left: 0.4rem;
    font-size: 0.68rem;
    color: var(--muted);
    border: 1px solid var(--border);
    border-radius: 3px;
    padding: 0 0.3rem;
  }

  .layer {
    border: 1px solid var(--border);
    border-radius: 6px;
    margin-bottom: 0.6rem;
  }

  .layer summary {
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    gap: 0.5rem;
    padding: 0.45rem 0.7rem;
    cursor: pointer;
    font-size: 0.82rem;
  }

  .lnum {
    font-weight: 600;
  }

  .kind {
    font-size: 0.68rem;
    border: 1px solid var(--border);
    border-radius: 3px;
    padding: 0 0.35rem;
    color: var(--muted);
  }

  .kind.marshal,
  .kind.binary {
    color: #b45309;
    border-color: #b45309;
  }

  .method {
    font-size: 0.78rem;
  }

  .size {
    margin-left: auto;
  }

  .layer-body {
    position: relative;
    padding: 0 0.7rem 0.7rem;
  }

  .copy {
    position: absolute;
    top: 0.4rem;
    right: 1.2rem;
    z-index: 1;
  }

  .code {
    margin: 0;
    padding: 0.5rem 0.6rem;
    background: var(--input-bg);
    border: 1px solid var(--border);
    border-radius: 4px;
    font-size: 0.76rem;
    line-height: 1.45;
    max-height: 24rem;
    overflow: auto;
    white-space: pre;
  }

  .strings {
    max-height: 14rem;
  }
</style>
