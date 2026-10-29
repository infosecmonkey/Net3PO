<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import { open, save } from "@tauri-apps/plugin-dialog";
  import ExportMenu from "$lib/components/ExportMenu.svelte";
  import { buildDiffReport } from "./report";
  import type {
    DiffAlgo,
    DiffOptions,
    DiffResult,
    DiffRow,
    DiffSide,
    DiffWhitespace,
  } from "$lib/tools/types";

  // Rendering every row of a huge full-context diff would stall the webview.
  const MAX_ROWS = 5000;

  // FortiOS lines that change on every backup without a real config change.
  const FORTIOS_VOLATILE = String.raw`^#(config-version|conf_file_ver|buildno|global_vdom)|set uuid |\sENC\s`;

  const EXAMPLE_LEFT = `#config-version=FGT60F-7.6.7-FW-build3401:opmode=0:vdom=0
config system interface
    edit "port1"
        set ip 192.168.1.99 255.255.255.0
        set allowaccess ping https ssh
    next
end
config firewall policy
    edit 12
        set name "LAN to WAN"
        set uuid 6f1c2a9e-8b7d-51ee-9f0a-1b2c3d4e5f60
        set srcintf "internal"
        set dstintf "wan1"
        set action accept
        set service "HTTPS" "DNS"
        set nat enable
    next
end`;

  const EXAMPLE_RIGHT = `#config-version=FGT60F-7.6.8-FW-build3456:opmode=0:vdom=0
config system interface
    edit "port1"
        set ip 192.168.1.99 255.255.255.0
        set allowaccess ping https
    next
end
config firewall policy
    edit 12
        set name "LAN to WAN"
        set uuid 0a9b8c7d-6e5f-51ee-8a7b-6c5d4e3f2a10
        set srcintf "internal"
        set dstintf "wan1"
        set action accept
        set service "HTTPS" "DNS" "NTP"
        set logtraffic all
        set nat enable
    next
end`;

  let left = $state("");
  let right = $state("");
  let leftName = $state("");
  let rightName = $state("");

  let whitespace = $state<DiffWhitespace>("trailing");
  let ignoreCase = $state(false);
  let ignoreBlankLines = $state(false);
  let ignorePattern = $state("");
  let contextSel = $state("3");
  let algorithm = $state<DiffAlgo>("histogram");
  let view = $state<"split" | "unified">("split");

  let result = $state<DiffResult | null>(null);
  let error = $state("");
  let notice = $state("");

  let options = $derived<DiffOptions>({
    whitespace,
    ignoreCase,
    ignoreBlankLines,
    ignorePattern,
    context: contextSel === "all" ? null : Number(contextSel),
    algorithm,
    leftName: leftName || "left",
    rightName: rightName || "right",
  });

  let debounce: ReturnType<typeof setTimeout> | undefined;

  $effect(() => {
    void JSON.stringify(options);
    void left;
    void right;
    clearTimeout(debounce);
    debounce = setTimeout(run, 250);
    return () => clearTimeout(debounce);
  });

  async function run() {
    if (left.length === 0 && right.length === 0) {
      result = null;
      error = "";
      return;
    }
    try {
      result = await invoke<DiffResult>("diff_compare", { left, right, options });
      error = "";
    } catch (e) {
      result = null;
      error = String(e);
    }
  }

  function baseName(path: string): string {
    return path.split(/[\\/]/).pop() ?? path;
  }

  async function openFile(which: "left" | "right") {
    notice = "";
    try {
      const path = await open({
        multiple: false,
        filters: [
          { name: "Config and text", extensions: ["conf", "cfg", "txt", "log"] },
          { name: "All files", extensions: ["*"] },
        ],
      });
      if (typeof path !== "string") return; // cancelled
      const text = await invoke<string>("diff_read_file", { path });
      if (which === "left") {
        left = text;
        leftName = baseName(path);
      } else {
        right = text;
        rightName = baseName(path);
      }
    } catch (e) {
      error = String(e);
    }
  }

  function swap() {
    [left, right] = [right, left];
    [leftName, rightName] = [rightName, leftName];
  }

  function loadExample() {
    left = EXAMPLE_LEFT;
    right = EXAMPLE_RIGHT;
    leftName = "fgt-backup-old.conf";
    rightName = "fgt-backup-new.conf";
  }

  function clearAll() {
    left = "";
    right = "";
    leftName = "";
    rightName = "";
  }

  async function copyUnified() {
    if (!result) return;
    try {
      await navigator.clipboard.writeText(result.unified);
      notice = "Copied unified diff.";
    } catch {
      notice = "Clipboard unavailable.";
    }
  }

  async function saveUnified() {
    if (!result) return;
    notice = "";
    try {
      const path = await save({
        defaultPath: "config.diff",
        filters: [{ name: "Diff", extensions: ["diff", "patch", "txt"] }],
      });
      if (!path) return; // cancelled
      await invoke("diff_save", { path, text: result.unified });
      notice = `Saved ${baseName(path)}.`;
    } catch (e) {
      error = String(e);
    }
  }

  // Hunks trimmed to MAX_ROWS total rows for rendering.
  let shown = $derived.by(() => {
    if (!result) return { hunks: [], cut: false };
    let budget = MAX_ROWS;
    const hunks = [];
    for (const h of result.hunks) {
      if (budget <= 0) break;
      const rows = h.rows.slice(0, budget);
      budget -= rows.length;
      hunks.push({ ...h, rows });
    }
    const total = result.hunks.reduce((n, h) => n + h.rows.length, 0);
    return { hunks, cut: total > MAX_ROWS };
  });

  interface Piece {
    text: string;
    hi: boolean;
  }

  // Split a side's text at its changed spans (char offsets, so use code points).
  function pieces(side: DiffSide): Piece[] {
    if (side.spans.length === 0) return [{ text: side.text, hi: false }];
    const cps = [...side.text];
    const out: Piece[] = [];
    let cursor = 0;
    for (const s of side.spans) {
      if (s.start > cursor) out.push({ text: cps.slice(cursor, s.start).join(""), hi: false });
      out.push({ text: cps.slice(s.start, s.end).join(""), hi: true });
      cursor = s.end;
    }
    if (cursor < cps.length) out.push({ text: cps.slice(cursor).join(""), hi: false });
    return out;
  }

  function leftClass(row: DiffRow): string {
    return row.kind === "delete" || row.kind === "change" ? "del" : row.left ? "" : "blank";
  }

  function rightClass(row: DiffRow): string {
    return row.kind === "insert" || row.kind === "change" ? "add" : row.right ? "" : "blank";
  }

  function unifiedClass(line: string): string {
    if (line.startsWith("+++") || line.startsWith("---")) return "file";
    if (line.startsWith("@@")) return "hunk";
    if (line.startsWith("+")) return "add";
    if (line.startsWith("-")) return "del";
    return "";
  }
</script>

<div class="panel">
  <header>
    <h1>Config Diff</h1>
    <p class="sub">
      Compare two configs side by side. Ignore options change what is compared, not
      what is shown.
    </p>
  </header>

  <div class="inputs">
    {#each [{ id: "left", label: "Left (before)" }, { id: "right", label: "Right (after)" }] as col (col.id)}
      <div class="input-col">
        <div class="input-head">
          <span class="label">{col.label}</span>
          <span class="name mono">{col.id === "left" ? leftName : rightName}</span>
          <button class="small" onclick={() => openFile(col.id as "left" | "right")}>Open file</button>
        </div>
        {#if col.id === "left"}
          <textarea class="mono" bind:value={left} spellcheck="false" placeholder="Paste the older config"></textarea>
        {:else}
          <textarea class="mono" bind:value={right} spellcheck="false" placeholder="Paste the newer config"></textarea>
        {/if}
      </div>
    {/each}
  </div>

  <div class="actions">
    <button class="small" onclick={swap}>Swap</button>
    <button class="small" onclick={loadExample}>Load example</button>
    <button class="small" onclick={clearAll} disabled={!left && !right}>Clear</button>
  </div>

  <div class="options">
    <label>
      whitespace
      <select bind:value={whitespace}>
        <option value="exact">exact</option>
        <option value="trailing">ignore trailing</option>
        <option value="amount">ignore amount (-b)</option>
        <option value="all">ignore all (-w)</option>
      </select>
    </label>
    <label>
      context
      <select bind:value={contextSel}>
        <option value="0">0 lines</option>
        <option value="3">3 lines</option>
        <option value="10">10 lines</option>
        <option value="all">full file</option>
      </select>
    </label>
    <label>
      algorithm
      <select bind:value={algorithm}>
        <option value="histogram">histogram</option>
        <option value="patience">patience</option>
        <option value="myers">myers</option>
      </select>
    </label>
    <label class="check"><input type="checkbox" bind:checked={ignoreCase} /> ignore case</label>
    <label class="check"><input type="checkbox" bind:checked={ignoreBlankLines} /> ignore blank lines</label>
  </div>

  <div class="field">
    <label for="ignore">Ignore lines matching (regex)</label>
    <div class="ignore-row">
      <input
        id="ignore"
        class="mono"
        bind:value={ignorePattern}
        placeholder="^#config-version|set uuid "
        spellcheck="false"
        autocapitalize="off"
        autocomplete="off"
      />
      <button class="small" onclick={() => (ignorePattern = FORTIOS_VOLATILE)}>FortiOS volatile</button>
    </div>
    <p class="hint">FortiOS volatile skips version headers, UUIDs and ENC secrets that change on every backup.</p>
  </div>

  {#if error}
    <div class="error mono">{error}</div>
  {/if}

  {#if result}
    <div class="summary">
      {#if result.identical}
        <strong>No differences</strong>
      {:else}
        <span class="stat add-fg">+{result.stats.added.toLocaleString()} added</span>
        <span class="stat del-fg">-{result.stats.removed.toLocaleString()} removed</span>
        <span class="stat">~{result.stats.changed.toLocaleString()} changed</span>
      {/if}
      <span class="muted">
        {result.stats.leftLines.toLocaleString()} / {result.stats.rightLines.toLocaleString()} lines
        {#if result.stats.ignoredLeft || result.stats.ignoredRight}
          , {result.stats.ignoredLeft.toLocaleString()} / {result.stats.ignoredRight.toLocaleString()} ignored
        {/if}
      </span>
      {#if !result.identical}
        <div class="spacer"></div>
        <div class="segmented">
          <button class:active={view === "split"} onclick={() => (view = "split")}>Side by side</button>
          <button class:active={view === "unified"} onclick={() => (view = "unified")}>Unified</button>
        </div>
        <button class="small" onclick={copyUnified}>Copy unified</button>
        <button class="small" onclick={saveUnified}>Save .diff</button>
      {/if}
      <ExportMenu
        build={() => (result ? buildDiffReport(result, options) : null)}
        name="config-diff"
      />
    </div>
    {#if notice}
      <p class="hint">{notice}</p>
    {/if}

    {#if !result.identical}
      {#if view === "split"}
        <div class="diff mono">
          {#each shown.hunks as h, hi (hi)}
            <div class="hunk-head">
              <span>{h.header}</span>
              {#if h.section.length > 0}
                <span class="section">{h.section.join(" > ")}</span>
              {/if}
            </div>
            <table>
              <colgroup><col class="num" /><col /><col class="num" /><col /></colgroup>
              <tbody>
                {#each h.rows as row, ri (ri)}
                  <tr>
                    <td class="ln {leftClass(row)}">{row.left?.number ?? ""}</td>
                    <td class="code {leftClass(row)}">{#if row.left}{#each pieces(row.left) as p, pi (pi)}{#if p.hi}<mark class="del-strong">{p.text}</mark>{:else}{p.text}{/if}{/each}{/if}</td>
                    <td class="ln {rightClass(row)}">{row.right?.number ?? ""}</td>
                    <td class="code {rightClass(row)}">{#if row.right}{#each pieces(row.right) as p, pi (pi)}{#if p.hi}<mark class="add-strong">{p.text}</mark>{:else}{p.text}{/if}{/each}{/if}</td>
                  </tr>
                {/each}
              </tbody>
            </table>
          {/each}
        </div>
        {#if shown.cut}
          <p class="hint">Showing the first {MAX_ROWS.toLocaleString()} rows. Save the unified diff for the rest, or reduce context.</p>
        {/if}
      {:else}
        <pre class="unified mono">{#each result.unified.replace(/\n$/, "").split("\n") as line, li (li)}<span class={unifiedClass(line)}>{line}</span>{/each}</pre>
      {/if}
    {/if}
  {/if}
</div>

<style>
  .panel {
    padding: 1.5rem 2rem;
    max-width: 1200px;
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

  .label,
  label {
    font-size: 0.8rem;
    color: var(--muted);
  }

  .inputs {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 1rem;
  }

  .input-head {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    margin-bottom: 0.35rem;
  }

  .name {
    flex: 1 1 auto;
    font-size: 0.75rem;
    color: var(--muted);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  textarea,
  input:not([type="checkbox"]),
  select {
    box-sizing: border-box;
    background: var(--input-bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    color: var(--fg);
  }

  textarea {
    width: 100%;
    min-height: 11rem;
    resize: vertical;
    padding: 0.5rem 0.6rem;
    font-size: 0.8rem;
    line-height: 1.4;
    white-space: pre;
  }

  textarea:focus,
  input:focus {
    outline: none;
    border-color: var(--accent);
  }

  select {
    font-size: 0.8rem;
    padding: 0.25rem 0.4rem;
    margin-left: 0.3rem;
  }

  button.small {
    background: var(--input-bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    color: var(--fg);
    font-size: 0.78rem;
    padding: 0.3rem 0.7rem;
    cursor: pointer;
    white-space: nowrap;
  }

  button.small:hover:not(:disabled) {
    background: var(--hover);
  }

  button.small:disabled {
    opacity: 0.5;
    cursor: default;
  }

  .actions {
    display: flex;
    gap: 0.5rem;
    margin: 0.6rem 0 1rem;
  }

  .options {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 0.6rem 1.2rem;
    margin-bottom: 0.9rem;
  }

  .options label {
    color: var(--fg);
  }

  label.check {
    display: flex;
    align-items: center;
    gap: 0.35rem;
  }

  .field {
    margin-bottom: 1rem;
  }

  .field label {
    display: block;
    margin-bottom: 0.35rem;
  }

  .ignore-row {
    display: flex;
    gap: 0.5rem;
  }

  .ignore-row input {
    flex: 1 1 auto;
    padding: 0.45rem 0.6rem;
    font-size: 0.85rem;
  }

  .hint {
    margin: 0.4rem 0 0;
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
    flex-wrap: wrap;
    align-items: center;
    gap: 0.5rem 0.9rem;
    font-size: 0.85rem;
  }

  .spacer {
    flex: 1 1 auto;
  }

  .muted {
    color: var(--muted);
    font-size: 0.8rem;
  }

  .stat {
    font-weight: 600;
  }

  .add-fg {
    color: var(--diff-add-fg);
  }

  .del-fg {
    color: var(--diff-del-fg);
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
    font-size: 0.78rem;
    padding: 0.3rem 0.7rem;
    cursor: pointer;
  }

  .segmented button:last-child {
    border-right: none;
  }

  .segmented button.active {
    background: var(--accent);
    color: var(--accent-fg);
    font-weight: 600;
  }

  .diff {
    margin-top: 0.9rem;
    border: 1px solid var(--border);
    border-radius: 6px;
    overflow: hidden;
    font-size: 0.78rem;
  }

  .hunk-head {
    display: flex;
    gap: 0.8rem;
    padding: 0.3rem 0.6rem;
    background: var(--sidebar-bg);
    color: var(--muted);
    border-bottom: 1px solid var(--border);
  }

  .hunk-head:not(:first-child) {
    border-top: 1px solid var(--border);
  }

  .section {
    color: var(--fg);
  }

  table {
    width: 100%;
    border-collapse: collapse;
    table-layout: fixed;
  }

  col.num {
    width: 3.2rem;
  }

  td {
    padding: 0 0.5rem;
    vertical-align: top;
    line-height: 1.5;
  }

  td.ln {
    text-align: right;
    color: var(--muted);
    user-select: none;
    border-right: 1px solid var(--border);
  }

  td.code {
    white-space: pre-wrap;
    overflow-wrap: anywhere;
  }

  td.code + td.ln {
    border-left: 1px solid var(--border);
  }

  .del {
    background: var(--diff-del-bg);
  }

  .add {
    background: var(--diff-add-bg);
  }

  .blank {
    background: repeating-linear-gradient(
      135deg,
      transparent 0 6px,
      var(--hover) 6px 7px
    );
  }

  mark {
    color: inherit;
    border-radius: 2px;
  }

  mark.del-strong {
    background: var(--diff-del-strong);
  }

  mark.add-strong {
    background: var(--diff-add-strong);
  }

  .unified {
    margin: 0.9rem 0 0;
    padding: 0.5rem 0;
    border: 1px solid var(--border);
    border-radius: 6px;
    font-size: 0.78rem;
    line-height: 1.5;
    overflow-x: auto;
  }

  .unified span {
    display: block;
    padding: 0 0.6rem;
    white-space: pre;
    min-height: 1.5em;
  }

  .unified .add {
    background: var(--diff-add-bg);
  }

  .unified .del {
    background: var(--diff-del-bg);
  }

  .unified .hunk {
    color: var(--muted);
    background: var(--sidebar-bg);
  }

  .unified .file {
    font-weight: 600;
  }
</style>
