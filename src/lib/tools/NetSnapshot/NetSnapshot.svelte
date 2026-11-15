<script lang="ts">
  // Network snapshot: record interfaces, routes, DNS, neighbors and listening
  // ports with the OS's own commands, keep snapshots locally, and compare two
  // of them (for example before and after a change or a VPN connect).
  import { invoke } from "@tauri-apps/api/core";
  import { ask, open, save } from "@tauri-apps/plugin-dialog";
  import { onMount } from "svelte";
  import ExportMenu from "$lib/components/ExportMenu.svelte";
  import {
    buildCompareReport,
    buildSnapshotReport,
    notable,
    SECTION_TABS,
    sectionCount,
    sectionTable,
    title,
    when,
    type SectionDiff,
    type SectionId,
    type Snapshot,
    type Summary,
  } from "./model";

  let list = $state<Summary[]>([]);
  let current = $state<Snapshot | null>(null);
  let tab = $state<SectionId>("interfaces");
  let filter = $state("");
  let mode = $state<"view" | "compare">("view");
  let taking = $state(false);
  let error = $state("");
  let message = $state("");
  let labelDraft = $state("");

  // Compare
  let aId = $state("");
  let bId = $state("");
  let diffs = $state<SectionDiff[] | null>(null);
  let comparing = $state(false);
  let showSection = $state<string>("");

  const aSum = $derived(list.find((s) => s.id === aId) ?? null);
  const bSum = $derived(list.find((s) => s.id === bId) ?? null);

  async function refresh() {
    try {
      list = await invoke<Summary[]>("snap_list");
    } catch (e) {
      error = String(e);
    }
  }

  onMount(refresh);

  function flash(m: string) {
    message = m;
    setTimeout(() => (message = ""), 2500);
  }

  async function take() {
    taking = true;
    error = "";
    try {
      const s = await invoke<Snapshot>("snap_take");
      await refresh();
      show(s);
      // The newest snapshot becomes "after"; the previous one "before".
      bId = s.id;
      aId = list.find((x) => x.id !== s.id)?.id ?? "";
      const failed = s.sources.filter((x) => !x.ok).length;
      flash(failed ? `Snapshot saved; ${failed} source${failed === 1 ? "" : "s"} failed (see Sources).` : "Snapshot saved.");
    } catch (e) {
      error = String(e);
    } finally {
      taking = false;
    }
  }

  function show(s: Snapshot) {
    current = s;
    labelDraft = s.label;
    filter = "";
    mode = "view";
  }

  async function select(id: string) {
    error = "";
    try {
      show(await invoke<Snapshot>("snap_get", { id }));
    } catch (e) {
      error = String(e);
    }
  }

  async function saveLabel() {
    if (!current) return;
    try {
      await invoke("snap_label", { id: current.id, label: labelDraft });
      current.label = labelDraft.trim();
      await refresh();
      flash("Label saved.");
    } catch (e) {
      error = String(e);
    }
  }

  async function remove() {
    if (!current) return;
    const ok = await ask(`Delete the snapshot "${title(current)}"? This cannot be undone.`, {
      title: "Delete snapshot",
      kind: "warning",
    });
    if (!ok) return;
    try {
      await invoke("snap_delete", { id: current.id });
      if (aId === current.id) aId = "";
      if (bId === current.id) bId = "";
      current = null;
      await refresh();
    } catch (e) {
      error = String(e);
    }
  }

  async function exportFile() {
    if (!current) return;
    try {
      const path = await save({
        defaultPath: `net3po-snapshot-${current.host || "host"}-${current.id}.json`,
        filters: [{ name: "Net3PO snapshot", extensions: ["json"] }],
      });
      if (typeof path !== "string") return;
      await invoke("snap_export_file", { id: current.id, path });
      flash("Saved.");
    } catch (e) {
      error = String(e);
    }
  }

  async function importFile() {
    error = "";
    try {
      const path = await open({ multiple: false, filters: [{ name: "Net3PO snapshot", extensions: ["json"] }] });
      if (typeof path !== "string") return;
      const s = await invoke<Summary>("snap_import_file", { path });
      await refresh();
      await select(s.id);
      flash("Snapshot added.");
    } catch (e) {
      error = String(e);
    }
  }

  async function compare() {
    if (!aId || !bId) {
      error = "Pick a before (A) and an after (B) snapshot.";
      return;
    }
    if (aId === bId) {
      error = "Pick two different snapshots.";
      return;
    }
    comparing = true;
    error = "";
    try {
      diffs = await invoke<SectionDiff[]>("snap_compare", { a: aId, b: bId });
      showSection = diffs.find((d) => d.changes.length)?.section ?? diffs[0]?.section ?? "";
    } catch (e) {
      error = String(e);
      diffs = null;
    } finally {
      comparing = false;
    }
  }

  function swap() {
    [aId, bId] = [bId, aId];
    diffs = null;
  }

  const table = $derived(current ? sectionTable(current, tab) : null);
  const rows = $derived.by(() => {
    if (!table) return [];
    const q = filter.trim().toLowerCase();
    return q ? table.rows.filter((r) => r.some((c) => c.toLowerCase().includes(q))) : table.rows;
  });
  const failedSources = $derived(current?.sources.filter((s) => !s.ok) ?? []);
  const notes = $derived(current?.sources.filter((s) => s.ok && s.note) ?? []);
  const findings = $derived(diffs ? notable(diffs) : []);
  const shown = $derived(diffs?.find((d) => d.section === showSection) ?? null);
</script>

<div class="panel">
  <header>
    <h1>Network Snapshot</h1>
    <p class="sub">
      Record this computer's interfaces, routes, DNS, ARP/neighbor table and listening ports, then compare two
      snapshots: before and after a change, a VPN connect, or between machines. Read-only, no admin rights; nothing
      is sent on the network. Snapshots stay on this computer.
    </p>
  </header>

  <div class="row">
    <button class="primary" onclick={take} disabled={taking}>{taking ? "Taking snapshot..." : "Take snapshot"}</button>
    <button class="secondary" onclick={importFile}>Open file...</button>
    <span class="spacer"></span>
    <div class="seg" role="tablist">
      <button role="tab" class:on={mode === "view"} aria-selected={mode === "view"} onclick={() => (mode = "view")}>View</button>
      <button role="tab" class:on={mode === "compare"} aria-selected={mode === "compare"} onclick={() => (mode = "compare")} disabled={list.length < 2}>Compare</button>
    </div>
  </div>
  {#if error}<div class="error">{error}</div>{/if}
  {#if message}<div class="ok-msg">{message}</div>{/if}

  <div class="layout">
    <aside>
      <div class="side-head">Saved ({list.length})</div>
      {#if !list.length}
        <p class="muted">No snapshots yet. Take one before a change, and another after.</p>
      {/if}
      {#each list as s (s.id)}
        <button class="snap" class:sel={current?.id === s.id && mode === "view"} onclick={() => select(s.id)}>
          <span class="snap-title">{title(s)}</span>
          <span class="muted">{s.label ? `${when(s.taken)} · ` : ""}{s.host || "-"} · {s.os}</span>
          <span class="muted">
            {s.interfaces} if · {s.routes} routes · {s.listeners} ports
            {#if s.failed}<span class="warn-tag">{s.failed} failed</span>{/if}
            {#if mode === "compare"}
              {#if s.id === aId}<span class="ab">A</span>{/if}
              {#if s.id === bId}<span class="ab">B</span>{/if}
            {/if}
          </span>
        </button>
      {/each}
    </aside>

    <section class="main">
      {#if mode === "view"}
        {#if current}
          <div class="meta">
            <div class="kv">
              <span><span class="muted">Taken</span> {when(current.taken)}</span>
              <span><span class="muted">Host</span> <span class="mono">{current.host || "-"}</span></span>
              <span><span class="muted">OS</span> {current.os}</span>
            </div>
            <div class="row tight">
              <input class="label-in" bind:value={labelDraft} placeholder="Label, for example before firewall change" maxlength="200" onkeydown={(e) => e.key === "Enter" && saveLabel()} />
              <button class="secondary" onclick={saveLabel} disabled={labelDraft.trim() === current.label}>Save label</button>
              <span class="spacer"></span>
              <ExportMenu build={() => (current ? buildSnapshotReport(current) : null)} name={`snapshot-${current.host || "host"}`} />
              <button class="secondary" onclick={exportFile} title="Save as a snapshot file, to compare on another computer">Save file...</button>
              <button class="secondary danger" onclick={remove}>Delete</button>
            </div>
          </div>

          {#if failedSources.length}
            <div class="warnbox">
              {#each failedSources as f (f.section + f.command)}
                <div><strong>{f.section}</strong> ({f.command}): {f.note}</div>
              {/each}
            </div>
          {/if}
          {#if notes.length}
            <div class="notebox">
              {#each notes as n (n.section + n.command)}
                <div><strong>{n.section}</strong>: {n.note}</div>
              {/each}
            </div>
          {/if}

          <div class="tabs" role="tablist">
            {#each SECTION_TABS as t (t.id)}
              <button role="tab" class:on={tab === t.id} aria-selected={tab === t.id} onclick={() => (tab = t.id)}>
                {t.label} <span class="count">{sectionCount(current, t.id)}</span>
              </button>
            {/each}
          </div>
          <div class="row tight">
            <input class="filter" bind:value={filter} placeholder="Filter rows" spellcheck="false" />
            {#if filter}<span class="muted">{rows.length} of {table?.rows.length}</span>{/if}
          </div>
          {#if table && rows.length}
            <div class="scroll">
              <table>
                <thead><tr>{#each table.headers as h (h)}<th>{h}</th>{/each}</tr></thead>
                <tbody>
                  {#each rows as r, i (i)}
                    <tr>{#each r as c, j (j)}<td class="mono">{c}</td>{/each}</tr>
                  {/each}
                </tbody>
              </table>
            </div>
          {:else}
            <p class="muted">{filter ? "No rows match." : "None recorded."}</p>
          {/if}

          <details class="sources">
            <summary>Sources</summary>
            <table>
              <thead><tr><th>Section</th><th>Command</th><th>Result</th></tr></thead>
              <tbody>
                {#each current.sources as s (s.section + s.command)}
                  <tr><td>{s.section}</td><td class="mono">{s.command}</td><td class:bad={!s.ok}>{s.ok ? s.note || "ok" : s.note}</td></tr>
                {/each}
              </tbody>
            </table>
          </details>
        {:else}
          <p class="muted">Take a snapshot, or pick one from the list.</p>
        {/if}
      {:else}
        <div class="row">
          <label class="inline">Before (A)
            <select bind:value={aId} onchange={() => (diffs = null)}>
              <option value="">Choose...</option>
              {#each list as s (s.id)}<option value={s.id}>{title(s)}</option>{/each}
            </select>
          </label>
          <button class="secondary" onclick={swap} title="Swap A and B" disabled={!aId && !bId}>Swap</button>
          <label class="inline">After (B)
            <select bind:value={bId} onchange={() => (diffs = null)}>
              <option value="">Choose...</option>
              {#each list as s (s.id)}<option value={s.id}>{title(s)}</option>{/each}
            </select>
          </label>
          <button class="primary" onclick={compare} disabled={comparing || !aId || !bId}>Compare</button>
          <span class="spacer"></span>
          {#if diffs && aSum && bSum}
            {@const a = aSum}
            {@const b = bSum}
            {@const d = diffs}
            <ExportMenu build={() => buildCompareReport(a, b, d)} name="snapshot-compare" />
          {/if}
        </div>
        {#if aSum && bSum && aSum.host !== bSum.host}
          <div class="notebox">A and B are from different computers ({aSum.host || "-"} and {bSum.host || "-"}): most rows will differ.</div>
        {/if}

        {#if diffs}
          {#if findings.length}
            <div class="findings">
              {#each findings as f, i (i)}
                <div class="finding {f.severity}"><strong>{f.title}</strong>{#if f.detail}<div class="mono small">{f.detail}</div>{/if}</div>
              {/each}
            </div>
          {/if}
          <div class="tabs" role="tablist">
            {#each diffs as d (d.section)}
              <button role="tab" class:on={showSection === d.section} aria-selected={showSection === d.section} onclick={() => (showSection = d.section)}>
                {d.section} <span class="count" class:hot={d.changes.length > 0}>{d.changes.length}</span>
              </button>
            {/each}
          </div>
          {#if shown}
            {#if shown.changes.length}
              <div class="scroll">
                <table>
                  <thead><tr><th>Change</th><th>Before (A)</th><th>After (B)</th><th>Fields</th></tr></thead>
                  <tbody>
                    {#each shown.changes as c (c.kind + c.key)}
                      <tr class={c.kind}>
                        <td><span class="kind {c.kind}">{c.kind}</span></td>
                        <td class="mono">{c.before || "-"}</td>
                        <td class="mono">{c.after || "-"}</td>
                        <td>{c.fields.join(", ") || "-"}</td>
                      </tr>
                    {/each}
                  </tbody>
                </table>
              </div>
            {:else}
              <p class="muted">No differences in {shown.section.toLowerCase()}.</p>
            {/if}
            <p class="muted">{shown.unchanged} unchanged. Neighbor state changes and new process IDs for the same program are not counted.</p>
          {/if}
        {:else}
          <p class="muted">Pick two snapshots and click Compare.</p>
        {/if}
      {/if}
    </section>
  </div>
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
    margin: 0 0 1rem;
    color: var(--muted);
    font-size: 0.85rem;
  }
  .mono {
    font-family: var(--mono);
  }
  .small {
    font-size: 0.76rem;
    margin-top: 0.15rem;
    word-break: break-all;
  }
  .row {
    display: flex;
    align-items: center;
    gap: 0.6rem;
    margin: 0.6rem 0;
    flex-wrap: wrap;
  }
  .row.tight {
    margin: 0.4rem 0;
  }
  .spacer {
    flex: 1;
  }
  .primary,
  .secondary {
    border-radius: 6px;
    padding: 0.42rem 0.95rem;
    font-size: 0.82rem;
    cursor: pointer;
    white-space: nowrap;
  }
  .primary {
    background: var(--accent);
    color: var(--accent-fg);
    border: 1px solid var(--accent);
    font-weight: 600;
  }
  .secondary {
    background: transparent;
    color: var(--fg);
    border: 1px solid var(--border);
  }
  .secondary.danger:hover {
    border-color: #c0392b;
    color: #c0392b;
  }
  button:disabled {
    opacity: 0.55;
    cursor: default;
  }
  input,
  select {
    box-sizing: border-box;
    background: var(--input-bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.38rem 0.55rem;
    color: var(--fg);
    font-size: 0.82rem;
  }
  input:focus,
  select:focus {
    outline: none;
    border-color: var(--accent);
  }
  .label-in {
    flex: 1;
    min-width: 14rem;
  }
  .filter {
    width: 16rem;
  }
  .inline {
    display: inline-flex;
    align-items: center;
    gap: 0.4rem;
    font-size: 0.8rem;
    color: var(--muted);
  }
  select {
    max-width: 18rem;
  }
  .error {
    color: var(--error-fg);
    font-size: 0.84rem;
    margin: 0.3rem 0;
  }
  .ok-msg {
    color: #15935a;
    font-size: 0.82rem;
    margin: 0.3rem 0;
  }
  .muted {
    color: var(--muted);
    font-size: 0.78rem;
  }
  .seg {
    display: inline-flex;
    border: 1px solid var(--border);
    border-radius: 6px;
    overflow: hidden;
  }
  .seg button {
    background: transparent;
    border: 0;
    color: var(--fg);
    padding: 0.38rem 0.9rem;
    font-size: 0.8rem;
    cursor: pointer;
  }
  .seg button.on {
    background: var(--accent);
    color: var(--accent-fg);
  }
  .layout {
    display: grid;
    grid-template-columns: 250px minmax(0, 1fr);
    gap: 1.2rem;
    margin-top: 0.6rem;
  }
  aside {
    border-right: 1px solid var(--border);
    padding-right: 0.8rem;
    max-height: 70vh;
    overflow-y: auto;
  }
  .side-head {
    font-size: 0.75rem;
    color: var(--muted);
    text-transform: uppercase;
    letter-spacing: 0.06em;
    margin-bottom: 0.4rem;
  }
  .snap {
    display: flex;
    flex-direction: column;
    gap: 0.1rem;
    width: 100%;
    text-align: left;
    background: transparent;
    border: 1px solid transparent;
    border-radius: 6px;
    padding: 0.4rem 0.5rem;
    color: var(--fg);
    cursor: pointer;
    margin-bottom: 0.2rem;
  }
  .snap:hover {
    border-color: var(--border);
  }
  .snap.sel {
    border-color: var(--accent);
  }
  .snap-title {
    font-size: 0.84rem;
    font-weight: 600;
  }
  .warn-tag {
    color: #b7791f;
    margin-left: 0.3rem;
  }
  .ab {
    display: inline-block;
    margin-left: 0.3rem;
    padding: 0 0.35rem;
    border-radius: 4px;
    background: var(--accent);
    color: var(--accent-fg);
    font-weight: 700;
    font-size: 0.7rem;
  }
  .main {
    min-width: 0;
  }
  .meta .kv {
    display: flex;
    flex-wrap: wrap;
    gap: 0.3rem 1.4rem;
    font-size: 0.84rem;
  }
  .warnbox,
  .notebox {
    border-radius: 6px;
    padding: 0.45rem 0.7rem;
    font-size: 0.8rem;
    margin: 0.5rem 0;
  }
  .warnbox {
    border: 1px solid #b7791f;
    background: rgba(183, 121, 31, 0.08);
  }
  .notebox {
    border: 1px solid var(--border);
    color: var(--muted);
  }
  .tabs {
    display: flex;
    flex-wrap: wrap;
    gap: 0.2rem;
    border-bottom: 1px solid var(--border);
    margin-top: 0.7rem;
  }
  .tabs button {
    background: transparent;
    border: 0;
    border-bottom: 2px solid transparent;
    color: var(--muted);
    padding: 0.4rem 0.7rem;
    font-size: 0.82rem;
    cursor: pointer;
  }
  .tabs button.on {
    color: var(--fg);
    border-bottom-color: var(--accent);
  }
  .count {
    font-size: 0.72rem;
    color: var(--muted);
    margin-left: 0.2rem;
  }
  .count.hot {
    color: #b7791f;
    font-weight: 700;
  }
  .scroll {
    max-height: 60vh;
    overflow: auto;
    margin-top: 0.4rem;
  }
  table {
    border-collapse: collapse;
    width: 100%;
    font-size: 0.78rem;
  }
  th,
  td {
    text-align: left;
    vertical-align: top;
    padding: 0.22rem 0.8rem 0.22rem 0;
    border-bottom: 1px solid var(--border);
    white-space: pre-wrap;
    word-break: break-word;
  }
  th {
    color: var(--muted);
    font-weight: 500;
    position: sticky;
    top: 0;
    background: var(--bg);
  }
  td.bad {
    color: #c0392b;
  }
  .kind {
    font-size: 0.72rem;
    font-weight: 700;
    text-transform: uppercase;
  }
  .kind.added {
    color: #15935a;
  }
  .kind.removed {
    color: #c0392b;
  }
  .kind.changed {
    color: #b7791f;
  }
  .findings {
    display: flex;
    flex-direction: column;
    gap: 0.35rem;
    margin: 0.5rem 0;
  }
  .finding {
    border-left: 3px solid var(--border);
    padding: 0.25rem 0.6rem;
    font-size: 0.82rem;
  }
  .finding.warn {
    border-left-color: #b7791f;
  }
  .finding.info {
    border-left-color: var(--accent);
  }
  .sources {
    margin-top: 1rem;
    font-size: 0.8rem;
  }
  .sources summary {
    cursor: pointer;
    color: var(--muted);
  }
  @media (max-width: 860px) {
    .layout {
      grid-template-columns: 1fr;
    }
    aside {
      border-right: 0;
      max-height: 14rem;
    }
  }
</style>
