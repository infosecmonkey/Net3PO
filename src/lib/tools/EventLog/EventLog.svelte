<script lang="ts">
  import { invoke, Channel } from "@tauri-apps/api/core";
  import { open } from "@tauri-apps/plugin-dialog";
  import { onDestroy } from "svelte";
  import ExportMenu from "$lib/components/ExportMenu.svelte";
  import type {
    EvtFilter,
    EvtLoadSummary,
    EvtQueryResult,
    EvtRecordDetail,
    EvtRow,
  } from "$lib/tools/types";
  import { buildEventReport, filterText, showTime, spanText } from "./report";

  const PAGE = 200;

  let summary = $state<EvtLoadSummary | null>(null);
  let loading = $state(false);
  let progress = $state({ records: 0, errors: 0 });
  let runId = 0;
  let error = $state("");

  let filter = $state<EvtFilter>(emptyFilter());
  let result = $state<EvtQueryResult | null>(null);
  let exportRows = $state<EvtRow[]>([]);
  let offset = $state(0);
  let querying = $state(false);
  let detail = $state<EvtRecordDetail | null>(null);
  let showErrors = $state(false);
  let fromText = $state("");
  let toText = $state("");
  let hover = $state<number | null>(null);
  let debounce: ReturnType<typeof setTimeout> | undefined;

  function emptyFilter(): EvtFilter {
    return {
      providers: [],
      channels: [],
      ids: "",
      levels: [],
      outcome: "",
      computers: [],
      fromMs: null,
      toMs: null,
      text: "",
      field: "",
      newestFirst: false,
    };
  }

  onDestroy(() => {
    clearTimeout(debounce);
    if (summary) void invoke("evtlog_close", { datasetId: summary.datasetId });
  });

  async function openFile() {
    error = "";
    const path = await open({
      multiple: false,
      directory: false,
      filters: [{ name: "Event logs", extensions: ["evtx", "xml", "csv"] }],
    });
    if (typeof path !== "string") return;
    if (summary) void invoke("evtlog_close", { datasetId: summary.datasetId });
    summary = null;
    result = null;
    detail = null;
    loading = true;
    progress = { records: 0, errors: 0 };
    runId = Math.floor(Math.random() * 0x7fffffff);
    const ch = new Channel<{ type: "progress"; records: number; errors: number }>();
    ch.onmessage = (ev) => (progress = { records: ev.records, errors: ev.errors });
    try {
      summary = await invoke<EvtLoadSummary>("evtlog_load", { runId, path, onEvent: ch });
      filter = emptyFilter();
      fromText = toText = "";
      offset = 0;
      await runQuery();
    } catch (e) {
      error = String(e);
    } finally {
      loading = false;
    }
  }

  async function cancelLoad() {
    await invoke("evtlog_cancel", { runId }).catch(() => {});
  }

  async function runQuery() {
    if (!summary) return;
    querying = true;
    error = "";
    try {
      const f = $state.snapshot(filter);
      const [q, rows] = await Promise.all([
        invoke<EvtQueryResult>("evtlog_query", { datasetId: summary.datasetId, filter: f, offset, limit: PAGE }),
        invoke<EvtRow[]>("evtlog_export_rows", { datasetId: summary.datasetId, filter: f, limit: 500 }),
      ]);
      result = q;
      exportRows = rows;
    } catch (e) {
      error = String(e);
    } finally {
      querying = false;
    }
  }

  /** Re-run after typing stops. */
  function changed() {
    offset = 0;
    clearTimeout(debounce);
    debounce = setTimeout(runQuery, 300);
  }

  function setTimeBound(which: "from" | "to", text: string) {
    // datetime-local has no zone; it is read in the same frame as the log
    // (UTC, or the export's own local wall-clock time).
    const ms = text ? Date.parse(`${text}Z`) : NaN;
    if (which === "from") filter.fromMs = Number.isNaN(ms) ? null : ms;
    else filter.toMs = Number.isNaN(ms) ? null : ms;
    changed();
  }

  function toggle(list: "providers" | "channels" | "computers", value: string) {
    const cur = filter[list];
    filter[list] = cur.includes(value) ? cur.filter((v) => v !== value) : [...cur, value];
    changed();
  }

  function pickId(value: string) {
    const [id, provider] = value.split("|");
    filter.ids = id;
    filter.providers = provider ? [provider] : [];
    changed();
  }

  function pickBucket(i: number) {
    if (!result) return;
    const t = result.timeline;
    filter.fromMs = t.startMs + i * t.bucketMs;
    filter.toMs = filter.fromMs + t.bucketMs - 1;
    fromText = new Date(filter.fromMs).toISOString().slice(0, 16);
    toText = new Date(filter.toMs).toISOString().slice(0, 16);
    changed();
  }

  // The Level menu shows the filter's levels, so Clear filter resets it too.
  const levelChoice = $derived(
    filter.levels.length === 0 ? "" : filter.levels.includes(4) ? "info" : String(filter.levels[0]),
  );

  function clearFilter() {
    filter = emptyFilter();
    fromText = toText = "";
    changed();
  }

  async function showRecord(r: EvtRow) {
    if (!summary) return;
    try {
      detail = await invoke<EvtRecordDetail>("evtlog_record", { datasetId: summary.datasetId, index: r.index });
    } catch (e) {
      error = String(e);
    }
  }

  function page(delta: number) {
    if (!result) return;
    offset = Math.max(0, Math.min(offset + delta * PAGE, Math.max(0, result.matched - 1)));
    void runQuery();
  }

  const maxBar = $derived(result ? Math.max(1, ...result.timeline.counts) : 1);
  const bucketLabel = (i: number) => {
    if (!result) return "";
    const t = result.timeline;
    const d = new Date(t.startMs + i * t.bucketMs).toISOString().replace("T", " ").slice(0, 16);
    return `${d}${summary?.zoneUnknown ? " (local)" : " UTC"}: ${t.counts[i]} event${t.counts[i] === 1 ? "" : "s"}`;
  };
  const lookAt = $derived(new Set(detail?.explanation?.lookAt.map((x) => x.toLowerCase()) ?? []));
</script>

<div class="panel">
  <header>
    <h1>Windows Event Log</h1>
    <p class="sub">
      Open an .evtx file, an Event Viewer or wevtutil XML export, or a CSV export. Parsing is
      local. Filter by ID, provider, channel, level, computer, time and field values.
    </p>
  </header>

  <div class="row">
    <button class="action" onclick={openFile} disabled={loading}>Open log file...</button>
    {#if loading}
      <span class="muted small">Reading... {progress.records.toLocaleString()} events{progress.errors ? `, ${progress.errors} unreadable` : ""}</span>
      <button class="secondary" onclick={cancelLoad}>Stop</button>
    {/if}
    {#if summary && result}
      <div class="spacer"></div>
      <ExportMenu build={() => (summary && result ? buildEventReport(summary, filter, result, exportRows) : null)} name={`events-${summary.name}`} />
    {/if}
  </div>

  {#if error}<div class="error mono">{error}</div>{/if}

  {#if summary}
    <div class="loaded">
      <strong>{summary.name}</strong>
      <span class="muted">{summary.format.toUpperCase()}, {summary.records.toLocaleString()} events, {spanText(summary)}</span>
      {#if summary.truncated}<span class="warnc">Limit of 500,000 events reached; the rest of the file was not loaded.</span>{/if}
      {#if summary.cancelled}<span class="warnc">Loading was stopped; only part of the file is shown.</span>{/if}
      {#if summary.errorCount > 0}
        <button class="linkish warnc" onclick={() => (showErrors = !showErrors)}>
          {summary.errorCount} unreadable record{summary.errorCount === 1 ? "" : "s"} skipped
        </button>
      {/if}
    </div>
    {#if showErrors}
      <pre class="raw small">{summary.errors.join("\n")}{summary.errorCount > summary.errors.length ? `\n... and ${summary.errorCount - summary.errors.length} more` : ""}</pre>
    {/if}
    {#each summary.warnings as w (w)}<div class="warn small">{w}</div>{/each}

    <div class="filters">
      <div class="field">
        <label for="ev-ids">Event IDs</label>
        <input id="ev-ids" class="mono" bind:value={filter.ids} oninput={changed} placeholder="4624, 4625, 4688-4690, -4634" />
      </div>
      <div class="field grow">
        <label for="ev-text">Text anywhere</label>
        <input id="ev-text" bind:value={filter.text} oninput={changed} placeholder="user name, IP, path, command line" />
      </div>
      <div class="field">
        <label for="ev-field">Field</label>
        <input id="ev-field" class="mono" bind:value={filter.field} oninput={changed} placeholder="TargetUserName=admin" />
      </div>
      <div class="field small-field">
        <label for="ev-level">Level</label>
        <select id="ev-level" value={levelChoice} onchange={(e) => { const v = e.currentTarget.value; filter.levels = v === "" ? [] : v === "info" ? [0, 4] : [Number(v)]; changed(); }}>
          <option value="">Any</option>
          <option value="1">Critical</option>
          <option value="2">Error</option>
          <option value="3">Warning</option>
          <option value="info">Information</option>
          <option value="5">Verbose</option>
        </select>
      </div>
      <div class="field small-field">
        <label for="ev-out">Audit</label>
        <select id="ev-out" bind:value={filter.outcome} onchange={changed}>
          <option value="">Any</option>
          <option value="success">Success</option>
          <option value="failure">Failure</option>
        </select>
      </div>
      <div class="field">
        <label for="ev-from">From ({summary.zoneUnknown ? "local, as in file" : "UTC"})</label>
        <input id="ev-from" type="datetime-local" bind:value={fromText} onchange={() => setTimeBound("from", fromText)} />
      </div>
      <div class="field">
        <label for="ev-to">To</label>
        <input id="ev-to" type="datetime-local" bind:value={toText} onchange={() => setTimeBound("to", toText)} />
      </div>
    </div>
    <div class="row">
      <label class="check"><input type="checkbox" bind:checked={filter.newestFirst} onchange={changed} /> Newest first</label>
      <button class="mini" onclick={clearFilter}>Clear filter</button>
      {#if result}
        <span class="muted small">{result.matched.toLocaleString()} of {result.total.toLocaleString()} events match{querying ? "..." : ""}</span>
      {/if}
      {#if filterText(filter) !== "none (all events)"}<span class="muted small">Filter: {filterText(filter)}</span>{/if}
    </div>

    {#if result}
      {#if result.timeline.counts.length > 1}
        <div class="timeline" role="group" aria-label="Events over time">
          <svg viewBox="0 0 {result.timeline.counts.length * 10} 60" preserveAspectRatio="none">
            {#each result.timeline.counts as c, i (i)}
              <rect
                x={i * 10 + 1}
                y={60 - (c / maxBar) * 58}
                width="8"
                height={(c / maxBar) * 58}
                class:hot={hover === i}
                role="button"
                tabindex="-1"
                aria-label={bucketLabel(i)}
                onmouseenter={() => (hover = i)}
                onmouseleave={() => (hover = null)}
                onclick={() => pickBucket(i)}
                onkeydown={() => {}}
              ><title>{bucketLabel(i)}</title></rect>
            {/each}
          </svg>
          <div class="tl-label small muted">
            {hover !== null ? bucketLabel(hover) : "Events over time. Click a bar to zoom to that period."}
          </div>
        </div>
      {/if}

      <div class="facets">
        <div class="facet">
          <div class="flabel">Event IDs</div>
          {#each result.facets.ids as c (c.value)}
            <button class="chip" onclick={() => pickId(c.value)} title={c.value.split("|")[1]}>
              <span class="mono">{c.value.split("|")[0]}</span> {c.label || c.value.split("|")[1]}
              <span class="n">{c.count.toLocaleString()}</span>
            </button>
          {/each}
        </div>
        {#each [["Channels", "channels"], ["Providers", "providers"], ["Computers", "computers"]] as [label, key] (key)}
          {@const list = result.facets[key as "channels" | "providers" | "computers"]}
          {#if list.length > 1 || filter[key as "channels" | "providers" | "computers"].length > 0}
            <div class="facet">
              <div class="flabel">{label}</div>
              {#each list as c (c.value)}
                <button
                  class="chip"
                  class:on={filter[key as "channels" | "providers" | "computers"].includes(c.value)}
                  onclick={() => toggle(key as "channels" | "providers" | "computers", c.value)}
                >{c.value || "(none)"} <span class="n">{c.count.toLocaleString()}</span></button>
              {/each}
            </div>
          {/if}
        {/each}
      </div>

      <div class="table-wrap">
        <table class="grid">
          <thead><tr><th>Time</th><th>Level</th><th>ID</th><th>Event</th><th>Computer</th><th>Details</th></tr></thead>
          <tbody>
            {#each result.rows as r (r.index)}
              <tr class:sel={detail?.record.index === r.index} onclick={() => showRecord(r)}>
                <td class="mono small nowrap">{showTime(r)}</td>
                <td class="small" class:bad={r.outcome === "Audit Failure" || r.level === "Error" || r.level === "Critical"} class:warnl={r.level === "Warning"}>{r.outcome || r.level}</td>
                <td class="mono">{r.eventId}</td>
                <td class="small">{r.title || r.provider}{#if r.title}<div class="muted">{r.provider}</div>{/if}</td>
                <td class="small">{r.computer}</td>
                <td class="mono small">{r.summary}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
      <div class="row">
        <button class="mini" onclick={() => page(-1)} disabled={offset === 0}>Previous</button>
        <span class="small muted">
          {result.matched === 0 ? "No events" : `${(offset + 1).toLocaleString()} to ${Math.min(offset + PAGE, result.matched).toLocaleString()} of ${result.matched.toLocaleString()}`}
        </span>
        <button class="mini" onclick={() => page(1)} disabled={offset + PAGE >= result.matched}>Next</button>
      </div>
    {/if}

    {#if detail}
      <section class="detail">
        <div class="dhead">
          <strong>Event {detail.record.eventId}</strong>
          <span>{detail.record.provider}</span>
          <span class="muted">{detail.record.channel}</span>
          <div class="spacer"></div>
          <button class="mini" onclick={() => (detail = null)}>Close</button>
        </div>
        <table class="kv small">
          <tbody>
            <tr><th>Time as written</th><td class="mono">{detail.record.timeRaw}</td></tr>
            <tr><th>Normalized</th><td class="mono">{detail.record.timeUtcMs !== null ? new Date(detail.record.timeUtcMs).toISOString() : detail.record.zoneUnknown ? "Not converted: the export has no time zone" : "Unreadable"}</td></tr>
            <tr><th>Level</th><td>{detail.record.outcome || detail.levelName}</td></tr>
            <tr><th>Computer</th><td>{detail.record.computer}</td></tr>
            {#if detail.record.recordId !== null}<tr><th>Record ID</th><td class="mono">{detail.record.recordId}</td></tr>{/if}
            {#if detail.record.userSid}<tr><th>User</th><td class="mono">{detail.record.userSid}</td></tr>{/if}
          </tbody>
        </table>

        {#if detail.explanation}
          <div class="explain">
            <div><strong>{detail.explanation.title}</strong></div>
            {#if detail.explanation.meaning}<div class="small">{detail.explanation.meaning}</div>{/if}
            {#if detail.explanation.lookAt.length}<div class="small muted">Look at: {detail.explanation.lookAt.join(", ")}</div>{/if}
            <div class="small caution">{detail.explanation.caution}</div>
          </div>
        {:else}
          <div class="small muted">No explanation for event {detail.record.eventId} from this provider.</div>
        {/if}

        {#if detail.decoded.length}
          <div class="small decoded">
            {#each detail.decoded as [k, v] (k)}<div><span class="mono">{k}</span>: {v}</div>{/each}
          </div>
        {/if}

        {#if detail.record.fields.length}
          <h3>Fields</h3>
          <table class="kv small">
            <tbody>
              {#each detail.record.fields as [k, v], i (i)}
                <tr class:key={lookAt.has(k.toLowerCase())}><th class="mono">{k}</th><td class="mono">{v}</td></tr>
              {/each}
            </tbody>
          </table>
        {/if}
        {#if detail.record.message}
          <h3>Message</h3>
          <pre class="raw small">{detail.record.message}</pre>
        {/if}
        {#if detail.record.raw}
          <details>
            <summary class="small muted">Raw record</summary>
            <pre class="raw small">{detail.record.raw}</pre>
          </details>
        {/if}
      </section>
    {/if}
  {:else if !loading}
    <p class="muted small">
      Supported: .evtx (Security, System, Sysmon and any other channel), XML from Event Viewer
      "Save as XML" or <span class="mono">wevtutil qe /f:xml</span>, and CSV from Event Viewer or
      <span class="mono">Export-Csv</span>. Up to 500,000 events per file.
    </p>
  {/if}
</div>

<style>
  .panel {
    --st-bad: #d1453b;
    --st-warn: #c69026;
    padding: 1.5rem 2rem 2rem;
    box-sizing: border-box;
    width: 100%;
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

  h3 {
    font-size: 0.85rem;
    margin: 0.8rem 0 0.3rem;
  }

  .row {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 0.6rem;
    margin: 0.5rem 0;
  }

  .spacer {
    flex: 1 1 auto;
  }

  .muted {
    color: var(--muted);
  }

  .small {
    font-size: 0.76rem;
  }

  .mono {
    font-family: var(--mono);
  }

  .nowrap {
    white-space: nowrap;
  }

  .warnc {
    color: var(--st-warn);
  }

  .action {
    background: var(--accent);
    border: 1px solid var(--accent);
    border-radius: 6px;
    padding: 0.5rem 1.2rem;
    color: var(--accent-fg);
    font-weight: 600;
    font-size: 0.85rem;
    cursor: pointer;
  }

  .action:disabled {
    opacity: 0.5;
  }

  .secondary,
  .mini,
  .chip {
    background: var(--btn-bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    color: var(--fg);
    cursor: pointer;
  }

  .secondary {
    padding: 0.45rem 0.9rem;
    font-size: 0.82rem;
  }

  .mini {
    padding: 0.15rem 0.55rem;
    font-size: 0.74rem;
  }

  .mini:disabled {
    opacity: 0.5;
    cursor: default;
  }

  .linkish {
    background: none;
    border: none;
    padding: 0;
    text-decoration: underline;
    cursor: pointer;
    font-size: inherit;
  }

  .error {
    background: var(--error-bg);
    border: 1px solid var(--error-border);
    color: var(--error-fg);
    border-radius: 6px;
    padding: 0.55rem 0.75rem;
    font-size: 0.82rem;
    margin: 0.5rem 0;
    white-space: pre-wrap;
  }

  .warn {
    border: 1px solid var(--st-warn);
    border-left-width: 3px;
    border-radius: 6px;
    padding: 0.35rem 0.6rem;
    margin: 0.35rem 0;
  }

  .loaded {
    display: flex;
    flex-wrap: wrap;
    gap: 0.6rem;
    align-items: baseline;
    font-size: 0.82rem;
    margin: 0.4rem 0;
  }

  .filters {
    display: flex;
    flex-wrap: wrap;
    gap: 0.6rem;
    margin-top: 0.6rem;
  }

  .field {
    display: flex;
    flex-direction: column;
    flex: 1 1 150px;
  }

  .field.grow {
    flex: 2 1 220px;
  }

  .field.small-field {
    flex: 0 1 110px;
  }

  label {
    font-size: 0.74rem;
    color: var(--muted);
    margin-bottom: 0.25rem;
  }

  label.check {
    display: flex;
    gap: 0.3rem;
    align-items: center;
    color: var(--fg);
    margin: 0;
  }

  input:not([type="checkbox"]),
  select {
    background: var(--input-bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.35rem 0.5rem;
    color: var(--fg);
    font-size: 0.82rem;
    box-sizing: border-box;
    width: 100%;
  }

  input:focus,
  select:focus {
    outline: none;
    border-color: var(--accent);
  }

  .timeline {
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.4rem 0.5rem 0.3rem;
    margin: 0.4rem 0;
  }

  .timeline svg {
    width: 100%;
    height: 60px;
    display: block;
  }

  .timeline rect {
    fill: var(--accent);
    opacity: 0.75;
    cursor: pointer;
  }

  .timeline rect.hot {
    opacity: 1;
  }

  .tl-label {
    margin-top: 0.2rem;
  }

  .facets {
    display: flex;
    flex-direction: column;
    gap: 0.35rem;
    margin: 0.5rem 0;
  }

  .facet {
    display: flex;
    flex-wrap: wrap;
    gap: 0.3rem;
    align-items: center;
  }

  .flabel {
    font-size: 0.72rem;
    color: var(--muted);
    width: 5.5rem;
    flex: 0 0 auto;
  }

  .chip {
    font-size: 0.72rem;
    padding: 0.1rem 0.45rem;
  }

  .chip.on {
    border-color: var(--accent);
    background: var(--active-bg);
  }

  .chip .n {
    color: var(--muted);
    margin-left: 0.25rem;
  }

  .table-wrap {
    border: 1px solid var(--border);
    border-radius: 6px;
    overflow: clip;
  }

  table {
    border-collapse: collapse;
    width: 100%;
    font-size: 0.8rem;
  }

  table.grid th {
    text-align: left;
    color: var(--muted);
    font-weight: 500;
    padding: 0.35rem 0.5rem;
    border-bottom: 1px solid var(--border);
    background: var(--sidebar-bg);
    position: sticky;
    top: 0;
  }

  table.grid td {
    padding: 0.3rem 0.5rem;
    border-bottom: 1px solid var(--border);
    vertical-align: top;
    word-break: break-word;
  }

  table.grid tbody tr {
    cursor: pointer;
  }

  table.grid tbody tr:hover td {
    background: var(--hover);
  }

  tr.sel td {
    background: var(--active-bg) !important;
  }

  td.bad {
    color: var(--st-bad);
    font-weight: 600;
  }

  td.warnl {
    color: var(--st-warn);
  }

  table.kv th {
    text-align: left;
    color: var(--muted);
    font-weight: 500;
    width: 13rem;
    padding: 0.2rem 0.6rem 0.2rem 0;
    vertical-align: top;
    word-break: break-word;
  }

  table.kv td {
    padding: 0.2rem 0;
    word-break: break-word;
  }

  tr.key th,
  tr.key td {
    color: var(--fg);
    font-weight: 600;
  }

  .detail {
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.7rem 0.9rem;
    margin-top: 0.8rem;
  }

  .dhead {
    display: flex;
    gap: 0.6rem;
    align-items: baseline;
    margin-bottom: 0.4rem;
  }

  .explain {
    border-left: 3px solid var(--accent);
    padding: 0.4rem 0.7rem;
    margin: 0.5rem 0;
    background: var(--sidebar-bg);
    border-radius: 0 6px 6px 0;
    display: flex;
    flex-direction: column;
    gap: 0.2rem;
  }

  .caution {
    color: var(--st-warn);
  }

  .decoded {
    margin: 0.3rem 0;
  }

  details {
    margin-top: 0.6rem;
  }

  summary {
    cursor: pointer;
  }

  pre.raw {
    font-family: var(--mono);
    white-space: pre-wrap;
    word-break: break-word;
    background: var(--sidebar-bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.5rem;
    max-height: 22rem;
    overflow: auto;
    user-select: text;
  }
</style>
