<script lang="ts">
  // FortiGate debug flow parser. Paste or open `diagnose debug flow`
  // output; traces are grouped and explained, with verdicts only where the
  // log states them and every fact linked to its line.
  import { invoke } from "@tauri-apps/api/core";
  import { open } from "@tauri-apps/plugin-dialog";
  import ExportMenu from "$lib/components/ExportMenu.svelte";
  import { buildFlowReport, facts, tuple, VERDICT_LABEL, type Parsed, type Trace, type Verdict } from "./model";

  let text = $state("");
  let parsed = $state<Parsed | null>(null);
  let error = $state("");
  let verdictFilter = $state<"" | Verdict>("");
  let search = $state("");
  let openTrace = $state<number | null>(null);
  let highlight = $state<number | null>(null);

  async function parse() {
    error = "";
    parsed = await invoke<Parsed>("flow_parse", { text });
    if (parsed.error) error = parsed.error;
    openTrace = parsed.traces.length === 1 ? parsed.traces[0].traceId : null;
  }

  async function openFile() {
    const p = await open({ multiple: false, filters: [{ name: "Text", extensions: ["txt", "log"] }, { name: "All files", extensions: ["*"] }] });
    if (typeof p !== "string") return;
    try {
      text = await invoke<string>("flow_read_file", { path: p });
      await parse();
    } catch (e) {
      error = String(e);
    }
  }

  const shown = $derived(
    (parsed?.traces ?? []).filter((t) => {
      if (verdictFilter && t.verdict !== verdictFilter) return false;
      if (!search.trim()) return true;
      const q = search.trim().toLowerCase();
      return `${tuple(t)} ${t.inIface?.value ?? ""} ${t.outIface?.value ?? ""} ${t.policy?.value ?? ""} ${t.events.map((e) => e.msg).join(" ")}`.toLowerCase().includes(q);
    }),
  );

  function counts(): Record<Verdict, number> {
    const c = { allowed: 0, denied: 0, dropped: 0, existingSession: 0, unknown: 0 };
    for (const t of parsed?.traces ?? []) c[t.verdict]++;
    return c;
  }

  function jump(t: Trace, line: number) {
    openTrace = t.traceId;
    highlight = line;
    setTimeout(() => document.getElementById(`ev-${t.traceId}-${line}`)?.scrollIntoView({ block: "center", behavior: "smooth" }), 30);
  }
</script>

<div class="panel">
  <header>
    <h1>Debug Flow Parser</h1>
    <p class="sub">
      Paste FortiGate <span class="mono">diagnose debug flow</span> output to see each packet's path: session,
      route, policy, NAT and verdict. Verdicts appear only where the log states them. Offline.
    </p>
  </header>

  <textarea class="mono" rows="8" bind:value={text} spellcheck="false" placeholder="paste debug flow output (with 'diagnose debug flow show function-name enable' for best results)"></textarea>
  <div class="row">
    <button class="primary" onclick={parse}>Parse</button>
    <button class="second" onclick={openFile}>Open file...</button>
    {#if parsed && parsed.traces.length}
      <span class="spacer"></span>
      <ExportMenu build={() => (parsed ? buildFlowReport(parsed) : null)} name="debug-flow" />
    {/if}
  </div>
  {#if error}<div class="error">{error}</div>{/if}

  {#if parsed && !parsed.error}
    {@const c = counts()}
    <div class="summary">
      <strong>{parsed.traces.length}</strong> trace{parsed.traces.length === 1 ? "" : "s"}:
      <span class="v allowed">{c.allowed} allowed</span>
      <span class="v denied">{c.denied} denied</span>
      <span class="v dropped">{c.dropped} dropped</span>
      <span class="v existingSession">{c.existingSession} existing session</span>
      <span class="v unknown">{c.unknown} no verdict</span>
      {#if parsed.unparsed}<span class="muted">· {parsed.unparsed} unreadable trace line{parsed.unparsed === 1 ? "" : "s"}</span>{/if}
      {#if parsed.truncated}<span class="muted">· stopped at 5,000 traces</span>{/if}
    </div>
    {#if !parsed.traces.length}<p class="muted">No debug flow lines found (looking for lines with trace_id= and msg=).</p>{/if}
    {#if parsed.traces.length}
      <div class="row">
        <select bind:value={verdictFilter} aria-label="Verdict">
          <option value="">all verdicts</option>
          {#each Object.entries(VERDICT_LABEL) as [k, label] (k)}<option value={k}>{label}</option>{/each}
        </select>
        <input class="mono grow" bind:value={search} placeholder="search address, interface, policy or message" spellcheck="false" />
      </div>
    {/if}

    {#each shown as t (t.traceId)}
      <div class="trace" class:open={openTrace === t.traceId}>
        <button class="thead" onclick={() => (openTrace = openTrace === t.traceId ? null : t.traceId)}>
          <span class="badge {t.verdict}">{VERDICT_LABEL[t.verdict]}</span>
          <span class="mono tup">{tuple(t)}</span>
          <span class="muted">{t.inIface?.value ?? "?"} &gt; {t.outIface?.value ?? "?"}</span>
          {#if t.policy}<span class="muted">· {t.policy.value}</span>{/if}
          <span class="spacer"></span>
          <span class="muted small">trace {t.traceId} · line {t.firstLine}</span>
        </button>
        {#if openTrace === t.traceId}
          <div class="tbody">
            <table class="kv">
              <tbody>
                {#each facts(t) as f, i (i)}
                  <tr>
                    <th>{f.key}</th>
                    <td>{f.value}</td>
                    <td class="ln">{#if f.line}<button class="link" onclick={() => jump(t, f.line ?? 0)}>line {f.line}</button>{/if}</td>
                  </tr>
                {/each}
              </tbody>
            </table>
            {#each t.notes as n (n)}<div class="note">{n}</div>{/each}
            <div class="events">
              {#each t.events as e (e.line)}
                <div class="ev {e.kind}" class:hl={highlight === e.line} id="ev-{t.traceId}-{e.line}">
                  <span class="ln mono">{e.line}</span>
                  <div>
                    <div class="mono msg">{#if e.func}<span class="fn">{e.func}</span> {/if}{e.msg}</div>
                    {#if e.note}<div class="enote">{e.note}</div>{/if}
                  </div>
                </div>
              {/each}
              {#if t.eventsTruncated}<div class="muted small">Only the first 500 lines of this trace are shown.</div>{/if}
            </div>
          </div>
        {/if}
      </div>
    {/each}
  {/if}
</div>

<style>
  .panel {
    padding: 1.5rem 2rem;
    max-width: 1100px;
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
  input,
  select {
    box-sizing: border-box;
    background: var(--input-bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.4rem 0.55rem;
    color: var(--fg);
    font-size: 0.8rem;
  }

  textarea {
    width: 100%;
    resize: vertical;
  }

  textarea:focus,
  input:focus,
  select:focus {
    outline: none;
    border-color: var(--accent);
  }

  .mono {
    font-family: var(--mono);
  }

  .row {
    display: flex;
    align-items: center;
    gap: 0.6rem;
    margin: 0.6rem 0;
    flex-wrap: wrap;
  }

  .grow {
    flex: 1;
  }

  .spacer {
    flex: 1;
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
    padding: 0.45rem 0.9rem;
    color: var(--fg);
    cursor: pointer;
    font-size: 0.84rem;
  }

  .link {
    background: none;
    border: none;
    color: var(--accent);
    font-size: 0.74rem;
    cursor: pointer;
    padding: 0;
  }

  .error {
    color: var(--error-fg);
    font-size: 0.84rem;
  }

  .muted {
    color: var(--muted);
    font-size: 0.8rem;
  }

  .small {
    font-size: 0.72rem;
  }

  .summary {
    display: flex;
    gap: 0.8rem;
    flex-wrap: wrap;
    align-items: baseline;
    font-size: 0.84rem;
    margin: 0.4rem 0;
  }

  .v.allowed,
  .badge.allowed {
    color: #15935a;
  }

  .v.denied,
  .v.dropped,
  .badge.denied,
  .badge.dropped {
    color: #c0392b;
  }

  .v.existingSession,
  .badge.existingSession {
    color: #2563eb;
  }

  .v.unknown,
  .badge.unknown {
    color: var(--muted);
  }

  .trace {
    border: 1px solid var(--border);
    border-radius: 8px;
    margin-bottom: 0.4rem;
  }

  .trace.open {
    border-color: var(--accent);
  }

  .thead {
    width: 100%;
    display: flex;
    align-items: center;
    gap: 0.6rem;
    background: none;
    border: none;
    color: var(--fg);
    text-align: left;
    padding: 0.45rem 0.7rem;
    cursor: pointer;
    font-size: 0.82rem;
  }

  .badge {
    font-weight: 700;
    font-size: 0.72rem;
    min-width: 6.5rem;
  }

  .tup {
    font-size: 0.8rem;
  }

  .tbody {
    padding: 0 0.8rem 0.7rem;
  }

  .kv {
    border-collapse: collapse;
    margin-bottom: 0.4rem;
  }

  .kv th {
    text-align: left;
    color: var(--muted);
    font-weight: 500;
    font-size: 0.78rem;
    padding: 0.15rem 1rem 0.15rem 0;
  }

  .kv td {
    font-size: 0.82rem;
    padding: 0.15rem 0.8rem 0.15rem 0;
  }

  .note {
    border-left: 3px solid #b7791f;
    padding: 0.2rem 0.6rem;
    font-size: 0.78rem;
    margin: 0.3rem 0;
  }

  .events {
    border-top: 1px solid var(--border);
    margin-top: 0.4rem;
    padding-top: 0.4rem;
    max-height: 26rem;
    overflow: auto;
  }

  .ev {
    display: grid;
    grid-template-columns: 3.2rem 1fr;
    gap: 0.4rem;
    padding: 0.2rem 0.3rem;
    border-left: 3px solid transparent;
  }

  .ev.hl {
    background: var(--active-bg);
  }

  .ev.allow {
    border-left-color: #15935a;
  }

  .ev.deny,
  .ev.drop {
    border-left-color: #c0392b;
  }

  .ev.policy,
  .ev.route,
  .ev.nat,
  .ev.session,
  .ev.ipsec {
    border-left-color: var(--border);
  }

  .ln {
    color: var(--muted);
    font-size: 0.72rem;
    text-align: right;
  }

  .msg {
    font-size: 0.76rem;
    overflow-wrap: anywhere;
  }

  .fn {
    color: var(--muted);
  }

  .enote {
    font-size: 0.74rem;
    color: var(--muted);
    margin-top: 0.1rem;
  }
</style>
