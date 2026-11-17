<script lang="ts">
  // FortiGate session list parser. Paste or open `diagnose sys session list`
  // (or `session6 list`) output and get a filterable table with decoded
  // state, NAT, counters, offload status and documented flag meanings.
  import { invoke } from "@tauri-apps/api/core";
  import { open } from "@tauri-apps/plugin-dialog";
  import ExportMenu from "$lib/components/ExportMenu.svelte";
  import {
    buildSessionReport,
    bytes,
    countBy,
    ep,
    facts,
    filterCommands,
    nat,
    offload,
    OFFLOAD_LABEL,
    searchText,
    secs,
    total,
    type Offload,
    type Parsed,
    type Session,
  } from "./model";

  type SortKey = "index" | "bytes" | "duration" | "expire";

  let text = $state("");
  let parsed = $state<Parsed | null>(null);
  let error = $state("");
  let search = $state("");
  let proto = $state("");
  let off = $state<"" | Offload>("");
  let sort = $state<SortKey>("index");
  let selected = $state<number | null>(null);
  let copied = $state("");

  const ROWS = 1000;

  async function parse() {
    error = "";
    parsed = await invoke<Parsed>("session_parse", { text });
    if (parsed.error) error = parsed.error;
    selected = parsed.sessions.length === 1 ? 1 : null;
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

  async function copy(key: string, value: string) {
    try {
      await navigator.clipboard.writeText(value);
      copied = key;
      setTimeout(() => (copied = ""), 1200);
    } catch {
      copied = "";
    }
  }

  const all = $derived(parsed?.sessions ?? []);
  const protos = $derived([...new Set(all.map((s) => s.protoName))].sort());
  const shown = $derived.by(() => {
    const q = search.trim().toLowerCase();
    const list = all.filter(
      (s) => (!proto || s.protoName === proto) && (!off || offload(s) === off) && (!q || searchText(s).includes(q)),
    );
    const by: Record<SortKey, (s: Session) => number> = {
      index: (s) => s.index,
      bytes: (s) => -total(s),
      duration: (s) => -(s.duration ?? 0),
      expire: (s) => s.expire ?? Number.MAX_SAFE_INTEGER,
    };
    return [...list].sort((a, b) => by[sort](a) - by[sort](b));
  });
  const current = $derived(all.find((s) => s.index === selected) ?? null);

  const top = (list: { key: string; count: number; bytes: number }[], field: "count" | "bytes") =>
    [...list].sort((a, b) => b[field] - a[field]).slice(0, 5);
  const summary = $derived.by(() => ({
    protos: top(countBy(shown, (s) => s.protoName), "count"),
    sources: top(countBy(shown, (s) => s.src?.addr ?? null), "bytes"),
    dests: top(countBy(shown, (s) => (s.dst ? `${s.protoName} ${ep(s.dst)}` : null)), "count"),
    policies: top(countBy(shown, (s) => (s.policyId !== null ? s.policyId : null)), "count"),
    offload: countBy(shown, (s) => OFFLOAD_LABEL[offload(s)]),
    reasons: top(
      countBy(
        shown.flatMap((s) => s.noOffload.map((r) => ({ ...s, _r: r.name }))),
        (s) => (s as Session & { _r: string })._r,
      ),
      "count",
    ),
  }));

  function pick(q: string) {
    search = q;
    selected = null;
  }
</script>

<div class="panel">
  <header>
    <h1>Session List Parser</h1>
    <p class="sub">
      Paste FortiGate <span class="mono">diagnose sys session list</span> or <span class="mono">session6 list</span> output to see
      each session's tuple, NAT, policy, counters, state flags and offload status. Offline.
    </p>
  </header>

  <textarea class="mono" rows="7" bind:value={text} spellcheck="false" placeholder="paste session list output (set a filter first with 'diagnose sys session filter ...' on busy units)"></textarea>
  <div class="row">
    <button class="primary" onclick={parse}>Parse</button>
    <button class="second" onclick={openFile}>Open file...</button>
    {#if parsed && all.length}
      <span class="spacer"></span>
      <ExportMenu build={() => (parsed ? buildSessionReport(parsed, shown) : null)} name="session-list" />
    {/if}
  </div>
  {#if error}<div class="error">{error}</div>{/if}

  {#if parsed && !parsed.error}
    <div class="summary">
      <strong>{all.length}</strong> session{all.length === 1 ? "" : "s"} parsed
      {#if parsed.totalReported !== null}
        <span class="muted">· FortiGate reported {parsed.totalReported} in total{parsed.totalReported > all.length ? " (the rest were filtered out or not pasted)" : ""}</span>
      {/if}
      {#if parsed.truncated}<span class="muted">· stopped at 100,000</span>{/if}
    </div>
    {#if !all.length}<p class="muted">No sessions found (looking for lines that start with "session info:").</p>{/if}

    {#if all.length}
      <div class="cards">
        <div class="card">
          <h3>Protocols</h3>
          {#each summary.protos as c (c.key)}<button class="link" onclick={() => (proto = c.key)}>{c.key}</button> <span class="muted">{c.count}</span><br />{/each}
        </div>
        <div class="card">
          <h3>Top sources by bytes</h3>
          {#each summary.sources as c (c.key)}<button class="link mono" onclick={() => pick(c.key)}>{c.key}</button> <span class="muted">{bytes(c.bytes)}</span><br />{/each}
        </div>
        <div class="card">
          <h3>Top destinations</h3>
          {#each summary.dests as c (c.key)}<button class="link mono" onclick={() => pick(c.key.split(" ")[1])}>{c.key}</button> <span class="muted">{c.count}</span><br />{/each}
        </div>
        <div class="card">
          <h3>Policies</h3>
          {#each summary.policies as c (c.key)}<button class="link" onclick={() => pick(`policy ${c.key}`)}>policy {c.key}</button> <span class="muted">{c.count}</span><br />{/each}
        </div>
        <div class="card">
          <h3>Offload</h3>
          {#each summary.offload as c (c.key)}<span>{c.key}</span> <span class="muted">{c.count}</span><br />{/each}
          {#each summary.reasons as c (c.key)}<button class="link mono small" onclick={() => pick(c.key)}>{c.key}</button> <span class="muted">{c.count}</span><br />{/each}
        </div>
      </div>

      <div class="row">
        <input class="mono grow" type="search" bind:value={search} placeholder="search address, port, policy, flag or offload reason" spellcheck="false" />
        <select bind:value={proto} aria-label="Protocol">
          <option value="">all protocols</option>
          {#each protos as p (p)}<option value={p}>{p}</option>{/each}
        </select>
        <select bind:value={off} aria-label="Offload">
          <option value="">any offload</option>
          {#each Object.entries(OFFLOAD_LABEL) as [k, label] (k)}<option value={k}>{label}</option>{/each}
        </select>
        <select bind:value={sort} aria-label="Sort">
          <option value="index">output order</option>
          <option value="bytes">most bytes</option>
          <option value="duration">oldest</option>
          <option value="expire">expiring soonest</option>
        </select>
      </div>
      <p class="muted small">{shown.length} shown{shown.length > ROWS ? `, first ${ROWS} listed` : ""}</p>

      <div class="layout" class:split={current !== null}>
        <div class="tablewrap">
          <table class="list">
            <thead>
              <tr><th>#</th><th>Proto</th><th>Source</th><th>Destination</th><th>NAT</th><th>Policy</th><th>Bytes out / in</th><th>Age</th><th>Expires</th><th>Offload</th></tr>
            </thead>
            <tbody>
              {#each shown.slice(0, ROWS) as s (s.index)}
                <tr class:sel={selected === s.index} class:warn={s.notes.some((n) => n.startsWith("SYN") || n.startsWith("No "))} onclick={() => (selected = selected === s.index ? null : s.index)}>
                  <td class="muted">{s.index}</td>
                  <td>{s.protoName}{#if s.stateText && s.proto !== 1}<span class="muted small state">{s.stateText}</span>{/if}</td>
                  <td class="mono">{ep(s.src)}</td>
                  <td class="mono">{ep(s.dst)}</td>
                  <td class="mono small">{nat(s)}</td>
                  <td>{s.policyId ?? ""}</td>
                  <td class="num">{bytes(s.orgBytes)} / {bytes(s.replyBytes)}</td>
                  <td class="num">{secs(s.duration)}</td>
                  <td class="num">{secs(s.expire)}</td>
                  <td><span class="off {offload(s)}">{OFFLOAD_LABEL[offload(s)]}</span></td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>

        {#if current}
          {@const s = current}
          <aside class="detail">
            <div class="dhead">
              <strong>Session {s.index}</strong>
              <span class="muted small">line {s.line}{s.ipv6 ? " · IPv6" : ""}</span>
              <span class="spacer"></span>
              <button class="mini" onclick={() => (selected = null)}>Close</button>
            </div>
            {#if s.notes.length}
              <ul class="notes">{#each s.notes as n (n)}<li>{n}</li>{/each}</ul>
            {/if}
            <table class="kv">
              <tbody>
                {#each facts(s) as f (f.key)}<tr><th>{f.key}</th><td class="mono">{f.value}</td></tr>{/each}
              </tbody>
            </table>

            {#if s.flags.length}
              <h3>State flags</h3>
              <table class="kv">
                <tbody>
                  {#each s.flags as f (f.name)}<tr><th class="mono">{f.name}</th><td class:muted={!f.meaning}>{f.meaning ?? "not documented"}</td></tr>{/each}
                </tbody>
              </table>
            {/if}

            {#if s.noOffload.length}
              <h3>Why it is not offloaded</h3>
              <table class="kv">
                <tbody>
                  {#each s.noOffload as f (f.name)}<tr><th class="mono">{f.name}</th><td class:muted={!f.meaning}>{f.meaning ?? "not documented"}</td></tr>{/each}
                </tbody>
              </table>
            {/if}

            {#if s.hooks.length}
              <h3>NAT hooks</h3>
              <table class="kv">
                <tbody>
                  {#each s.hooks as h, i (i)}
                    <tr>
                      <th class="mono">{h.hook} {h.dir} {h.act}</th>
                      <td class="mono">{ep(h.src)} &gt; {ep(h.dst)}{h.nat ? ` (${ep(h.nat)})` : ""}</td>
                    </tr>
                  {/each}
                </tbody>
              </table>
            {/if}

            <div class="dhead">
              <h3>Show it on the FortiGate</h3>
              <span class="spacer"></span>
              <button class="mini" onclick={() => copy("cli", filterCommands(s))}>{copied === "cli" ? "Copied" : "Copy"}</button>
            </div>
            <pre class="mono code">{filterCommands(s)}</pre>
            <p class="muted small">Interface indexes map to names with <span class="mono">diagnose netlink interface list</span>.</p>

            <details>
              <summary>Raw output</summary>
              <pre class="mono code">{s.raw}</pre>
            </details>
          </aside>
        {/if}
      </div>
    {/if}
  {/if}
</div>

<style>
  .panel {
    padding: 1.5rem 2rem;
    max-width: 1400px;
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

  textarea {
    box-sizing: border-box;
    width: 100%;
    background: var(--input-bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.5rem 0.6rem;
    color: var(--fg);
    font-size: 0.8rem;
    resize: vertical;
  }

  textarea:focus,
  input:focus,
  select:focus {
    outline: none;
    border-color: var(--accent);
  }

  input,
  select {
    background: var(--input-bg);
    border: 1px solid var(--border);
    border-radius: 4px;
    color: var(--fg);
    padding: 0.3rem 0.45rem;
    font-size: 0.8rem;
  }

  .grow {
    flex: 1;
    min-width: 14rem;
  }

  .mono {
    font-family: var(--mono);
  }

  .row {
    display: flex;
    align-items: center;
    gap: 0.6rem;
    margin: 0.7rem 0;
    flex-wrap: wrap;
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

  .mini {
    background: var(--input-bg);
    border: 1px solid var(--border);
    border-radius: 4px;
    color: var(--fg);
    font-size: 0.72rem;
    padding: 0.12rem 0.5rem;
    cursor: pointer;
  }

  .link {
    background: none;
    border: none;
    padding: 0;
    color: var(--accent);
    cursor: pointer;
    font-size: inherit;
    text-align: left;
  }

  .muted {
    color: var(--muted);
    font-size: 0.8rem;
    font-weight: normal;
  }

  .small {
    font-size: 0.74rem;
  }

  .error {
    color: var(--error-fg);
    font-size: 0.82rem;
  }

  .summary {
    font-size: 0.86rem;
    margin: 0.5rem 0;
  }

  .cards {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(190px, 1fr));
    gap: 0.6rem;
    margin: 0.6rem 0;
  }

  .card {
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.5rem 0.7rem;
    font-size: 0.78rem;
    line-height: 1.55;
    overflow-wrap: anywhere;
  }

  h3 {
    font-size: 0.8rem;
    margin: 0.6rem 0 0.3rem;
  }

  .card h3 {
    margin-top: 0;
    color: var(--muted);
    font-weight: 600;
  }

  .layout {
    display: grid;
    grid-template-columns: 1fr;
    gap: 0.8rem;
  }

  .layout.split {
    grid-template-columns: minmax(0, 1.4fr) minmax(320px, 1fr);
  }

  .state {
    margin-left: 0.35rem;
  }

  .tablewrap {
    align-self: start;
    overflow: auto;
    max-height: 70vh;
    border: 1px solid var(--border);
    border-radius: 6px;
  }

  table {
    border-collapse: collapse;
    width: 100%;
  }

  .list th {
    position: sticky;
    top: 0;
    background: var(--bg, var(--input-bg));
    text-align: left;
    font-size: 0.72rem;
    color: var(--muted);
    padding: 0.3rem 0.5rem;
    border-bottom: 1px solid var(--border);
    white-space: nowrap;
  }

  .list td {
    padding: 0.22rem 0.5rem;
    font-size: 0.78rem;
    border-bottom: 1px solid var(--border);
    white-space: nowrap;
  }

  .list tr {
    cursor: pointer;
  }

  .list tr:hover td {
    background: color-mix(in srgb, var(--accent) 8%, transparent);
  }

  .list tr.sel td {
    background: color-mix(in srgb, var(--accent) 18%, transparent);
  }

  .list tr.warn td:first-child {
    box-shadow: inset 3px 0 0 #b45309;
  }

  .num {
    text-align: right;
  }

  .off {
    font-size: 0.7rem;
    border-radius: 3px;
    padding: 0 0.35rem;
    border: 1px solid var(--border);
  }

  .off.both {
    color: #15803d;
    border-color: #15803d;
  }

  .off.none {
    color: #b45309;
    border-color: #b45309;
  }

  .detail {
    align-self: start;
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.6rem 0.8rem;
    font-size: 0.8rem;
    max-height: 70vh;
    overflow: auto;
  }

  .dhead {
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }

  .notes {
    margin: 0.4rem 0;
    padding-left: 1.1rem;
    color: #b45309;
    font-size: 0.78rem;
  }

  .kv th {
    text-align: left;
    font-weight: 600;
    color: var(--muted);
    font-size: 0.74rem;
    padding: 0.15rem 0.6rem 0.15rem 0;
    vertical-align: top;
    white-space: nowrap;
  }

  .kv td {
    font-size: 0.78rem;
    padding: 0.15rem 0;
    overflow-wrap: anywhere;
  }

  .code {
    background: var(--input-bg);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 0.4rem 0.5rem;
    font-size: 0.74rem;
    white-space: pre-wrap;
    overflow-wrap: anywhere;
    margin: 0.3rem 0;
  }

  details summary {
    cursor: pointer;
    color: var(--muted);
    margin-top: 0.5rem;
  }

  @media (max-width: 1000px) {
    .layout.split {
      grid-template-columns: 1fr;
    }
  }
</style>
