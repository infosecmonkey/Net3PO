<script lang="ts">
  // DNS Benchmark: compare resolvers over UDP, TCP, DoT and DoH, check DNSSEC
  // validation and NXDOMAIN hijacking. Changing this computer's DNS is left to
  // the copied commands; nothing here needs admin rights.
  import { onMount } from "svelte";
  import { invoke, Channel } from "@tauri-apps/api/core";
  import { confirm } from "@tauri-apps/plugin-dialog";
  import ExportMenu from "$lib/components/ExportMenu.svelte";
  import { selectOnFocus } from "$lib/actions/selectOnFocus";
  import { loadCollection, saveCollection } from "$lib/store";
  import { settings } from "$lib/settings.svelte";
  import {
    applyCommands,
    buildReport,
    DNSSEC_LABEL,
    ms,
    TRANSPORT_LABEL,
    TRANSPORTS,
    type BenchEvent,
    type Check,
    type Custom,
    type Defaults,
    type ResolverSpec,
    type Row,
    type Transport,
  } from "./model";

  let defaults = $state<Defaults | null>(null);
  let customs = $state<Custom[]>([]);
  /** Selected resolver ids (provider ids, "system-<ip>", custom ids). */
  let picked = $state<Record<string, boolean>>({});
  let transports = $state<Record<Transport, boolean>>({ udp: true, tcp: false, dot: true, doh: true });
  let ipv6 = $state(false);
  let rounds = $state(10);
  let checks = $state(true);

  let running = $state(false);
  let runId = 0;
  let progress = $state({ done: 0, total: 0 });
  let rows = $state<Row[]>([]);
  let checkResults = $state<Record<string, Check>>({});
  let finished = $state<{ elapsedMs: number; cancelled: boolean } | null>(null);
  let error = $state("");
  let lastRun = $state<{ transports: Transport[]; rounds: number }>({ transports: [], rounds: 0 });

  type SortKey = "cached" | "uncached" | "name";
  let sortKey = $state<SortKey>("cached");
  let selected = $state<string | null>(null);
  let copied = $state("");
  let form = $state<Custom | null>(null);

  onMount(async () => {
    try {
      defaults = await invoke<Defaults>("dns_bench_defaults");
      for (const p of defaults.providers) picked[p.id] = ["cloudflare", "google", "quad9", "opendns"].includes(p.id);
      for (const ip of defaults.system) picked[`system-${ip}`] = true;
    } catch (e) {
      error = String(e);
    }
    try {
      customs = (await loadCollection<Custom>("dns_resolvers")).items;
      for (const c of customs) picked[c.id] ??= true;
    } catch (e) {
      error = String(e);
    }
  });

  /** Resolvers to send, with display info. */
  function specs(): ResolverSpec[] {
    const out: ResolverSpec[] = [];
    for (const ip of defaults?.system ?? []) {
      const id = `system-${ip}`;
      if (picked[id]) out.push({ id, name: "This computer", ip, doh: "", dot: "" });
    }
    for (const p of defaults?.providers ?? []) {
      if (!picked[p.id]) continue;
      out.push({ id: `${p.id}-v4`, name: p.name, ip: p.ipv4[0], doh: p.doh, dot: p.dot });
      if (ipv6 && p.ipv6[0]) out.push({ id: `${p.id}-v6`, name: p.name, ip: p.ipv6[0], doh: p.doh, dot: p.dot });
    }
    for (const c of customs) {
      if (picked[c.id]) out.push({ id: c.id, name: c.name || c.ip, ip: c.ip, doh: c.doh, dot: c.dot });
    }
    return out;
  }

  const count = $derived(specs().length);

  async function start() {
    error = "";
    const list = specs();
    const ts = TRANSPORTS.map((t) => t.id).filter((t) => transports[t]);
    if (!list.length) return void (error = "Pick at least one resolver.");
    if (!ts.length) return void (error = "Pick at least one transport.");
    const n = Math.round(Number(rounds));
    if (!Number.isFinite(n) || n < 1 || n > 50) return void (error = "Rounds must be 1 to 50.");
    const byId = new Map(list.map((s) => [s.id, s]));
    rows = [];
    checkResults = {};
    finished = null;
    selected = null;
    progress = { done: 0, total: 0 };
    lastRun = { transports: ts, rounds: n };
    running = true;
    runId += 1;
    const channel = new Channel<BenchEvent>();
    channel.onmessage = (e) => {
      switch (e.type) {
        case "started":
          progress = { done: 0, total: e.total };
          break;
        case "progress":
          progress = { done: e.done, total: e.total };
          break;
        case "result": {
          const s = byId.get(e.resolverId);
          rows.push({
            resolverId: e.resolverId,
            name: s?.name ?? e.resolverId,
            ip: s?.ip ?? "",
            transport: e.transport,
            connectMs: e.connectMs,
            cached: e.cached,
            uncached: e.uncached,
            error: e.error,
          });
          break;
        }
        case "check":
          checkResults[e.resolverId] = { dnssec: e.dnssec, hijack: e.hijack };
          break;
        case "done":
          finished = { elapsedMs: e.elapsedMs, cancelled: e.cancelled };
          break;
        case "error":
          error = e.message;
          break;
      }
    };
    try {
      await invoke("dns_bench_run", { runId, config: { resolvers: list, transports: ts, rounds: n, checks }, onEvent: channel });
    } catch (e) {
      error = String(e);
    } finally {
      running = false;
    }
  }

  async function cancel() {
    await invoke("dns_bench_cancel", { runId });
  }

  const sorted = $derived.by(() => {
    const key = (r: Row) => (sortKey === "cached" ? r.cached.medianMs : r.uncached.medianMs) ?? Infinity;
    return [...rows].sort((a, b) =>
      sortKey === "name" ? a.name.localeCompare(b.name) || a.transport.localeCompare(b.transport) : key(a) - key(b),
    );
  });

  /** Fastest cached median per transport, for highlighting. */
  const best = $derived.by(() => {
    const out: Partial<Record<Transport, number>> = {};
    for (const r of rows) {
      const v = r.cached.medianMs;
      if (v !== null && r.cached.lossPct < 50 && (out[r.transport] === undefined || v < out[r.transport]!)) out[r.transport] = v;
    }
    return out;
  });

  /** Addresses for the apply commands: both of a provider's, or the one tested. */
  function applyIps(resolverId: string): string[] {
    const p = defaults?.providers.find((x) => resolverId === `${x.id}-v4` || resolverId === `${x.id}-v6`);
    if (p) return resolverId.endsWith("-v6") ? p.ipv6 : p.ipv4;
    const r = rows.find((x) => x.resolverId === resolverId);
    return r ? [r.ip] : [];
  }

  const os = $derived(settings.detected?.os ?? "");

  async function copy(text: string) {
    try {
      await navigator.clipboard.writeText(text);
      copied = text;
      setTimeout(() => (copied = ""), 1500);
    } catch {
      copied = "";
    }
  }

  async function saveCustom() {
    if (!form) return;
    const c = { ...form, name: form.name.trim(), ip: form.ip.trim(), doh: form.doh.trim(), dot: form.dot.trim() };
    if (!c.ip) return void (error = "IP address is required.");
    if (c.doh && !/^https:\/\/[^/\s]+/.test(c.doh)) return void (error = "DoH URL must start with https://");
    const i = customs.findIndex((x) => x.id === c.id);
    if (i >= 0) customs[i] = c;
    else customs.push(c);
    picked[c.id] = true;
    form = null;
    error = "";
    try {
      await saveCollection("dns_resolvers", customs);
    } catch (e) {
      error = String(e);
    }
  }

  async function removeCustom(c: Custom) {
    if (!(await confirm(`Delete "${c.name || c.ip}"?`, { title: "Delete resolver", kind: "warning" }))) return;
    customs = customs.filter((x) => x.id !== c.id);
    delete picked[c.id];
    try {
      await saveCollection("dns_resolvers", customs);
    } catch (e) {
      error = String(e);
    }
  }

  const pct = $derived(progress.total ? Math.min(100, Math.round((100 * progress.done) / progress.total)) : 0);
</script>

<div class="panel">
  <header>
    <h1>DNS Benchmark</h1>
    <p class="sub">
      Compare resolvers over UDP, TCP, DNS over TLS and DNS over HTTPS. Measures cached and uncached lookups, and checks
      DNSSEC validation and NXDOMAIN hijacking. Queries go to the resolvers you pick, only when you click Run.
    </p>
  </header>

  <div class="config">
    <section class="card">
      <h2>Resolvers <span class="muted">({count} selected)</span></h2>
      {#if !defaults}
        <p class="hint">Loading...</p>
      {:else}
        {#if defaults.system.length}
          <div class="group-label">This computer</div>
          {#each defaults.system as ip (ip)}
            <label class="res"><input type="checkbox" bind:checked={picked[`system-${ip}`]} /> <span class="mono">{ip}</span></label>
          {/each}
        {/if}
        <div class="group-label">Public</div>
        {#each defaults.providers as p (p.id)}
          <label class="res" title={[p.ipv4.join(", "), p.doh, p.dot].filter(Boolean).join("\n")}>
            <input type="checkbox" bind:checked={picked[p.id]} />
            <span>{p.name} <span class="mono muted">{p.ipv4[0]}</span></span>
            <span class="note">{p.note}{!p.dot ? "; no DoT" : ""}</span>
          </label>
        {/each}
        <div class="group-label">
          Custom
          <button class="small" onclick={() => { error = ""; form = { id: crypto.randomUUID(), name: "", ip: "", doh: "", dot: "" }; }}>+ Resolver</button>
        </div>
        {#each customs as c (c.id)}
          <div class="res">
            <input type="checkbox" bind:checked={picked[c.id]} aria-label={c.name || c.ip} />
            <span>{c.name || c.ip} <span class="mono muted">{c.ip}</span></span>
            <span class="acts">
              <button class="icon" title="Edit" onclick={() => { error = ""; form = { ...c }; }}>e</button>
              <button class="icon" title="Delete" onclick={() => removeCustom(c)}>x</button>
            </span>
          </div>
        {:else}
          <p class="hint">None. Add an internal resolver, a firewall or an ISP resolver.</p>
        {/each}
      {/if}
    </section>

    <section class="card">
      <h2>Options</h2>
      <div class="opts">
        {#each TRANSPORTS as t (t.id)}
          <label title={t.hint}><input type="checkbox" bind:checked={transports[t.id]} /> {t.label}</label>
        {/each}
      </div>
      <label class="opt"><input type="checkbox" bind:checked={ipv6} /> Also test public resolvers over IPv6</label>
      <label class="opt"><input type="checkbox" bind:checked={checks} /> DNSSEC and NXDOMAIN checks</label>
      <label class="opt">Rounds <input class="num mono" type="number" min="1" max="50" bind:value={rounds} use:selectOnFocus /></label>
      <p class="hint">
        Each round sends one cached and one uncached query per resolver and transport. DoT and DoH reuse one connection;
        its setup time shows as Connect.
      </p>
      <div class="run">
        {#if running}
          <button class="primary" onclick={cancel}>Cancel</button>
          <div class="bar"><div style="width: {pct}%"></div></div>
          <span class="muted">{pct}%</span>
        {:else}
          <button class="primary" onclick={start} disabled={!defaults}>Run</button>
          {#if finished}
            <span class="muted">{finished.cancelled ? "Cancelled" : "Done"} in {(finished.elapsedMs / 1000).toFixed(1)} s</span>
          {/if}
        {/if}
        <span class="spacer"></span>
        <ExportMenu
          name="dns-benchmark"
          disabled={!rows.length}
          build={() =>
            rows.length
              ? buildReport(sorted, checkResults, { ...lastRun, elapsedMs: finished?.elapsedMs ?? null, cancelled: finished?.cancelled ?? false })
              : null}
        />
      </div>
    </section>
  </div>

  {#if error}<div class="error mono">{error}</div>{/if}

  {#if rows.length}
    <div class="table-head">
      <h2>Results</h2>
      <span class="spacer"></span>
      <label class="muted">Sort by
        <select bind:value={sortKey}>
          <option value="cached">Cached median</option>
          <option value="uncached">Uncached median</option>
          <option value="name">Name</option>
        </select>
      </label>
    </div>
    <div class="scroll">
      <table>
        <thead>
          <tr>
            <th>Resolver</th>
            <th>Transport</th>
            <th class="n" title="Popular names, median / 90th percentile">Cached ms</th>
            <th class="n" title="Random names that force a lookup, median / 90th percentile">Uncached ms</th>
            <th class="n">Loss</th>
            <th class="n" title="TCP or TLS handshake; for DoH the first request">Connect ms</th>
            <th>DNSSEC</th>
            <th>NXDOMAIN</th>
          </tr>
        </thead>
        <tbody>
          {#each sorted as r (r.resolverId + r.transport)}
            {@const c = checkResults[r.resolverId]}
            {@const loss = Math.max(r.cached.lossPct, r.uncached.lossPct)}
            <tr class:sel={selected === r.resolverId} onclick={() => (selected = selected === r.resolverId || r.resolverId.startsWith("system-") ? null : r.resolverId)}>
              <td>
                {r.name} <span class="mono muted">{r.ip}</span>
                {#if r.error}<div class="err-text mono">{r.error}</div>{/if}
              </td>
              <td>{TRANSPORT_LABEL[r.transport]}</td>
              <td class="n mono" class:best={r.cached.medianMs !== null && r.cached.medianMs === best[r.transport]}>
                {ms(r.cached.medianMs)} <span class="muted">/ {ms(r.cached.p90Ms)}</span>
              </td>
              <td class="n mono">{ms(r.uncached.medianMs)} <span class="muted">/ {ms(r.uncached.p90Ms)}</span></td>
              <td class="n mono" class:warn={loss > 0}>{loss}%</td>
              <td class="n mono">{ms(r.connectMs)}</td>
              <td class:ok={c?.dnssec === "validating"} class:warn={c?.dnssec === "notValidating"}>{c ? DNSSEC_LABEL[c.dnssec] : "-"}</td>
              <td class:ok={c?.hijack === false} class:bad={c?.hijack === true}>
                {c ? (c.hijack === true ? "Hijacked" : c.hijack === false ? "Correct" : "Unknown") : "-"}
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
    <p class="hint">Click a public or custom resolver for commands that switch this computer to it. The fastest cached median per transport is highlighted.</p>

    {#if selected}
      {@const ips = applyIps(selected)}
      {@const blocks = applyCommands(ips)}
      <section class="card apply">
        <div class="table-head">
          <h2>Use {rows.find((x) => x.resolverId === selected)?.name} on this computer</h2>
          <span class="spacer"></span>
          <button class="icon" title="Close" onclick={() => (selected = null)}>x</button>
        </div>
        <p class="hint">
          Net3PO does not change system settings. Run these yourself; they need admin rights. Replace the value in angle
          brackets. VPN clients and device management can override DNS; check with Network Snapshot afterwards.
        </p>
        {#each [...blocks].sort((a, b) => Number(b.os === os) - Number(a.os === os)) as b (b.os)}
          <details open={b.os === os || !os}>
            <summary>{b.label}{b.os === os ? " (this computer)" : ""}</summary>
            {#each b.lines as l (l.title)}
              <div class="cmd">
                <span class="label">{l.title}</span>
                <code class="mono">{l.cmd}</code>
                <button class="small" onclick={() => copy(l.cmd)}>{copied === l.cmd ? "Copied" : "Copy"}</button>
              </div>
            {/each}
          </details>
        {/each}
      </section>
    {/if}
  {/if}
</div>

{#if form}
  <div class="overlay" role="presentation" onclick={(e) => e.target === e.currentTarget && (form = null)}>
    <div class="dialog" role="dialog" aria-modal="true" aria-label="Resolver">
      <h2>{customs.some((c) => c.id === form?.id) ? "Edit resolver" : "New resolver"}</h2>
      <label>Name <input bind:value={form.name} placeholder="Branch firewall" /></label>
      <label>IP address <input class="mono" bind:value={form.ip} placeholder="192.0.2.53 or 2001:db8::53" spellcheck="false" autocapitalize="off" /></label>
      <label>DoH URL <input class="mono" bind:value={form.doh} placeholder="https://dns.example.net/dns-query (optional)" spellcheck="false" autocapitalize="off" /></label>
      <label>DoT host name <input class="mono" bind:value={form.dot} placeholder="dns.example.net (optional)" spellcheck="false" autocapitalize="off" /></label>
      <p class="hint">DoH and DoT connect to the IP address above and check the certificate against the host name.</p>
      <div class="actions">
        <button class="small" onclick={() => (form = null)}>Cancel</button>
        <button class="primary" onclick={saveCustom}>Save</button>
      </div>
    </div>
  </div>
{/if}

<style>
  .panel {
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
    max-width: 60rem;
  }

  h2 {
    font-size: 0.95rem;
    margin: 0 0 0.5rem;
  }

  .config {
    display: grid;
    grid-template-columns: minmax(18rem, 1.2fr) minmax(16rem, 1fr);
    gap: 0.9rem;
    align-items: start;
  }

  @media (max-width: 900px) {
    .config {
      grid-template-columns: 1fr;
    }
  }

  .card {
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 0.8rem 1rem;
    background: var(--sidebar-bg);
  }

  .group-label {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    font-size: 0.72rem;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    color: var(--muted);
    margin: 0.6rem 0 0.25rem;
  }

  .res {
    display: flex;
    align-items: baseline;
    gap: 0.45rem;
    font-size: 0.84rem;
    padding: 0.12rem 0;
    cursor: pointer;
  }

  .res .note {
    margin-left: auto;
    color: var(--muted);
    font-size: 0.74rem;
    text-align: right;
  }

  .res .acts {
    margin-left: auto;
    display: flex;
    gap: 0.25rem;
  }

  .opts {
    display: flex;
    flex-wrap: wrap;
    gap: 0.4rem 1rem;
    font-size: 0.85rem;
    margin-bottom: 0.5rem;
  }

  .opt {
    display: flex;
    align-items: center;
    gap: 0.45rem;
    font-size: 0.84rem;
    margin: 0.3rem 0;
  }

  .num {
    width: 4.5rem;
  }

  .run {
    display: flex;
    align-items: center;
    gap: 0.6rem;
    margin-top: 0.6rem;
    font-size: 0.82rem;
  }

  .bar {
    flex: 1;
    max-width: 12rem;
    height: 6px;
    border-radius: 3px;
    background: var(--input-bg);
    border: 1px solid var(--border);
    overflow: hidden;
  }

  .bar div {
    height: 100%;
    background: var(--accent);
    transition: width 0.2s;
  }

  .spacer {
    flex: 1;
  }

  .muted {
    color: var(--muted);
  }

  .hint {
    color: var(--muted);
    font-size: 0.78rem;
    margin: 0.4rem 0;
  }

  .mono,
  code {
    font-family: var(--mono);
  }

  .table-head {
    display: flex;
    align-items: center;
    gap: 0.6rem;
    margin-top: 1.2rem;
    font-size: 0.82rem;
  }

  .table-head h2 {
    margin: 0;
  }

  .apply .table-head {
    margin-top: 0;
  }

  .scroll {
    overflow-x: auto;
    margin-top: 0.5rem;
  }

  table {
    border-collapse: collapse;
    width: 100%;
    font-size: 0.82rem;
  }

  th,
  td {
    text-align: left;
    padding: 0.35rem 0.6rem;
    border-bottom: 1px solid var(--border);
    vertical-align: top;
  }

  th {
    color: var(--muted);
    font-weight: 600;
    font-size: 0.76rem;
    white-space: nowrap;
  }

  .n {
    text-align: right;
    white-space: nowrap;
  }

  tbody tr {
    cursor: pointer;
  }

  tbody tr:hover {
    background: var(--hover);
  }

  tr.sel {
    background: var(--hover);
  }

  td.best {
    color: #16a34a;
    font-weight: 600;
  }

  td.ok {
    color: #16a34a;
  }

  td.warn {
    color: #c69026;
  }

  td.bad {
    color: #dc2626;
    font-weight: 600;
  }

  .err-text {
    color: var(--error-fg);
    font-size: 0.74rem;
  }

  .apply {
    margin-top: 1rem;
  }

  details {
    margin-top: 0.5rem;
    font-size: 0.82rem;
  }

  summary {
    cursor: pointer;
    font-weight: 600;
  }

  .cmd {
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    gap: 0.45rem;
    margin: 0.35rem 0 0 0.8rem;
  }

  .cmd .label {
    color: var(--muted);
    font-size: 0.76rem;
    min-width: 13rem;
  }

  .cmd code {
    font-size: 0.76rem;
    background: var(--input-bg);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 0.1rem 0.35rem;
    overflow-wrap: anywhere;
  }

  input:not([type]),
  input.mono,
  select {
    box-sizing: border-box;
    background: var(--input-bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    color: var(--fg);
    font-size: 0.82rem;
    padding: 0.3rem 0.45rem;
  }

  button.small,
  button.icon {
    background: var(--input-bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    color: var(--fg);
    font-size: 0.74rem;
    padding: 0.2rem 0.5rem;
    cursor: pointer;
  }

  button.icon {
    padding: 0.1rem 0.4rem;
  }

  button.primary {
    background: var(--accent);
    border: none;
    border-radius: 6px;
    color: #fff;
    font-size: 0.82rem;
    padding: 0.35rem 1rem;
    cursor: pointer;
  }

  button:disabled {
    opacity: 0.5;
  }

  .error {
    background: var(--error-bg);
    border: 1px solid var(--error-border);
    color: var(--error-fg);
    border-radius: 6px;
    padding: 0.5rem 0.7rem;
    font-size: 0.8rem;
    margin-top: 0.8rem;
    white-space: pre-wrap;
  }

  .overlay {
    position: fixed;
    inset: 0;
    background: rgba(0, 0, 0, 0.45);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 50;
  }

  .dialog {
    background: var(--bg, var(--sidebar-bg));
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 1rem 1.2rem;
    width: min(30rem, 92vw);
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }

  .dialog label {
    display: flex;
    flex-direction: column;
    gap: 0.2rem;
    font-size: 0.78rem;
    color: var(--muted);
  }

  .actions {
    display: flex;
    justify-content: flex-end;
    gap: 0.5rem;
    margin-top: 0.4rem;
  }
</style>
