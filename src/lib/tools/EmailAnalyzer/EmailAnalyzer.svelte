<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import { open } from "@tauri-apps/plugin-dialog";
  import ExportMenu from "$lib/components/ExportMenu.svelte";
  import { openInDnsAnalyzer } from "$lib/nav.svelte";
  import type {
    EmailAnalysis,
    EmailBlocklist,
    EmailBlocklistReport,
    EmailIpOwner,
    EmailSev,
  } from "$lib/tools/types";
  import { buildEmailReport, fmtDelay, fmtUtc, ownerLines, STATUS_LABEL } from "./report";

  let text = $state("");
  let known = $state("");
  let analysis = $state<EmailAnalysis | null>(null);
  let source = $state("");
  let error = $state("");
  let busy = $state(false);

  let blocklists = $state<EmailBlocklist[]>([]);
  let zones = $state<string[]>([]);
  let customZone = $state("");
  let owners = $state<EmailIpOwner[]>([]);
  let lists = $state<EmailBlocklistReport[]>([]);
  let lookupBusy = $state<Record<string, boolean>>({});
  let lookupError = $state("");
  let copied = $state(false);

  const BADGE: Record<EmailSev, string> = { pass: "PASS", info: "INFO", warn: "WARN", fail: "FAIL" };

  $effect(() => {
    invoke<EmailBlocklist[]>("email_blocklists")
      .then((l) => {
        blocklists = l;
        zones = l.map((b) => b.zone);
      })
      .catch(() => {});
  });

  const knownList = $derived(known.split(/[\s,;]+/).filter((k) => k.length > 0));
  const from = $derived(analysis?.addresses.find((a) => a.role === "From") ?? null);
  // Public IPs in the route, newest handoff first, for the lookup buttons.
  const lookupIps = $derived.by(() => {
    if (!analysis) return [] as string[];
    const ips = [...analysis.origin.map((o) => o.ip)];
    for (const h of analysis.hops) if (h.fromIp && !h.nonPublicIp && !ips.includes(h.fromIp)) ips.push(h.fromIp);
    return ips;
  });

  function reset() {
    owners = [];
    lists = [];
    lookupError = "";
  }

  async function analyze() {
    error = "";
    busy = true;
    try {
      analysis = await invoke<EmailAnalysis>("email_analyze", { text, known: knownList });
      source = "Pasted text";
      reset();
    } catch (e) {
      analysis = null;
      error = String(e);
    } finally {
      busy = false;
    }
  }

  async function openFile() {
    error = "";
    const path = await open({
      multiple: false,
      directory: false,
      filters: [{ name: "Email message", extensions: ["eml", "txt"] }],
    });
    if (typeof path !== "string") return;
    busy = true;
    try {
      analysis = await invoke<EmailAnalysis>("email_open", { path, known: knownList });
      source = path.split(/[\\/]/).pop() ?? path;
      text = "";
      reset();
    } catch (e) {
      analysis = null;
      error = String(e);
    } finally {
      busy = false;
    }
  }

  async function ownerLookup(ip: string) {
    lookupError = "";
    lookupBusy = { ...lookupBusy, [`o:${ip}`]: true };
    try {
      const o = await invoke<EmailIpOwner>("email_ip_owner", { ip });
      owners = [...owners.filter((x) => x.ip !== o.ip), o];
    } catch (e) {
      lookupError = String(e);
    } finally {
      lookupBusy = { ...lookupBusy, [`o:${ip}`]: false };
    }
  }

  async function listLookup(ip: string) {
    lookupError = "";
    const chosen = [...zones];
    if (customZone.trim()) chosen.push(customZone.trim());
    lookupBusy = { ...lookupBusy, [`b:${ip}`]: true };
    try {
      const r = await invoke<EmailBlocklistReport>("email_blocklist_check", { ip, zones: chosen });
      lists = [...lists.filter((x) => x.ip !== r.ip), r];
    } catch (e) {
      lookupError = String(e);
    } finally {
      lookupBusy = { ...lookupBusy, [`b:${ip}`]: false };
    }
  }

  function toggleZone(zone: string, on: boolean) {
    zones = on ? [...zones, zone] : zones.filter((z) => z !== zone);
  }

  async function copyIocs() {
    if (!analysis) return;
    await navigator.clipboard.writeText(analysis.iocs.map((i) => i.defanged).join("\n"));
    copied = true;
    setTimeout(() => (copied = false), 1500);
  }

  function clearAll() {
    text = "";
    analysis = null;
    error = "";
    reset();
  }
</script>

<div class="panel">
  <header>
    <h1>Email Header Analyzer</h1>
    <p class="sub">
      Paste a message's headers or open a .eml file. Parsing is local and nothing in the
      message is rendered or opened. Lookups of IP owners and blocklists run only when you
      click them.
    </p>
  </header>

  <textarea
    class="input mono"
    bind:value={text}
    spellcheck="false"
    placeholder="Paste the full header block here, starting at the first Received: or Return-Path: line"
  ></textarea>
  <div class="row">
    <div class="field grow">
      <label for="em-known">Customer's genuine domains (optional, for the lookalike check)</label>
      <input id="em-known" class="mono" bind:value={known} spellcheck="false" placeholder="example.com, example.net" />
    </div>
  </div>
  <div class="row">
    <button class="action" onclick={analyze} disabled={busy || text.trim() === ""}>{busy ? "Analyzing..." : "Analyze"}</button>
    <button class="secondary" onclick={openFile} disabled={busy}>Open .eml...</button>
    {#if text || analysis}<button class="secondary" onclick={clearAll}>Clear</button>{/if}
    {#if analysis}
      <span class="muted small">{source}: {analysis.inputKind === "message" ? "full message" : "headers only"}</span>
      <div class="spacer"></div>
      <ExportMenu build={() => (analysis ? buildEmailReport(analysis, owners, lists) : null)} name={`email-${from?.domain ?? "analysis"}`} />
    {/if}
  </div>

  {#if error}<div class="error mono">{error}</div>{/if}

  {#if analysis}
    <section>
      <h2>Summary</h2>
      <table class="kv">
        <tbody>
          <tr><th>Subject</th><td>{analysis.subject || "(none)"}</td></tr>
          <tr><th>Date</th><td>{analysis.date || "(none)"}{analysis.dateTs !== null ? ` (${fmtUtc(analysis.dateTs)})` : ""}</td></tr>
          {#each analysis.addresses.filter((a) => a.role !== "To" && a.role !== "Cc") as a, i (i)}
            <tr><th>{a.role}</th><td class="mono">{a.name ? `"${a.name}" ` : ""}{a.address}</td></tr>
          {/each}
          {#if analysis.addresses.some((a) => a.role === "To" || a.role === "Cc")}
            <tr>
              <th>Recipients</th>
              <td class="mono">{analysis.addresses.filter((a) => a.role === "To" || a.role === "Cc").map((a) => a.address).join(", ")}</td>
            </tr>
          {/if}
          <tr><th>Message-ID</th><td class="mono">{analysis.messageId || "(none)"}</td></tr>
        </tbody>
      </table>
    </section>

    <section>
      <h2>Findings</h2>
      {#each analysis.findings as f, i (i)}
        <div class="finding {f.severity}">
          <span class="badge">{BADGE[f.severity]}</span>
          <span class="cat">{f.category}</span>
          <strong>{f.title}</strong>
          {#if f.detail}<div class="detail">{f.detail}</div>{/if}
        </div>
      {/each}
    </section>

    <section>
      <h2>Sending server</h2>
      {#if analysis.origin.length === 0}
        <p class="muted small">No public sending address in the Received chain.</p>
      {/if}
      {#each analysis.origin as o (o.ip)}
        <div class="origin">
          <div>
            <span class="tag">{o.basis === "handoff" ? "Most reliable" : "Earliest, forgeable"}</span>
            <strong class="mono">{o.ip}</strong>
            {#if o.host}<span class="mono muted">{o.host}</span>{/if}
            <span class="muted small">hop {o.hop}</span>
          </div>
          <div class="small muted">{o.explanation}</div>
        </div>
      {/each}

      {#if lookupIps.length > 0}
        <div class="checks">
          <div class="checks-head">
            <strong class="small">Online checks</strong>
            <span class="muted small">Run only when you click. Owner lookups use DNS plus one HTTPS request to the regional internet registry (RDAP); blocklist checks use DNS.</span>
          </div>
          <div class="zones">
            {#each blocklists as b (b.zone)}
              <label class="zone" title={b.note}>
                <input type="checkbox" checked={zones.includes(b.zone)} onchange={(e) => toggleZone(b.zone, e.currentTarget.checked)} />
                {b.name}
              </label>
            {/each}
            <input class="mono custom" bind:value={customZone} spellcheck="false" placeholder="other list zone" />
          </div>
          {#each lookupIps as ip (ip)}
            <div class="iprow">
              <span class="mono">{ip}</span>
              <button class="mini" onclick={() => ownerLookup(ip)} disabled={lookupBusy[`o:${ip}`]}>
                {lookupBusy[`o:${ip}`] ? "Looking up..." : "Who owns this IP"}
              </button>
              <button class="mini" onclick={() => listLookup(ip)} disabled={lookupBusy[`b:${ip}`] || ip.includes(":")}>
                {lookupBusy[`b:${ip}`] ? "Checking..." : "Check blocklists"}
              </button>
            </div>
          {/each}
          {#if lookupError}<div class="error small">{lookupError}</div>{/if}
          {#each owners as o (o.ip)}
            <div class="result">
              <div class="result-head">IP owner: <span class="mono">{o.ip}</span></div>
              <table class="kv small">
                <tbody>
                  {#each ownerLines(o) as r (r.key)}<tr><th>{r.key}</th><td>{r.value}</td></tr>{/each}
                </tbody>
              </table>
              {#if o.errors.length}<div class="small warnc">{o.errors.join("; ")}</div>{/if}
              <div class="small muted">
                ASN and prefix show who routes the address today; RDAP shows who it is registered
                to. They can differ (cloud, hosting and leased ranges). Report abuse to the RDAP
                abuse contact.
              </div>
            </div>
          {/each}
          {#each lists as l (l.ip)}
            <div class="result">
              <div class="result-head">Blocklists: <span class="mono">{l.ip}</span> <span class="muted small">{new Date(l.lookedUpMs).toLocaleTimeString()}</span></div>
              <table class="grid small">
                <tbody>
                  {#each l.results as r (r.zone)}
                    <tr>
                      <td class="mono">{r.zone}</td>
                      <td><span class="st {r.status}">{STATUS_LABEL[r.status]}</span></td>
                      <td>{r.detail}{r.reason ? `: ${r.reason}` : ""}</td>
                    </tr>
                  {/each}
                </tbody>
              </table>
            </div>
          {/each}
        </div>
      {/if}
    </section>

    <section>
      <h2>Route <span class="muted small">oldest first</span></h2>
      {#if analysis.hops.length === 0}<p class="muted small">No Received headers.</p>{/if}
      {#if analysis.hops.length > 0}
        <div class="table-wrap">
          <table class="grid">
            <thead><tr><th>#</th><th>Time (UTC)</th><th>Delay</th><th>From</th><th>By</th><th>With</th></tr></thead>
            <tbody>
              {#each analysis.hops as h (h.index)}
                <tr class:skew={h.delaySecs !== null && h.delaySecs < -60}>
                  <td>{h.index}</td>
                  <td class="mono small">{fmtUtc(h.timestamp) || h.date}</td>
                  <td class="mono small">{fmtDelay(h.delaySecs)}</td>
                  <td class="mono small">
                    {h.fromHost || (h.parsed ? "" : "(unparsed)")}
                    {#if h.fromIp}<div class:muted={h.nonPublicIp}>{h.fromIp}{h.nonPublicIp ? " private" : ""}</div>{/if}
                    {#if h.fromRdns && h.fromRdns !== h.fromHost}<div class="muted">rDNS {h.fromRdns}</div>{/if}
                    {#if h.helo && h.helo !== h.fromHost}<div class="muted">helo {h.helo}</div>{/if}
                  </td>
                  <td class="mono small">{h.byHost}</td>
                  <td class="mono small">{h.protocol}{h.tls ? ` ${h.tls}` : ""}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
        <details>
          <summary class="small muted">Received lines as written</summary>
          <pre class="raw">{analysis.hops.map((h) => `${h.index}: ${h.raw}`).join("\n\n")}</pre>
        </details>
      {/if}
    </section>

    <section>
      <h2>Authentication claimed in the header</h2>
      <p class="small muted">
        Written by mail systems along the route and copied here as found. Trust only results
        from your own receiving system; Net3PO has not verified them.
      </p>
      {#each analysis.authResults as r, i (i)}
        <div class="claim">
          <div class="small"><strong>{r.authservId || "Receiving system (not named; Microsoft 365 omits it)"}</strong> <span class="muted">{r.header}{r.instance ? ` i=${r.instance}` : ""}</span></div>
          {#each r.methods as m, j (j)}
            <div class="method">
              <span class="mono">{m.method}</span>
              <span class="res {m.result}">{m.result}</span>
              <span class="mono muted small">{m.props.map(([k, v]) => `${k}=${v}`).join("  ")}</span>
            </div>
          {/each}
        </div>
      {/each}
      {#each analysis.receivedSpf as s, i (i)}
        <div class="claim small mono">Received-SPF: {s}</div>
      {/each}
      {#if analysis.authResults.length === 0 && analysis.receivedSpf.length === 0}
        <p class="muted small">None present.</p>
      {/if}
      {#if analysis.arcSets > 0}<p class="small muted">{analysis.arcSets} ARC set{analysis.arcSets === 1 ? "" : "s"} present (forwarded or relayed mail).</p>{/if}
    </section>

    <section>
      <h2>DKIM signatures</h2>
      {#if analysis.dkim.length === 0}<p class="muted small">No DKIM-Signature header.</p>{/if}
      {#each analysis.dkim as d, i (i)}
        <div class="dkim">
          <div class="dkim-head">
            <span class="mono"><strong>{d.domain || "(no d=)"}</strong> s={d.selector || "?"}</span>
            <span class="tag" class:ok={d.alignment !== "none"} class:warnt={d.alignment === "none"}>
              {d.alignment === "none" ? "not aligned with From" : `${d.alignment} alignment`}
            </span>
            <span class="muted small">{d.algorithm} {d.canonicalization}</span>
            <div class="spacer"></div>
            {#if d.domain && d.selector}
              <button class="mini primary" onclick={() => openInDnsAnalyzer(d.domain, [d.selector])}>Check in DNS Analyzer</button>
            {/if}
          </div>
          {#if d.keyName}<div class="small mono muted">Key record: {d.keyName} (TXT)</div>{/if}
          <div class="small muted">Signed headers: {d.signedHeaders.join(", ") || "(none)"}</div>
          {#each d.notes as n (n)}<div class="small warnc">{n}</div>{/each}
        </div>
      {/each}
      {#if analysis.dkim.length > 0}
        <p class="small muted">
          A header alone cannot prove a signature is valid: that needs the original message bytes
          and the public key. The DNS Analyzer checks that the key exists, its size, and whether it
          is revoked.
        </p>
      {/if}
    </section>

    {#if analysis.domains.length > 0}
      <section>
        <h2>Domains</h2>
        <table class="grid small">
          <tbody>
            {#each analysis.domains as d (d.domain)}
              <tr>
                <td class="mono">{d.domain}{d.unicode ? ` (displays as ${d.unicode})` : ""}</td>
                <td class="muted">{d.roles.join(", ")}</td>
                <td><button class="mini" onclick={() => openInDnsAnalyzer(d.domain, [])}>DNS Analyzer</button></td>
              </tr>
            {/each}
          </tbody>
        </table>
        {#if analysis.lookalikes.length > 0}
          <h3>Lookalikes</h3>
          {#each analysis.lookalikes as l, i (i)}
            <div class="small look">
              <span class="mono"><strong>{l.domain}</strong></span> resembles <span class="mono">{l.resembles}</span>
              <span class="muted">({l.against === "brand" ? "common brand" : l.against === "known" ? "your list" : "in this message"})</span>:
              {l.reason}
            </div>
          {/each}
        {/if}
      </section>
    {/if}

    {#if analysis.attachments.length > 0 || analysis.inputKind === "message"}
      <section>
        <h2>Body and attachments</h2>
        <p class="small muted">
          {analysis.textParts} text part{analysis.textParts === 1 ? "" : "s"}, {analysis.htmlParts} HTML part{analysis.htmlParts === 1 ? "" : "s"}.
          The body is never rendered and remote images are never loaded.
        </p>
        {#if analysis.attachments.length > 0}
          <table class="grid small">
            <thead><tr><th>Name</th><th>Type</th><th>Size</th><th></th></tr></thead>
            <tbody>
              {#each analysis.attachments as a, i (i)}
                <tr class:skew={a.risky}>
                  <td class="mono">{a.name || "(unnamed)"}</td>
                  <td class="mono">{a.contentType}</td>
                  <td>{a.size.toLocaleString()} bytes</td>
                  <td>{a.risky ? "risky type" : ""}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        {/if}
      </section>
    {/if}

    {#if analysis.iocs.length > 0}
      <section>
        <div class="sechead">
          <h2>Indicators</h2>
          <button class="mini" onclick={copyIocs}>{copied ? "Copied" : "Copy defanged"}</button>
        </div>
        <table class="grid small">
          <tbody>
            {#each analysis.iocs as i, n (n)}
              <tr>
                <td class="muted">{i.kind}</td>
                <td class="mono">{i.defanged}</td>
                <td class="muted">{i.layer === 0 ? "headers" : "body"}{i.private ? ", private" : ""}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </section>
    {/if}

    {#if analysis.notableHeaders.length > 0}
      <section>
        <h2>Notable headers</h2>
        <table class="kv small">
          <tbody>
            {#each analysis.notableHeaders as [k, v], i (i)}<tr><th>{k}</th><td class="mono">{v}</td></tr>{/each}
          </tbody>
        </table>
      </section>
    {/if}

    <details>
      <summary class="small muted">All {analysis.headers.length} header fields</summary>
      <table class="kv small">
        <tbody>
          {#each analysis.headers as [k, v], i (i)}<tr><th>{k}</th><td class="mono">{v}</td></tr>{/each}
        </tbody>
      </table>
    </details>
  {/if}
</div>

<style>
  .panel {
    --st-ok: #2ea043;
    --st-bad: #d1453b;
    --st-warn: #c69026;
    --st-info: #3b82f6;
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

  h2 {
    font-size: 0.95rem;
    font-weight: 600;
    margin: 1.3rem 0 0.5rem;
  }

  h3 {
    font-size: 0.85rem;
    margin: 0.8rem 0 0.3rem;
  }

  .input {
    width: 100%;
    min-height: 10rem;
    box-sizing: border-box;
    resize: vertical;
    background: var(--input-bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.55rem;
    color: var(--fg);
    font-size: 0.8rem;
  }

  .row {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 0.6rem;
    margin: 0.6rem 0;
  }

  .field {
    display: flex;
    flex-direction: column;
  }

  .field.grow {
    flex: 1 1 280px;
  }

  label {
    font-size: 0.78rem;
    color: var(--muted);
    margin-bottom: 0.3rem;
  }

  input:not([type="checkbox"]) {
    background: var(--input-bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.4rem 0.55rem;
    color: var(--fg);
    font-size: 0.85rem;
  }

  input:focus,
  textarea:focus {
    outline: none;
    border-color: var(--accent);
  }

  .spacer {
    flex: 1 1 auto;
  }

  .mono {
    font-family: var(--mono);
  }

  .muted {
    color: var(--muted);
  }

  .small {
    font-size: 0.76rem;
  }

  .action {
    background: var(--accent);
    border: 1px solid var(--accent);
    border-radius: 6px;
    padding: 0.5rem 1.3rem;
    color: var(--accent-fg);
    font-weight: 600;
    font-size: 0.85rem;
    cursor: pointer;
  }

  .action:disabled {
    opacity: 0.5;
    cursor: default;
  }

  .secondary,
  .mini {
    background: var(--btn-bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    color: var(--fg);
    cursor: pointer;
  }

  .secondary {
    padding: 0.5rem 1rem;
    font-size: 0.85rem;
  }

  .mini {
    padding: 0.15rem 0.55rem;
    font-size: 0.74rem;
  }

  .mini.primary {
    border-color: var(--accent);
    color: var(--accent);
  }

  .mini:disabled {
    opacity: 0.5;
    cursor: default;
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

  table {
    border-collapse: collapse;
    width: 100%;
    font-size: 0.8rem;
  }

  table.kv th {
    text-align: left;
    color: var(--muted);
    font-weight: 500;
    width: 11rem;
    padding: 0.25rem 0.6rem 0.25rem 0;
    vertical-align: top;
  }

  table.kv td,
  table.grid td {
    padding: 0.25rem 0.5rem;
    vertical-align: top;
    word-break: break-word;
  }

  table.grid th {
    text-align: left;
    color: var(--muted);
    font-weight: 500;
    padding: 0.35rem 0.5rem;
    border-bottom: 1px solid var(--border);
    background: var(--sidebar-bg);
  }

  table.grid td {
    border-bottom: 1px solid var(--border);
  }

  .table-wrap {
    border: 1px solid var(--border);
    border-radius: 6px;
    overflow: clip;
  }

  tr.skew td {
    background: color-mix(in srgb, var(--st-warn) 10%, transparent);
  }

  .finding {
    border: 1px solid var(--border);
    border-left-width: 4px;
    border-radius: 6px;
    padding: 0.45rem 0.7rem;
    margin-bottom: 0.4rem;
    font-size: 0.82rem;
  }

  .finding .badge {
    display: inline-block;
    font-size: 0.66rem;
    font-weight: 700;
    padding: 0 0.35rem;
    border-radius: 3px;
    margin-right: 0.4rem;
    color: #fff;
  }

  .finding .cat {
    color: var(--muted);
    font-size: 0.74rem;
    margin-right: 0.35rem;
  }

  .finding .detail {
    color: var(--muted);
    margin-top: 0.2rem;
  }

  .finding.pass {
    border-left-color: var(--st-ok);
  }
  .finding.pass .badge {
    background: var(--st-ok);
  }
  .finding.info {
    border-left-color: var(--st-info);
  }
  .finding.info .badge {
    background: var(--st-info);
  }
  .finding.warn {
    border-left-color: var(--st-warn);
  }
  .finding.warn .badge {
    background: var(--st-warn);
  }
  .finding.fail {
    border-left-color: var(--st-bad);
  }
  .finding.fail .badge {
    background: var(--st-bad);
  }

  .origin,
  .claim,
  .dkim,
  .result {
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.5rem 0.7rem;
    margin-bottom: 0.45rem;
  }

  .origin > div:first-child,
  .dkim-head,
  .iprow,
  .checks-head,
  .sechead {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 0.5rem;
  }

  .tag {
    display: inline-block;
    border: 1px solid var(--border);
    border-radius: 3px;
    padding: 0 0.35rem;
    font-size: 0.7rem;
    color: var(--muted);
  }

  .tag.ok {
    color: var(--st-ok);
    border-color: var(--st-ok);
  }

  .tag.warnt {
    color: var(--st-warn);
    border-color: var(--st-warn);
  }

  .warnc {
    color: var(--st-warn);
  }

  .checks {
    border: 1px dashed var(--border);
    border-radius: 6px;
    padding: 0.6rem 0.7rem;
    margin-top: 0.5rem;
    display: flex;
    flex-direction: column;
    gap: 0.45rem;
  }

  .zones {
    display: flex;
    flex-wrap: wrap;
    gap: 0.7rem;
    align-items: center;
  }

  .zone {
    display: flex;
    align-items: center;
    gap: 0.25rem;
    font-size: 0.76rem;
    color: var(--fg);
    margin: 0;
    cursor: help;
  }

  .custom {
    width: 11rem;
    font-size: 0.76rem !important;
    padding: 0.2rem 0.4rem !important;
  }

  .result-head {
    font-size: 0.8rem;
    font-weight: 600;
    margin-bottom: 0.3rem;
  }

  .st {
    font-size: 0.72rem;
    font-weight: 600;
  }

  .st.listed {
    color: var(--st-bad);
  }

  .st.notListed {
    color: var(--st-ok);
  }

  .st.refused,
  .st.error {
    color: var(--st-warn);
  }

  .method {
    display: flex;
    flex-wrap: wrap;
    gap: 0.5rem;
    align-items: baseline;
    margin-top: 0.2rem;
    font-size: 0.8rem;
  }

  .res {
    font-weight: 600;
  }

  .res.pass {
    color: var(--st-ok);
  }

  .res.fail,
  .res.permerror {
    color: var(--st-bad);
  }

  .res.softfail,
  .res.temperror,
  .res.neutral {
    color: var(--st-warn);
  }

  .look {
    margin: 0.2rem 0;
  }

  details {
    margin-top: 0.8rem;
  }

  summary {
    cursor: pointer;
  }

  pre.raw {
    font-family: var(--mono);
    font-size: 0.72rem;
    white-space: pre-wrap;
    word-break: break-word;
    background: var(--sidebar-bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.5rem;
    user-select: text;
  }
</style>
