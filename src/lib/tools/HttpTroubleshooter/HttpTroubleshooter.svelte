<script lang="ts">
  // HTTP/API troubleshooter: build a request, follow redirects hop by hop,
  // see timings, headers, TLS and the body, plus contextual header notes.
  import { invoke } from "@tauri-apps/api/core";
  import ExportMenu from "$lib/components/ExportMenu.svelte";
  import { selectOnFocus } from "$lib/actions/selectOnFocus";
  import { buildHttpReport, sizeText, timingText } from "./report";
  import type { HttpHop, HttpRequest, HttpResult } from "./types";

  const METHODS = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"];

  let url = $state("");
  let method = $state("GET");
  let headers = $state<{ name: string; value: string }[]>([{ name: "", value: "" }]);
  let body = $state("");
  let connectIp = $state("");
  let follow = $state(true);
  let maxRedirects = $state(10);
  let timeoutSecs = $state(15);
  let insecure = $state(false);

  let result = $state<HttpResult | null>(null);
  let selected = $state(0);
  let busy = $state(false);
  let error = $state("");
  let pretty = $state(true);

  const hasBody = $derived(!["GET", "HEAD", "OPTIONS"].includes(method) || body.length > 0);
  const hop = $derived<HttpHop | null>(result ? (result.hops[selected] ?? null) : null);

  function addHeader() {
    headers = [...headers, { name: "", value: "" }];
  }

  function removeHeader(i: number) {
    headers = headers.filter((_, j) => j !== i);
    if (headers.length === 0) headers = [{ name: "", value: "" }];
  }

  async function send() {
    if (!url.trim()) {
      error = "Enter a URL.";
      return;
    }
    busy = true;
    error = "";
    const req: HttpRequest = {
      url: url.trim(),
      method,
      headers: headers.filter((h) => h.name.trim()).map((h) => [h.name.trim(), h.value]),
      body: hasBody ? body : "",
      connectIp: connectIp.trim(),
      followRedirects: follow,
      maxRedirects: Math.max(0, Math.min(20, maxRedirects || 0)),
      insecure,
      timeoutSecs: Math.max(1, Math.min(120, timeoutSecs || 15)),
    };
    try {
      result = await invoke<HttpResult>("http_send", { req });
      selected = result.hops.length - 1;
    } catch (e) {
      result = null;
      error = String(e);
    } finally {
      busy = false;
    }
  }

  function onKey(e: KeyboardEvent) {
    if (e.key === "Enter") void send();
  }

  function statusClass(s: number): string {
    if (s >= 500) return "s5";
    if (s >= 400) return "s4";
    if (s >= 300) return "s3";
    return "s2";
  }

  function shownBody(h: HttpHop): string {
    if (h.bodyText === null) return "";
    if (pretty && h.contentType.includes("json")) {
      try {
        return JSON.stringify(JSON.parse(h.bodyText), null, 2);
      } catch {
        return h.bodyText;
      }
    }
    return h.bodyText;
  }

  /** Bar widths for the timing breakdown, as percentages of the total. */
  function bars(h: HttpHop): { label: string; ms: number; cls: string }[] {
    const t = h.timing;
    return [
      { label: "DNS", ms: t.dnsMs ?? 0, cls: "dns" },
      { label: "Connect", ms: t.connectMs, cls: "tcp" },
      { label: "TLS", ms: t.tlsMs ?? 0, cls: "tls" },
      { label: "First byte", ms: t.firstByteMs, cls: "ttfb" },
    ].filter((b) => b.ms > 0);
  }
</script>

<div class="panel">
  <header>
    <h1>HTTP Troubleshooter</h1>
    <p class="sub">
      Send any request, follow redirects hop by hop, and see timings, TLS, headers and the body.
      HTTP/1.1 only.
    </p>
  </header>

  <div class="reqline">
    <select bind:value={method} aria-label="Method">
      {#each METHODS as m (m)}<option>{m}</option>{/each}
    </select>
    <input class="mono url" bind:value={url} onkeydown={onKey} spellcheck="false" autocapitalize="off" autocomplete="off" placeholder="https://host/path" aria-label="URL" />
    <button class="run" onclick={send} disabled={busy}>{busy ? "Sending..." : "Send"}</button>
  </div>

  <div class="group">Headers</div>
  {#each headers as h, i (i)}
    <div class="hrow">
      <input class="mono" bind:value={h.name} spellcheck="false" placeholder="Name" aria-label="Header name" />
      <input class="mono" bind:value={h.value} spellcheck="false" placeholder="Value" aria-label="Header value" />
      <button class="mini" onclick={() => removeHeader(i)} aria-label="Remove header">×</button>
    </div>
  {/each}
  <button class="link" onclick={addHeader}>+ Add header</button>

  {#if hasBody}
    <div class="group">Body</div>
    <textarea class="mono" rows="5" bind:value={body} spellcheck="false" placeholder="Request body (set Content-Type in the headers)"></textarea>
  {/if}

  <details class="adv">
    <summary>Options</summary>
    <div class="opts">
      <label class="check"><input type="checkbox" bind:checked={follow} /> Follow redirects</label>
      <label class="inline">Max <input class="num mono" type="number" min="0" max="20" bind:value={maxRedirects} use:selectOnFocus disabled={!follow} /></label>
      <label class="inline">Timeout (s) <input class="num mono" type="number" min="1" max="120" bind:value={timeoutSecs} use:selectOnFocus /></label>
      <label class="inline grow">Connect to IP <input class="mono" bind:value={connectIp} spellcheck="false" placeholder="resolve the host" /></label>
      <label class="check danger"><input type="checkbox" bind:checked={insecure} /> Skip certificate validation</label>
    </div>
    <p class="hint">
      Connect to IP sends requests for the URL's host to that address, keeping the Host header and
      SNI. Credentials (Authorization, Cookie) are never forwarded to a different origin on redirect.
    </p>
  </details>

  {#if error}<div class="error mono">{error}</div>{/if}

  {#if result && !busy}
    {#if result.insecure}
      <div class="warnbox">Certificate validation was off. TLS results below are not verified.</div>
    {/if}
    <div class="bar">
      <h2>Requests <span class="muted small">{result.hops.length}</span></h2>
      <ExportMenu build={() => (result ? buildHttpReport(result) : null)} name="http" />
    </div>
    <div class="hops">
      {#each result.hops as h, i (i)}
        <button class="hop" class:active={i === selected} onclick={() => (selected = i)}>
          <span class="st {statusClass(h.status)}">{h.status}</span>
          <span class="mono m">{h.method}</span>
          <span class="mono u" title={h.url}>{h.url}</span>
          <span class="muted small">{h.timing.totalMs} ms</span>
        </button>
      {/each}
    </div>
    {#if result.error}<div class="warnbox">Stopped: {result.error}</div>{/if}

    {#if hop}
      <section>
        <div class="timing">
          {#each bars(hop) as b (b.label)}
            <span class="seg {b.cls}" style="flex: {b.ms} 0 0" title="{b.label} {b.ms} ms"></span>
          {/each}
        </div>
        <div class="muted small">{timingText(hop)} · {hop.address} · {hop.version}{hop.interim.length ? ` · interim ${hop.interim.join(", ")}` : ""}</div>
        {#each hop.notes as n (n)}<div class="note">{n}</div>{/each}
      </section>

      {#if hop.tls}
        <section>
          <h3>TLS</h3>
          <table class="kv">
            <tbody>
              <tr><th>Protocol</th><td>{hop.tls.protocol}, <span class="mono">{hop.tls.cipher}</span>{hop.tls.alpn ? `, ALPN ${hop.tls.alpn}` : ""}</td></tr>
              <tr><th>Validation</th><td class:bad={hop.tls.validation !== "verified"}>{hop.tls.validation}</td></tr>
              <tr><th>Certificate</th><td class="mono">{hop.tls.certSubject}</td></tr>
              <tr><th>Issuer</th><td class="mono">{hop.tls.certIssuer}</td></tr>
              <tr><th>Expires</th><td>{new Date(hop.tls.certNotAfterMs).toISOString().slice(0, 10)}</td></tr>
            </tbody>
          </table>
        </section>
      {/if}

      <section>
        <h3>Response headers <span class="muted small">{hop.status} {hop.reason}</span></h3>
        <table class="kv">
          <tbody>
            {#each hop.headers as [n, v], i (i)}<tr><th class="mono">{n}</th><td class="mono">{v}</td></tr>{/each}
          </tbody>
        </table>
        <details>
          <summary>Request headers sent</summary>
          <table class="kv">
            <tbody>
              {#each hop.requestHeaders as [n, v], i (i)}<tr><th class="mono">{n}</th><td class="mono">{v}</td></tr>{/each}
              {#if hop.requestBodyLen}<tr><th>Body</th><td>{sizeText(hop.requestBodyLen)}</td></tr>{/if}
            </tbody>
          </table>
          <p class="hint">Host, User-Agent, Accept, Accept-Encoding and Connection are added unless you set them. Credential values are masked here.</p>
        </details>
      </section>

      <section>
        <h3>
          Body <span class="muted small">{sizeText(hop.bodyLen)}{hop.contentType ? `, ${hop.contentType}` : ""}{hop.bodyTruncated ? ", first 256 KB shown" : ""}</span>
          {#if hop.contentType.includes("json") && hop.bodyText}
            <label class="check inline-right"><input type="checkbox" bind:checked={pretty} /> Pretty</label>
          {/if}
        </h3>
        {#if hop.bodyText !== null && hop.bodyText.length}
          <pre class="body mono">{shownBody(hop)}</pre>
        {:else if hop.bodyHex}
          <div class="muted small">Binary content, first 512 bytes as hex. Never rendered or run.</div>
          <pre class="body mono">{hop.bodyHex}</pre>
        {:else}
          <div class="muted small">(empty)</div>
        {/if}
      </section>
    {/if}

    {#if result.observations.length}
      <section>
        <h3>Header observations <span class="muted small">final response</span></h3>
        <ul class="obs">
          {#each result.observations as o, i (i)}
            <li class={o.severity}>
              <strong>{o.title}</strong>
              {#if o.detail}<span class="muted"> {o.detail}</span>{/if}
            </li>
          {/each}
        </ul>
        <p class="hint">Context for troubleshooting, not a security rating. They describe this response's headers only.</p>
      </section>
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

  input,
  select,
  textarea {
    box-sizing: border-box;
    background: var(--input-bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.45rem 0.6rem;
    color: var(--fg);
    font-size: 0.86rem;
  }

  input:focus,
  select:focus,
  textarea:focus {
    outline: none;
    border-color: var(--accent);
  }

  textarea {
    width: 100%;
    font-size: 0.8rem;
    resize: vertical;
  }

  .mono {
    font-family: var(--mono);
  }

  .reqline {
    display: flex;
    gap: 0.5rem;
    margin-bottom: 0.8rem;
  }

  .reqline .url {
    flex: 1;
    min-width: 0;
  }

  .group {
    font-size: 0.7rem;
    color: var(--muted);
    text-transform: uppercase;
    letter-spacing: 0.04em;
    margin: 0.6rem 0 0.3rem;
  }

  .hrow {
    display: grid;
    grid-template-columns: 14rem 1fr auto;
    gap: 0.4rem;
    margin-bottom: 0.3rem;
  }

  .mini {
    background: var(--input-bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    color: var(--muted);
    padding: 0 0.6rem;
    cursor: pointer;
  }

  .link {
    background: none;
    border: none;
    color: var(--accent);
    font-size: 0.8rem;
    padding: 0.2rem 0;
    cursor: pointer;
  }

  .adv {
    margin: 0.8rem 0;
  }

  summary {
    font-size: 0.78rem;
    color: var(--muted);
    cursor: pointer;
  }

  .opts {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 0.6rem 1.2rem;
    margin-top: 0.6rem;
    font-size: 0.82rem;
  }

  .check {
    display: inline-flex;
    align-items: center;
    gap: 0.35rem;
  }

  .check.danger {
    color: var(--error-fg);
  }

  .inline {
    display: inline-flex;
    align-items: center;
    gap: 0.4rem;
    color: var(--muted);
  }

  .inline.grow input {
    width: 14rem;
  }

  .num {
    width: 4.5rem;
  }

  .hint {
    font-size: 0.74rem;
    color: var(--muted);
    margin: 0.4rem 0 0;
  }

  .run {
    background: var(--accent);
    border: 1px solid var(--accent);
    border-radius: 6px;
    padding: 0.45rem 1.1rem;
    color: var(--accent-fg);
    font-weight: 600;
    font-size: 0.85rem;
    cursor: pointer;
  }

  .run:disabled {
    opacity: 0.6;
    cursor: default;
  }

  .error {
    background: var(--error-bg);
    border: 1px solid var(--error-border);
    color: var(--error-fg);
    border-radius: 6px;
    padding: 0.6rem 0.8rem;
    font-size: 0.82rem;
    margin: 0.8rem 0;
    white-space: pre-wrap;
  }

  .warnbox,
  .note {
    border-left: 3px solid #b7791f;
    padding: 0.3rem 0.7rem;
    font-size: 0.8rem;
    margin: 0.4rem 0;
  }

  .bar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-top: 1rem;
  }

  h2 {
    font-size: 1rem;
    margin: 0;
  }

  h3 {
    font-size: 0.9rem;
    margin: 0 0 0.4rem;
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }

  .muted {
    color: var(--muted);
    font-weight: normal;
  }

  .small {
    font-size: 0.75rem;
  }

  .hops {
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
    margin: 0.5rem 0;
  }

  .hop {
    display: grid;
    grid-template-columns: 3rem 4.5rem 1fr auto;
    align-items: center;
    gap: 0.5rem;
    background: none;
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.35rem 0.6rem;
    color: var(--fg);
    text-align: left;
    cursor: pointer;
    font-size: 0.82rem;
  }

  .hop.active {
    border-color: var(--accent);
    background: var(--hover);
  }

  .hop .u {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .st {
    font-size: 0.72rem;
    font-weight: 700;
    text-align: center;
    padding: 0.08rem 0.3rem;
    border-radius: 4px;
    color: #fff;
  }

  .st.s2 {
    background: #15935a;
  }

  .st.s3 {
    background: #2563eb;
  }

  .st.s4 {
    background: #b7791f;
  }

  .st.s5 {
    background: #c0392b;
  }

  section {
    margin: 1rem 0;
  }

  .timing {
    display: flex;
    height: 0.6rem;
    border-radius: 3px;
    overflow: hidden;
    margin-bottom: 0.3rem;
    background: var(--hover);
  }

  .seg.dns {
    background: #8b5cf6;
  }

  .seg.tcp {
    background: #2563eb;
  }

  .seg.tls {
    background: #0d9488;
  }

  .seg.ttfb {
    background: #b7791f;
  }

  .kv {
    border-collapse: collapse;
    width: 100%;
  }

  .kv th {
    text-align: left;
    font-weight: 500;
    color: var(--muted);
    font-size: 0.78rem;
    padding: 0.18rem 1rem 0.18rem 0;
    vertical-align: top;
    white-space: nowrap;
    width: 1%;
  }

  .kv td {
    font-size: 0.8rem;
    padding: 0.18rem 0;
    overflow-wrap: anywhere;
  }

  .kv td.bad {
    color: var(--error-fg);
  }

  .body {
    background: var(--input-bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.5rem 0.6rem;
    font-size: 0.76rem;
    white-space: pre-wrap;
    overflow-wrap: anywhere;
    max-height: 28rem;
    overflow: auto;
    margin: 0;
  }

  .inline-right {
    margin-left: auto;
    font-weight: normal;
    font-size: 0.75rem;
  }

  .obs {
    list-style: none;
    padding: 0;
    margin: 0;
    display: flex;
    flex-direction: column;
    gap: 0.3rem;
    font-size: 0.82rem;
  }

  .obs li {
    border-left: 3px solid var(--border);
    padding-left: 0.6rem;
  }

  .obs li.pass {
    border-color: #15935a;
  }

  .obs li.info {
    border-color: #2563eb;
  }

  .obs li.warn {
    border-color: #b7791f;
  }
</style>
