<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import ExportMenu from "$lib/components/ExportMenu.svelte";
  import type { DnsAnalysis, Severity } from "$lib/tools/types";
  import { buildDnsReport } from "./report";

  let domain = $state("");
  let server = $state("");
  let selectorsStr = $state("");

  let report = $state<DnsAnalysis | null>(null);
  let error = $state("");
  let loading = $state(false);

  async function analyze() {
    if (domain.trim().length === 0) {
      error = "Enter a domain to analyze.";
      return;
    }
    loading = true;
    error = "";
    try {
      const dkimSelectors = selectorsStr.split(/[\s,]+/).filter((s) => s.length > 0);
      report = await invoke<DnsAnalysis>("dns_analyze", {
        domain,
        server,
        dkimSelectors,
      });
    } catch (e) {
      report = null;
      error = String(e);
    } finally {
      loading = false;
    }
  }

  function onKeydown(e: KeyboardEvent) {
    if (e.key === "Enter") analyze();
  }

  const BADGE: Record<Severity, string> = {
    pass: "PASS",
    info: "INFO",
    warn: "WARN",
    fail: "FAIL",
  };
</script>

<div class="panel">
  <header>
    <h1>DNS Analyzer</h1>
    <p class="sub">
      Audit a domain's mail and DNS posture: SPF, DMARC, DKIM, MX, DNSSEC, and
      nameserver health.
    </p>
  </header>

  <div class="fields">
    <div class="field grow">
      <label for="domain">Domain</label>
      <input
        id="domain"
        class="mono"
        bind:value={domain}
        onkeydown={onKeydown}
        spellcheck="false"
        autocapitalize="off"
        autocomplete="off"
        placeholder="example.com"
      />
    </div>
    <div class="field">
      <label for="server">Server (optional)</label>
      <input
        id="server"
        class="mono"
        bind:value={server}
        onkeydown={onKeydown}
        spellcheck="false"
        placeholder="system resolver"
      />
    </div>
    <div class="field">
      <label for="selectors">DKIM selectors (optional)</label>
      <input
        id="selectors"
        class="mono"
        bind:value={selectorsStr}
        onkeydown={onKeydown}
        spellcheck="false"
        placeholder="e.g. google selector1"
      />
    </div>
  </div>

  <button class="run" onclick={analyze} disabled={loading}>
    {loading ? "Analyzing..." : "Analyze"}
  </button>

  {#if error}
    <div class="error mono">{error}</div>
  {/if}

  {#if report && !loading}
    <div class="server-line">
      <span class="muted">Resolved via {report.server}</span>
      <ExportMenu build={() => (report ? buildDnsReport(report) : null)} name={`dns-${report.domain}`} />
    </div>
    <div class="sections">
      {#each report.sections as section (section.name)}
        <div class="section">
          <div class="section-head">
            <span class="badge {section.status}">{BADGE[section.status]}</span>
            <h2>{section.name}</h2>
          </div>
          <ul class="findings">
            {#each section.findings as f (f.message)}
              <li>
                <span class="dot {f.severity}" title={f.severity}></span>
                <span>{f.message}</span>
              </li>
            {/each}
          </ul>
          {#if section.records.length > 0}
            <details>
              <summary>Records</summary>
              {#each section.records as r (r)}
                <pre class="record mono">{r}</pre>
              {/each}
            </details>
          {/if}
        </div>
      {/each}
    </div>
  {/if}
</div>

<style>
  .panel {
    padding: 1.5rem 2rem;
    max-width: 860px;
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

  .fields {
    display: flex;
    flex-wrap: wrap;
    gap: 0.9rem;
    margin-bottom: 0.9rem;
  }

  .field {
    display: flex;
    flex-direction: column;
    flex: 1 1 200px;
  }

  .field.grow {
    flex: 1 1 240px;
  }

  label {
    font-size: 0.8rem;
    color: var(--muted);
    margin-bottom: 0.35rem;
  }

  input {
    width: 100%;
    box-sizing: border-box;
    background: var(--input-bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.5rem 0.6rem;
    color: var(--fg);
    font-size: 0.9rem;
  }

  input:focus {
    outline: none;
    border-color: var(--accent);
  }

  .mono {
    font-family: var(--mono);
  }

  .run {
    background: var(--accent);
    border: 1px solid var(--accent);
    border-radius: 6px;
    padding: 0.5rem 1.1rem;
    color: var(--accent-fg);
    font-weight: 600;
    font-size: 0.85rem;
    cursor: pointer;
    margin-bottom: 1rem;
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
    margin-bottom: 0.9rem;
    white-space: pre-wrap;
  }

  .server-line {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 1rem;
    font-size: 0.78rem;
    margin: 0 0 0.75rem;
  }

  .muted {
    color: var(--muted);
  }

  .sections {
    display: flex;
    flex-direction: column;
    gap: 0.9rem;
  }

  .section {
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 0.8rem 1rem;
  }

  .section-head {
    display: flex;
    align-items: center;
    gap: 0.6rem;
    margin-bottom: 0.5rem;
  }

  .section-head h2 {
    margin: 0;
    font-size: 1rem;
  }

  .badge {
    font-size: 0.65rem;
    font-weight: 700;
    letter-spacing: 0.05em;
    padding: 0.1rem 0.4rem;
    border-radius: 4px;
    color: #fff;
  }

  .badge.pass,
  .dot.pass {
    background: #15935a;
  }
  .badge.info,
  .dot.info {
    background: #2563eb;
  }
  .badge.warn,
  .dot.warn {
    background: #b7791f;
  }
  .badge.fail,
  .dot.fail {
    background: #c0392b;
  }

  .findings {
    list-style: none;
    margin: 0;
    padding: 0;
    display: flex;
    flex-direction: column;
    gap: 0.3rem;
  }

  .findings li {
    display: flex;
    align-items: baseline;
    gap: 0.5rem;
    font-size: 0.85rem;
  }

  .dot {
    flex: 0 0 auto;
    width: 0.55rem;
    height: 0.55rem;
    border-radius: 50%;
    display: inline-block;
    transform: translateY(1px);
  }

  details {
    margin-top: 0.5rem;
  }

  summary {
    font-size: 0.78rem;
    color: var(--muted);
    cursor: pointer;
  }

  .record {
    margin: 0.4rem 0 0;
    padding: 0.5rem 0.6rem;
    background: var(--input-bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    font-size: 0.78rem;
    white-space: pre-wrap;
    overflow-wrap: anywhere;
  }
</style>
