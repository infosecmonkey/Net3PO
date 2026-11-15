<script lang="ts">
  // TLS, certificate and CSR inspector. Live mode connects only when asked;
  // decode mode is fully offline. What the server presented and negotiated
  // is shown apart from Net3PO's own trust and hostname evaluation.
  import { invoke } from "@tauri-apps/api/core";
  import { open } from "@tauri-apps/plugin-dialog";
  import ExportMenu from "$lib/components/ExportMenu.svelte";
  import { selectOnFocus } from "$lib/actions/selectOnFocus";
  import CertCard from "./CertCard.svelte";
  import { buildDecodeReport, buildLiveReport } from "./report";
  import {
    STARTTLS_PORTS,
    type DecodeResult,
    type LiveRequest,
    type LiveResult,
    type StartTls,
    type SuiteResult,
  } from "./types";

  let mode = $state<"live" | "decode">("live");

  // Live
  let target = $state("");
  let port = $state(443);
  let portTouched = $state(false);
  let starttls = $state<StartTls>("none");
  let connectIp = $state("");
  let sni = $state(true);
  let live = $state<LiveResult | null>(null);
  let suites = $state<SuiteResult[] | null>(null);
  let liveBusy = $state(false);
  let suiteBusy = $state(false);
  let liveError = $state("");

  // Decode
  let pemText = $state("");
  let decoded = $state<DecodeResult | null>(null);
  let decodeError = $state("");

  const MODES: { id: StartTls; label: string }[] = [
    { id: "none", label: "None (direct TLS)" },
    { id: "smtp", label: "SMTP" },
    { id: "imap", label: "IMAP" },
    { id: "pop3", label: "POP3" },
    { id: "ftp", label: "FTP" },
  ];

  // A port typed in the host ("host:8443", a URL) wins over the Port field,
  // as the backend applies it; show it there so the field never misleads.
  const typedPort = $derived.by(() => {
    let s = target.trim().replace(/^[a-z][a-z0-9+.-]*:\/\//i, "");
    s = s.split(/[/?#]/)[0].replace(/^.*@/, "");
    const m = s.match(/^\[[^\]]*\]:(\d+)$/) ?? (s.split(":").length === 2 ? s.match(/:(\d+)$/) : null);
    const n = m ? Number(m[1]) : NaN;
    return n >= 1 && n <= 65535 ? n : null;
  });

  function setMode(m: StartTls) {
    starttls = m;
    if (!portTouched) port = STARTTLS_PORTS[m];
  }

  function request(): LiveRequest {
    return { target: target.trim(), port: port || null, connectIp: connectIp.trim(), sni, starttls };
  }

  async function inspect() {
    if (!target.trim()) {
      liveError = "Enter a hostname or IP address.";
      return;
    }
    liveBusy = true;
    liveError = "";
    suites = null;
    try {
      live = await invoke<LiveResult>("tls_inspect", { req: request() });
    } catch (e) {
      live = null;
      liveError = String(e);
    } finally {
      liveBusy = false;
    }
  }

  async function testSuites() {
    suiteBusy = true;
    try {
      suites = await invoke<SuiteResult[]>("tls_test_suites", { req: request() });
    } catch (e) {
      liveError = String(e);
    } finally {
      suiteBusy = false;
    }
  }

  async function decodeText() {
    decodeError = "";
    if (!pemText.trim()) {
      decoded = null;
      return;
    }
    try {
      decoded = await invoke<DecodeResult>("tls_decode", { text: pemText });
    } catch (e) {
      decoded = null;
      decodeError = String(e);
      return;
    }
    // Never keep a pasted private key on screen or in memory longer than needed.
    if (decoded.privateKeySkipped) {
      pemText = pemText.replace(/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----\s*/g, "");
    }
  }

  async function openFile() {
    decodeError = "";
    const path = await open({
      multiple: false,
      filters: [{ name: "Certificate or CSR", extensions: ["pem", "crt", "cer", "der", "csr", "req", "p7b", "txt"] }],
    });
    if (typeof path !== "string") return;
    try {
      decoded = await invoke<DecodeResult>("tls_decode_file", { path });
    } catch (e) {
      decoded = null;
      decodeError = String(e);
    }
  }

  function onKey(e: KeyboardEvent) {
    if (e.key === "Enter") void inspect();
  }

  const accepted = $derived(suites?.filter((s) => s.support === "accepted").length ?? 0);
</script>

<div class="panel">
  <header>
    <h1>TLS Inspector</h1>
    <p class="sub">
      Inspect a live TLS endpoint (with STARTTLS for mail and FTP), or decode certificates and
      CSRs offline.
    </p>
  </header>

  <div class="tabs" role="tablist">
    <button role="tab" aria-selected={mode === "live"} class:active={mode === "live"} onclick={() => (mode = "live")}>Live endpoint</button>
    <button role="tab" aria-selected={mode === "decode"} class:active={mode === "decode"} onclick={() => (mode = "decode")}>Decode PEM / DER</button>
  </div>

  {#if mode === "live"}
    <div class="fields">
      <div class="field grow">
        <label for="tgt">Host</label>
        <input id="tgt" class="mono" bind:value={target} onkeydown={onKey} spellcheck="false" autocapitalize="off" autocomplete="off" placeholder="hostname, IP, or URL" />
      </div>
      <div class="field small">
        <label for="port">Port</label>
        {#if typedPort !== null}
          <input id="port" class="mono" type="number" value={typedPort} disabled title="Port taken from the Host field" />
        {:else}
          <input id="port" class="mono" type="number" min="1" max="65535" bind:value={port} oninput={() => (portTouched = true)} onkeydown={onKey} use:selectOnFocus />
        {/if}
      </div>
      <div class="field">
        <label for="stls">STARTTLS</label>
        <select id="stls" value={starttls} onchange={(e) => setMode(e.currentTarget.value as StartTls)}>
          {#each MODES as m (m.id)}<option value={m.id}>{m.label}</option>{/each}
        </select>
      </div>
    </div>
    <details class="adv">
      <summary>Advanced</summary>
      <div class="fields">
        <div class="field">
          <label for="cip">Connect to IP (optional)</label>
          <input id="cip" class="mono" bind:value={connectIp} onkeydown={onKey} spellcheck="false" placeholder="resolve the host" />
          <span class="hint">Test a specific server or VIP while keeping the hostname for SNI and checks.</span>
        </div>
        <label class="check"><input type="checkbox" bind:checked={sni} /> Send SNI</label>
      </div>
    </details>

    <div class="actions">
      <button class="run" onclick={inspect} disabled={liveBusy}>{liveBusy ? "Connecting..." : "Inspect"}</button>
      {#if live}
        <button class="second" onclick={testSuites} disabled={suiteBusy || liveBusy} title="One handshake per supported version and cipher suite">
          {suiteBusy ? "Testing..." : "Test versions and ciphers"}
        </button>
        <span class="spacer"></span>
        <ExportMenu build={() => (live ? buildLiveReport(live, suites) : null)} name={`tls-${live.host}`} />
      {/if}
    </div>
    {#if liveError}<div class="error mono">{liveError}</div>{/if}

    {#if live && !liveBusy}
      <section>
        <h2>Connection <span class="muted small">as measured</span></h2>
        <table class="kv">
          <tbody>
            <tr><th>Connected to</th><td class="mono">{live.address}</td></tr>
            <tr><th>SNI sent</th><td class="mono">{live.sniSent ?? "(none)"}</td></tr>
            <tr><th>Protocol</th><td>{live.protocol}</td></tr>
            <tr><th>Cipher suite</th><td class="mono">{live.cipherSuite}</td></tr>
            <tr><th>Key exchange</th><td class="mono">{live.keyExchange || "(not reported)"}</td></tr>
            <tr><th>ALPN</th><td class="mono">{live.alpn || "(none)"}</td></tr>
            <tr>
              <th>Timing</th>
              <td>connect {live.timing.connectMs} ms{live.timing.starttlsMs !== null ? `, STARTTLS ${live.timing.starttlsMs} ms` : ""}, handshake {live.timing.handshakeMs} ms</td>
            </tr>
          </tbody>
        </table>
        {#if live.transcript.length}
          <details>
            <summary>STARTTLS exchange</summary>
            <pre class="code mono">{live.transcript.join("\n")}</pre>
          </details>
        {/if}
      </section>

      <section>
        <h2>Evaluation <span class="muted small">Net3PO's checks, not the server's claims</span></h2>
        <ul class="findings">
          <li class={live.trust.chainTrusted ? "pass" : "fail"}>
            {live.trust.chainTrusted ? "Chain leads to a trusted root" : `Not trusted: ${live.trust.chainError}`}
          </li>
          <li class={live.trust.nameMatch ? "pass" : "fail"}>
            {live.trust.nameMatch ? `${live.trust.checkedName} is covered by ${live.trust.nameMatch}` : `No SAN covers ${live.trust.checkedName}`}
          </li>
          {#each live.chainNotes as n (n)}<li class="warn">{n}</li>{/each}
        </ul>
        <p class="hint">
          Checked against the {live.trust.store}. Your OS or browser may trust different roots.
          Revocation is not checked.
        </p>
      </section>

      {#if suites}
        <section>
          <h2>Versions and ciphers <span class="muted small">{accepted} of {suites.length} accepted</span></h2>
          <table class="grid">
            <thead><tr><th>Version</th><th>Cipher suite</th><th>Result</th><th></th></tr></thead>
            <tbody>
              {#each suites as s (s.suite)}
                <tr>
                  <td>{s.version}</td>
                  <td class="mono">{s.suite}</td>
                  <td><span class="st {s.support}">{s.support}</span></td>
                  <td class="muted small">{s.detail}</td>
                </tr>
              {/each}
            </tbody>
          </table>
          <p class="hint">
            Only modern TLS 1.2 and 1.3 suites can be offered by this build. TLS 1.0/1.1, CBC and
            static RSA suites are not tested, so their absence here says nothing about the server.
          </p>
        </section>
      {/if}

      <section>
        <h2>Presented chain <span class="muted small">in the order the server sent it</span></h2>
        <div class="cards">
          {#each live.chain as c, i (c.sha256)}
            <CertCard title={i === 0 ? "Leaf" : `Certificate ${i + 1}`} cert={c} open={i === 0} />
          {/each}
        </div>
      </section>
    {/if}
  {:else}
    <div class="field">
      <label for="pem">Certificates or CSR (PEM)</label>
      <textarea
        id="pem"
        class="mono"
        rows="8"
        bind:value={pemText}
        spellcheck="false"
        placeholder={"-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"}
      ></textarea>
      <span class="hint">Several blocks are fine (a chain or bundle). Private keys are ignored and removed from the box.</span>
    </div>
    <div class="actions">
      <button class="run" onclick={decodeText}>Decode</button>
      <button class="second" onclick={openFile}>Open file...</button>
      <span class="spacer"></span>
      {#if decoded && decoded.items.length}
        <ExportMenu build={() => (decoded ? buildDecodeReport(decoded) : null)} name="certificates" />
      {/if}
    </div>
    {#if decodeError}<div class="error mono">{decodeError}</div>{/if}
    {#if decoded}
      {#if decoded.privateKeySkipped}
        <div class="warnbox">A private key was in the input. It was not parsed, stored or included in any report.</div>
      {/if}
      {#each decoded.warnings as w (w)}<div class="warnbox">{w}</div>{/each}
      <div class="cards">
        {#each decoded.items as item, i (i)}
          {#if item.type === "certificate"}
            <CertCard title={`Certificate ${i + 1}`} cert={item.cert} open={decoded.items.length === 1} />
          {:else}
            <CertCard title={`CSR ${i + 1}`} csr={item.csr} open />
          {/if}
        {/each}
      </div>
      <p class="hint">Decoding shows what a certificate says. It does not establish trust or check revocation.</p>
    {/if}
  {/if}
</div>

<style>
  .panel {
    padding: 1.5rem 2rem;
    max-width: 960px;
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

  .tabs {
    display: flex;
    gap: 0.25rem;
    border-bottom: 1px solid var(--border);
    margin-bottom: 1rem;
  }

  .tabs button {
    background: none;
    border: none;
    border-bottom: 2px solid transparent;
    color: var(--muted);
    padding: 0.4rem 0.8rem;
    font-size: 0.85rem;
    cursor: pointer;
  }

  .tabs button.active {
    color: var(--fg);
    border-bottom-color: var(--accent);
  }

  .fields {
    display: flex;
    flex-wrap: wrap;
    gap: 0.9rem;
    margin-bottom: 0.8rem;
    align-items: flex-end;
  }

  .field {
    display: flex;
    flex-direction: column;
    flex: 1 1 180px;
  }

  .field.grow {
    flex: 3 1 260px;
  }

  .field.small {
    flex: 0 0 6rem;
  }

  label {
    font-size: 0.8rem;
    color: var(--muted);
    margin-bottom: 0.35rem;
  }

  input,
  select,
  textarea {
    width: 100%;
    box-sizing: border-box;
    background: var(--input-bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.5rem 0.6rem;
    color: var(--fg);
    font-size: 0.88rem;
  }

  textarea {
    font-size: 0.78rem;
    resize: vertical;
  }

  input:focus,
  select:focus,
  textarea:focus {
    outline: none;
    border-color: var(--accent);
  }

  .check {
    display: flex;
    align-items: center;
    gap: 0.4rem;
    margin: 0 0 0.5rem;
    color: var(--fg);
  }

  .check input {
    width: auto;
  }

  .adv {
    margin-bottom: 0.8rem;
  }

  .adv summary,
  details summary {
    font-size: 0.78rem;
    color: var(--muted);
    cursor: pointer;
    margin-bottom: 0.5rem;
  }

  .hint {
    font-size: 0.74rem;
    color: var(--muted);
    margin: 0.3rem 0 0;
  }

  .actions {
    display: flex;
    align-items: center;
    gap: 0.6rem;
    margin: 0.4rem 0 1rem;
  }

  .spacer {
    flex: 1;
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
  }

  .second {
    background: var(--input-bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.5rem 0.9rem;
    color: var(--fg);
    font-size: 0.82rem;
    cursor: pointer;
  }

  .run:disabled,
  .second:disabled {
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

  .warnbox {
    border-left: 3px solid #b7791f;
    padding: 0.35rem 0.7rem;
    font-size: 0.8rem;
    margin-bottom: 0.6rem;
  }

  section {
    margin-bottom: 1.3rem;
  }

  h2 {
    font-size: 0.98rem;
    margin: 0 0 0.5rem;
  }

  .muted {
    color: var(--muted);
    font-weight: normal;
  }

  .small {
    font-size: 0.75rem;
  }

  .mono {
    font-family: var(--mono);
  }

  .kv th {
    text-align: left;
    font-weight: 500;
    color: var(--muted);
    font-size: 0.8rem;
    padding: 0.2rem 1rem 0.2rem 0;
    white-space: nowrap;
  }

  .kv td {
    font-size: 0.84rem;
    padding: 0.2rem 0;
  }

  .grid {
    border-collapse: collapse;
    width: 100%;
  }

  .grid th,
  .grid td {
    text-align: left;
    padding: 0.25rem 0.6rem 0.25rem 0;
    border-bottom: 1px solid var(--border);
    font-size: 0.8rem;
  }

  .grid th {
    color: var(--muted);
    font-weight: 500;
  }

  .st {
    font-size: 0.7rem;
    font-weight: 700;
    padding: 0.05rem 0.4rem;
    border-radius: 4px;
    color: #fff;
  }

  .st.accepted {
    background: #15935a;
  }

  .st.rejected {
    background: #6b7280;
  }

  .st.error {
    background: #b7791f;
  }

  .findings {
    list-style: none;
    padding: 0;
    margin: 0;
    display: flex;
    flex-direction: column;
    gap: 0.3rem;
    font-size: 0.85rem;
  }

  .findings li::before {
    content: "";
    display: inline-block;
    width: 0.55rem;
    height: 0.55rem;
    border-radius: 50%;
    margin-right: 0.5rem;
  }

  .findings li.pass::before {
    background: #15935a;
  }

  .findings li.fail::before {
    background: #c0392b;
  }

  .findings li.warn::before {
    background: #b7791f;
  }

  .code {
    background: var(--input-bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.5rem 0.6rem;
    font-size: 0.76rem;
    white-space: pre-wrap;
    margin: 0;
  }

  .cards {
    display: flex;
    flex-direction: column;
    gap: 0.6rem;
    margin-bottom: 0.6rem;
  }
</style>
