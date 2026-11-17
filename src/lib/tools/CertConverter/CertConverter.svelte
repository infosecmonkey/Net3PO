<script lang="ts">
  // Certificate Converter: read certificates, chains, keys and CSRs from PEM,
  // DER, P7B and PFX; show the chain and key matches; write another format.
  // Everything stays on this computer and nothing is saved by the app.
  import { onDestroy, onMount } from "svelte";
  import { invoke } from "@tauri-apps/api/core";
  import { getCurrentWebview } from "@tauri-apps/api/webview";
  import { open, save } from "@tauri-apps/plugin-dialog";

  interface Sans {
    dns: string[];
    ip: string[];
    email: string[];
    uri: string[];
  }
  interface CertInfo {
    subject: string;
    subjectCn: string;
    issuer: string;
    serial: string;
    notBeforeMs: number;
    notAfterMs: number;
    validity: "notYetValid" | "valid" | "expired";
    daysLeft: number;
    sans: Sans;
    key: { algorithm: string; bits: number; curve: string; spkiSha256: string };
    signatureAlgorithm: string;
    isCa: boolean;
    keyUsage: string[];
    extendedKeyUsage: string[];
    selfSigned: boolean;
    sha256: string;
    sha1: string;
    notes: string[];
  }
  interface CertView {
    index: number;
    source: string;
    role: string;
    info: CertInfo | null;
    error: string | null;
    keys: number[];
  }
  interface KeyView {
    index: number;
    source: string;
    description: string;
    certs: number[];
    checkable: boolean;
  }
  interface CsrView {
    source: string;
    info: { subject: string; subjectCn: string; sans: Sans; key: CertInfo["key"]; signatureValid: boolean; notes: string[] } | null;
    error: string | null;
    keys: number[];
  }
  interface Summary {
    certs: CertView[];
    keys: KeyView[];
    csrs: CsrView[];
    chain: number[];
    endsAtRoot: boolean;
    missingIssuer: string | null;
    warnings: string[];
    needsPassword: boolean;
    wrongPassword: boolean;
  }
  interface InputItem {
    name: string;
    data: string;
  }

  type Format = "pemChain" | "pemLeaf" | "derLeaf" | "p7b" | "pfx" | "keyPkcs8Pem" | "keyTraditionalPem" | "keyDer";
  const FORMATS: { id: Format; label: string; ext: string; key: boolean; hint: string }[] = [
    { id: "pemChain", label: "PEM chain", ext: "chain.pem", key: false, hint: "Leaf then intermediates, as web servers and FortiGate expect." },
    { id: "pemLeaf", label: "PEM certificate", ext: "crt", key: false, hint: "The leaf certificate only." },
    { id: "derLeaf", label: "DER certificate", ext: "cer", key: false, hint: "Binary, one certificate (Windows .cer)." },
    { id: "p7b", label: "P7B / PKCS#7", ext: "p7b", key: false, hint: "Certificate chain without a key (Windows, Java)." },
    { id: "pfx", label: "PFX / PKCS#12", ext: "pfx", key: true, hint: "Key, certificate and chain in one password-protected file." },
    { id: "keyPkcs8Pem", label: "Key, PKCS#8 PEM", ext: "key", key: true, hint: "BEGIN PRIVATE KEY. Unencrypted." },
    { id: "keyTraditionalPem", label: "Key, traditional PEM", ext: "key", key: true, hint: "BEGIN RSA / EC PRIVATE KEY (PKCS#1 or SEC1). Unencrypted." },
    { id: "keyDer", label: "Key, DER", ext: "der", key: true, hint: "Binary PKCS#8. Unencrypted." },
  ];

  let inputs = $state<InputItem[]>([]);
  let password = $state("");
  let pasted = $state("");
  let showPaste = $state(false);
  let summary = $state<Summary | null>(null);
  let busy = $state(false);
  let error = $state("");
  let dragging = $state(false);

  let format = $state<Format>("pemChain");
  let includeRoot = $state(false);
  let p7bPem = $state(false);
  let pfxPassword = $state("");
  let pfxConfirm = $state("");
  let pfxLegacy = $state(false);
  let pfxName = $state("");
  let preview = $state("");
  let status = $state("");
  let copied = $state(false);
  let openCert = $state<number | null>(null);

  let unlisten: (() => void) | null = null;

  function toB64(bytes: Uint8Array): string {
    let s = "";
    for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
    return btoa(s);
  }

  onMount(async () => {
    try {
      unlisten = await getCurrentWebview().onDragDropEvent((e) => {
        const p = e.payload;
        if (p.type === "enter" || p.type === "over") dragging = true;
        else if (p.type === "leave") dragging = false;
        else if (p.type === "drop") {
          dragging = false;
          void addPaths(p.paths);
        }
      });
    } catch {
      // Drag and drop is optional.
    }
  });

  onDestroy(() => unlisten?.());

  async function addPaths(paths: string[]) {
    error = "";
    for (const path of paths.slice(0, 20)) {
      try {
        const f = await invoke<InputItem>("cert_read_file", { path });
        if (!inputs.some((i) => i.name === f.name && i.data === f.data)) inputs.push(f);
      } catch (e) {
        error = String(e);
      }
    }
    await inspect();
  }

  async function browse() {
    const picked = await open({
      multiple: true,
      directory: false,
      title: "Open certificates, keys, P7B or PFX",
      filters: [
        { name: "Certificates and keys", extensions: ["pem", "crt", "cer", "der", "key", "p7b", "p7c", "pfx", "p12", "csr", "req", "txt"] },
        { name: "All files", extensions: ["*"] },
      ],
    });
    if (!picked) return;
    await addPaths(Array.isArray(picked) ? picked : [picked]);
  }

  async function addPasted() {
    if (!pasted.trim()) return;
    inputs.push({ name: `Pasted text ${inputs.filter((i) => i.name.startsWith("Pasted")).length + 1}`, data: toB64(new TextEncoder().encode(pasted)) });
    pasted = "";
    showPaste = false;
    await inspect();
  }

  async function inspect() {
    preview = "";
    status = "";
    if (!inputs.length) {
      summary = null;
      return;
    }
    busy = true;
    try {
      summary = await invoke<Summary>("cert_inspect", { inputs, password });
      error = "";
    } catch (e) {
      error = String(e);
    } finally {
      busy = false;
    }
  }

  function remove(i: number) {
    inputs.splice(i, 1);
    void inspect();
  }

  function clearAll() {
    inputs = [];
    summary = null;
    password = "";
    pfxPassword = "";
    pfxConfirm = "";
    preview = "";
    status = "";
    error = "";
  }

  const leaf = $derived(summary && summary.chain.length ? summary.certs[summary.chain[0]] : null);
  const chainCerts = $derived(summary ? summary.chain.map((i) => summary!.certs[i]) : []);
  const others = $derived(summary ? summary.certs.filter((c) => !summary!.chain.includes(c.index)) : []);
  const fmt = $derived(FORMATS.find((f) => f.id === format)!);
  const canCopy = $derived(["pemChain", "pemLeaf"].includes(format) || (format === "p7b" && p7bPem));

  function output() {
    switch (format) {
      case "pemChain":
        return { format, includeRoot };
      case "p7b":
        return { format, includeRoot, pem: p7bPem };
      case "pfx":
        return { format, password: pfxPassword, legacy: pfxLegacy, includeRoot, name: pfxName };
      default:
        return { format };
    }
  }

  function check(): string {
    if (!summary?.certs.length && !fmt.key) return "No certificate loaded.";
    if (fmt.key && !summary?.keys.length) return "No private key loaded.";
    if (format === "pfx") {
      if (!summary?.certs.length) return "A PFX needs the certificate too.";
      if (!pfxPassword) return "Set a password for the PFX.";
      if (pfxPassword !== pfxConfirm) return "The PFX passwords do not match.";
    }
    return "";
  }

  function baseName(): string {
    const cn = leaf?.info?.subjectCn || "certificate";
    return cn.replace(/^\*\./, "wildcard.").replace(/[^A-Za-z0-9._-]+/g, "_").slice(0, 60) || "certificate";
  }

  async function show() {
    const msg = check();
    if (msg) return void (error = msg);
    error = "";
    try {
      const r = await invoke<{ text: string | null }>("cert_export", { inputs, password, output: output(), path: null });
      preview = r.text ?? "";
    } catch (e) {
      error = String(e);
    }
  }

  async function copy() {
    await show();
    if (!preview) return;
    try {
      await navigator.clipboard.writeText(preview);
      copied = true;
      setTimeout(() => (copied = false), 1500);
    } catch {
      copied = false;
    }
  }

  async function saveAs() {
    const msg = check();
    if (msg) return void (error = msg);
    error = "";
    const ext = format === "p7b" && p7bPem ? "p7b" : fmt.ext;
    const path = await save({
      title: `Save ${fmt.label}`,
      defaultPath: `${baseName()}.${ext}`,
    });
    if (!path) return;
    try {
      const r = await invoke<{ bytes: number }>("cert_export", { inputs, password, output: output(), path });
      status = `Saved ${r.bytes} bytes to ${path}${fmt.key && format !== "pfx" ? ". The key is not encrypted; keep the file safe." : "."}`;
    } catch (e) {
      error = String(e);
    }
  }

  function date(ms: number): string {
    return new Date(ms).toISOString().slice(0, 10);
  }

  function keyText(k: CertInfo["key"]): string {
    return k.curve ? `${k.algorithm} ${k.curve}` : `${k.algorithm} ${k.bits || ""}`.trim();
  }

  function expiry(c: CertInfo): { text: string; cls: string } {
    if (c.validity === "expired") return { text: `Expired ${date(c.notAfterMs)}`, cls: "bad" };
    if (c.validity === "notYetValid") return { text: `Not valid until ${date(c.notBeforeMs)}`, cls: "warn" };
    return { text: `${c.daysLeft} days left (${date(c.notAfterMs)})`, cls: c.daysLeft < 30 ? "warn" : "ok" };
  }
</script>

<div class="panel" class:dragging>
  <header>
    <h1>Certificate Converter</h1>
    <p class="sub">
      Open or drop certificates, chains, private keys, CSRs, P7B or PFX files. See the chain and which key matches, then
      save as PEM, DER, P7B, PFX or another key format. Offline; nothing is stored.
    </p>
  </header>

  <section class="card inputs">
    <div class="row">
      <button class="primary" onclick={browse}>Open files</button>
      <button class="small" onclick={() => (showPaste = !showPaste)}>{showPaste ? "Cancel paste" : "Paste text"}</button>
      <span class="hint drop">or drop files here</span>
      <span class="spacer"></span>
      <label class="pw">
        Password
        <input
          type="password"
          bind:value={password}
          placeholder="for PFX or encrypted keys"
          autocomplete="off"
          onkeydown={(e) => e.key === "Enter" && inspect()}
          onchange={inspect}
        />
      </label>
      {#if inputs.length}<button class="small" onclick={clearAll}>Clear</button>{/if}
    </div>
    {#if showPaste}
      <textarea class="mono" rows="6" bind:value={pasted} placeholder="-----BEGIN CERTIFICATE-----" spellcheck="false"></textarea>
      <div class="row"><button class="small" onclick={addPasted} disabled={!pasted.trim()}>Add</button></div>
    {/if}
    {#if inputs.length}
      <div class="files">
        {#each inputs as f, i (f.name + i)}
          <span class="file mono">{f.name}<button class="x" title="Remove" onclick={() => remove(i)}>x</button></span>
        {/each}
      </div>
    {/if}
  </section>

  {#if error}<div class="error mono">{error}</div>{/if}
  {#if busy}<p class="hint">Reading...</p>{/if}

  {#if summary}
    {#if summary.needsPassword}
      <div class="warnbox">
        {summary.wrongPassword ? "The password did not open a PFX or encrypted key." : "A PFX or encrypted key needs its password."}
        Enter it above and press Enter.
      </div>
    {/if}
    {#each summary.warnings as w (w)}<div class="note-line">{w}</div>{/each}

    {#if summary.certs.length}
      <h2>Chain</h2>
      <div class="chain">
        {#each chainCerts as c, pos (c.index)}
          {@const e = c.info ? expiry(c.info) : null}
          <div class="cert">
            <button class="cert-head" onclick={() => (openCert = openCert === c.index ? null : c.index)}>
              <span class="role role-{c.role.toLowerCase().replace(/ /g, '-')}">{c.role}</span>
              <span class="cn">{c.info?.subjectCn || c.info?.subject || "(unreadable)"}</span>
              {#if c.keys.length}<span class="match">key matches</span>{/if}
              <span class="spacer"></span>
              {#if e}<span class="exp {e.cls}">{e.text}</span>{/if}
            </button>
            {#if openCert === c.index && c.info}
              {@render details(c)}
            {/if}
          </div>
          {#if pos < chainCerts.length - 1}<div class="link">issued by</div>{/if}
        {/each}
        {#if summary.missingIssuer}
          <div class="missing">Issuer not loaded: <span class="mono">{summary.missingIssuer}</span>. Add that certificate to complete the chain.</div>
        {:else if !summary.endsAtRoot && summary.chain.length}
          <div class="missing">The chain does not reach a root.</div>
        {/if}
      </div>
      {#if others.length}
        <h3>Other certificates (not in this chain)</h3>
        {#each others as c (c.index)}
          <div class="cert">
            <button class="cert-head" onclick={() => (openCert = openCert === c.index ? null : c.index)}>
              <span class="cn">{c.info?.subjectCn || c.info?.subject || "(unreadable)"}</span>
              <span class="muted mono">{c.source}</span>
            </button>
            {#if openCert === c.index && c.info}{@render details(c)}{/if}
          </div>
        {/each}
      {/if}
    {/if}

    {#if summary.keys.length}
      <h2>Private keys</h2>
      {#each summary.keys as k (k.index)}
        <div class="keyrow">
          <strong>{k.description}</strong>
          <span class="muted mono">{k.source}</span>
          {#if k.certs.length}
            <span class="ok">Matches {k.certs.map((i) => summary!.certs[i].info?.subjectCn || `certificate ${i + 1}`).join(", ")}</span>
          {:else if !k.checkable}
            <span class="warn">Can not check which certificate it matches</span>
          {:else if summary.certs.length}
            <span class="bad">Matches no loaded certificate</span>
          {/if}
        </div>
      {/each}
    {/if}

    {#if summary.csrs.length}
      <h2>Certificate requests</h2>
      {#each summary.csrs as r, i (i)}
        <div class="keyrow">
          <strong>{r.info?.subjectCn || r.info?.subject || "(unreadable)"}</strong>
          {#if r.info}<span class="muted">{keyText(r.info.key)}</span>{/if}
          {#if r.info?.sans.dns.length}<span class="muted mono">{r.info.sans.dns.join(", ")}</span>{/if}
          {#if r.keys.length}<span class="ok">Matches a loaded key</span>{/if}
          {#if r.error}<span class="bad">{r.error}</span>{/if}
        </div>
      {/each}
    {/if}

    {#if summary.certs.length || summary.keys.length}
      <h2>Convert</h2>
      <section class="card">
        <div class="formats" role="radiogroup" aria-label="Output format">
          {#each FORMATS as f (f.id)}
            <label class="fmt" class:sel={format === f.id} title={f.hint}>
              <input type="radio" name="format" value={f.id} bind:group={format} onchange={() => (preview = "")} />
              {f.label}
            </label>
          {/each}
        </div>
        <p class="hint">{fmt.hint}</p>
        <div class="opts">
          {#if format === "pemChain" || format === "p7b" || format === "pfx"}
            <label><input type="checkbox" bind:checked={includeRoot} /> Include the root</label>
          {/if}
          {#if format === "p7b"}
            <label><input type="checkbox" bind:checked={p7bPem} /> PEM (BEGIN PKCS7) instead of binary</label>
          {/if}
        </div>
        {#if format === "pfx"}
          <div class="pfx">
            <label>PFX password <input type="password" bind:value={pfxPassword} autocomplete="new-password" /></label>
            <label>Confirm <input type="password" bind:value={pfxConfirm} autocomplete="new-password" /></label>
            <label>Friendly name <input bind:value={pfxName} placeholder={baseName()} /></label>
            <label class="check"><input type="checkbox" bind:checked={pfxLegacy} /> Legacy encryption (3DES, SHA-1) for older devices and Windows Server 2016 or earlier</label>
          </div>
        {/if}
        {#if fmt.key && format !== "pfx"}
          <p class="warn-text">The key is written unencrypted. Store it somewhere safe and delete copies you do not need.</p>
        {/if}
        <div class="row">
          <button class="primary" onclick={saveAs}>Save...</button>
          {#if canCopy}
            <button class="small" onclick={show}>Show</button>
            <button class="small" onclick={copy}>{copied ? "Copied" : "Copy"}</button>
          {/if}
        </div>
        {#if status}<div class="okbox">{status}</div>{/if}
        {#if preview && canCopy}<pre class="preview mono">{preview}</pre>{/if}
      </section>
    {/if}
  {:else if !inputs.length}
    <p class="hint">Nothing loaded yet. Private keys and passwords stay in this window and are cleared when you click Clear or close the app.</p>
  {/if}
</div>

{#snippet details(c: CertView)}
  {@const i = c.info!}
  <dl class="details">
    <dt>Subject</dt><dd class="mono">{i.subject}</dd>
    <dt>Issuer</dt><dd class="mono">{i.issuer}</dd>
    {#if i.sans.dns.length || i.sans.ip.length}
      <dt>Names (SAN)</dt><dd class="mono">{[...i.sans.dns, ...i.sans.ip].join(", ")}</dd>
    {/if}
    <dt>Valid</dt><dd>{date(i.notBeforeMs)} to {date(i.notAfterMs)}</dd>
    <dt>Key</dt><dd>{keyText(i.key)}</dd>
    <dt>Signature</dt><dd>{i.signatureAlgorithm}</dd>
    <dt>Serial</dt><dd class="mono">{i.serial}</dd>
    {#if i.keyUsage.length}<dt>Key usage</dt><dd>{i.keyUsage.join(", ")}</dd>{/if}
    {#if i.extendedKeyUsage.length}<dt>Extended key usage</dt><dd>{i.extendedKeyUsage.join(", ")}</dd>{/if}
    <dt>CA</dt><dd>{i.isCa ? "Yes" : "No"}</dd>
    <dt>SHA-256</dt><dd class="mono fp">{i.sha256}</dd>
    <dt>SHA-1</dt><dd class="mono fp">{i.sha1}</dd>
    <dt>From</dt><dd class="mono">{c.source}</dd>
  </dl>
  {#each i.notes as n (n)}<div class="note-line">{n}</div>{/each}
{/snippet}

<style>
  .panel {
    padding: 1.5rem 2rem 2rem;
    box-sizing: border-box;
    width: 100%;
    max-width: 64rem;
    min-height: 100%;
  }

  .panel.dragging {
    outline: 2px dashed var(--accent);
    outline-offset: -8px;
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
    margin: 1.2rem 0 0.5rem;
  }

  h3 {
    font-size: 0.85rem;
    margin: 0.9rem 0 0.4rem;
    color: var(--muted);
  }

  .card {
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 0.8rem 1rem;
    background: var(--sidebar-bg);
  }

  .row {
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    gap: 0.5rem;
    margin-top: 0.4rem;
  }

  .inputs .row:first-child {
    margin-top: 0;
  }

  .spacer {
    flex: 1;
  }

  .pw {
    display: flex;
    align-items: center;
    gap: 0.4rem;
    font-size: 0.8rem;
    color: var(--muted);
  }

  textarea {
    width: 100%;
    box-sizing: border-box;
    margin-top: 0.6rem;
    font-size: 0.78rem;
  }

  .files {
    display: flex;
    flex-wrap: wrap;
    gap: 0.35rem;
    margin-top: 0.6rem;
  }

  .file {
    display: inline-flex;
    align-items: center;
    gap: 0.3rem;
    font-size: 0.76rem;
    background: var(--input-bg);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 0.1rem 0.25rem 0.1rem 0.6rem;
  }

  .x {
    background: none;
    border: none;
    color: var(--muted);
    cursor: pointer;
    font-size: 0.75rem;
  }

  .chain {
    display: flex;
    flex-direction: column;
  }

  .cert {
    border: 1px solid var(--border);
    border-radius: 8px;
    background: var(--sidebar-bg);
    margin-bottom: 0.3rem;
  }

  .cert-head {
    display: flex;
    align-items: center;
    gap: 0.6rem;
    width: 100%;
    background: none;
    border: none;
    color: var(--fg);
    text-align: left;
    padding: 0.5rem 0.8rem;
    cursor: pointer;
    font-size: 0.85rem;
  }

  .cert-head:hover {
    background: var(--hover);
  }

  .role {
    font-size: 0.7rem;
    border-radius: 4px;
    padding: 0.05rem 0.4rem;
    border: 1px solid var(--border);
    color: var(--muted);
    min-width: 5.5rem;
    text-align: center;
  }

  .role-leaf {
    border-color: var(--accent);
    color: var(--accent);
  }

  .cn {
    font-weight: 600;
  }

  .match {
    font-size: 0.72rem;
    color: #16a34a;
  }

  .exp {
    font-size: 0.76rem;
  }

  .link {
    font-size: 0.7rem;
    color: var(--muted);
    margin: 0 0 0.3rem 1.4rem;
  }

  .missing {
    font-size: 0.8rem;
    border-left: 3px solid #c69026;
    padding-left: 0.6rem;
    margin-top: 0.3rem;
  }

  .details {
    display: grid;
    grid-template-columns: max-content 1fr;
    gap: 0.2rem 0.9rem;
    margin: 0;
    padding: 0.2rem 0.9rem 0.7rem;
    font-size: 0.78rem;
  }

  .details dt {
    color: var(--muted);
  }

  .details dd {
    margin: 0;
    overflow-wrap: anywhere;
  }

  .fp {
    font-size: 0.72rem;
  }

  .keyrow {
    display: flex;
    flex-wrap: wrap;
    align-items: baseline;
    gap: 0.6rem;
    font-size: 0.84rem;
    padding: 0.3rem 0;
    border-bottom: 1px solid var(--border);
  }

  .ok {
    color: #16a34a;
  }

  .warn {
    color: #c69026;
  }

  .bad {
    color: #dc2626;
  }

  .muted {
    color: var(--muted);
    font-size: 0.76rem;
  }

  .hint {
    color: var(--muted);
    font-size: 0.78rem;
    margin: 0.4rem 0;
  }

  .drop {
    margin: 0;
  }

  .formats {
    display: flex;
    flex-wrap: wrap;
    gap: 0.35rem;
  }

  .fmt {
    display: flex;
    align-items: center;
    gap: 0.3rem;
    font-size: 0.8rem;
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.25rem 0.55rem;
    cursor: pointer;
    background: var(--input-bg);
  }

  .fmt.sel {
    border-color: var(--accent);
  }

  .fmt input {
    margin: 0;
  }

  .opts {
    display: flex;
    flex-wrap: wrap;
    gap: 0.4rem 1.2rem;
    font-size: 0.82rem;
  }

  .opts label {
    display: flex;
    align-items: center;
    gap: 0.35rem;
  }

  .pfx {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(13rem, 1fr));
    gap: 0.5rem 0.9rem;
    margin-top: 0.5rem;
  }

  .pfx label {
    display: flex;
    flex-direction: column;
    gap: 0.2rem;
    font-size: 0.78rem;
    color: var(--muted);
  }

  .pfx label.check {
    grid-column: 1 / -1;
    flex-direction: row;
    align-items: center;
    gap: 0.4rem;
    color: var(--fg);
    font-size: 0.82rem;
  }

  .warn-text {
    font-size: 0.8rem;
    border-left: 3px solid #c69026;
    padding-left: 0.6rem;
  }

  .note-line {
    font-size: 0.78rem;
    color: var(--muted);
    border-left: 3px solid var(--border);
    padding-left: 0.6rem;
    margin: 0.25rem 0;
  }

  .warnbox,
  .okbox {
    border-radius: 6px;
    padding: 0.5rem 0.7rem;
    font-size: 0.82rem;
    margin-top: 0.7rem;
  }

  .warnbox {
    border: 1px solid #c69026;
  }

  .okbox {
    border: 1px solid #16a34a;
    overflow-wrap: anywhere;
  }

  .preview {
    margin-top: 0.6rem;
    max-height: 16rem;
    overflow: auto;
    font-size: 0.72rem;
    background: var(--input-bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.5rem;
  }

  .mono {
    font-family: var(--mono);
  }

  input:not([type]),
  input[type="password"],
  textarea {
    box-sizing: border-box;
    background: var(--input-bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    color: var(--fg);
    font-size: 0.82rem;
    padding: 0.3rem 0.45rem;
  }

  input:focus,
  textarea:focus {
    outline: none;
    border-color: var(--accent);
  }

  button.small {
    background: var(--input-bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    color: var(--fg);
    font-size: 0.78rem;
    padding: 0.3rem 0.65rem;
    cursor: pointer;
  }

  button.primary {
    background: var(--accent);
    border: none;
    border-radius: 6px;
    color: #fff;
    font-size: 0.82rem;
    padding: 0.38rem 1rem;
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
</style>
