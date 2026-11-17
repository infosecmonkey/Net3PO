<script lang="ts">
  // Obfuscator: replace addresses, names, accounts, secrets, MACs and serial
  // numbers in pasted text before it goes to an AI assistant, a ticket or an
  // email, then map the reply back. Offline; the mapping stays in memory.
  import { invoke } from "@tauri-apps/api/core";
  import { ask } from "@tauri-apps/plugin-dialog";
  import { onMount } from "svelte";
  import { loadCollection, saveCollection } from "$lib/store";
  import {
    KIND_LABEL,
    parseExclusions,
    parseRules,
    type MappingEntry,
    type RedactKind,
    type RedactOptions,
  } from "$lib/report/redact";
  import { resetSession, session } from "./session.svelte";

  interface Piece {
    text: string;
    kind: RedactKind | null;
  }
  interface Obfuscated {
    text: string;
    key: string;
    mapping: MappingEntry[];
    replacements: number;
    emails: number;
    privateKeys: number;
    certificates: number;
    pieces: Piece[] | null;
  }
  interface Restored {
    text: string;
    restored: number;
    secretsKept: number;
    unknown: string[];
  }
  interface Settings {
    ips: boolean;
    hostnames: boolean;
    emails: boolean;
    usernames: boolean;
    secrets: boolean;
    macs: boolean;
    serials: boolean;
    certificates: boolean;
    fakeAddresses: boolean;
    rulesText: string;
    exclusionsText: string;
  }

  const DEFAULTS: Settings = {
    ips: true,
    hostnames: true,
    emails: true,
    usernames: true,
    secrets: true,
    macs: true,
    serials: true,
    certificates: true,
    fakeAddresses: true,
    rulesText: "",
    exclusionsText: "",
  };

  const CATEGORIES: { key: keyof Settings; label: string }[] = [
    { key: "ips", label: "IP addresses" },
    { key: "hostnames", label: "Hostnames and domains" },
    { key: "emails", label: "Email addresses" },
    { key: "usernames", label: "Usernames" },
    { key: "secrets", label: "Passwords, keys and tokens" },
    { key: "macs", label: "MAC addresses" },
    { key: "serials", label: "Serial numbers" },
    { key: "certificates", label: "Certificates" },
  ];

  let settings = $state<Settings>({ ...DEFAULTS });
  let loaded = false;
  let tab = $state<"obfuscate" | "restore">("obfuscate");
  let input = $state("");
  let result = $state<Obfuscated | null>(null);
  let busy = $state(false);
  let error = $state("");
  let copied = $state("");
  let filter = $state("");
  let showSecrets = $state(false);

  let reply = $state("");
  let restoreSecrets = $state(false);
  let restored = $state<Restored | null>(null);

  onMount(async () => {
    try {
      const { items } = await loadCollection<Settings>("obfuscator_settings");
      settings = { ...DEFAULTS, ...(items[0] ?? {}) };
    } catch {
      settings = { ...DEFAULTS };
    }
    loaded = true;
  });

  $effect(() => {
    const snapshot = $state.snapshot(settings);
    if (loaded) saveCollection("obfuscator_settings", [snapshot]).catch(() => {});
  });

  function options(): RedactOptions {
    const s = settings;
    return {
      ips: s.ips,
      hostnames: s.hostnames,
      emails: s.emails,
      usernames: s.usernames,
      secrets: s.secrets,
      macs: s.macs,
      serials: s.serials,
      certificates: s.certificates,
      fakeAddresses: s.fakeAddresses,
      rules: parseRules(s.rulesText),
      exclusions: parseExclusions(s.exclusionsText),
    };
  }

  async function obfuscate() {
    if (!input.trim() || busy) return;
    busy = true;
    error = "";
    try {
      const r = await invoke<Obfuscated>("obfuscate_text", {
        text: input,
        opts: options(),
        key: session.key,
        mapping: $state.snapshot(session.mapping),
      });
      session.key = r.key;
      session.mapping = r.mapping;
      result = r;
    } catch (e) {
      error = String(e);
    } finally {
      busy = false;
    }
  }

  async function restore() {
    if (!reply.trim()) return;
    error = "";
    try {
      restored = await invoke<Restored>("obfuscate_restore", {
        text: reply,
        mapping: $state.snapshot(session.mapping),
        secrets: restoreSecrets,
      });
    } catch (e) {
      error = String(e);
    }
  }

  async function newSession() {
    if (session.mapping.length > 0) {
      const ok = await ask(
        "Start a new session? The current mapping is discarded, so earlier output can no longer be restored.",
        { title: "New session", kind: "warning" },
      );
      if (!ok) return;
    }
    resetSession();
    result = null;
    restored = null;
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

  function onKey(e: KeyboardEvent, run: () => void) {
    if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) {
      e.preventDefault();
      run();
    }
  }

  const mask = (v: string) => (v.length <= 2 ? "••" : `${v[0]}${"•".repeat(Math.min(v.length - 2, 10))}${v[v.length - 1]}`);

  const thisRun = $derived((result?.mapping ?? []).filter((m) => m.count > 0));
  const shown = $derived.by(() => {
    const q = filter.trim().toLowerCase();
    if (!q) return thisRun;
    return thisRun.filter(
      (m) =>
        m.token.toLowerCase().includes(q) ||
        KIND_LABEL[m.kind].toLowerCase().includes(q) ||
        (m.kind !== "secret" && m.original.toLowerCase().includes(q)),
    );
  });
  const byKind = $derived.by(() => {
    const counts = new Map<RedactKind, number>();
    for (const m of thisRun) counts.set(m.kind, (counts.get(m.kind) ?? 0) + 1);
    return [...counts].map(([k, n]) => `${n} ${KIND_LABEL[k]}`).join(", ");
  });
</script>

<div class="panel">
  <header>
    <h1>Obfuscator</h1>
    <p class="sub">
      Replace IPs, hostnames, accounts, secrets, MACs and serial numbers before you paste text into an AI
      assistant, a ticket or an email. Restore puts the real values back into the reply. Offline.
    </p>
  </header>

  <div class="tabs">
    <button class:active={tab === "obfuscate"} onclick={() => (tab = "obfuscate")}>Obfuscate</button>
    <button class:active={tab === "restore"} onclick={() => (tab = "restore")}>Restore</button>
    <span class="spacer"></span>
    <span class="muted" title="Kept in memory until you quit the app or start a new session">
      Session: {session.mapping.length} value{session.mapping.length === 1 ? "" : "s"} mapped
    </span>
    <button class="mini" onclick={newSession}>New session</button>
  </div>

  {#if tab === "obfuscate"}
    <div class="opts">
      {#each CATEGORIES as c (c.key)}
        <label class="check"><input type="checkbox" bind:checked={settings[c.key] as boolean} /> {c.label}</label>
      {/each}
    </div>
    <div class="row">
      <label class="field">
        Addresses
        <select bind:value={settings.fakeAddresses}>
          <option value={true}>Fake addresses that keep subnets and vendors</option>
          <option value={false}>Numbered tokens ([IP-1], [MAC-1])</option>
        </select>
      </label>
    </div>
    <details class="rules">
      <summary>Rules and exclusions</summary>
      <div class="cols">
        <label>
          <span>Rules, one per line: <code>find</code>, <code>find =&gt; replacement</code> or <code>re:regex =&gt; replacement</code></span>
          <textarea class="mono" rows="4" bind:value={settings.rulesText} spellcheck="false" placeholder="customer or site names"></textarea>
        </label>
        <label>
          <span>Keep (never replace): a domain, an IPv4 address or a CIDR range</span>
          <textarea class="mono" rows="4" bind:value={settings.exclusionsText} spellcheck="false" placeholder="vendor domains, public resolvers"></textarea>
        </label>
      </div>
    </details>

    <textarea
      class="mono"
      rows="10"
      bind:value={input}
      spellcheck="false"
      placeholder="paste a config, log or command output"
      onkeydown={(e) => onKey(e, obfuscate)}
    ></textarea>
    <div class="row">
      <button class="primary" onclick={obfuscate} disabled={busy || !input.trim()}>{busy ? "Working..." : "Obfuscate"}</button>
      <span class="muted small">Ctrl or Cmd + Enter</span>
    </div>
    {#if error}<div class="error">{error}</div>{/if}

    {#if result}
      <div class="bar">
        <span class="muted">
          {result.replacements} replacement{result.replacements === 1 ? "" : "s"}{byKind ? `: ${byKind}` : ""}{result.privateKeys
            ? `, ${result.privateKeys} private key${result.privateKeys === 1 ? "" : "s"} removed`
            : ""}{result.certificates ? `, ${result.certificates} certificate${result.certificates === 1 ? "" : "s"} removed` : ""}
        </span>
        <span class="spacer"></span>
        <button class="mini" onclick={() => copy("out", result?.text ?? "")}>{copied === "out" ? "Copied" : "Copy output"}</button>
      </div>
      <pre class="out mono">{#if result.pieces}{#each result.pieces as p, i (i)}{#if p.kind}<mark class={p.kind}>{p.text}</mark>{:else}{p.text}{/if}{/each}{:else}{result.text}{/if}</pre>
      <p class="warn">Detection is by pattern and context and can miss names it cannot know. Read the output before you send it, and add rules for anything left.</p>

      {#if thisRun.length}
        <div class="bar">
          <h2>Replacements <span class="muted">{thisRun.length}</span></h2>
          <input class="filter" type="search" bind:value={filter} placeholder="filter" />
          <label class="check"><input type="checkbox" bind:checked={showSecrets} /> Show secrets</label>
        </div>
        <table>
          <thead><tr><th>Type</th><th>Original</th><th>Replacement</th><th class="n">Count</th></tr></thead>
          <tbody>
            {#each shown.slice(0, 2000) as m (m.kind + m.token + m.original)}
              <tr>
                <td class="muted">{KIND_LABEL[m.kind]}</td>
                <td class="mono v">{m.kind === "secret" && !showSecrets ? mask(m.original) : m.original}</td>
                <td class="mono v"><mark class={m.kind}>{m.token}</mark></td>
                <td class="muted n">{m.count}</td>
              </tr>
            {/each}
          </tbody>
        </table>
        {#if shown.length > 2000}<p class="muted small">Showing the first 2,000.</p>{/if}
      {/if}
    {/if}
  {:else}
    {#if session.mapping.length === 0}
      <p class="muted">Nothing to restore yet. Obfuscate some text first; this session's mapping is what Restore uses.</p>
    {/if}
    <textarea
      class="mono"
      rows="10"
      bind:value={reply}
      spellcheck="false"
      placeholder="paste the reply that uses the replaced values"
      onkeydown={(e) => onKey(e, restore)}
    ></textarea>
    <div class="row">
      <button class="primary" onclick={restore} disabled={!reply.trim() || session.mapping.length === 0}>Restore</button>
      <label class="check"><input type="checkbox" bind:checked={restoreSecrets} /> Put secrets back too</label>
    </div>
    {#if error}<div class="error">{error}</div>{/if}
    {#if restored}
      <div class="bar">
        <span class="muted">
          {restored.restored} value{restored.restored === 1 ? "" : "s"} restored{restored.secretsKept
            ? `, ${restored.secretsKept} secret${restored.secretsKept === 1 ? "" : "s"} left masked`
            : ""}
        </span>
        <span class="spacer"></span>
        <button class="mini" onclick={() => copy("restored", restored?.text ?? "")}>{copied === "restored" ? "Copied" : "Copy"}</button>
      </div>
      <pre class="out mono">{restored.text}</pre>
      {#if restored.unknown.length}
        <p class="warn">
          Not from this session, left as is: {restored.unknown.slice(0, 20).join(", ")}{restored.unknown.length > 20 ? ", ..." : ""}
        </p>
      {/if}
    {/if}
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

  .tabs {
    display: flex;
    align-items: center;
    gap: 0.4rem;
    border-bottom: 1px solid var(--border);
    margin-bottom: 0.8rem;
    flex-wrap: wrap;
  }

  .tabs > button:not(.mini) {
    background: none;
    border: none;
    border-bottom: 2px solid transparent;
    color: var(--muted);
    padding: 0.4rem 0.8rem;
    cursor: pointer;
    font-size: 0.86rem;
  }

  .tabs > button.active {
    color: var(--fg);
    border-bottom-color: var(--accent);
    font-weight: 600;
  }

  .opts {
    display: flex;
    flex-wrap: wrap;
    gap: 0.4rem 1rem;
    margin-bottom: 0.6rem;
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
  select:focus,
  .filter:focus {
    outline: none;
    border-color: var(--accent);
  }

  select,
  .filter {
    background: var(--input-bg);
    border: 1px solid var(--border);
    border-radius: 4px;
    color: var(--fg);
    padding: 0.25rem 0.4rem;
    font-size: 0.8rem;
  }

  .field {
    display: inline-flex;
    align-items: center;
    gap: 0.5rem;
    font-size: 0.8rem;
  }

  .rules {
    margin: 0.2rem 0 0.7rem;
    font-size: 0.8rem;
  }

  .rules summary {
    cursor: pointer;
    color: var(--muted);
  }

  .cols {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 0.8rem;
    margin-top: 0.5rem;
  }

  .cols label {
    display: flex;
    flex-direction: column;
    gap: 0.3rem;
    color: var(--muted);
    font-size: 0.76rem;
  }

  .mono {
    font-family: var(--mono);
  }

  .row,
  .bar {
    display: flex;
    align-items: center;
    gap: 0.7rem;
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

  .primary:disabled {
    opacity: 0.5;
    cursor: default;
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

  .check {
    display: inline-flex;
    align-items: center;
    gap: 0.35rem;
    font-size: 0.8rem;
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

  .warn {
    color: #b45309;
    font-size: 0.78rem;
    margin: 0.4rem 0;
  }

  .out {
    margin: 0;
    padding: 0.6rem;
    background: var(--input-bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    font-size: 0.8rem;
    white-space: pre-wrap;
    overflow-wrap: anywhere;
    max-height: 28rem;
    overflow: auto;
  }

  mark {
    color: inherit;
    border-radius: 2px;
    padding: 0 1px;
    background: hsl(var(--h, 210) 70% 50% / 0.22);
  }

  mark.ip {
    --h: 210;
  }
  mark.host {
    --h: 160;
  }
  mark.user {
    --h: 280;
  }
  mark.secret {
    --h: 0;
  }
  mark.mac {
    --h: 40;
  }
  mark.serial {
    --h: 320;
  }
  mark.custom {
    --h: 100;
  }

  h2 {
    font-size: 0.92rem;
    margin: 0;
  }

  table {
    border-collapse: collapse;
    width: 100%;
  }

  th {
    text-align: left;
    font-size: 0.74rem;
    color: var(--muted);
    font-weight: 600;
    border-bottom: 1px solid var(--border);
    padding: 0.2rem 0.6rem 0.2rem 0;
  }

  td {
    padding: 0.18rem 0.6rem 0.18rem 0;
    font-size: 0.8rem;
    border-bottom: 1px solid var(--border);
    vertical-align: top;
  }

  td.v {
    overflow-wrap: anywhere;
  }

  .n {
    white-space: nowrap;
    width: 1%;
    text-align: right;
  }

  @media (max-width: 760px) {
    .cols {
      grid-template-columns: 1fr;
    }
  }
</style>
