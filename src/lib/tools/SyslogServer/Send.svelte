<script lang="ts">
  import { invoke, Channel } from "@tauri-apps/api/core";
  import type { SyslogSendEvent } from "$lib/tools/types";

  const KINDS = ["mixed", "ssh", "sudo", "kernel", "cron", "app", "fortigate"];
  const FACILITIES = [
    "kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news", "uucp", "cron",
    "authpriv", "ftp", "local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7",
  ];
  const SEVERITIES = ["emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"];
  const MAX_ROWS = 2000;

  let server = $state("127.0.0.1");
  let port = $state(514);
  let proto = $state("udp");
  let format = $state("3164");
  let kind = $state("mixed");
  let count = $state(20);
  let rate = $state(2);
  let hostname = $state("");
  let message = $state("");
  let app = $state("testapp");
  let facility = $state("local0");
  let severity = $state(-1); // -1 = use generator/default

  let sending = $state(false);
  let error = $state("");
  let sentCount = $state(0);
  let lines = $state<{ index: number; severity: string; line: string }[]>([]);
  let sendId = 0;

  async function start() {
    if (server.trim().length === 0) {
      error = "Enter a destination server.";
      return;
    }
    error = "";
    lines = [];
    sentCount = 0;
    sending = true;
    sendId = Math.floor(Math.random() * 0x7fffffff);

    const channel = new Channel<SyslogSendEvent>();
    channel.onmessage = (ev) => {
      if (ev.type === "sent") {
        sentCount = ev.index;
        lines = [{ index: ev.index, severity: ev.severity, line: ev.line }, ...lines].slice(0, MAX_ROWS);
      } else if (ev.type === "done") {
        sentCount = ev.sent;
      }
    };

    const config = {
      server,
      port,
      proto,
      format,
      kind,
      count,
      rate,
      hostname: hostname.trim() || null,
      message: message.trim() || null,
      app,
      facility,
      severity: severity >= 0 ? severity : null,
    };

    try {
      await invoke("syslog_send", { sendId, config, onEvent: channel });
    } catch (e) {
      error = String(e);
    } finally {
      sending = false;
    }
  }

  async function stop() {
    try {
      await invoke("syslog_stop", { listenerId: sendId });
    } catch {
      // ignore
    }
  }
</script>

<div class="send">
  <div class="grid">
    <div class="field grow">
      <label for="server">Destination server</label>
      <input id="server" class="mono" bind:value={server} disabled={sending} spellcheck="false" />
    </div>
    <div class="field">
      <label for="sport">Port</label>
      <input id="sport" type="number" min="1" max="65535" bind:value={port} disabled={sending} />
    </div>
    <div class="field">
      <label for="proto">Transport</label>
      <select id="proto" bind:value={proto} disabled={sending}>
        <option value="udp">UDP</option>
        <option value="tcp">TCP</option>
      </select>
    </div>
    <div class="field">
      <label for="fmt">Format</label>
      <select id="fmt" bind:value={format} disabled={sending}>
        <option value="3164">RFC 3164</option>
        <option value="5424">RFC 5424</option>
      </select>
    </div>
  </div>

  <div class="grid">
    <div class="field">
      <label for="kind">Message type</label>
      <select id="kind" bind:value={kind} disabled={sending || message.trim().length > 0}>
        {#each KINDS as k (k)}<option value={k}>{k}</option>{/each}
      </select>
    </div>
    <div class="field">
      <label for="count">Count (0 = until stopped)</label>
      <input id="count" type="number" min="0" bind:value={count} disabled={sending} />
    </div>
    <div class="field">
      <label for="rate">Rate (msg/s, 0 = max)</label>
      <input id="rate" type="number" min="0" step="0.5" bind:value={rate} disabled={sending} />
    </div>
    <div class="field">
      <label for="sev">Severity</label>
      <select id="sev" bind:value={severity} disabled={sending}>
        <option value={-1}>auto</option>
        {#each SEVERITIES as s, i (s)}<option value={i}>{i} {s}</option>{/each}
      </select>
    </div>
  </div>

  <details class="advanced">
    <summary>Custom message / fields</summary>
    <div class="grid">
      <div class="field grow">
        <label for="msg">Exact message (overrides generator)</label>
        <input id="msg" class="mono" bind:value={message} disabled={sending} spellcheck="false" placeholder="leave blank to generate" />
      </div>
      <div class="field">
        <label for="host">Hostname</label>
        <input id="host" class="mono" bind:value={hostname} disabled={sending} spellcheck="false" placeholder="random" />
      </div>
    </div>
    <div class="grid">
      <div class="field">
        <label for="app">App (with custom message)</label>
        <input id="app" class="mono" bind:value={app} disabled={sending} spellcheck="false" />
      </div>
      <div class="field">
        <label for="fac">Facility (with custom message)</label>
        <select id="fac" bind:value={facility} disabled={sending}>
          {#each FACILITIES as f (f)}<option value={f}>{f}</option>{/each}
        </select>
      </div>
    </div>
  </details>

  <div class="row">
    {#if sending}
      <button class="action stop" onclick={stop}>Stop</button>
    {:else}
      <button class="action" onclick={start}>Send</button>
    {/if}
    <span class="count muted">{sentCount.toLocaleString()} sent</span>
  </div>

  {#if error}
    <div class="error mono">{error}</div>
  {/if}

  {#if lines.length > 0}
    <div class="log">
      {#each lines as l (l.index)}
        <div class="logline mono">
          <span class="idx">{l.index}</span>
          <span class="sev {l.severity}">{l.severity}</span>
          <span class="text">{l.line}</span>
        </div>
      {/each}
    </div>
  {/if}
</div>

<style>
  .send {
    display: flex;
    flex-direction: column;
    gap: 0.9rem;
  }

  .grid {
    display: flex;
    flex-wrap: wrap;
    gap: 0.75rem;
  }

  .field {
    display: flex;
    flex-direction: column;
    flex: 1 1 140px;
  }

  .field.grow {
    flex: 2 1 240px;
  }

  label {
    font-size: 0.78rem;
    color: var(--muted);
    margin-bottom: 0.3rem;
  }

  input,
  select {
    width: 100%;
    box-sizing: border-box;
    background: var(--input-bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.45rem 0.55rem;
    color: var(--fg);
    font-size: 0.88rem;
  }

  input:focus,
  select:focus {
    outline: none;
    border-color: var(--accent);
  }

  .mono {
    font-family: var(--mono);
  }

  .advanced summary {
    font-size: 0.82rem;
    color: var(--muted);
    cursor: pointer;
    margin-bottom: 0.5rem;
  }

  .advanced .grid {
    margin-bottom: 0.6rem;
  }

  .row {
    display: flex;
    align-items: center;
    gap: 0.9rem;
  }

  .action {
    background: var(--accent);
    border: 1px solid var(--accent);
    border-radius: 6px;
    padding: 0.5rem 1.3rem;
    color: #fff;
    font-weight: 600;
    font-size: 0.85rem;
    cursor: pointer;
  }

  .action.stop {
    background: var(--btn-bg);
    border-color: var(--error-border);
    color: var(--error-fg);
  }

  .count {
    font-size: 0.82rem;
  }

  .muted {
    color: var(--muted);
  }

  .error {
    background: var(--error-bg);
    border: 1px solid var(--error-border);
    color: var(--error-fg);
    border-radius: 6px;
    padding: 0.6rem 0.8rem;
    font-size: 0.82rem;
    white-space: pre-wrap;
  }

  .log {
    border: 1px solid var(--border);
    border-radius: 6px;
    max-height: 45vh;
    overflow: auto;
  }

  .logline {
    display: flex;
    gap: 0.6rem;
    padding: 0.25rem 0.6rem;
    border-bottom: 1px solid var(--border);
    font-size: 0.78rem;
    align-items: baseline;
  }

  .logline:last-child {
    border-bottom: none;
  }

  .idx {
    color: var(--muted);
    min-width: 2.5rem;
    text-align: right;
  }

  .sev {
    min-width: 4rem;
    font-weight: 600;
  }

  .sev.emerg,
  .sev.alert,
  .sev.crit,
  .sev.err {
    color: #e05c4a;
  }
  .sev.warning {
    color: #d99a2b;
  }
  .sev.notice,
  .sev.info,
  .sev.debug {
    color: var(--muted);
  }

  .text {
    word-break: break-all;
  }
</style>
