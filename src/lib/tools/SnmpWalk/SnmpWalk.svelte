<script lang="ts">
  import { invoke, Channel } from "@tauri-apps/api/core";
  import { open } from "@tauri-apps/plugin-dialog";
  import type { SnmpWalkEvent } from "$lib/tools/types";

  const MAX_ROWS = 50000;
  const AUTH_PROTOS = ["none", "md5", "sha1", "sha224", "sha256", "sha384", "sha512"];
  const CIPHERS = ["none", "des", "aes128", "aes192", "aes256"];

  let host = $state("");
  let port = $state(161);
  let version = $state("v2c");
  let community = $state("public");
  let username = $state("");
  let authProtocol = $state("sha1");
  let authPassword = $state("");
  let privCipher = $state("aes128");
  let privPassword = $state("");
  let startOid = $state("1.3.6.1.2.1");

  let walking = $state(false);
  let error = $state("");
  let rows = $state<{ oid: string; name: string; valueType: string; value: string }[]>([]);
  let doneMsg = $state("");
  let mibTotal = $state(0);
  let walkId = 0;

  $effect(() => {
    invoke<{ total: number }>("snmp_mib_info")
      .then((i) => (mibTotal = i.total))
      .catch(() => {});
  });

  async function loadMib() {
    try {
      const path = await open({
        multiple: false,
        filters: [
          { name: "MIB", extensions: ["mib", "txt", "my"] },
          { name: "All files", extensions: ["*"] },
        ],
      });
      if (typeof path !== "string") return;
      const info = await invoke<{ total: number }>("snmp_load_mib", { path });
      mibTotal = info.total;
    } catch (e) {
      error = String(e);
    }
  }

  async function walk() {
    if (host.trim().length === 0) {
      error = "Enter a target host or IP.";
      return;
    }
    error = "";
    doneMsg = "";
    rows = [];
    walking = true;
    walkId = Math.floor(Math.random() * 0x7fffffff);

    const channel = new Channel<SnmpWalkEvent>();
    channel.onmessage = (ev) => {
      if (ev.type === "varbind") {
        if (rows.length < MAX_ROWS) {
          rows = [...rows, { oid: ev.oid, name: ev.name, valueType: ev.valueType, value: ev.value }];
        }
      } else if (ev.type === "done") {
        if (ev.error) {
          error = ev.error;
        } else {
          doneMsg = `${ev.cancelled ? "Cancelled" : "Done"}: ${ev.count.toLocaleString()} values.`;
        }
        walking = false;
      }
    };

    const config = {
      host,
      port,
      version,
      community,
      username,
      authProtocol,
      authPassword,
      privCipher,
      privPassword,
      startOid,
      timeoutMs: 3000,
    };

    try {
      await invoke("snmp_walk", { walkId, config, onEvent: channel });
    } catch (e) {
      error = String(e);
      walking = false;
    }
  }

  async function cancel() {
    try {
      await invoke("snmp_walk_cancel", { walkId });
    } catch {
      // ignore
    }
  }
</script>

<div class="panel">
  <header>
    <h1>SNMP Walk</h1>
    <p class="sub">
      Walk an OID subtree over SNMP v1, v2c, or v3. {mibTotal.toLocaleString()} MIB
      names loaded.
    </p>
  </header>

  <div class="grid">
    <div class="field grow">
      <label for="host">Host or IP</label>
      <input id="host" class="mono" bind:value={host} disabled={walking} spellcheck="false" />
    </div>
    <div class="field">
      <label for="port">Port</label>
      <input id="port" type="number" min="1" max="65535" bind:value={port} disabled={walking} />
    </div>
    <div class="field">
      <label for="ver">Version</label>
      <select id="ver" bind:value={version} disabled={walking}>
        <option value="v1">v1</option>
        <option value="v2c">v2c</option>
        <option value="v3">v3</option>
      </select>
    </div>
  </div>

  {#if version === "v3"}
    <div class="grid">
      <div class="field">
        <label for="user">Username</label>
        <input id="user" class="mono" bind:value={username} disabled={walking} spellcheck="false" />
      </div>
      <div class="field">
        <label for="authp">Auth</label>
        <select id="authp" bind:value={authProtocol} disabled={walking}>
          {#each AUTH_PROTOS as a (a)}<option value={a}>{a}</option>{/each}
        </select>
      </div>
      <div class="field grow">
        <label for="authpw">Auth password</label>
        <input id="authpw" type="password" bind:value={authPassword} disabled={walking || authProtocol === "none"} />
      </div>
    </div>
    <div class="grid">
      <div class="field">
        <label for="cipher">Privacy</label>
        <select id="cipher" bind:value={privCipher} disabled={walking || authProtocol === "none"}>
          {#each CIPHERS as c (c)}<option value={c}>{c}</option>{/each}
        </select>
      </div>
      <div class="field grow">
        <label for="privpw">Privacy password</label>
        <input id="privpw" type="password" bind:value={privPassword} disabled={walking || privCipher === "none" || authProtocol === "none"} />
      </div>
    </div>
  {:else}
    <div class="grid">
      <div class="field grow">
        <label for="comm">Community</label>
        <input id="comm" class="mono" bind:value={community} disabled={walking} spellcheck="false" />
      </div>
    </div>
  {/if}

  <div class="grid">
    <div class="field grow">
      <label for="oid">Start OID (name or dotted)</label>
      <input id="oid" class="mono" bind:value={startOid} disabled={walking} spellcheck="false" />
    </div>
  </div>

  <div class="row">
    <button class="secondary" onclick={loadMib} disabled={walking}>Load MIB</button>
    {#if walking}
      <button class="action stop" onclick={cancel}>Cancel</button>
    {:else}
      <button class="action" onclick={walk}>Walk</button>
    {/if}
    {#if doneMsg}<span class="done muted">{doneMsg}</span>{/if}
  </div>

  {#if error}
    <div class="error mono">{error}</div>
  {/if}

  {#if rows.length > 0}
    <div class="table-scroll">
      <table>
        <thead>
          <tr><th>OID</th><th>Name</th><th>Type</th><th>Value</th></tr>
        </thead>
        <tbody>
          {#each rows as r, i (i)}
            <tr>
              <td class="mono dim">{r.oid}</td>
              <td class="mono">{r.name}</td>
              <td class="dim">{r.valueType}</td>
              <td class="mono val">{r.value}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
    <p class="count muted">{rows.length.toLocaleString()} rows{#if rows.length >= MAX_ROWS} (display capped){/if}</p>
  {:else if walking}
    <p class="muted waiting">Walking...</p>
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
    margin: 0 0 1.25rem;
    color: var(--muted);
    font-size: 0.85rem;
  }

  .grid {
    display: flex;
    flex-wrap: wrap;
    gap: 0.75rem;
    margin-bottom: 0.75rem;
  }

  .field {
    display: flex;
    flex-direction: column;
    flex: 1 1 130px;
  }

  .field.grow {
    flex: 2 1 220px;
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

  input:disabled,
  select:disabled {
    opacity: 0.55;
  }

  .mono {
    font-family: var(--mono);
  }

  .row {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    margin: 0.3rem 0 1rem;
  }

  .secondary {
    background: var(--btn-bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.5rem 0.9rem;
    color: var(--fg);
    font-size: 0.85rem;
    cursor: pointer;
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

  .action.stop {
    background: var(--btn-bg);
    border-color: var(--error-border);
    color: var(--error-fg);
  }

  .done {
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

  .table-scroll {
    border: 1px solid var(--border);
    border-radius: 6px;
    overflow: auto;
    max-height: 55vh;
  }

  table {
    border-collapse: collapse;
    width: 100%;
    font-size: 0.8rem;
  }

  th {
    text-align: left;
    color: var(--muted);
    font-weight: 500;
    padding: 0.4rem 0.6rem;
    border-bottom: 1px solid var(--border);
    position: sticky;
    top: 0;
    background: var(--sidebar-bg);
    white-space: nowrap;
  }

  td {
    padding: 0.3rem 0.6rem;
    border-bottom: 1px solid var(--border);
    vertical-align: top;
  }

  tr:last-child td {
    border-bottom: none;
  }

  .dim {
    color: var(--muted);
    white-space: nowrap;
  }

  .val {
    word-break: break-word;
  }

  .count {
    font-size: 0.78rem;
    margin: 0.5rem 0 0;
  }

  .waiting {
    font-size: 0.85rem;
  }
</style>
