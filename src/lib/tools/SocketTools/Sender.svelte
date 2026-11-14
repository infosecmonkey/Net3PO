<script lang="ts">
  // Send one TCP or UDP payload and show what comes back, timestamped.
  import { Channel, invoke } from "@tauri-apps/api/core";
  import ExportMenu from "$lib/components/ExportMenu.svelte";
  import { selectOnFocus } from "$lib/actions/selectOnFocus";
  import ChunkView from "./ChunkView.svelte";
  import { buildSendReport } from "./report";
  import { newId, stamp, type LogLine, type PayloadKind, type Proto, type SendEvent } from "./types";

  let host = $state("");
  let port = $state<number | null>(null);
  let proto = $state<Proto>("tcp");
  let kind = $state<PayloadKind>("text");
  let payload = $state("");
  let waitMs = $state(3000);
  let timeoutMs = $state(5000);
  let hex = $state(false);

  let log = $state<LogLine<SendEvent>[]>([]);
  let running = $state(false);
  let error = $state("");
  let id = 0;
  let seq = 0;

  async function send() {
    if (!host.trim() || !port) {
      error = "Enter a host and port.";
      return;
    }
    error = "";
    log = [];
    id = newId();
    running = true;
    const ch = new Channel<SendEvent>();
    ch.onmessage = (ev) => {
      log = [...log, { id: seq++, at: new Date(), ev }];
    };
    try {
      await invoke("sock_send", {
        id,
        req: { host: host.trim(), port, proto, payload, kind, waitMs, connectTimeoutMs: timeoutMs },
        onEvent: ch,
      });
    } catch (e) {
      error = String(e);
    } finally {
      running = false;
    }
  }

  function stop() {
    void invoke("sock_stop", { id });
  }
</script>

<div class="row">
  <div class="field grow">
    <label for="s-host">Host</label>
    <input id="s-host" class="mono" bind:value={host} spellcheck="false" autocapitalize="off" placeholder="hostname or IP" />
  </div>
  <div class="field port">
    <label for="s-port">Port</label>
    <input id="s-port" class="mono" type="number" min="1" max="65535" bind:value={port} placeholder="port" />
  </div>
  <div class="field">
    <span class="lbl">Protocol</span>
    <div class="seg">
      <button class:on={proto === "tcp"} onclick={() => (proto = "tcp")}>TCP</button>
      <button class:on={proto === "udp"} onclick={() => (proto = "udp")}>UDP</button>
    </div>
  </div>
</div>

<div class="field">
  <div class="lblrow">
    <label for="s-payload">Payload</label>
    <div class="seg small">
      <button class:on={kind === "text"} onclick={() => (kind = "text")}>Text</button>
      <button class:on={kind === "hex"} onclick={() => (kind = "hex")}>Hex</button>
    </div>
  </div>
  <textarea id="s-payload" class="mono" rows="4" bind:value={payload} spellcheck="false"
    placeholder={kind === "text" ? "text; escapes \\r \\n \\t \\0 \\xHH" : "hex bytes, e.g. 16 03 01"}></textarea>
</div>

<div class="row">
  <label class="inline">Wait for replies (ms) <input class="num mono" type="number" min="0" max="120000" bind:value={waitMs} use:selectOnFocus /></label>
  {#if proto === "tcp"}
    <label class="inline">Connect timeout (ms) <input class="num mono" type="number" min="100" max="60000" bind:value={timeoutMs} use:selectOnFocus /></label>
  {/if}
  <span class="spacer"></span>
  {#if running}
    <button class="second" onclick={stop}>Stop</button>
  {:else}
    <button class="run" onclick={send}>Send</button>
  {/if}
</div>

{#if error}<div class="error mono">{error}</div>{/if}

{#if log.length}
  <div class="bar">
    <label class="inline"><input type="checkbox" bind:checked={hex} /> Hex view</label>
    <ExportMenu build={() => buildSendReport(`${host}:${port}`, proto, log)} name="socket-send" />
  </div>
  <div class="log">
    {#each log as l (l.id)}
      {@const e = l.ev}
      <div class="line">
        <span class="t mono">{stamp(l.at)}</span>
        {#if e.type === "resolved"}
          <span>Target {e.addr}</span>
        {:else if e.type === "connected"}
          <span>Connected in {e.ms.toFixed(2)} ms from {e.local}</span>
        {:else if e.type === "sent"}
          <span>Sent {e.bytes} bytes</span>
        {:else if e.type === "received"}
          <span>Received {e.chunk.bytes} bytes at +{e.atMs.toFixed(0)} ms</span>
        {:else if e.type === "done"}
          <span><strong>Done:</strong> {e.reason}. {e.received} bytes received.</span>
        {/if}
      </div>
      {#if e.type === "received"}<ChunkView chunk={e.chunk} {hex} />{/if}
      {#if e.type === "done" && e.note}<div class="note">{e.note}</div>{/if}
    {/each}
  </div>
{/if}

