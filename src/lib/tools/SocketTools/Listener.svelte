<script lang="ts">
  // Listen on a TCP or UDP port and show connections and data as they arrive.
  import { Channel, invoke } from "@tauri-apps/api/core";
  import { selectOnFocus } from "$lib/actions/selectOnFocus";
  import ChunkView from "./ChunkView.svelte";
  import { newId, stamp, type ListenEvent, type LogLine, type PayloadKind, type Proto } from "./types";

  /** Lines kept on screen; older ones are dropped. */
  const MAX_LINES = 2000;

  let proto = $state<Proto>("tcp");
  let bind = $state("");
  let port = $state(9000);
  let echo = $state(false);
  let banner = $state("");
  let bannerKind = $state<PayloadKind>("text");
  let hex = $state(false);

  let log = $state<LogLine<ListenEvent>[]>([]);
  let dropped = $state(0);
  let running = $state(false);
  let listeningOn = $state("");
  let error = $state("");
  let bytes = $state(0);
  let id = 0;
  let seq = 0;

  async function start() {
    error = "";
    log = [];
    dropped = 0;
    bytes = 0;
    id = newId();
    running = true;
    const ch = new Channel<ListenEvent>();
    ch.onmessage = (ev) => {
      if (ev.type === "started") listeningOn = ev.addr;
      if (ev.type === "data") bytes += ev.chunk.bytes;
      const next = [...log, { id: seq++, at: new Date(), ev }];
      if (next.length > MAX_LINES) {
        dropped += next.length - MAX_LINES;
        next.splice(0, next.length - MAX_LINES);
      }
      log = next;
    };
    try {
      await invoke("sock_listen", {
        id,
        req: { proto, bind: bind.trim(), port, echo, banner, bannerKind },
        onEvent: ch,
      });
    } catch (e) {
      error = String(e);
    } finally {
      running = false;
      listeningOn = "";
    }
  }

  function stop() {
    void invoke("sock_stop", { id });
  }
</script>

<div class="row">
  <div class="field">
    <span class="lbl">Protocol</span>
    <div class="seg">
      <button class:on={proto === "tcp"} onclick={() => (proto = "tcp")} disabled={running}>TCP</button>
      <button class:on={proto === "udp"} onclick={() => (proto = "udp")} disabled={running}>UDP</button>
    </div>
  </div>
  <div class="field grow">
    <label for="l-bind">Bind address</label>
    <input id="l-bind" class="mono" bind:value={bind} spellcheck="false" placeholder="all IPv4 addresses" disabled={running} />
  </div>
  <div class="field port">
    <label for="l-port">Port</label>
    <input id="l-port" class="mono" type="number" min="1" max="65535" bind:value={port} use:selectOnFocus disabled={running} />
  </div>
</div>

<div class="row">
  <label class="inline"><input type="checkbox" bind:checked={echo} disabled={running} /> Echo data back</label>
  <span class="spacer"></span>
  {#if running}
    <button class="second" onclick={stop}>Stop</button>
  {:else}
    <button class="run" onclick={start}>Start listening</button>
  {/if}
</div>
<details class="adv">
  <summary>Reply on connect (optional)</summary>
  <div class="lblrow">
    <span class="hint">Sent once to each new TCP connection or UDP sender.</span>
    <div class="seg small">
      <button class:on={bannerKind === "text"} onclick={() => (bannerKind = "text")}>Text</button>
      <button class:on={bannerKind === "hex"} onclick={() => (bannerKind = "hex")}>Hex</button>
    </div>
  </div>
  <textarea class="mono" rows="2" bind:value={banner} spellcheck="false" disabled={running} placeholder="for example a fake service banner"></textarea>
</details>

{#if error}<div class="error mono">{error}</div>{/if}
{#if running && listeningOn}
  <div class="status">Listening on {proto.toUpperCase()} {listeningOn} · {bytes} bytes received. Your firewall may need to allow it.</div>
{/if}

{#if log.length}
  <div class="bar">
    <label class="inline"><input type="checkbox" bind:checked={hex} /> Hex view</label>
    {#if dropped}<span class="muted small">{dropped} older lines dropped</span>{/if}
  </div>
  <div class="log">
    {#each log as l (l.id)}
      {@const e = l.ev}
      <div class="line">
        <span class="t mono">{stamp(l.at)}</span>
        {#if e.type === "started"}
          <span>Listening on {e.addr}</span>
        {:else if e.type === "accepted"}
          <span>#{e.conn} connection from <span class="mono">{e.peer}</span></span>
        {:else if e.type === "data"}
          <span>{e.conn !== null ? `#${e.conn} ` : ""}<span class="mono">{e.peer}</span> sent {e.chunk.bytes} bytes</span>
        {:else if e.type === "closed"}
          <span>#{e.conn} {e.peer} closed: {e.reason}, {e.bytes} bytes</span>
        {:else if e.type === "rejected"}
          <span class="warnc">Rejected {e.peer}: {e.reason}</span>
        {:else if e.type === "stopped"}
          <span>Stopped</span>
        {/if}
      </div>
      {#if e.type === "data"}<ChunkView chunk={e.chunk} {hex} />{/if}
    {/each}
  </div>
{/if}
