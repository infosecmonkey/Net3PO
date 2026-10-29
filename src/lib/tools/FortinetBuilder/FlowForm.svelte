<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import type { BuildError } from "$lib/tools/types";
  import CommandOutput from "./CommandOutput.svelte";
  import { PROTOCOLS } from "./options";

  interface Props {
    onsave: (title: string, notes: string, command: string) => void;
  }
  let { onsave }: Props = $props();

  let addr = $state("");
  let saddr = $state("");
  let daddr = $state("");
  let port = $state("");
  let sport = $state("");
  let dport = $state("");
  let proto = $state<number | null>(null);
  let vdom = $state("");
  let traceCount = $state("1000");
  let resetFirst = $state(true);
  let showFunctionName = $state(true);
  let showIprope = $state(false);
  let timestamps = $state(true);
  let stopBlock = $state(true);

  let command = $state("");
  let error = $state<BuildError | null>(null);

  $effect(() => {
    const input = {
      kind: "flow",
      addr, saddr, daddr, port, sport, dport, proto, vdom, traceCount,
      resetFirst, showFunctionName, showIprope, timestamps, stopBlock,
    };
    invoke<string>("fortinet_build", { input })
      .then((c) => {
        command = c;
        error = null;
      })
      .catch((e) => (error = e as BuildError));
  });

  const bad = (f: string) => error?.field === f;
  const title = $derived(
    ["Flow", addr || saddr || daddr, (port || dport) && `:${port || dport}`].filter(Boolean).join(" "),
  );
  const unfiltered = $derived(!addr && !saddr && !daddr && !port && !sport && !dport && proto === null);
</script>

<p class="help">
  Trace how the FortiGate handles a packet with <code>diagnose debug flow</code>: route lookup,
  policy match, NAT, and session creation. Start the trace, then generate the traffic.
</p>

<div class="grid">
  <div class="field"><label for="f-addr">Address (either)</label><input id="f-addr" class="mono" class:bad={bad("addr")} bind:value={addr} placeholder="10.0.0.5" spellcheck="false" /></div>
  <div class="field"><label for="f-saddr">Source address</label><input id="f-saddr" class="mono" class:bad={bad("saddr")} bind:value={saddr} spellcheck="false" /></div>
  <div class="field"><label for="f-daddr">Destination address</label><input id="f-daddr" class="mono" class:bad={bad("daddr")} bind:value={daddr} spellcheck="false" /></div>
</div>
<div class="grid">
  <div class="field small"><label for="f-port">Port (either)</label><input id="f-port" class="mono" class:bad={bad("port")} bind:value={port} spellcheck="false" /></div>
  <div class="field small"><label for="f-sport">Source port</label><input id="f-sport" class="mono" class:bad={bad("sport")} bind:value={sport} spellcheck="false" /></div>
  <div class="field small"><label for="f-dport">Destination port</label><input id="f-dport" class="mono" class:bad={bad("dport")} bind:value={dport} placeholder="443" spellcheck="false" /></div>
  <div class="field small">
    <label for="f-proto">Protocol</label>
    <select id="f-proto" bind:value={proto}>
      {#each PROTOCOLS as p (p.label)}<option value={p.number}>{p.label}</option>{/each}
    </select>
  </div>
  <div class="field small"><label for="f-vdom">VDOM index</label><input id="f-vdom" class="mono" class:bad={bad("vdom")} bind:value={vdom} spellcheck="false" /></div>
  <div class="field small"><label for="f-count">Trace count</label><input id="f-count" class="mono" class:bad={bad("traceCount")} bind:value={traceCount} spellcheck="false" /></div>
</div>

<div class="checks">
  <label class="check"><input type="checkbox" bind:checked={resetFirst} /> Reset debug state first</label>
  <label class="check"><input type="checkbox" bind:checked={showFunctionName} /> Show function names</label>
  <label class="check"><input type="checkbox" bind:checked={showIprope} /> Show iprope (policy lookup)</label>
  <label class="check"><input type="checkbox" bind:checked={timestamps} /> Console timestamps</label>
  <label class="check"><input type="checkbox" bind:checked={stopBlock} /> Append stop-debug block</label>
</div>
{#if unfiltered}
  <p class="warnline">No address, port, or protocol filter: on a busy unit an unfiltered flow trace floods the console.</p>
{/if}

<CommandOutput category="flow" defaultTitle={title} {command} {error} onsave={(t, n) => onsave(t, n, command)} />
