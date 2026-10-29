<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import type { BuildError } from "$lib/tools/types";
  import CommandOutput from "./CommandOutput.svelte";

  interface Props {
    onsave: (title: string, notes: string, command: string) => void;
  }
  let { onsave }: Props = $props();

  let showStatus = $state(true);
  let gateway = $state("");
  let tunnelBy = $state<"name" | "number">("name");
  let tunnels = $state("");
  let tunnelNumber = $state("");
  let resetFirst = $state(true);
  let vdom = $state("");
  let remAddr4 = $state("");
  let locAddr4 = $state("");
  let remAddr6 = $state("");
  let dstPort = $state("");
  let listFilter = $state(false);
  let timestamps = $state(true);
  let level = $state("-1");
  let stopBlock = $state(true);

  let command = $state("");
  let error = $state<BuildError | null>(null);

  $effect(() => {
    const input = {
      kind: "vpn",
      showStatus, gateway, tunnelBy, tunnels, tunnelNumber, resetFirst, vdom,
      remAddr4, locAddr4, remAddr6, dstPort, listFilter, timestamps, level, stopBlock,
    };
    invoke<string>("fortinet_build", { input })
      .then((c) => {
        command = c;
        error = null;
      })
      .catch((e) => (error = e as BuildError));
  });

  const bad = (f: string) => error?.field === f;
  const title = $derived(["IKE debug", gateway, remAddr4 && `peer ${remAddr4}`].filter(Boolean).join(" "));
  const unfiltered = $derived(!gateway && !remAddr4 && !locAddr4 && !remAddr6 && !dstPort);
</script>

<p class="help">
  Check IPsec gateway and tunnel state, then run a filtered live IKE debug with
  <code>diagnose vpn ike log filter</code> and <code>diagnose debug application ike</code>.
  Filter options follow FortiOS 7.6.
</p>

<div class="grid">
  <div class="field"><label for="v-gw">Phase 1 name</label><input id="v-gw" class="mono" class:bad={bad("gateway")} bind:value={gateway} placeholder="to-branch1" spellcheck="false" /></div>
  <div class="field"><label for="v-rem">Remote gateway (rem-addr4)</label><input id="v-rem" class="mono" class:bad={bad("remAddr4")} bind:value={remAddr4} placeholder="203.0.113.10" spellcheck="false" /></div>
  <div class="field"><label for="v-loc">Local gateway (loc-addr4)</label><input id="v-loc" class="mono" class:bad={bad("locAddr4")} bind:value={locAddr4} spellcheck="false" /></div>
</div>
<div class="grid">
  <div class="field"><label for="v-rem6">Remote gateway IPv6 (rem-addr6)</label><input id="v-rem6" class="mono" class:bad={bad("remAddr6")} bind:value={remAddr6} spellcheck="false" /></div>
  <div class="field small"><label for="v-port">Destination port</label><input id="v-port" class="mono" class:bad={bad("dstPort")} bind:value={dstPort} placeholder="500 or 4500" spellcheck="false" /></div>
  <div class="field small"><label for="v-vd">VDOM index (-1 = all)</label><input id="v-vd" class="mono" class:bad={bad("vdom")} bind:value={vdom} spellcheck="false" /></div>
  <div class="field small"><label for="v-level">IKE debug level</label><input id="v-level" class="mono" class:bad={bad("level")} bind:value={level} spellcheck="false" /></div>
</div>

<div class="checks">
  <label class="check"><input type="checkbox" bind:checked={showStatus} /> Show gateway and tunnel status first</label>
</div>
{#if showStatus}
  <div class="grid">
    <div class="field small">
      <label for="v-by">List tunnels by</label>
      <select id="v-by" bind:value={tunnelBy}>
        <option value="name">Name</option>
        <option value="number">Number</option>
      </select>
    </div>
    {#if tunnelBy === "name"}
      <div class="field"><label for="v-tun">Tunnel names (up to 8, blank = all)</label><input id="v-tun" class="mono" class:bad={bad("tunnels")} bind:value={tunnels} placeholder="spoke1, spoke2" spellcheck="false" /></div>
    {:else}
      <div class="field small"><label for="v-num">Tunnel number</label><input id="v-num" class="mono" class:bad={bad("tunnelNumber")} bind:value={tunnelNumber} spellcheck="false" /></div>
    {/if}
  </div>
{/if}

<div class="checks">
  <label class="check"><input type="checkbox" bind:checked={resetFirst} /> Reset debug state first</label>
  <label class="check"><input type="checkbox" bind:checked={listFilter} /> Show the active filter</label>
  <label class="check"><input type="checkbox" bind:checked={timestamps} /> Console timestamps</label>
  <label class="check"><input type="checkbox" bind:checked={stopBlock} /> Append stop-debug block</label>
</div>
{#if unfiltered}
  <p class="warnline">No IKE filter set: with many tunnels the debug mixes every negotiation together. Filter by phase 1 name or remote gateway.</p>
{/if}

<CommandOutput category="vpn" defaultTitle={title} {command} {error} onsave={(t, n) => onsave(t, n, command)} />
