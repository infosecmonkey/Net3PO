<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import { loadCollection } from "$lib/store";
  import type { BuildError } from "$lib/tools/types";
  import CommandOutput from "./CommandOutput.svelte";
  import { COMMON_INTERFACES, TOS_KEYWORDS } from "./options";

  interface Props {
    onsave: (title: string, notes: string, command: string) => void;
  }
  let { onsave }: Props = $props();

  let target = $state("");
  let resetFirst = $state(true);
  let source = $state("");
  let iface = $state("");
  let repeatCount = $state("");
  let timeout = $state("");
  let dataSize = $state("");
  let tos = $state("");
  let pattern = $state("");
  let interval = $state("");
  let ttl = $state("");
  let vrf = $state("");
  let useSdwan = $state(false);
  let dfBit = $state(false);
  let adaptive = $state(false);
  let validateReply = $state(false);
  let viewSettings = $state(true);

  let command = $state("");
  let error = $state<BuildError | null>(null);
  let myIfaces = $state<string[]>([]);

  $effect(() => {
    loadCollection<string>("fortinet_interfaces")
      .then((l) => (myIfaces = l.items.filter((x) => typeof x === "string")))
      .catch(() => {});
  });

  $effect(() => {
    const input = {
      kind: "ping",
      target, resetFirst, source, interface: iface, repeatCount, timeout, dataSize,
      tos, pattern, interval, ttl, vrf, useSdwan, dfBit, adaptive, validateReply, viewSettings,
    };
    invoke<string>("fortinet_build", { input })
      .then((c) => {
        command = c;
        error = null;
      })
      .catch((e) => (error = e as BuildError));
  });

  const bad = (f: string) => error?.field === f && (f !== "target" || target.trim() !== "");
  const shownError = $derived(error?.field === "target" && target.trim() === "" ? null : error);
</script>

<p class="help">
  Ping from the FortiGate itself with <code>exec ping-options</code> and <code>exec ping</code>:
  pick the source IP or egress interface to test a specific path. Blank fields are omitted.
</p>

<div class="grid">
  <div class="field"><label for="p-target">Destination</label><input id="p-target" class="mono" class:bad={bad("target")} bind:value={target} placeholder="8.8.8.8 or fortinet.com" spellcheck="false" /></div>
  <div class="field"><label for="p-src">Source IP (or auto)</label><input id="p-src" class="mono" class:bad={bad("source")} bind:value={source} placeholder="10.10.10.1" spellcheck="false" disabled={iface.trim() !== ""} /></div>
  <div class="field">
    <label for="p-if">Egress interface (or auto)</label>
    <input id="p-if" class="mono" class:bad={bad("interface")} bind:value={iface} list="p-if-list" placeholder="wan1" spellcheck="false" disabled={source.trim() !== ""} />
    <datalist id="p-if-list">{#each [...COMMON_INTERFACES.filter((i) => i !== "any"), ...myIfaces] as i (i)}<option value={i}></option>{/each}</datalist>
  </div>
</div>
<div class="grid">
  <div class="field small"><label for="p-count">Repeat count</label><input id="p-count" class="mono" class:bad={bad("repeatCount")} bind:value={repeatCount} placeholder="5" spellcheck="false" /></div>
  <div class="field small"><label for="p-to">Timeout (s)</label><input id="p-to" class="mono" class:bad={bad("timeout")} bind:value={timeout} spellcheck="false" /></div>
  <div class="field small"><label for="p-size">Data size (bytes)</label><input id="p-size" class="mono" class:bad={bad("dataSize")} bind:value={dataSize} placeholder="1472" spellcheck="false" /></div>
  <div class="field small">
    <label for="p-tos">TOS</label>
    <select id="p-tos" bind:value={tos}>
      <option value="">(omit)</option>
      {#each TOS_KEYWORDS as k (k)}<option value={k}>{k}</option>{/each}
    </select>
  </div>
  <div class="field small"><label for="p-pat">Payload pattern (hex)</label><input id="p-pat" class="mono" class:bad={bad("pattern")} bind:value={pattern} placeholder="ff" spellcheck="false" /></div>
</div>
<div class="grid">
  <div class="field small"><label for="p-int">Interval (s)</label><input id="p-int" class="mono" class:bad={bad("interval")} bind:value={interval} spellcheck="false" /></div>
  <div class="field small"><label for="p-ttl">TTL</label><input id="p-ttl" class="mono" class:bad={bad("ttl")} bind:value={ttl} spellcheck="false" /></div>
  <div class="field small"><label for="p-vrf">VRF ID</label><input id="p-vrf" class="mono" class:bad={bad("vrf")} bind:value={vrf} spellcheck="false" /></div>
</div>

<div class="checks">
  <label class="check"><input type="checkbox" bind:checked={resetFirst} /> Reset ping options first</label>
  <label class="check"><input type="checkbox" bind:checked={useSdwan} /> Use SD-WAN rules for egress</label>
  <label class="check"><input type="checkbox" bind:checked={dfBit} /> Set DF bit</label>
  <label class="check"><input type="checkbox" bind:checked={adaptive} /> Adaptive ping</label>
  <label class="check"><input type="checkbox" bind:checked={validateReply} /> Validate reply</label>
  <label class="check"><input type="checkbox" bind:checked={viewSettings} /> Show settings before ping</label>
</div>
<p class="note muted">
  Source IP and egress interface are either/or: clear one to use the other.
  Ping options stay set for your admin session, so a reset first avoids inheriting an earlier source or
  size. For an MTU test, set DF and a data size: 1472 bytes of data makes a 1500-byte packet.
</p>

{#if target.trim() === ""}
  <p class="muted note">Enter a destination to build the command.</p>
{:else}
  <CommandOutput category="ping" defaultTitle={`Ping ${target}${source ? ` from ${source}` : ""}${iface ? ` via ${iface}` : ""}`} {command} error={shownError} onsave={(t, n) => onsave(t, n, command)} />
{/if}
