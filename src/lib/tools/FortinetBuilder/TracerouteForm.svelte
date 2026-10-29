<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import { loadCollection } from "$lib/store";
  import type { BuildError } from "$lib/tools/types";
  import CommandOutput from "./CommandOutput.svelte";
  import { COMMON_INTERFACES } from "./options";

  interface Props {
    onsave: (title: string, notes: string, command: string) => void;
  }
  let { onsave }: Props = $props();

  let target = $state("");
  let resetFirst = $state(true);
  let source = $state("");
  let device = $state("");
  let queries = $state("");
  let vrf = $state("");
  let useSdwan = $state(false);
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
    const input = { kind: "traceroute", target, resetFirst, source, device, queries, vrf, useSdwan, viewSettings };
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
  Trace from the FortiGate with <code>exec traceroute-options</code> and <code>exec traceroute</code>,
  sourced from a specific IP or interface. Blank fields are omitted.
</p>

<div class="grid">
  <div class="field"><label for="t-target">Destination</label><input id="t-target" class="mono" class:bad={bad("target")} bind:value={target} placeholder="1.1.1.1 or fortinet.com" spellcheck="false" /></div>
  <div class="field"><label for="t-src">Source IP (or auto)</label><input id="t-src" class="mono" class:bad={bad("source")} bind:value={source} spellcheck="false" /></div>
  <div class="field">
    <label for="t-dev">Device (interface)</label>
    <input id="t-dev" class="mono" class:bad={bad("device")} bind:value={device} list="t-dev-list" placeholder="wan1 or auto" spellcheck="false" />
    <datalist id="t-dev-list">{#each [...COMMON_INTERFACES.filter((i) => i !== "any"), ...myIfaces] as i (i)}<option value={i}></option>{/each}</datalist>
  </div>
</div>
<div class="grid">
  <div class="field small"><label for="t-q">Queries per hop</label><input id="t-q" class="mono" class:bad={bad("queries")} bind:value={queries} placeholder="3" spellcheck="false" /></div>
  <div class="field small"><label for="t-vrf">VRF ID</label><input id="t-vrf" class="mono" class:bad={bad("vrf")} bind:value={vrf} spellcheck="false" /></div>
</div>

<div class="checks">
  <label class="check"><input type="checkbox" bind:checked={resetFirst} /> Reset traceroute options first</label>
  <label class="check"><input type="checkbox" bind:checked={useSdwan} /> Use SD-WAN rules for egress</label>
  <label class="check"><input type="checkbox" bind:checked={viewSettings} /> Show settings before trace</label>
</div>

{#if target.trim() === ""}
  <p class="muted note">Enter a destination to build the command.</p>
{:else}
  <CommandOutput category="traceroute" defaultTitle={`Traceroute ${target}${source ? ` from ${source}` : ""}`} {command} error={shownError} onsave={(t, n) => onsave(t, n, command)} />
{/if}
