<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import type { BuildError } from "$lib/tools/types";
  import CommandOutput from "./CommandOutput.svelte";

  interface Props {
    onsave: (title: string, notes: string, command: string) => void;
  }
  let { onsave }: Props = $props();

  type Variant = "top" | "topAll" | "topMem" | "topFd" | "topSockmem";
  const VARIANTS: { value: Variant; label: string; help: string }[] = [
    { value: "top", label: "top", help: "Top processes, refreshing. Press p (CPU), m (memory), q (quit) while running." },
    { value: "topAll", label: "top-all", help: "Like top, but per thread." },
    { value: "topMem", label: "top-mem", help: "Processes using the most memory. Good for leaks and conserve mode." },
    { value: "topFd", label: "top-fd", help: "Processes with the most active file descriptors." },
    { value: "topSockmem", label: "top-sockmem", help: "Processes using the most socket memory." },
  ];

  let variant = $state<Variant>("top");
  let delay = $state("");
  let lines = $state("");
  let iterations = $state("");
  let count = $state("");
  let perfStatus = $state(true);
  let perfTop = $state(false);
  let sysinfoMemory = $state(false);
  let sysinfoCpu = $state(false);
  let sysinfoInterrupts = $state(false);
  let sysinfoSlab = $state(false);
  let sysinfoConserve = $state(false);

  let command = $state("");
  let error = $state<BuildError | null>(null);

  $effect(() => {
    const input = {
      kind: "system", variant, delay, lines, iterations, count,
      perfStatus, perfTop, sysinfoMemory, sysinfoCpu, sysinfoInterrupts, sysinfoSlab, sysinfoConserve,
    };
    invoke<string>("fortinet_build", { input })
      .then((c) => {
        command = c;
        error = null;
      })
      .catch((e) => (error = e as BuildError));
  });

  const bad = (f: string) => error?.field === f;
  const interactive = $derived(variant === "top" || variant === "topAll");
  const help = $derived(VARIANTS.find((v) => v.value === variant)?.help ?? "");
</script>

<p class="help">CPU, memory, and process usage on the FortiGate. Options match FortiOS 7.6.</p>

<div class="grid">
  <div class="field small">
    <label for="y-var">Command</label>
    <select id="y-var" bind:value={variant}>
      {#each VARIANTS as v (v.value)}<option value={v.value}>diagnose sys {v.label}</option>{/each}
    </select>
  </div>
  {#if interactive}
    <div class="field small"><label for="y-delay">Delay (s, default 5)</label><input id="y-delay" class="mono" class:bad={bad("delay")} bind:value={delay} spellcheck="false" /></div>
    <div class="field small"><label for="y-lines">Max lines (default 20)</label><input id="y-lines" class="mono" class:bad={bad("lines")} bind:value={lines} spellcheck="false" /></div>
    <div class="field small"><label for="y-iter">Iterations (default unlimited)</label><input id="y-iter" class="mono" class:bad={bad("iterations")} bind:value={iterations} spellcheck="false" /></div>
  {:else}
    <div class="field small"><label for="y-count">Processes (default 5)</label><input id="y-count" class="mono" class:bad={bad("count")} bind:value={count} spellcheck="false" /></div>
  {/if}
</div>
<p class="note muted">{help}{#if interactive} Arguments are positional, so a later one fills in the defaults before it.{/if}</p>

<h3>Run first</h3>
<div class="checks">
  <label class="check"><input type="checkbox" bind:checked={perfStatus} /> Performance status</label>
  <label class="check"><input type="checkbox" bind:checked={perfTop} /> Performance top</label>
  <label class="check"><input type="checkbox" bind:checked={sysinfoMemory} /> Memory info</label>
  <label class="check"><input type="checkbox" bind:checked={sysinfoCpu} /> CPU info</label>
  <label class="check"><input type="checkbox" bind:checked={sysinfoInterrupts} /> Interrupts</label>
  <label class="check"><input type="checkbox" bind:checked={sysinfoSlab} /> Memory allocation (slab)</label>
  <label class="check"><input type="checkbox" bind:checked={sysinfoConserve} /> Conserve mode status</label>
</div>

<CommandOutput category="system" defaultTitle={`System ${VARIANTS.find((v) => v.value === variant)?.label ?? "top"}`} {command} {error} onsave={(t, n) => onsave(t, n, command)} />

<style>
  h3 {
    font-size: 0.84rem;
    font-weight: 600;
    margin: 1rem 0 0.4rem;
  }
</style>
