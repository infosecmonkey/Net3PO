<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import type { BuildError } from "$lib/tools/types";
  import CommandOutput from "./CommandOutput.svelte";

  interface Props {
    onsave: (title: string, notes: string, command: string) => void;
  }
  let { onsave }: Props = $props();

  /** `diagnose sys ha dump-by` targets (`core::ha::DUMP_BY`). */
  const DUMP_BY = ["group", "vcluster", "vdom", "device", "kernel", "rcache", "debug-zone"];

  let getStatus = $state(true);
  let diagStatus = $state(false);
  let history = $state(false);
  let stats = $state(false);
  let heartbeat = $state(false);
  let mac = $state(false);
  let syncStats = $state(false);
  let hasyncStats = $state(false);
  let checksumCluster = $state(false);
  let serials = $state("");
  let checksumShow = $state(false);
  let checksumScope = $state("");
  let showNonsync = $state(false);
  let recalculate = $state(false);
  let dumpBy = $state("");
  let debugHatalk = $state(false);
  let debugHasync = $state(false);
  let resetFirst = $state(true);
  let timestamps = $state(true);
  let level = $state("-1");
  let stopBlock = $state(true);
  let resetUptime = $state<"none" | "all" | "primaryOnly">("none");
  let synchronize = $state<"none" | "start" | "stop">("none");
  let manage = $state(false);
  let manageIndex = $state("0");
  let manageAdmin = $state("");

  let command = $state("");
  let error = $state<BuildError | null>(null);

  $effect(() => {
    const input = {
      kind: "ha",
      getStatus, diagStatus, history, stats, heartbeat, mac, syncStats, hasyncStats,
      checksumCluster, serials, checksumShow, checksumScope, showNonsync, recalculate, dumpBy,
      debugHatalk, debugHasync, resetFirst, timestamps, level, stopBlock,
      resetUptime, synchronize, manage, manageIndex, manageAdmin,
    };
    invoke<string>("fortinet_build", { input })
      .then((c) => {
        command = c;
        error = null;
      })
      .catch((e) => (error = e as BuildError));
  });

  const bad = (f: string) => error?.field === f;
  const changes = $derived(resetUptime !== "none" || synchronize !== "none" || manage);
</script>

<p class="help">
  Check FortiGate HA cluster health: status, failover history, sync, checksums, and a live
  hatalk/hasync debug. Options match FortiOS 7.6.
</p>

<h3>Status and health</h3>
<div class="checks">
  <label class="check"><input type="checkbox" bind:checked={getStatus} /> get system ha status</label>
  <label class="check"><input type="checkbox" bind:checked={diagStatus} /> HA status (diagnose)</label>
  <label class="check"><input type="checkbox" bind:checked={history} /> Failover history</label>
  <label class="check"><input type="checkbox" bind:checked={stats} /> HA statistics</label>
  <label class="check"><input type="checkbox" bind:checked={heartbeat} /> Heartbeat stats</label>
  <label class="check"><input type="checkbox" bind:checked={mac} /> Virtual MAC info</label>
  <label class="check"><input type="checkbox" bind:checked={syncStats} /> Sync statistics</label>
  <label class="check"><input type="checkbox" bind:checked={hasyncStats} /> hasync daemon stats</label>
</div>

<h3>Checksums and dumps</h3>
<div class="checks">
  <label class="check"><input type="checkbox" bind:checked={checksumCluster} /> Cluster checksum</label>
  <label class="check"><input type="checkbox" bind:checked={checksumShow} /> Show checksum</label>
  <label class="check"><input type="checkbox" bind:checked={showNonsync} /> Show non-sync checksum</label>
  <label class="check"><input type="checkbox" bind:checked={recalculate} /> Recalculate checksum</label>
</div>
<div class="grid">
  {#if checksumCluster}
    <div class="field"><label for="h-ser">Serial numbers (up to 16, blank = all members)</label><input id="h-ser" class="mono" class:bad={bad("serials")} bind:value={serials} placeholder="FGVM08TM24000123" spellcheck="false" /></div>
  {/if}
  {#if checksumShow}
    <div class="field small"><label for="h-scope">Checksum scope (blank = system)</label><input id="h-scope" class="mono" class:bad={bad("checksumScope")} bind:value={checksumScope} placeholder="global or root" spellcheck="false" /></div>
  {/if}
  <div class="field small">
    <label for="h-dump">Dump HA data by</label>
    <select id="h-dump" bind:value={dumpBy}>
      <option value="">(none)</option>
      {#each DUMP_BY as d (d)}<option value={d}>{d}</option>{/each}
    </select>
  </div>
</div>
{#if recalculate}
  <p class="note muted">Recalculate is the usual fix when <code>checksum cluster</code> shows members disagreeing; compare again afterwards.</p>
{/if}

<h3>Live debug</h3>
<div class="checks">
  <label class="check"><input type="checkbox" bind:checked={debugHatalk} /> hatalk (heartbeat, election)</label>
  <label class="check"><input type="checkbox" bind:checked={debugHasync} /> hasync (config sync)</label>
</div>
{#if debugHatalk || debugHasync}
  <div class="grid">
    <div class="field small"><label for="h-level">Debug level</label><input id="h-level" class="mono" class:bad={bad("level")} bind:value={level} spellcheck="false" /></div>
  </div>
  <div class="checks">
    <label class="check"><input type="checkbox" bind:checked={resetFirst} /> Reset debug state first</label>
    <label class="check"><input type="checkbox" bind:checked={timestamps} /> Console timestamps</label>
    <label class="check"><input type="checkbox" bind:checked={stopBlock} /> Append stop-debug block</label>
  </div>
{/if}

<div class="danger-box">
  <h3>Changes cluster state</h3>
  <p class="note">
    These act on the cluster. Resetting uptime can trigger a failover; synchronize starts or stops
    config sync; manage logs in to a peer unit. They are placed last, under a comment header.
  </p>
  <div class="grid">
    <div class="field small">
      <label for="h-ru">Reset HA uptime</label>
      <select id="h-ru" bind:value={resetUptime}>
        <option value="none">(no)</option>
        <option value="primaryOnly">Primary only (safer)</option>
        <option value="all">reset-uptime</option>
      </select>
    </div>
    <div class="field small">
      <label for="h-sync">HA synchronize</label>
      <select id="h-sync" bind:value={synchronize}>
        <option value="none">(no)</option>
        <option value="start">start</option>
        <option value="stop">stop</option>
      </select>
    </div>
  </div>
  <div class="checks">
    <label class="check"><input type="checkbox" bind:checked={manage} /> Log in to a peer unit (execute ha manage)</label>
  </div>
  {#if manage}
    <div class="grid">
      <div class="field small"><label for="h-idx">Peer index</label><input id="h-idx" class="mono" class:bad={bad("manageIndex")} bind:value={manageIndex} spellcheck="false" /></div>
      <div class="field small"><label for="h-adm">Admin name</label><input id="h-adm" class="mono" class:bad={bad("manageAdmin")} bind:value={manageAdmin} placeholder="admin" spellcheck="false" autocomplete="off" /></div>
    </div>
    <p class="note muted">
      The FortiGate prompts for the password; it is never part of the command. Find the peer index
      with <code>execute ha manage ?</code>.
    </p>
  {/if}
</div>

<CommandOutput category="ha" defaultTitle={changes ? "HA (changes cluster state)" : "HA health check"} {command} {error} onsave={(t, n) => onsave(t, n, command)} />

<style>
  h3 {
    font-size: 0.84rem;
    font-weight: 600;
    margin: 1rem 0 0.4rem;
  }

  .danger-box {
    border: 1px solid var(--error-border);
    border-left-width: 3px;
    border-radius: 6px;
    padding: 0.2rem 0.8rem 0.6rem;
    margin-top: 1rem;
  }
</style>
