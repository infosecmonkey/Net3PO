<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import type { BuildError } from "$lib/tools/types";
  import CommandOutput from "./CommandOutput.svelte";

  interface Props {
    onsave: (title: string, notes: string, command: string) => void;
  }
  let { onsave }: Props = $props();

  // Keep in sync with core::routing.
  const OSPF_AREAS = ["lsa", "packet", "events", "ifsm", "nfsm", "nsm", "route"];
  const BGP_AREAS = ["events", "fsm", "keepalives", "updates", "filters", "dampening", "nsm"];
  const TABLE_VIEWS = ["all", "static", "connected", "ospf", "bgp", "rip", "isis", "database"];

  let mode = $state<"ospf" | "bgp" | "table">("ospf");

  let ospfStatus = $state(true);
  let ospfNeighbor = $state(true);
  let ospfInterface = $state(false);
  let ospfDatabase = $state(false);
  let ospfRoute = $state(false);
  let ospfRib = $state(false);
  let ospfBorderRouters = $state(false);
  let ospfVirtualLinks = $state(false);
  let ospfDebug = $state(false);
  let ospfAreas = $state<string[]>([]);

  let bgpSummary = $state(true);
  let bgpPeer = $state("");
  let bgpRoutes = $state(false);
  let bgpAdvertised = $state(false);
  let bgpReceived = $state(false);
  let bgpNetwork = $state(false);
  let bgpPrefix = $state("");
  let bgpDebug = $state(false);
  let bgpAreas = $state<string[]>([]);

  let tableViews = $state<string[]>(["all"]);
  let detailsIp = $state("");
  let prouteList = $state(false);
  let proute6List = $state(false);
  let prouteStats = $state(false);

  let resetFirst = $state(true);
  let timestamps = $state(true);
  let stopBlock = $state(true);

  let command = $state("");
  let error = $state<BuildError | null>(null);

  $effect(() => {
    const input = {
      kind: "routing", mode,
      ospfStatus, ospfNeighbor, ospfInterface, ospfDatabase, ospfRoute, ospfRib,
      ospfBorderRouters, ospfVirtualLinks, ospfDebug, ospfAreas,
      bgpSummary, bgpPeer, bgpRoutes, bgpAdvertised, bgpReceived, bgpNetwork, bgpPrefix,
      bgpDebug, bgpAreas,
      tableViews, detailsIp, prouteList, proute6List, prouteStats,
      resetFirst, timestamps, stopBlock,
    };
    invoke<string>("fortinet_build", { input })
      .then((c) => {
        command = c;
        error = null;
      })
      .catch((e) => (error = e as BuildError));
  });

  const bad = (f: string) => error?.field === f;

  function toggle(list: string[], v: string): string[] {
    return list.includes(v) ? list.filter((x) => x !== v) : [...list, v];
  }

  const debugOn = $derived((mode === "ospf" && ospfDebug) || (mode === "bgp" && bgpDebug));
  const title = $derived(
    mode === "ospf" ? "OSPF check" : mode === "bgp" ? `BGP${bgpPeer ? ` neighbor ${bgpPeer}` : " check"}` : "Routing table",
  );
</script>

<p class="help">Routing table, OSPF, BGP, and policy routes, with optional live protocol debugs. Options match FortiOS 7.6.</p>

<div class="modes" role="radiogroup" aria-label="Routing mode">
  <label class="check"><input type="radio" bind:group={mode} value="ospf" /> OSPF</label>
  <label class="check"><input type="radio" bind:group={mode} value="bgp" /> BGP</label>
  <label class="check"><input type="radio" bind:group={mode} value="table" /> Routing table / policy routes</label>
</div>

{#if mode === "ospf"}
  <div class="checks">
    <label class="check"><input type="checkbox" bind:checked={ospfStatus} /> Status</label>
    <label class="check"><input type="checkbox" bind:checked={ospfNeighbor} /> Neighbors</label>
    <label class="check"><input type="checkbox" bind:checked={ospfInterface} /> Interfaces</label>
    <label class="check"><input type="checkbox" bind:checked={ospfDatabase} /> Database (LSDB)</label>
    <label class="check"><input type="checkbox" bind:checked={ospfRoute} /> OSPF routes</label>
    <label class="check"><input type="checkbox" bind:checked={ospfRib} /> OSPF routes in RIB</label>
    <label class="check"><input type="checkbox" bind:checked={ospfBorderRouters} /> Border routers</label>
    <label class="check"><input type="checkbox" bind:checked={ospfVirtualLinks} /> Virtual links</label>
  </div>
  <div class="checks">
    <label class="check"><input type="checkbox" bind:checked={ospfDebug} /> Live OSPF debug</label>
  </div>
  {#if ospfDebug}
    <div class="areas">
      <span class="muted">Areas (none = all):</span>
      {#each OSPF_AREAS as a (a)}
        <label class="check"><input type="checkbox" checked={ospfAreas.includes(a)} onchange={() => (ospfAreas = toggle(ospfAreas, a))} /> {a}</label>
      {/each}
    </div>
  {/if}
{:else if mode === "bgp"}
  <div class="checks">
    <label class="check"><input type="checkbox" bind:checked={bgpSummary} /> Summary</label>
    <label class="check"><input type="checkbox" bind:checked={bgpNetwork} /> Network table</label>
  </div>
  <div class="grid">
    <div class="field"><label for="r-peer">Neighbor IP</label><input id="r-peer" class="mono" class:bad={bad("bgpPeer")} bind:value={bgpPeer} placeholder="169.254.0.1" spellcheck="false" /></div>
    {#if bgpNetwork}
      <div class="field"><label for="r-pfx">Network prefix (optional)</label><input id="r-pfx" class="mono" class:bad={bad("bgpPrefix")} bind:value={bgpPrefix} placeholder="10.0.0.0/8" spellcheck="false" /></div>
    {/if}
  </div>
  <div class="checks">
    <label class="check"><input type="checkbox" bind:checked={bgpRoutes} /> Neighbor routes</label>
    <label class="check"><input type="checkbox" bind:checked={bgpAdvertised} /> Advertised routes</label>
    <label class="check"><input type="checkbox" bind:checked={bgpReceived} /> Received routes</label>
  </div>
  {#if bgpReceived}
    <p class="note muted">Received routes need soft-reconfiguration inbound enabled for the neighbor.</p>
  {/if}
  <div class="checks">
    <label class="check"><input type="checkbox" bind:checked={bgpDebug} /> Live BGP debug</label>
  </div>
  {#if bgpDebug}
    <div class="areas">
      <span class="muted">Areas (none = all):</span>
      {#each BGP_AREAS as a (a)}
        <label class="check"><input type="checkbox" checked={bgpAreas.includes(a)} onchange={() => (bgpAreas = toggle(bgpAreas, a))} /> {a}</label>
      {/each}
    </div>
  {/if}
{:else}
  <div class="areas">
    <span class="muted">Routing table:</span>
    {#each TABLE_VIEWS as v (v)}
      <label class="check"><input type="checkbox" checked={tableViews.includes(v)} onchange={() => (tableViews = toggle(tableViews, v))} /> {v}</label>
    {/each}
  </div>
  <div class="grid">
    <div class="field"><label for="r-det">Route details for IP</label><input id="r-det" class="mono" class:bad={bad("detailsIp")} bind:value={detailsIp} placeholder="8.8.8.8" spellcheck="false" /></div>
  </div>
  <div class="checks">
    <label class="check"><input type="checkbox" bind:checked={prouteList} /> Policy routes (IPv4)</label>
    <label class="check"><input type="checkbox" bind:checked={proute6List} /> Policy routes (IPv6)</label>
    <label class="check"><input type="checkbox" bind:checked={prouteStats} /> Policy route stats</label>
  </div>
{/if}

{#if debugOn}
  <div class="checks">
    <label class="check"><input type="checkbox" bind:checked={resetFirst} /> Reset debug state first</label>
    <label class="check"><input type="checkbox" bind:checked={timestamps} /> Console timestamps</label>
    <label class="check"><input type="checkbox" bind:checked={stopBlock} /> Append stop-debug block</label>
  </div>
{/if}

<CommandOutput category="routing" defaultTitle={title} {command} {error} onsave={(t, n) => onsave(t, n, command)} />

<style>
  .modes {
    display: flex;
    flex-wrap: wrap;
    gap: 1.2rem;
    margin: 0 0 0.9rem;
    padding-bottom: 0.7rem;
    border-bottom: 1px solid var(--border);
  }

  .areas {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 0.5rem 1rem;
    margin: 0.2rem 0 0.7rem;
    font-size: 0.82rem;
  }
</style>
