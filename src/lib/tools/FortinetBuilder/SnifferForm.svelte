<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import { openTool } from "$lib/nav.svelte";
  import { loadCollection, saveCollection } from "$lib/store";
  import type { BuildError } from "$lib/tools/types";
  import CommandOutput from "./CommandOutput.svelte";
  import {
    BPF_PRESETS,
    BPF_PROTOCOLS,
    COMMON_INTERFACES,
    DIRECTIONS,
    ICMP_TYPES,
    TCP_FLAGS,
    VERBOSITY,
  } from "./options";

  interface Props {
    onsave: (title: string, notes: string, command: string) => void;
  }
  let { onsave }: Props = $props();

  type Dir = "any" | "src" | "dst";

  // Command fields.
  let iface = $state("any");
  let useCustomFilter = $state(false);
  let customFilter = $state("");
  let host = $state("");
  let hostDir = $state<Dir>("any");
  let net = $state("");
  let netDir = $state<Dir>("any");
  let ports = $state("");
  let portDir = $state<Dir>("any");
  let proto = $state("");
  let verbose = $state(4);
  let count = $state("");
  let timestamp = $state<"relative" | "utc" | "local">("local");

  let command = $state("");
  let error = $state<BuildError | null>(null);

  // Saved custom interfaces.
  let myIfaces = $state<string[]>([]);
  let ifaceMsg = $state("");

  // BPF snippet builder.
  let snipType = $state("host");
  let snipIp = $state("");
  let snipCidr = $state("");
  let snipPorts = $state("");
  let snipDir = $state<Dir>("any");
  let snipProto = $state("tcp");
  let snipMac = $state("");
  let snipVlan = $state("");
  let snipFlags = $state<string[]>(["syn"]);
  let snipExact = $state(false);
  let snipIcmp = $state("echo");
  let snipV6 = $state(false);
  let snipNumber = $state("");
  let negate = $state(false);
  let wrap = $state(true);
  let combineOr = $state(false);
  let snipError = $state("");

  let offload = $state("");
  let offloadCopied = $state(false);

  $effect(() => {
    loadCollection<string>("fortinet_interfaces")
      .then((l) => (myIfaces = l.items.filter((x) => typeof x === "string")))
      .catch(() => {});
    invoke<string>("fortinet_offload_snippet").then((s) => (offload = s));
  });

  $effect(() => {
    const input = {
      kind: "sniffer",
      interface: iface,
      useCustomFilter, customFilter,
      host, hostDir, net, netDir, ports, portDir, proto,
      verbose, count, timestamp,
    };
    invoke<string>("fortinet_build", { input })
      .then((c) => {
        command = c;
        error = null;
      })
      .catch((e) => (error = e as BuildError));
  });

  const bad = (f: string) => error?.field === f;

  async function saveIface() {
    const name = iface.trim();
    if (!name || COMMON_INTERFACES.includes(name) || myIfaces.includes(name) || bad("interface")) return;
    const next = [...myIfaces, name].sort();
    try {
      await saveCollection("fortinet_interfaces", next);
      myIfaces = next;
      ifaceMsg = `Saved ${name}.`;
    } catch (e) {
      ifaceMsg = String(e);
    }
    setTimeout(() => (ifaceMsg = ""), 2000);
  }

  async function removeIface(name: string) {
    const next = myIfaces.filter((x) => x !== name);
    try {
      await saveCollection("fortinet_interfaces", next);
      myIfaces = next;
    } catch (e) {
      ifaceMsg = String(e);
    }
  }

  function snippet() {
    switch (snipType) {
      case "host": return { type: "host", ip: snipIp, dir: snipDir };
      case "network": return { type: "network", cidr: snipCidr, dir: snipDir };
      case "ports": return { type: "ports", list: snipPorts, dir: snipDir };
      case "protocol": return { type: "protocol", name: snipProto };
      case "etherHost": return { type: "etherHost", mac: snipMac, dir: snipDir };
      case "vlan": return { type: "vlan", id: snipVlan };
      case "tcpFlags": return { type: "tcpFlags", flags: snipFlags, exact: snipExact };
      case "icmpType": return { type: "icmpType", kind: snipIcmp };
      case "ipVersion": return { type: "ipVersion", v6: snipV6 };
      case "etherProto": return { type: "etherProto", number: snipNumber };
      case "ipProto": return { type: "ipProto", number: snipNumber };
      default: return { type: snipType };
    }
  }

  async function addSnippet() {
    try {
      customFilter = await invoke<string>("fortinet_bpf_add", {
        existing: customFilter, snippet: snippet(), negate, wrap, or: combineOr,
      });
      snipError = "";
    } catch (e) {
      snipError = (e as BuildError).message ?? String(e);
    }
  }

  async function addPreset(expr: string) {
    try {
      customFilter = await invoke<string>("fortinet_bpf_preset", { existing: customFilter, expr, or: combineOr });
    } catch (e) {
      snipError = (e as BuildError).message ?? String(e);
    }
  }

  function toggleFlag(f: string) {
    snipFlags = snipFlags.includes(f) ? snipFlags.filter((x) => x !== f) : [...snipFlags, f];
  }

  async function copyOffload() {
    await navigator.clipboard.writeText(offload);
    offloadCopied = true;
    setTimeout(() => (offloadCopied = false), 1500);
  }

  const usesDir = $derived(["host", "network", "ports", "etherHost"].includes(snipType));
</script>

<p class="help">
  Capture packets with <code>diagnose sniffer packet</code> using tcpdump/BPF filter syntax.
  Paste the output into
  <button class="link" onclick={() => openTool("forti-sniffer")}>FortiGate Sniffer to PCAP</button>
  to open it in Wireshark (verbosity 6 gives full packets).
</p>

<div class="offload">
  <div class="strong">Disable ASIC / NPU offload to see every packet</div>
  <div class="muted small">
    Offloaded sessions bypass the CPU sniffer after the first packets. If you only see the SYN,
    disable offload on the policy, re-create the session, and re-enable offload when done.
  </div>
  <pre class="code mono">{offload}</pre>
  <button class="secondary" onclick={copyOffload}>{offloadCopied ? "Copied" : "Copy offload-disable snippet"}</button>
</div>

<div class="grid">
  <div class="field">
    <label for="n-iface">Interface</label>
    <input id="n-iface" class="mono" class:bad={bad("interface")} bind:value={iface} list="n-iface-list" spellcheck="false" />
    <datalist id="n-iface-list">
      {#each [...COMMON_INTERFACES, ...myIfaces] as i (i)}<option value={i}></option>{/each}
    </datalist>
  </div>
  <div class="field small">
    <label for="n-verbose">Verbosity</label>
    <select id="n-verbose" bind:value={verbose}>
      {#each VERBOSITY as v (v.level)}<option value={v.level}>{v.label}</option>{/each}
    </select>
  </div>
  <div class="field small"><label for="n-count">Count (blank = until stopped)</label><input id="n-count" class="mono" class:bad={bad("count")} bind:value={count} spellcheck="false" /></div>
  <div class="field small">
    <label for="n-ts">Timestamps</label>
    <select id="n-ts" bind:value={timestamp}>
      <option value="relative">Relative</option>
      <option value="utc">Absolute UTC (a)</option>
      <option value="local">Absolute local (l)</option>
    </select>
  </div>
</div>
<div class="ifacebar">
  <button class="secondary" onclick={saveIface}>Save interface name</button>
  {#each myIfaces as i (i)}
    <span class="chip mono">{i}<button class="x" aria-label="Remove {i}" onclick={() => removeIface(i)}>x</button></span>
  {/each}
  {#if ifaceMsg}<span class="muted small">{ifaceMsg}</span>{/if}
</div>

<div class="checks">
  <label class="check"><input type="checkbox" bind:checked={useCustomFilter} /> Custom BPF filter</label>
</div>

{#if !useCustomFilter}
  <div class="grid">
    <div class="field"><label for="n-host">Host</label><input id="n-host" class="mono" class:bad={bad("host")} bind:value={host} placeholder="10.0.0.1" spellcheck="false" /></div>
    <div class="field small"><label for="n-hostdir">Host direction</label><select id="n-hostdir" bind:value={hostDir}>{#each DIRECTIONS as d (d.value)}<option value={d.value}>{d.label}</option>{/each}</select></div>
    <div class="field"><label for="n-net">Network</label><input id="n-net" class="mono" class:bad={bad("net")} bind:value={net} placeholder="10.0.0.0/24" spellcheck="false" /></div>
    <div class="field small"><label for="n-netdir">Network direction</label><select id="n-netdir" bind:value={netDir}>{#each DIRECTIONS as d (d.value)}<option value={d.value}>{d.label}</option>{/each}</select></div>
  </div>
  <div class="grid">
    <div class="field"><label for="n-ports">Ports (comma separated)</label><input id="n-ports" class="mono" class:bad={bad("ports")} bind:value={ports} placeholder="80, 443" spellcheck="false" /></div>
    <div class="field small"><label for="n-portdir">Port direction</label><select id="n-portdir" bind:value={portDir}>{#each DIRECTIONS as d (d.value)}<option value={d.value}>{d.label}</option>{/each}</select></div>
    <div class="field small"><label for="n-proto">Protocol</label><select id="n-proto" bind:value={proto}><option value="">Any</option>{#each BPF_PROTOCOLS as p (p)}<option value={p}>{p}</option>{/each}</select></div>
  </div>
{:else}
  <div class="field">
    <label for="n-custom">BPF filter</label>
    <textarea id="n-custom" class="mono" class:bad={bad("customFilter")} rows="2" bind:value={customFilter} spellcheck="false"></textarea>
  </div>

  <div class="bpf">
    <div class="small muted">Presets (click to add)</div>
    <div class="presets">
      {#each BPF_PRESETS as p (p.label)}
        <button class="secondary sm" title={p.expr} onclick={() => addPreset(p.expr)}>{p.label}</button>
      {/each}
    </div>

    <div class="grid">
      <div class="field small">
        <label for="b-type">Snippet type</label>
        <select id="b-type" bind:value={snipType}>
          <option value="host">Host (IP)</option>
          <option value="network">Network (CIDR)</option>
          <option value="ports">Port(s)</option>
          <option value="protocol">Protocol</option>
          <option value="etherHost">Ethernet host (MAC)</option>
          <option value="vlan">VLAN</option>
          <option value="tcpFlags">TCP flags</option>
          <option value="icmpType">ICMP type</option>
          <option value="etherBroadcast">Ether broadcast</option>
          <option value="etherMulticast">Ether multicast</option>
          <option value="ipVersion">IP version</option>
          <option value="etherProto">Ether protocol #</option>
          <option value="ipProto">IP protocol #</option>
        </select>
      </div>

      {#if snipType === "host"}
        <div class="field"><label for="b-ip">IP address</label><input id="b-ip" class="mono" bind:value={snipIp} spellcheck="false" /></div>
      {:else if snipType === "network"}
        <div class="field"><label for="b-cidr">CIDR</label><input id="b-cidr" class="mono" bind:value={snipCidr} placeholder="10.0.0.0/24" spellcheck="false" /></div>
      {:else if snipType === "ports"}
        <div class="field"><label for="b-ports">Ports</label><input id="b-ports" class="mono" bind:value={snipPorts} placeholder="53, 123" spellcheck="false" /></div>
      {:else if snipType === "protocol"}
        <div class="field small"><label for="b-proto">Protocol</label><select id="b-proto" bind:value={snipProto}>{#each BPF_PROTOCOLS as p (p)}<option value={p}>{p}</option>{/each}</select></div>
      {:else if snipType === "etherHost"}
        <div class="field"><label for="b-mac">MAC</label><input id="b-mac" class="mono" bind:value={snipMac} placeholder="00:1b:44:11:3a:b7" spellcheck="false" /></div>
      {:else if snipType === "vlan"}
        <div class="field small"><label for="b-vlan">VLAN ID (blank = any)</label><input id="b-vlan" class="mono" bind:value={snipVlan} spellcheck="false" /></div>
      {:else if snipType === "tcpFlags"}
        <div class="field">
          <span class="lbl">Flags</span>
          <div class="checks tight">
            {#each TCP_FLAGS as f (f)}
              <label class="check"><input type="checkbox" checked={snipFlags.includes(f)} onchange={() => toggleFlag(f)} /> {f.toUpperCase()}</label>
            {/each}
            <label class="check"><input type="checkbox" bind:checked={snipExact} /> Exact match</label>
          </div>
        </div>
      {:else if snipType === "icmpType"}
        <div class="field"><label for="b-icmp">ICMP type</label><select id="b-icmp" bind:value={snipIcmp}>{#each ICMP_TYPES as t (t.kind)}<option value={t.kind}>{t.label}</option>{/each}</select></div>
      {:else if snipType === "ipVersion"}
        <div class="field small"><label for="b-ipv">Version</label><select id="b-ipv" bind:value={snipV6}><option value={false}>IPv4</option><option value={true}>IPv6</option></select></div>
      {:else if snipType === "etherProto" || snipType === "ipProto"}
        <div class="field small"><label for="b-num">Number (decimal or 0x hex)</label><input id="b-num" class="mono" bind:value={snipNumber} placeholder={snipType === "etherProto" ? "0x0806" : "47"} spellcheck="false" /></div>
      {/if}

      {#if usesDir}
        <div class="field small"><label for="b-dir">Direction</label><select id="b-dir" bind:value={snipDir}>{#each DIRECTIONS as d (d.value)}<option value={d.value}>{d.label}</option>{/each}</select></div>
      {/if}
    </div>

    <div class="checks">
      <label class="check"><input type="checkbox" bind:checked={negate} /> Negate (NOT)</label>
      <label class="check"><input type="checkbox" bind:checked={wrap} disabled={negate} /> Wrap in parentheses</label>
      <span class="combine">
        Combine with
        <select bind:value={combineOr} aria-label="Combine with">
          <option value={false}>AND</option>
          <option value={true}>OR</option>
        </select>
      </span>
      <button class="action sm" onclick={addSnippet}>Add to filter</button>
      <button class="secondary sm" onclick={() => (customFilter = "")}>Clear filter</button>
    </div>
    {#if snipError}<p class="snerr">{snipError}</p>{/if}
  </div>
{/if}

<CommandOutput category="sniffer" defaultTitle={`Sniffer on ${iface || "any"}`} {command} {error} onsave={(t, n) => onsave(t, n, command)} />

<style>
  .offload {
    border: 1px solid #c69026;
    border-left-width: 3px;
    border-radius: 6px;
    padding: 0.6rem 0.8rem;
    margin-bottom: 1rem;
    display: flex;
    flex-direction: column;
    gap: 0.45rem;
    align-items: flex-start;
  }

  .offload .code {
    margin: 0;
    padding: 0.5rem 0.7rem;
    background: var(--sidebar-bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    font-size: 0.8rem;
    align-self: stretch;
  }

  .ifacebar {
    display: flex;
    flex-wrap: wrap;
    gap: 0.5rem;
    align-items: center;
    margin: -0.2rem 0 0.8rem;
  }

  .chip {
    display: inline-flex;
    align-items: center;
    gap: 0.3rem;
    border: 1px solid var(--border);
    border-radius: 1rem;
    padding: 0.1rem 0.3rem 0.1rem 0.6rem;
    font-size: 0.78rem;
  }

  .chip .x {
    background: none;
    border: none;
    color: var(--muted);
    cursor: pointer;
  }

  .bpf {
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.7rem 0.8rem;
    margin-top: 0.6rem;
  }

  .presets {
    display: flex;
    flex-wrap: wrap;
    gap: 0.4rem;
    margin: 0.35rem 0 0.8rem;
  }

  .combine {
    display: inline-flex;
    align-items: center;
    gap: 0.4rem;
    font-size: 0.82rem;
  }

  .combine select {
    width: auto;
  }

  .lbl {
    font-size: 0.78rem;
    color: var(--muted);
    margin-bottom: 0.3rem;
  }

  .tight {
    margin: 0.2rem 0 0;
  }

  .snerr {
    color: var(--error-fg);
    font-size: 0.8rem;
    margin: 0.4rem 0 0;
  }

  .small {
    font-size: 0.78rem;
  }

  .strong {
    font-weight: 600;
    font-size: 0.86rem;
  }
</style>
