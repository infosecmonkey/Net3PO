<script lang="ts">
  // Capture and display filter builder. Conditions inside a group must all
  // match; groups are alternatives. Three separate outputs, never mixed.
  import { invoke } from "@tauri-apps/api/core";
  import ExportMenu from "$lib/components/ExportMenu.svelte";
  import { selectOnFocus } from "$lib/actions/selectOnFocus";
  import {
    buildFilterReport,
    FLAG_NAMES,
    nextId,
    PROTOS,
    SCENARIOS,
    term,
    TERM_LABEL,
    toWire,
    type Filters,
    type GroupUI,
    type Output,
    type TermType,
  } from "./model";

  let groups = $state<GroupUI[]>([{ id: nextId(), terms: [term("host")] }]);
  let iface = $state("any");
  let result = $state<Filters | null>(null);
  let copied = $state("");
  type Target = "tcpdump" | "wireshark" | "fortigate";
  let target = $state<Target>("wireshark");
  const TARGETS: { id: Target; label: string }[] = [
    { id: "tcpdump", label: "tcpdump" },
    { id: "wireshark", label: "Wireshark" },
    { id: "fortigate", label: "FortiGate" },
  ];

  /** The capture filter as a tcpdump command line. */
  function tcpdumpCmd(o: Output): Output {
    if (o.error) return o;
    return {
      text: `tcpdump -nn '${o.text}'`,
      error: null,
      notes: [
        "Add -i <interface> to pick an interface (tcpdump -D lists them), and -w file.pcap to save for Wireshark.",
        ...o.notes,
      ],
    };
  }
  let timer: ReturnType<typeof setTimeout> | undefined;

  function schedule() {
    clearTimeout(timer);
    timer = setTimeout(async () => {
      const wire = groups.map((g) => ({ terms: g.terms.map(toWire) }));
      result = await invoke<Filters>("filter_build", { groups: wire, interface: iface });
    }, 150);
  }

  $effect(() => {
    // Rebuild whenever anything in the groups or the interface changes.
    JSON.stringify(groups);
    void iface;
    schedule();
  });

  function loadScenario(name: string) {
    const s = SCENARIOS.find((x) => x.name === name);
    if (s) groups = s.groups().map((terms) => ({ id: nextId(), terms }));
  }

  function addTerm(g: GroupUI, type: TermType) {
    g.terms.push(term(type));
  }

  function removeTerm(g: GroupUI, id: number) {
    g.terms = g.terms.filter((t) => t.id !== id);
    if (!g.terms.length) groups = groups.filter((x) => x.id !== g.id);
    if (!groups.length) groups = [{ id: nextId(), terms: [term("host")] }];
  }

  function toggleFlag(flags: string[], f: string): string[] {
    return flags.includes(f) ? flags.filter((x) => x !== f) : [...flags, f];
  }

  async function copy(key: string, value: string) {
    try {
      await navigator.clipboard.writeText(value);
      copied = key;
      setTimeout(() => (copied = ""), 1200);
    } catch {
      copied = "";
    }
  }

  const TYPES: TermType[] = ["host", "net", "port", "proto", "tcpFlags", "vlan", "mac"];
</script>

{#snippet outCard(key: string, title: string, sub: string, o: Output)}
  <div class="out">
    <div class="out-head">
      <strong>{title}</strong>
      <span class="muted">{sub}</span>
      {#if o.text}<button class="mini" onclick={() => copy(key, o.text)}>{copied === key ? "Copied" : "Copy"}</button>{/if}
    </div>
    {#if o.error}
      <div class="cant">{o.error}</div>
    {:else}
      <pre class="mono code">{o.text}</pre>
      {#each o.notes as n (n)}<div class="note">{n}</div>{/each}
    {/if}
  </div>
{/snippet}

<div class="panel">
  <header>
    <h1>Packet Filter Builder</h1>
    <p class="sub">Build capture filters (BPF), Wireshark display filters and FortiGate sniffer commands from the same conditions. Offline.</p>
  </header>

  <div class="row">
    <label class="inline">Start from
      <select onchange={(e) => { loadScenario(e.currentTarget.value); e.currentTarget.value = ""; }}>
        <option value="">a scenario...</option>
        {#each SCENARIOS as s (s.name)}<option value={s.name}>{s.name}</option>{/each}
      </select>
    </label>
    <label class="inline" title="Used in the FortiGate command">FortiGate interface <input class="mono iface" bind:value={iface} use:selectOnFocus spellcheck="false" /></label>
  </div>

  {#each groups as g, gi (g.id)}
    {#if gi > 0}<div class="or">OR</div>{/if}
    <div class="group">
      <div class="ghead">Match <strong>all</strong> of:</div>
      {#each g.terms as t (t.id)}
        <div class="term">
          <select bind:value={t.type} aria-label="Condition type">
            {#each TYPES as ty (ty)}<option value={ty}>{TERM_LABEL[ty]}</option>{/each}
            {#if t.type === "displayOnly"}<option value="displayOnly">Display-only</option>{/if}
          </select>
          {#if t.type === "host"}
            <input class="mono" bind:value={t.addr} placeholder="IPv4 or IPv6 address" spellcheck="false" />
          {:else if t.type === "net"}
            <input class="mono" bind:value={t.cidr} placeholder="network/prefix" spellcheck="false" />
          {:else if t.type === "port"}
            <input class="mono" bind:value={t.ports} placeholder="ports or ranges, e.g. 80,443,8000-8100" spellcheck="false" />
            <select bind:value={t.l4} aria-label="Transport"><option value="any">TCP or UDP</option><option value="tcp">TCP</option><option value="udp">UDP</option></select>
          {:else if t.type === "proto"}
            <select bind:value={t.name} aria-label="Protocol">{#each PROTOS as p (p)}<option value={p}>{p}</option>{/each}</select>
          {:else if t.type === "tcpFlags"}
            <span class="flags">
              {#each FLAG_NAMES as f (f)}
                <label class="chk"><input type="checkbox" checked={t.flags.includes(f)} onchange={() => (t.flags = toggleFlag(t.flags, f))} /> {f.toUpperCase()}</label>
              {/each}
              <label class="chk" title="Only these flags set; the others clear"><input type="checkbox" bind:checked={t.exact} /> only these</label>
            </span>
          {:else if t.type === "vlan"}
            <input class="mono short" bind:value={t.vlan} placeholder="any VLAN" spellcheck="false" />
          {:else if t.type === "mac"}
            <input class="mono" bind:value={t.addr} placeholder="MAC address" spellcheck="false" />
          {:else if t.type === "displayOnly"}
            <span class="mono expr">{t.expr}</span>
          {/if}
          {#if t.type === "host" || t.type === "net" || t.type === "port" || t.type === "mac"}
            <select bind:value={t.dir} aria-label="Direction"><option value="any">either way</option><option value="src">source</option><option value="dst">destination</option></select>
          {/if}
          <label class="chk" title="Exclude matching traffic"><input type="checkbox" bind:checked={t.negate} /> not</label>
          <button class="x" onclick={() => removeTerm(g, t.id)} aria-label="Remove condition">×</button>
        </div>
      {/each}
      <select class="add" onchange={(e) => { addTerm(g, e.currentTarget.value as TermType); e.currentTarget.value = ""; }}>
        <option value="">+ add condition...</option>
        {#each TYPES as ty (ty)}<option value={ty}>{TERM_LABEL[ty]}</option>{/each}
      </select>
    </div>
  {/each}
  <button class="link" onclick={() => groups.push({ id: nextId(), terms: [term("host")] })}>+ Add an OR group</button>

  {#if result}
    {#if result.errors.length}
      <div class="error">{#each result.errors as e (e)}<div>{e}</div>{/each}</div>
    {:else}
      <div class="bar">
        <div class="explain">{result.explanation}</div>
        <ExportMenu build={() => (result ? buildFilterReport(result) : null)} name="filters" />
      </div>
      <div class="targets" role="tablist">
        {#each TARGETS as t (t.id)}
          <button role="tab" aria-selected={target === t.id} class:on={target === t.id} onclick={() => (target = t.id)}>{t.label}</button>
        {/each}
      </div>
      {#if target === "tcpdump"}
        {@render outCard("tcpdump", "tcpdump command", "capture filter (BPF)", tcpdumpCmd(result.bpf))}
      {:else if target === "wireshark"}
        {@render outCard("ws", "Display filter", "paste into Wireshark's display filter bar", result.wireshark)}
        {@render outCard("bpf", "Capture filter", "Capture > Options, before starting a capture (same language as tcpdump)", result.bpf)}
      {:else}
        {@render outCard("fgt", "FortiGate sniffer", "diagnose sniffer packet (same filter language as tcpdump)", result.fortigate)}
      {/if}
    {/if}
  {/if}
</div>

<style>
  .panel {
    padding: 1.5rem 2rem;
    max-width: 1000px;
  }

  header h1 {
    margin: 0 0 0.25rem;
    font-size: 1.3rem;
  }

  .sub {
    margin: 0 0 1rem;
    color: var(--muted);
    font-size: 0.85rem;
  }

  input,
  select {
    box-sizing: border-box;
    background: var(--input-bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.35rem 0.5rem;
    color: var(--fg);
    font-size: 0.84rem;
  }

  input[type="checkbox"] {
    padding: 0;
  }

  input:focus,
  select:focus {
    outline: none;
    border-color: var(--accent);
  }

  .mono {
    font-family: var(--mono);
  }

  .row {
    display: flex;
    gap: 1.2rem;
    align-items: center;
    flex-wrap: wrap;
    margin-bottom: 0.8rem;
  }

  .inline {
    display: inline-flex;
    align-items: center;
    gap: 0.5rem;
    font-size: 0.82rem;
    color: var(--muted);
  }

  .iface {
    width: 8rem;
  }

  .group {
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 0.6rem 0.8rem;
  }

  .ghead {
    font-size: 0.78rem;
    color: var(--muted);
    margin-bottom: 0.4rem;
  }

  .or {
    text-align: center;
    font-size: 0.72rem;
    font-weight: 700;
    color: var(--accent);
    margin: 0.35rem 0;
    letter-spacing: 0.08em;
  }

  .term {
    display: flex;
    align-items: center;
    gap: 0.45rem;
    margin-bottom: 0.4rem;
    flex-wrap: wrap;
  }

  .term input:not([type="checkbox"]) {
    flex: 1 1 14rem;
    min-width: 0;
  }

  .term input.short {
    flex: 0 0 7rem;
  }

  .flags {
    display: inline-flex;
    flex-wrap: wrap;
    gap: 0.5rem;
  }

  .chk {
    display: inline-flex;
    align-items: center;
    gap: 0.25rem;
    font-size: 0.78rem;
  }

  .expr {
    font-size: 0.82rem;
    flex: 1;
  }

  .x {
    background: none;
    border: none;
    color: var(--muted);
    font-size: 1.1rem;
    cursor: pointer;
  }

  .add {
    font-size: 0.78rem;
    color: var(--muted);
  }

  .link {
    background: none;
    border: none;
    color: var(--accent);
    font-size: 0.8rem;
    padding: 0.5rem 0;
    cursor: pointer;
  }

  .error {
    color: var(--error-fg);
    font-size: 0.82rem;
    margin: 0.8rem 0;
  }

  .bar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 1rem;
    margin: 0.9rem 0 0.5rem;
  }

  .explain {
    font-size: 0.86rem;
  }

  .targets {
    display: inline-flex;
    border: 1px solid var(--border);
    border-radius: 6px;
    overflow: hidden;
    margin-bottom: 0.6rem;
  }

  .targets button {
    background: var(--input-bg);
    border: none;
    color: var(--muted);
    padding: 0.38rem 1rem;
    font-size: 0.84rem;
    cursor: pointer;
  }

  .targets button + button {
    border-left: 1px solid var(--border);
  }

  .targets button.on {
    background: var(--accent);
    color: var(--accent-fg);
  }

  .out {
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 0.6rem 0.8rem;
    margin-bottom: 0.6rem;
  }

  .out-head {
    display: flex;
    align-items: center;
    gap: 0.6rem;
    font-size: 0.84rem;
    margin-bottom: 0.35rem;
  }

  .out-head .mini {
    margin-left: auto;
  }

  .muted {
    color: var(--muted);
    font-size: 0.76rem;
  }

  .mini {
    background: var(--input-bg);
    border: 1px solid var(--border);
    border-radius: 4px;
    color: var(--fg);
    font-size: 0.72rem;
    padding: 0.1rem 0.5rem;
    cursor: pointer;
  }

  .code {
    margin: 0;
    padding: 0.45rem 0.6rem;
    background: var(--input-bg);
    border-radius: 4px;
    font-size: 0.82rem;
    white-space: pre-wrap;
    overflow-wrap: anywhere;
  }

  .note {
    font-size: 0.74rem;
    color: var(--muted);
    margin-top: 0.3rem;
  }

  .cant {
    font-size: 0.82rem;
    color: #b7791f;
  }
</style>
