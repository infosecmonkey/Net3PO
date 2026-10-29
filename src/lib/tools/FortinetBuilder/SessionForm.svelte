<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import type { BuildError } from "$lib/tools/types";
  import CommandOutput from "./CommandOutput.svelte";
  import { PROTOCOLS } from "./options";

  interface Props {
    onsave: (title: string, notes: string, command: string) => void;
  }
  let { onsave }: Props = $props();

  let src = $state("");
  let dst = $state("");
  let sport = $state("");
  let dport = $state("");
  let proto = $state<number | null>(null);
  let vdom = $state("");
  let negate = $state(false);
  let clearFirst = $state(true);
  let list = $state(true);
  let stats = $state(false);

  let command = $state("");
  let error = $state<BuildError | null>(null);

  $effect(() => {
    const input = { kind: "session", src, dst, sport, dport, proto, vdom, negate, clearFirst, list, stats };
    invoke<string>("fortinet_build", { input })
      .then((c) => {
        command = c;
        error = null;
      })
      .catch((e) => (error = e as BuildError));
  });

  const bad = (f: string) => error?.field === f;
  const title = $derived(
    ["Session", src && `src ${src}`, dst && `dst ${dst}`, dport && `:${dport}`].filter(Boolean).join(" "),
  );
</script>

<p class="help">
  Find live sessions with <code>diagnose sys session</code>. All filters combine with AND.
</p>

<div class="grid">
  <div class="field"><label for="s-src">Source IP</label><input id="s-src" class="mono" class:bad={bad("src")} bind:value={src} placeholder="10.1.1.10" spellcheck="false" /></div>
  <div class="field"><label for="s-dst">Destination IP</label><input id="s-dst" class="mono" class:bad={bad("dst")} bind:value={dst} placeholder="8.8.8.8" spellcheck="false" /></div>
  <div class="field small"><label for="s-sport">Source port</label><input id="s-sport" class="mono" class:bad={bad("sport")} bind:value={sport} spellcheck="false" /></div>
  <div class="field small"><label for="s-dport">Destination port</label><input id="s-dport" class="mono" class:bad={bad("dport")} bind:value={dport} placeholder="443" spellcheck="false" /></div>
  <div class="field small">
    <label for="s-proto">Protocol</label>
    <select id="s-proto" bind:value={proto}>
      {#each PROTOCOLS as p (p.label)}<option value={p.number}>{p.label}</option>{/each}
    </select>
  </div>
  <div class="field small"><label for="s-vdom">VDOM index</label><input id="s-vdom" class="mono" class:bad={bad("vdom")} bind:value={vdom} placeholder="0" spellcheck="false" /></div>
</div>

<div class="checks">
  <label class="check"><input type="checkbox" bind:checked={clearFirst} /> Clear filter first</label>
  <label class="check"><input type="checkbox" bind:checked={negate} /> Negate filter</label>
  <label class="check"><input type="checkbox" bind:checked={stats} /> Include session stats</label>
  <label class="check"><input type="checkbox" bind:checked={list} /> List matching sessions</label>
</div>
<p class="note muted">VDOM takes the numeric index from <code>diagnose sys vd list</code>, not the name.</p>

<CommandOutput category="session" defaultTitle={title} {command} {error} onsave={(t, n) => onsave(t, n, command)} />
