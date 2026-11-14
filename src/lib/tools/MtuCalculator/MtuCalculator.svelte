<script lang="ts">
  // MTU, MSS and tunnel overhead: stack encapsulations and see the byte
  // breakdown. Arithmetic only; Traceroute's Path MTU mode measures a path.
  import { invoke } from "@tauri-apps/api/core";
  import ExportMenu from "$lib/components/ExportMenu.svelte";
  import { selectOnFocus } from "$lib/actions/selectOnFocus";
  import { buildMtuReport, LAYER_LABEL, newLayer, PRESETS, type Layer, type MtuResult } from "./model";

  let linkMtu = $state(1500);
  let layers = $state<Layer[]>([newLayer("esp")]);
  let result = $state<MtuResult | null>(null);

  $effect(() => {
    const mtu = linkMtu;
    const ls = $state.snapshot(layers);
    void invoke<MtuResult>("mtu_calculate", { linkMtu: Number(mtu) || 0, layers: ls }).then((r) => (result = r));
  });

  function preset(name: string) {
    const p = PRESETS.find((x) => x.name === name);
    if (p) {
      linkMtu = p.mtu;
      layers = p.layers();
    }
  }

  function move(i: number, d: number) {
    const j = i + d;
    if (j >= 0 && j < layers.length) [layers[i], layers[j]] = [layers[j], layers[i]];
  }

  const TYPES = Object.keys(LAYER_LABEL) as Layer["type"][];
</script>

{#snippet ipSel(l: { outer: "v4" | "v6" })}
  <select bind:value={l.outer} aria-label="Outer IP version"><option value="v4">outer IPv4</option><option value="v6">outer IPv6</option></select>
{/snippet}

<div class="panel">
  <header>
    <h1>MTU Calculator</h1>
    <p class="sub">Stack encapsulations to see overhead, the inner IP MTU and the TCP MSS to clamp. Offline arithmetic; Traceroute's Path MTU mode measures a real path.</p>
  </header>

  <div class="row">
    <label class="inline">Link IP MTU <input class="mono num" type="number" min="68" max="65535" bind:value={linkMtu} use:selectOnFocus /></label>
    <button class="link" onclick={() => (linkMtu = 1500)}>1500</button>
    <button class="link" onclick={() => (linkMtu = 9000)}>9000</button>
    <label class="inline">Preset
      <select onchange={(e) => { preset(e.currentTarget.value); e.currentTarget.value = ""; }}>
        <option value="">choose...</option>
        {#each PRESETS as p (p.name)}<option value={p.name}>{p.name}</option>{/each}
      </select>
    </label>
  </div>

  <div class="layers">
    <div class="lbl">Layers, outermost first</div>
    {#each layers as l, i (i)}
      <div class="layer">
        <span class="n">{i + 1}.</span>
        <strong>{LAYER_LABEL[l.type]}</strong>
        {#if l.type === "dot1q"}
          <select bind:value={l.tags} aria-label="Tags"><option value={1}>1 tag</option><option value={2}>2 tags (QinQ)</option></select>
        {:else if l.type === "mpls"}
          <label class="inline">labels <input class="mono tiny" type="number" min="1" max="8" bind:value={l.labels} /></label>
        {:else if l.type === "gre"}
          {@render ipSel(l)}
          <label class="chk"><input type="checkbox" bind:checked={l.key} /> key</label>
          <label class="chk"><input type="checkbox" bind:checked={l.seq} /> sequence</label>
          <label class="chk"><input type="checkbox" bind:checked={l.checksum} /> checksum</label>
        {:else if l.type === "ipInIp" || l.type === "wireGuard"}
          {@render ipSel(l)}
        {:else if l.type === "vxlan"}
          {@render ipSel(l)}
          <label class="chk"><input type="checkbox" bind:checked={l.innerVlan} /> inner VLAN tag</label>
        {:else if l.type === "esp"}
          <select bind:value={l.tunnel} aria-label="Mode"><option value={true}>tunnel mode</option><option value={false}>transport mode</option></select>
          {#if l.tunnel}{@render ipSel(l)}{/if}
          <select bind:value={l.cipher} aria-label="Cipher" onchange={() => { if (l.type === "esp") l.integrity = l.cipher === "aesGcm" || l.cipher === "chaCha20Poly1305" ? "none" : l.integrity === "none" ? "sha256" : l.integrity; }}>
            <option value="aesGcm">AES-GCM</option>
            <option value="chaCha20Poly1305">ChaCha20-Poly1305</option>
            <option value="aesCbc">AES-CBC</option>
            <option value="desCbc">3DES/DES-CBC</option>
            <option value="null">NULL</option>
          </select>
          <select bind:value={l.integrity} aria-label="Integrity">
            <option value="none">no separate integrity (AEAD)</option>
            <option value="sha1">HMAC-SHA1 / MD5 (12)</option>
            <option value="sha256">HMAC-SHA256 (16)</option>
            <option value="sha384">HMAC-SHA384 (24)</option>
            <option value="sha512">HMAC-SHA512 (32)</option>
          </select>
          <label class="chk"><input type="checkbox" bind:checked={l.natT} /> NAT-T</label>
        {/if}
        <span class="spacer"></span>
        <button class="icon" onclick={() => move(i, -1)} disabled={i === 0} aria-label="Move up">↑</button>
        <button class="icon" onclick={() => move(i, 1)} disabled={i === layers.length - 1} aria-label="Move down">↓</button>
        <button class="icon" onclick={() => layers.splice(i, 1)} aria-label="Remove layer">×</button>
      </div>
    {/each}
    <select class="add" onchange={(e) => { if (e.currentTarget.value) layers.push(newLayer(e.currentTarget.value as Layer["type"])); e.currentTarget.value = ""; }}>
      <option value="">+ add layer...</option>
      {#each TYPES as t (t)}<option value={t}>{LAYER_LABEL[t]}</option>{/each}
    </select>
  </div>

  {#if result}
    {#if result.errors.length}
      <div class="error">{#each result.errors as e (e)}<div>{e}</div>{/each}</div>
    {:else}
      <div class="big">
        <div><span class="v">{result.innerMtu}</span><span class="k">inner IP MTU</span></div>
        <div><span class="v">{result.mssV4}</span><span class="k">TCP MSS, IPv4 inside</span></div>
        <div><span class="v">{result.mssV6}</span><span class="k">TCP MSS, IPv6 inside</span></div>
        <div><span class="v">{result.overhead}</span><span class="k">bytes overhead</span></div>
        <span class="spacer"></span>
        <ExportMenu build={() => (result ? buildMtuReport(result, $state.snapshot(layers)) : null)} name="mtu" />
      </div>
      <table>
        <thead><tr><th>Layer</th><th>Part</th><th class="r">Bytes</th></tr></thead>
        <tbody>
          <tr><td></td><td>link IP MTU</td><td class="r mono">{result.linkMtu}</td></tr>
          {#each result.rows as r, i (i)}<tr><td>{r.layer}</td><td>{r.part}</td><td class="r mono">{r.bytes}</td></tr>{/each}
          <tr class="total"><td></td><td>left for the inner packet</td><td class="r mono">{result.innerMtu}</td></tr>
        </tbody>
      </table>
      {#each result.notes as n (n)}<div class="note">{n}</div>{/each}
    {/if}
  {/if}
</div>

<style>
  .panel {
    padding: 1.5rem 2rem;
    max-width: 980px;
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
    padding: 0.32rem 0.45rem;
    color: var(--fg);
    font-size: 0.82rem;
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
    align-items: center;
    gap: 0.8rem;
    flex-wrap: wrap;
    margin-bottom: 0.9rem;
  }

  .inline {
    display: inline-flex;
    align-items: center;
    gap: 0.4rem;
    font-size: 0.82rem;
    color: var(--muted);
  }

  .num {
    width: 6rem;
  }

  .tiny {
    width: 3.5rem;
  }

  .link {
    background: none;
    border: none;
    color: var(--accent);
    font-size: 0.8rem;
    cursor: pointer;
    padding: 0;
  }

  .layers {
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 0.6rem 0.8rem;
    margin-bottom: 1rem;
  }

  .lbl {
    font-size: 0.75rem;
    color: var(--muted);
    margin-bottom: 0.4rem;
  }

  .layer {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    flex-wrap: wrap;
    padding: 0.3rem 0;
    border-bottom: 1px solid var(--border);
    font-size: 0.84rem;
  }

  .n {
    color: var(--muted);
    width: 1.4rem;
  }

  .chk {
    display: inline-flex;
    align-items: center;
    gap: 0.25rem;
    font-size: 0.78rem;
  }

  .spacer {
    flex: 1;
  }

  .icon {
    background: none;
    border: none;
    color: var(--muted);
    cursor: pointer;
    font-size: 0.9rem;
  }

  .icon:disabled {
    opacity: 0.3;
  }

  .add {
    margin-top: 0.5rem;
    color: var(--muted);
  }

  .error {
    color: var(--error-fg);
    font-size: 0.84rem;
  }

  .big {
    display: flex;
    align-items: flex-end;
    gap: 1.6rem;
    flex-wrap: wrap;
    margin-bottom: 0.8rem;
  }

  .big > div {
    display: flex;
    flex-direction: column;
  }

  .v {
    font-size: 1.5rem;
    font-weight: 700;
    font-family: var(--mono);
  }

  .k {
    font-size: 0.72rem;
    color: var(--muted);
  }

  table {
    border-collapse: collapse;
    width: 100%;
    font-size: 0.82rem;
  }

  th,
  td {
    text-align: left;
    padding: 0.22rem 0.8rem 0.22rem 0;
    border-bottom: 1px solid var(--border);
  }

  th {
    color: var(--muted);
    font-weight: 500;
  }

  .r {
    text-align: right;
  }

  tr.total td {
    font-weight: 700;
  }

  .note {
    font-size: 0.76rem;
    color: var(--muted);
    margin-top: 0.4rem;
  }
</style>
