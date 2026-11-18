<script lang="ts">
  // PCAP/PCAPNG inspector: summaries, packet fields and hex, conversations,
  // talkers, protocols and DNS from a capture file, or FortiGate sniffer
  // text. Facts from the capture only; Wireshark for deep analysis.
  import { Channel, invoke } from "@tauri-apps/api/core";
  import { open, save } from "@tauri-apps/plugin-dialog";
  import { onDestroy } from "svelte";
  import ExportMenu from "$lib/components/ExportMenu.svelte";
  import { session as obfuscatorSession } from "$lib/tools/Obfuscator/session.svelte";
  import {
    buildPcapReport,
    bytes,
    clock,
    duration,
    type Filter,
    type OpenResult,
    type PacketDetail,
    OBJECT_KIND,
    type ExtractOptions,
    type ExtractResult,
    type SanitizeOptions,
    type SanitizeReport,
    type Summary,
  } from "./model";

  const PAGE = 500;
  type Tab = "packets" | "conversations" | "talkers" | "protocols" | "dns";

  let id = Math.floor(Math.random() * 0x7fffffff);
  let loaded = $state<OpenResult | null>(null);
  let loading = $state(false);
  let progress = $state({ bytes: 0, total: 0 });
  let error = $state("");
  let tab = $state<Tab>("packets");

  let filter = $state<Filter>({ text: "", proto: "", ip: "", port: null, onlyFlagged: false });
  let rows = $state<Summary[]>([]);
  let total = $state(0);
  let offset = $state(0);
  let detail = $state<PacketDetail | null>(null);
  let selected = $state<number | null>(null);

  // Clean copy.
  let cleanOpen = $state(false);
  let cleanOpts = $state({ stripPayload: true, addresses: true, macs: true, matchObfuscator: false });
  let cleaning = $state(false);
  let cleanReport = $state<SanitizeReport | null>(null);
  let cleanPath = $state("");

  // Extract files.
  let extractOpen = $state(false);
  let extractOpts = $state<ExtractOptions>({ http: true, ftp: true, tftp: true, voice: true, decompress: true });
  let extracting = $state(false);
  let extracted = $state<ExtractResult | null>(null);
  let picked = $state<Record<number, boolean>>({});
  let objFilter = $state("");
  let savedMsg = $state("");

  const shownObjects = $derived.by(() => {
    const q = objFilter.trim().toLowerCase();
    const list = extracted?.objects ?? [];
    return q ? list.filter((o) => `${o.kind} ${o.name} ${o.contentType} ${o.endpoints} ${o.detail}`.toLowerCase().includes(q)) : list;
  });
  const pickedIds = $derived(Object.entries(picked).filter(([, v]) => v).map(([k]) => Number(k)));

  async function choose() {
    const p = await open({
      multiple: false,
      filters: [
        { name: "Captures", extensions: ["pcap", "pcapng", "cap", "dmp"] },
        { name: "FortiGate sniffer text", extensions: ["txt", "log"] },
        { name: "All files", extensions: ["*"] },
      ],
    });
    if (typeof p !== "string") return;
    await load(p);
  }

  async function load(path: string) {
    if (loaded) void invoke("pcap_close", { id });
    id = Math.floor(Math.random() * 0x7fffffff);
    loading = true;
    error = "";
    loaded = null;
    detail = null;
    selected = null;
    progress = { bytes: 0, total: 0 };
    const ch = new Channel<{ type: "progress"; bytes: number; total: number }>();
    ch.onmessage = (e) => (progress = { bytes: e.bytes, total: e.total });
    try {
      loaded = await invoke<OpenResult>("pcap_open", { id, path, onEvent: ch });
      offset = 0;
      tab = "packets";
      await query();
    } catch (e) {
      error = String(e);
    } finally {
      loading = false;
    }
  }

  async function query() {
    if (!loaded) return;
    try {
      const res = await invoke<{ rows: Summary[]; total: number }>("pcap_query", {
        id,
        filter: { ...filter, port: filter.port ? Number(filter.port) : null },
        offset,
        limit: PAGE,
      });
      rows = res.rows;
      total = res.total;
      error = "";
    } catch (e) {
      error = String(e);
    }
  }

  let qTimer: ReturnType<typeof setTimeout> | undefined;
  function filterChanged() {
    clearTimeout(qTimer);
    qTimer = setTimeout(() => {
      offset = 0;
      void query();
    }, 200);
  }

  async function pick(r: Summary) {
    selected = r.index;
    try {
      detail = await invoke<PacketDetail>("pcap_packet", { id, index: r.index });
    } catch (e) {
      error = String(e);
    }
  }

  function page(d: number) {
    offset = Math.max(0, Math.min(offset + d * PAGE, Math.max(0, total - 1)));
    void query();
  }

  async function wireshark() {
    try {
      await invoke("pcap_open_external", { id });
    } catch (e) {
      error = String(e);
    }
  }

  async function saveClean() {
    if (!loaded) return;
    const stem = loaded.name.replace(/\.[^.]+$/, "");
    const out = await save({
      defaultPath: `${stem}-clean.pcapng`,
      filters: [{ name: "PCAPNG", extensions: ["pcapng"] }],
    });
    if (!out) return;
    cleaning = true;
    cleanReport = null;
    error = "";
    progress = { bytes: 0, total: 0 };
    const ch = new Channel<{ type: "progress"; bytes: number; total: number }>();
    ch.onmessage = (e) => (progress = { bytes: e.bytes, total: e.total });
    const opts: SanitizeOptions = {
      stripPayload: cleanOpts.stripPayload,
      addresses: cleanOpts.addresses,
      macs: cleanOpts.macs,
      key: cleanOpts.matchObfuscator ? obfuscatorSession.key : "",
    };
    try {
      cleanReport = await invoke<SanitizeReport>("pcap_sanitize", { id, out, opts, onEvent: ch });
      cleanPath = out;
      // Start the Obfuscator session with this key, so pasted text matches.
      if (cleanOpts.matchObfuscator && !obfuscatorSession.key) obfuscatorSession.key = cleanReport.key;
    } catch (e) {
      error = String(e);
    } finally {
      cleaning = false;
    }
  }

  async function findObjects() {
    if (!loaded) return;
    extracting = true;
    extracted = null;
    picked = {};
    savedMsg = "";
    error = "";
    progress = { bytes: 0, total: 0 };
    const ch = new Channel<{ type: "progress"; bytes: number; total: number }>();
    ch.onmessage = (e) => (progress = { bytes: e.bytes, total: e.total });
    try {
      extracted = await invoke<ExtractResult>("pcap_extract", { id, opts: $state.snapshot(extractOpts), onEvent: ch });
    } catch (e) {
      error = String(e);
    } finally {
      extracting = false;
    }
  }

  function pickAll(on: boolean) {
    const next: Record<number, boolean> = { ...picked };
    for (const o of shownObjects) next[o.id] = on;
    picked = next;
  }

  async function saveObjects(ids: number[]) {
    if (!ids.length) return;
    const folder = await open({ directory: true, multiple: false, title: "Folder for the extracted files" });
    if (typeof folder !== "string") return;
    try {
      const r = await invoke<{ saved: { id: number; path: string }[]; errors: string[] }>("pcap_extract_save", { id, folder, ids });
      savedMsg = `Saved ${r.saved.length} file${r.saved.length === 1 ? "" : "s"} to ${folder}.`;
      if (r.errors.length) error = r.errors.slice(0, 5).join("\n");
    } catch (e) {
      error = String(e);
    }
  }

  function showFor(value: Partial<Filter>) {
    filter = { text: "", proto: "", ip: "", port: null, onlyFlagged: false, ...value };
    tab = "packets";
    offset = 0;
    void query();
  }

  const layers = $derived.by(() => {
    if (!detail) return [] as [string, { name: string; value: string }[]][];
    const m = new Map<string, { name: string; value: string }[]>();
    for (const f of detail.fields) {
      if (!m.has(f.layer)) m.set(f.layer, []);
      m.get(f.layer)!.push(f);
    }
    return [...m.entries()];
  });

  onDestroy(() => {
    if (loaded) void invoke("pcap_close", { id });
  });
</script>

<div class="panel">
  <header>
    <h1>PCAP Inspector</h1>
    <p class="sub">
      Summarize a PCAP or PCAPNG capture, or FortiGate sniffer text: packets with L2 to L4 fields and hex,
      conversations, top talkers, protocols and DNS. Offline. For full protocol analysis, open the file in Wireshark.
    </p>
  </header>

  <div class="row">
    <button class="primary" onclick={choose} disabled={loading}>Open capture...</button>
    {#if loading}
      <button class="second" onclick={() => invoke("pcap_cancel", { id })}>Stop</button>
      <span class="muted">Reading {bytes(progress.bytes)}{progress.total ? ` of ${bytes(progress.total)}` : ""}...</span>
    {/if}
    {#if loaded}
      <button class="second" onclick={wireshark}>Open in Wireshark</button>
      <button class="second" class:on={cleanOpen} onclick={() => (cleanOpen = !cleanOpen)}>Clean copy...</button>
      <button class="second" class:on={extractOpen} onclick={() => (extractOpen = !extractOpen)}>Extract files...</button>
      <span class="spacer"></span>
      <ExportMenu build={() => (loaded ? buildPcapReport(loaded) : null)} name={`capture-${loaded.name}`} />
    {/if}
  </div>
  {#if loaded && cleanOpen}
    <section class="clean">
      <h2>Clean copy for sharing</h2>
      <p class="muted small">
        Writes a new PCAPNG file; the original is not changed. Use it before sending a capture to a vendor, a forum or an AI
        assistant.
      </p>
      <div class="opts">
        <label class="chk"><input type="checkbox" bind:checked={cleanOpts.stripPayload} /> Remove payloads (keep link, IP and TCP/UDP headers)</label>
        <label class="chk"><input type="checkbox" bind:checked={cleanOpts.addresses} /> Replace IP addresses (keep subnets)</label>
        <label class="chk"><input type="checkbox" bind:checked={cleanOpts.macs} /> Replace MAC addresses (keep vendor)</label>
        <label class="chk" title="Same fake addresses as text you obfuscate in the Obfuscator during this app session">
          <input type="checkbox" bind:checked={cleanOpts.matchObfuscator} /> Match the Obfuscator session
        </label>
      </div>
      {#if !cleanOpts.stripPayload}
        <p class="warn">Without removing payloads, names and addresses inside application data (DNS, DHCP, HTTP, TLS server names, logins) stay as they are.</p>
      {/if}
      <div class="row">
        <button class="primary" onclick={saveClean} disabled={cleaning || !(cleanOpts.stripPayload || cleanOpts.addresses || cleanOpts.macs)}>
          {cleaning ? "Writing..." : "Save clean copy..."}
        </button>
        {#if cleaning}
          <button class="second" onclick={() => invoke("pcap_cancel", { id })}>Stop</button>
          <span class="muted">{bytes(progress.bytes)}{progress.total ? ` of ${bytes(progress.total)}` : ""}</span>
        {/if}
      </div>
      {#if cleanReport}
        {@const r = cleanReport}
        {#if r.cancelled}
          <div class="warn">Stopped. The partial file was deleted.</div>
        {:else}
          <div class="okbox">
            Saved {r.written.toLocaleString()} of {r.packets.toLocaleString()} packets to <span class="mono">{cleanPath}</span>.
            {r.stripped ? `${r.stripped.toLocaleString()} payloads removed (${bytes(r.bytesRemoved)}). ` : ""}
            {r.addresses ? `${r.addresses} IP addresses and ` : ""}{r.macs ? `${r.macs} MAC addresses replaced. ` : ""}
            {r.otherCut ? `${r.otherCut.toLocaleString()} other frames (ARP variants, LLDP, CDP, STP and similar) cut to their link header. ` : ""}
            {r.dropped ? `${r.dropped.toLocaleString()} packets left out (link type not supported).` : ""}
          </div>
        {/if}
        {#each r.warnings as w (w)}<div class="warn">{w}</div>{/each}
        {#if r.mapping.length}
          <details class="map">
            <summary>Replaced addresses ({r.mapping.length}{r.mapping.length >= 2000 ? ", first 2,000" : ""}); shown here only</summary>
            <table>
              <tbody>
                {#each r.mapping as m (m.kind + m.original)}
                  <tr><td class="muted">{m.kind === "ip" ? "IP" : "MAC"}</td><td class="mono">{m.original}</td><td class="mono">{m.fake}</td></tr>
                {/each}
              </tbody>
            </table>
          </details>
        {/if}
      {/if}
    </section>
  {/if}
  {#if loaded && extractOpen}
    <section class="clean">
      <h2>Extract files and calls</h2>
      <p class="muted small">
        Finds files carried in clear text (HTTP, FTP, TFTP) and G.711 voice calls (RTP, saved as WAV). Encrypted traffic such as
        HTTPS, FTPS and SRTP cannot be extracted.
      </p>
      <div class="opts">
        <label class="chk"><input type="checkbox" bind:checked={extractOpts.http} /> HTTP objects and uploads</label>
        <label class="chk"><input type="checkbox" bind:checked={extractOpts.ftp} /> FTP transfers</label>
        <label class="chk"><input type="checkbox" bind:checked={extractOpts.tftp} /> TFTP transfers</label>
        <label class="chk"><input type="checkbox" bind:checked={extractOpts.voice} /> Voice calls (RTP G.711)</label>
        <label class="chk"><input type="checkbox" bind:checked={extractOpts.decompress} /> Decode gzip and deflate bodies</label>
      </div>
      <div class="row">
        <button class="primary" onclick={findObjects} disabled={extracting || !(extractOpts.http || extractOpts.ftp || extractOpts.tftp || extractOpts.voice)}>
          {extracting ? "Searching..." : "Find"}
        </button>
        {#if extracting}
          <button class="second" onclick={() => invoke("pcap_cancel", { id })}>Stop</button>
          <span class="muted">{bytes(progress.bytes)}{progress.total ? ` of ${bytes(progress.total)}` : ""}</span>
        {/if}
      </div>
      {#if extracted}
        {#each extracted.warnings as w (w)}<div class="warn">{w}</div>{/each}
        {#if extracted.cancelled}<div class="warn">Stopped; only the part read was searched.</div>{/if}
        {#if !extracted.objects.length}
          <p class="muted">Nothing found.</p>
        {:else}
          <p class="warn">
            These files come from network traffic and may be malicious. They are saved, never opened. Scan them before you open
            them.
          </p>
          <div class="row">
            <input class="mono grow" bind:value={objFilter} placeholder="filter by name, type, address or request" spellcheck="false" />
            <button class="mini" onclick={() => pickAll(true)}>Select shown</button>
            <button class="mini" onclick={() => pickAll(false)}>Clear</button>
            <button class="primary" onclick={() => saveObjects(pickedIds)} disabled={!pickedIds.length}>Save {pickedIds.length || ""} to folder...</button>
          </div>
          {#if savedMsg}<div class="okbox">{savedMsg}</div>{/if}
          <div class="table-wrap objs">
            <table class="pk">
              <thead><tr><th></th><th>Type</th><th>Name</th><th>Size</th><th>From &gt; to</th><th>Details</th><th>#</th></tr></thead>
              <tbody>
                {#each shownObjects as o (o.id)}
                  <tr class:bad={!o.complete}>
                    <td><input type="checkbox" bind:checked={picked[o.id]} aria-label="Select {o.name}" /></td>
                    <td>{OBJECT_KIND[o.kind]}</td>
                    <td class="mono" title={`SHA-256 ${o.sha256}`}>{o.name}{#if !o.complete}<span class="tag" title="Bytes are missing (lost packets, capture cut or size limit)">incomplete</span>{/if}</td>
                    <td class="num">{bytes(o.size)}</td>
                    <td class="mono small">{o.endpoints}</td>
                    <td class="small">{o.contentType ? `${o.contentType} · ` : ""}{o.detail}</td>
                    <td class="num">{o.firstPacket}</td>
                  </tr>
                {/each}
              </tbody>
            </table>
          </div>
        {/if}
      {/if}
    </section>
  {/if}
  {#if loading && progress.total}<div class="bar"><div class="fill" style="width: {Math.min(100, (100 * progress.bytes) / progress.total)}%"></div></div>{/if}
  {#if error}<div class="error">{error}</div>{/if}

  {#if loaded}
    {@const s = loaded.stats}
    <div class="cards">
      <div><span class="v">{s.packets.toLocaleString()}</span><span class="k">packets</span></div>
      <div><span class="v">{bytes(s.bytes)}</span><span class="k">on the wire</span></div>
      <div><span class="v">{duration(s)}</span><span class="k">duration</span></div>
      <div><span class="v">{s.tcpSyn}</span><span class="k">TCP SYN</span></div>
      <div><span class="v">{s.tcpRst}</span><span class="k">TCP resets</span></div>
      <div><span class="v">{s.encrypted}</span><span class="k">encrypted payloads</span></div>
      <div class:warnv={s.truncated > 0}><span class="v">{s.truncated}</span><span class="k">truncated</span></div>
      <div class:warnv={s.malformed > 0}><span class="v">{s.malformed}</span><span class="k">malformed or undecoded</span></div>
    </div>
    <div class="muted small">{loaded.name} · {loaded.format} · {s.linkTypes.join(", ")}{s.firstNs ? ` · starts ${new Date(s.firstNs / 1e6).toISOString().replace("T", " ").slice(0, 19)} UTC` : ""}</div>
    {#each loaded.warnings as w (w)}<div class="warn">{w}</div>{/each}
    {#if loaded.cancelled}<div class="warn">Reading was stopped; figures cover only the part read.</div>{/if}

    <div class="tabs" role="tablist">
      {#each [["packets", "Packets"], ["conversations", "Conversations"], ["talkers", "Top talkers"], ["protocols", "Protocols"], ["dns", "DNS"]] as [t, label] (t)}
        <button role="tab" aria-selected={tab === t} class:active={tab === t} onclick={() => (tab = t as Tab)}>{label}</button>
      {/each}
    </div>

    {#if tab === "packets"}
      <div class="filters">
        <input class="mono grow" bind:value={filter.text} oninput={filterChanged} placeholder="search source, destination, protocol, info" spellcheck="false" />
        <select bind:value={filter.proto} onchange={filterChanged} aria-label="Protocol">
          <option value="">any protocol</option>
          {#each s.protocols as p (p.name)}<option value={p.name}>{p.name}</option>{/each}
        </select>
        <input class="mono ip" bind:value={filter.ip} oninput={filterChanged} placeholder="IP address" spellcheck="false" />
        <input class="mono port" type="number" min="1" max="65535" bind:value={filter.port} oninput={filterChanged} placeholder="port" />
        <label class="chk"><input type="checkbox" bind:checked={filter.onlyFlagged} onchange={filterChanged} /> truncated or malformed</label>
      </div>
      <div class="pager">
        <span class="muted small">{total.toLocaleString()} match{total === 1 ? "" : "es"}{total ? `, showing ${offset + 1} to ${Math.min(offset + PAGE, total)}` : ""}{loaded.listed < s.packets ? ` (first ${loaded.listed.toLocaleString()} packets listed)` : ""}</span>
        <span class="spacer"></span>
        <button class="mini" onclick={() => page(-1)} disabled={offset === 0}>Previous</button>
        <button class="mini" onclick={() => page(1)} disabled={offset + PAGE >= total}>Next</button>
      </div>
      <div class="table-wrap">
        <table class="pk">
          <thead><tr><th>#</th><th>Time (UTC)</th><th>Source</th><th>Destination</th><th>Protocol</th><th>Len</th><th>Info</th></tr></thead>
          <tbody>
            {#each rows as r (r.index)}
              <tr class:sel={selected === r.index} class:bad={r.malformed} onclick={() => pick(r)}>
                <td class="n">{r.index + 1}</td>
                <td class="mono">{clock(r.tsNs)}</td>
                <td class="mono">{r.src}</td>
                <td class="mono">{r.dst}</td>
                <td>{r.proto}{#if r.encrypted}<span class="tag">enc</span>{/if}</td>
                <td class="n">{r.origLen}{#if r.truncated}<span class="tag" title="captured {r.capLen} of {r.origLen} bytes">cut</span>{/if}</td>
                <td class="info">{r.info}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
      {#if detail}
        <div class="detail">
          <div class="dcol">
            <strong>Packet {detail.summary.index + 1}</strong> <span class="muted small">{detail.link}</span>
            {#if detail.malformed}<div class="warn">{detail.malformed}</div>{/if}
            {#each layers as [layer, fields] (layer)}
              <div class="layer">{layer}</div>
              <table class="kv"><tbody>{#each fields as f, i (i)}<tr><th>{f.name}</th><td class="mono">{f.value}</td></tr>{/each}</tbody></table>
            {/each}
          </div>
          <pre class="mono hex">{detail.hex}</pre>
        </div>
      {/if}
    {:else if tab === "conversations"}
      <table class="grid">
        <thead><tr><th>Protocol</th><th>Endpoint A</th><th>Endpoint B</th><th class="n">Packets</th><th class="n">Bytes</th><th>Duration</th></tr></thead>
        <tbody>
          {#each s.conversations as c, i (i)}
            <tr>
              <td>{c.proto}</td><td class="mono">{c.a}</td><td class="mono">{c.b}</td><td class="n">{c.packets.toLocaleString()}</td><td class="n">{bytes(c.bytes)}</td>
              <td class="muted">{((c.lastNs - c.firstNs) / 1e9).toFixed(2)} s</td>
            </tr>
          {/each}
        </tbody>
      </table>
      <p class="muted small">Top 1,000 by bytes.{s.keysCapped ? " Tracking stopped adding new entries after 50,000." : ""}</p>
    {:else if tab === "talkers"}
      <table class="grid">
        <thead><tr><th>Address</th><th class="n">Packets</th><th class="n">Bytes</th><th></th></tr></thead>
        <tbody>
          {#each s.talkers as t (t.name)}
            <tr><td class="mono">{t.name}</td><td class="n">{t.packets.toLocaleString()}</td><td class="n">{bytes(t.bytes)}</td><td><button class="link" onclick={() => showFor({ ip: t.name })}>packets</button></td></tr>
          {/each}
        </tbody>
      </table>
    {:else if tab === "protocols"}
      <table class="grid">
        <thead><tr><th>Protocol</th><th class="n">Packets</th><th class="n">Bytes</th><th class="n">Share</th><th></th></tr></thead>
        <tbody>
          {#each s.protocols as p (p.name)}
            <tr>
              <td>{p.name}</td><td class="n">{p.packets.toLocaleString()}</td><td class="n">{bytes(p.bytes)}</td><td class="n">{((100 * p.packets) / Math.max(1, s.packets)).toFixed(1)}%</td>
              <td><button class="link" onclick={() => showFor({ proto: p.name })}>packets</button></td>
            </tr>
          {/each}
        </tbody>
      </table>
      <p class="muted small">Labels come from ports and payload checks; a protocol on a non-standard port shows as plain TCP or UDP.</p>
    {:else}
      {#if !s.dns.length}<p class="muted">No DNS traffic decoded.</p>{/if}
      <table class="grid">
        <thead><tr><th>Name</th><th>Type</th><th class="n">Queries</th><th class="n">Responses</th><th>Errors</th></tr></thead>
        <tbody>
          {#each s.dns as d, i (i)}
            <tr><td class="mono">{d.name}</td><td>{d.qtype}</td><td class="n">{d.queries}</td><td class="n">{d.responses}</td><td class:errc={d.errors.length}>{d.errors.map(([c, n]) => `${c} x${n}`).join(", ")}</td></tr>
          {/each}
        </tbody>
      </table>
    {/if}
  {/if}
</div>

<style>
  .panel {
    padding: 1.5rem 2rem;
    max-width: 1200px;
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

  .row,
  .filters,
  .pager {
    display: flex;
    align-items: center;
    gap: 0.6rem;
    flex-wrap: wrap;
    margin-bottom: 0.6rem;
  }

  .spacer {
    flex: 1;
  }

  input,
  select {
    box-sizing: border-box;
    background: var(--input-bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.35rem 0.5rem;
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

  .grow {
    flex: 1 1 16rem;
  }

  .ip {
    width: 10rem;
  }

  .port {
    width: 5.5rem;
  }

  .mono {
    font-family: var(--mono);
  }

  .primary {
    background: var(--accent);
    color: var(--accent-fg);
    border: 1px solid var(--accent);
    border-radius: 6px;
    padding: 0.45rem 1rem;
    font-weight: 600;
    cursor: pointer;
  }

  .second {
    background: var(--input-bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.45rem 0.9rem;
    color: var(--fg);
    cursor: pointer;
    font-size: 0.84rem;
  }

  .mini {
    background: var(--input-bg);
    border: 1px solid var(--border);
    border-radius: 4px;
    color: var(--fg);
    font-size: 0.74rem;
    padding: 0.15rem 0.55rem;
    cursor: pointer;
  }

  .mini:disabled {
    opacity: 0.4;
  }

  .link {
    background: none;
    border: none;
    color: var(--accent);
    font-size: 0.76rem;
    cursor: pointer;
    padding: 0;
  }

  .chk {
    display: inline-flex;
    align-items: center;
    gap: 0.3rem;
    font-size: 0.78rem;
  }

  .muted {
    color: var(--muted);
    font-size: 0.8rem;
  }

  .small {
    font-size: 0.74rem;
  }

  .bar {
    height: 5px;
    background: var(--hover);
    border-radius: 3px;
    overflow: hidden;
    margin-bottom: 0.6rem;
  }

  .fill {
    height: 100%;
    background: var(--accent);
  }

  .error {
    color: var(--error-fg);
    font-size: 0.84rem;
    margin: 0.5rem 0;
  }

  .warn {
    border-left: 3px solid #b7791f;
    padding: 0.25rem 0.6rem;
    font-size: 0.78rem;
    margin: 0.35rem 0;
  }

  .cards {
    display: flex;
    flex-wrap: wrap;
    gap: 1.4rem;
    margin: 0.6rem 0 0.3rem;
  }

  .cards > div {
    display: flex;
    flex-direction: column;
  }

  .v {
    font-size: 1.2rem;
    font-weight: 700;
  }

  .k {
    font-size: 0.7rem;
    color: var(--muted);
  }

  .warnv .v {
    color: #b7791f;
  }

  .tabs {
    display: flex;
    gap: 0.25rem;
    border-bottom: 1px solid var(--border);
    margin: 0.9rem 0 0.7rem;
  }

  .tabs button {
    background: none;
    border: none;
    border-bottom: 2px solid transparent;
    color: var(--muted);
    padding: 0.4rem 0.8rem;
    font-size: 0.85rem;
    cursor: pointer;
  }

  .tabs button.active {
    color: var(--fg);
    border-bottom-color: var(--accent);
  }

  .table-wrap {
    max-height: 26rem;
    overflow: auto;
    border: 1px solid var(--border);
    border-radius: 6px;
  }

  table {
    border-collapse: collapse;
    width: 100%;
    font-size: 0.78rem;
  }

  th,
  td {
    text-align: left;
    padding: 0.2rem 0.6rem 0.2rem 0.4rem;
    border-bottom: 1px solid var(--border);
    white-space: nowrap;
  }

  th {
    position: sticky;
    top: 0;
    background: var(--bg);
    color: var(--muted);
    font-weight: 500;
  }

  .pk tr {
    cursor: pointer;
  }

  .pk tr:hover td {
    background: var(--hover);
  }

  .pk tr.sel td {
    background: var(--active-bg);
  }

  .pk tr.bad td {
    color: #b7791f;
  }

  .n {
    text-align: right;
  }

  .info {
    white-space: normal;
    min-width: 18rem;
  }

  .tag {
    font-size: 0.62rem;
    border: 1px solid var(--border);
    border-radius: 3px;
    padding: 0 0.25rem;
    margin-left: 0.3rem;
    color: var(--muted);
  }

  .detail {
    display: grid;
    grid-template-columns: minmax(16rem, 1fr) minmax(20rem, 1.2fr);
    gap: 1rem;
    margin-top: 0.8rem;
  }

  .layer {
    font-weight: 600;
    font-size: 0.8rem;
    margin: 0.5rem 0 0.15rem;
  }

  .kv th {
    position: static;
    width: 1%;
    font-weight: 400;
  }

  .hex {
    margin: 0;
    font-size: 0.74rem;
    background: var(--input-bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.5rem;
    max-height: 28rem;
    overflow: auto;
  }

  .grid td.errc {
    color: var(--error-fg);
  }

  .clean {
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.7rem 0.9rem;
    margin: 0.6rem 0;
  }

  .clean h2 {
    font-size: 0.95rem;
    margin: 0 0 0.2rem;
  }

  .opts {
    display: flex;
    flex-wrap: wrap;
    gap: 0.4rem 1.1rem;
    margin: 0.5rem 0;
  }

  .okbox {
    border: 1px solid #16a34a;
    border-radius: 6px;
    padding: 0.5rem 0.7rem;
    font-size: 0.8rem;
    margin: 0.5rem 0;
    overflow-wrap: anywhere;
  }

  .map {
    font-size: 0.8rem;
    margin-top: 0.4rem;
  }

  .map summary {
    cursor: pointer;
    color: var(--muted);
  }

  .map table {
    border-collapse: collapse;
    margin-top: 0.3rem;
  }

  .map td {
    padding: 0.1rem 0.8rem 0.1rem 0;
    font-size: 0.78rem;
  }

  button.on {
    border-color: var(--accent);
  }

  .objs {
    max-height: 22rem;
  }

  .tag {
    font-size: 0.66rem;
    border: 1px solid #b45309;
    color: #b45309;
    border-radius: 3px;
    padding: 0 0.3rem;
    margin-left: 0.4rem;
  }

  td.num {
    text-align: right;
    white-space: nowrap;
  }
</style>
