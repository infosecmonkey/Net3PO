<script lang="ts">
  import { invoke, Channel } from "@tauri-apps/api/core";
  import { save } from "@tauri-apps/plugin-dialog";
  import type { MacRow, PortMap, PortMapEvent, PortRow } from "$lib/tools/types";

  const MAX_ROWS = 5000;
  const AUTH_PROTOS = ["none", "md5", "sha1", "sha224", "sha256", "sha384", "sha512"];
  const CIPHERS = ["none", "des", "aes128", "aes192", "aes256"];

  let host = $state("");
  let port = $state(161);
  let version = $state("v2c");
  let community = $state("public");
  let username = $state("");
  let authProtocol = $state("sha1");
  let authPassword = $state("");
  let privCipher = $state("aes128");
  let privPassword = $state("");
  let arpHost = $state("");

  let mapping = $state(false);
  let stage = $state("");
  let error = $state("");
  let map = $state<PortMap | null>(null);
  let mapId = 0;

  let view = $state<"macs" | "ports">("macs");
  let selectedIf = $state<number | null>(null);
  let search = $state("");
  let hideUplinks = $state(true);
  let showAll = $state(false);
  let showPortMacs = $state(false);
  let copied = $state(false);

  /** Split a name into text and number runs so Gi1/0/10 sorts after Gi1/0/9. */
  function natKey(s: string): (string | number)[] {
    return (s.match(/\d+|\D+/g) ?? []).map((p) => (/^\d+$/.test(p) ? Number(p) : p));
  }

  function natCmp(a: string, b: string): number {
    const ka = natKey(a);
    const kb = natKey(b);
    for (let i = 0; i < Math.min(ka.length, kb.length); i++) {
      const x = ka[i];
      const y = kb[i];
      if (x === y) continue;
      if (typeof x === "number" && typeof y === "number") return x - y;
      return String(x).localeCompare(String(y));
    }
    return ka.length - kb.length;
  }

  /** Faceplate groups: ports sharing a name prefix (e.g. "Gi1/0/"). */
  const groups = $derived.by(() => {
    if (!map) return [];
    const ports = map.ports.filter((p) => showAll || p.physical);
    const byPrefix = new Map<string, PortRow[]>();
    for (const p of [...ports].sort((a, b) => natCmp(a.name, b.name))) {
      const prefix = p.name.replace(/\d+$/, "");
      if (!byPrefix.has(prefix)) byPrefix.set(prefix, []);
      byPrefix.get(prefix)!.push(p);
    }
    return [...byPrefix.entries()].map(([prefix, ports]) => ({ prefix, ports }));
  });

  const sortedPorts = $derived(
    map ? [...map.ports].filter((p) => showAll || p.physical).sort((a, b) => natCmp(a.name, b.name)) : [],
  );

  const macsByIf = $derived.by(() => {
    const byIf = new Map<number, MacRow[]>();
    for (const m of map?.macs ?? []) {
      if (m.ifIndex === null) continue;
      if (!byIf.has(m.ifIndex)) byIf.set(m.ifIndex, []);
      byIf.get(m.ifIndex)!.push(m);
    }
    return byIf;
  });

  const aliasByIf = $derived(new Map((map?.ports ?? []).map((p) => [p.ifIndex, p.alias])));

  const selectedPort = $derived(map?.ports.find((p) => p.ifIndex === selectedIf) ?? null);

  const shownMacs = $derived.by(() => {
    if (!map) return [];
    const q = search.trim().toLowerCase();
    const qHex = q.replace(/[:.\-\s]/g, "");
    return map.macs.filter((m) => {
      if (selectedIf !== null) {
        if (m.ifIndex !== selectedIf) return false;
      } else if (hideUplinks && m.onUplink) {
        return false;
      }
      if (!q) return true;
      if (qHex && m.mac.replace(/:/g, "").toLowerCase().includes(qHex)) return true;
      return [m.vendor ?? "", m.port, m.vlan?.toString() ?? "", ...m.ips].some((f) =>
        f.toLowerCase().includes(q),
      );
    });
  });

  function shortLabel(p: PortRow): string {
    const m = p.name.match(/(\d+)$/);
    return m ? m[1] : p.name;
  }

  function tileState(p: PortRow): string {
    if (p.adminStatus === "down") return "disabled";
    return p.operStatus === "up" ? "up" : "down";
  }

  function tileTitle(p: PortRow): string {
    const lines = [p.name];
    if (p.alias) lines.push(p.alias);
    lines.push(`admin ${p.adminStatus || "?"}, oper ${p.operStatus || "?"}`);
    if (p.speed) lines.push(p.speed);
    if (p.pvid !== null) lines.push(`PVID ${p.pvid}`);
    lines.push(`${p.macCount} MAC${p.macCount === 1 ? "" : "s"}${p.uplink ? " (likely uplink)" : ""}`);
    return lines.join("\n");
  }

  function selectPort(ifIndex: number) {
    selectedIf = selectedIf === ifIndex ? null : ifIndex;
    view = "macs";
  }

  async function run() {
    if (host.trim().length === 0) {
      error = "Enter the switch host or IP.";
      return;
    }
    error = "";
    map = null;
    selectedIf = null;
    stage = "Starting";
    mapping = true;
    mapId = Math.floor(Math.random() * 0x7fffffff);

    const channel = new Channel<PortMapEvent>();
    channel.onmessage = (ev) => {
      switch (ev.type) {
        case "stage":
          stage = ev.message;
          break;
        case "done":
          map = ev.map;
          stage = "";
          mapping = false;
          break;
        case "error":
          error = ev.message;
          stage = "";
          mapping = false;
          break;
        case "cancelled":
          stage = "Cancelled.";
          mapping = false;
          break;
      }
    };

    const snmp = {
      host,
      port,
      version,
      community,
      username,
      authProtocol,
      authPassword,
      privCipher,
      privPassword,
      timeoutMs: 3000,
    };
    try {
      await invoke("port_map", { mapId, config: { snmp, arpHost }, onEvent: channel });
    } catch (e) {
      error = String(e);
      stage = "";
      mapping = false;
    }
  }

  async function cancel() {
    try {
      await invoke("port_map_cancel", { mapId });
    } catch {
      // ignore
    }
  }

  function csvField(s: string): string {
    return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
  }

  function csvLine(fields: (string | number | null | undefined)[]): string {
    return fields.map((f) => csvField(f == null ? "" : String(f))).join(",");
  }

  /** MACs view: one row per shown MAC. */
  function macsCsv(): string {
    const lines = shownMacs.map((m) =>
      csvLine([
        m.mac,
        m.vendor,
        m.vlan,
        m.port,
        m.ifIndex !== null ? aliasByIf.get(m.ifIndex) : "",
        m.ips.join(" "),
      ]),
    );
    return ["mac,vendor,vlan,port,description,ips", ...lines].join("\n");
  }

  /** Ports view: one row per MAC with its port details; MAC-less ports get one row. */
  function portsCsv(): string {
    const lines: string[] = [];
    for (const p of sortedPorts) {
      const status = p.adminStatus === "down" ? "admin down" : p.operStatus;
      const base = [p.name, p.alias, status, p.speed, p.pvid, p.vlans.join(" ")];
      const macs = macsByIf.get(p.ifIndex) ?? [];
      if (macs.length === 0) {
        lines.push(csvLine([...base, "", "", "", ""]));
      }
      for (const m of macs) {
        lines.push(csvLine([...base, m.mac, m.vendor, m.vlan, m.ips.join(" ")]));
      }
    }
    return ["port,description,status,speed,pvid,vlans,mac,vendor,mac_vlan,ips", ...lines].join("\n");
  }

  function currentCsv(): string {
    return view === "macs" ? macsCsv() : portsCsv();
  }

  async function copyCsv() {
    try {
      await navigator.clipboard.writeText(currentCsv());
      copied = true;
      setTimeout(() => (copied = false), 1500);
    } catch (e) {
      error = `Copy failed: ${e}`;
    }
  }

  async function saveCsv() {
    try {
      const device = (map?.sysName || host).split(".")[0].replace(/[^\w.-]/g, "_");
      const path = await save({
        defaultPath: `${device}-${view}.csv`,
        filters: [{ name: "CSV", extensions: ["csv"] }],
      });
      if (typeof path !== "string") return;
      await invoke("port_map_save", { path, contents: currentCsv() + "\n" });
    } catch (e) {
      error = String(e);
    }
  }

</script>

<div class="panel">
  <header>
    <h1>Switch Port Mapper</h1>
    <p class="sub">
      Map learned MAC addresses to switch ports over SNMP (BRIDGE-MIB, Q-BRIDGE-MIB,
      Cisco per-VLAN). Optional router ARP adds IPs.
    </p>
  </header>

  <div class="grid">
    <div class="field grow">
      <label for="host">Switch host or IP</label>
      <input id="host" class="mono" bind:value={host} disabled={mapping} spellcheck="false" />
    </div>
    <div class="field">
      <label for="port">Port</label>
      <input id="port" type="number" min="1" max="65535" bind:value={port} disabled={mapping} />
    </div>
    <div class="field">
      <label for="ver">Version</label>
      <select id="ver" bind:value={version} disabled={mapping}>
        <option value="v1">v1</option>
        <option value="v2c">v2c</option>
        <option value="v3">v3</option>
      </select>
    </div>
  </div>

  {#if version === "v3"}
    <div class="grid">
      <div class="field">
        <label for="user">Username</label>
        <input id="user" class="mono" bind:value={username} disabled={mapping} spellcheck="false" />
      </div>
      <div class="field">
        <label for="authp">Auth</label>
        <select id="authp" bind:value={authProtocol} disabled={mapping}>
          {#each AUTH_PROTOS as a (a)}<option value={a}>{a}</option>{/each}
        </select>
      </div>
      <div class="field grow">
        <label for="authpw">Auth password</label>
        <input id="authpw" type="password" bind:value={authPassword} disabled={mapping || authProtocol === "none"} />
      </div>
    </div>
    <div class="grid">
      <div class="field">
        <label for="cipher">Privacy</label>
        <select id="cipher" bind:value={privCipher} disabled={mapping || authProtocol === "none"}>
          {#each CIPHERS as c (c)}<option value={c}>{c}</option>{/each}
        </select>
      </div>
      <div class="field grow">
        <label for="privpw">Privacy password</label>
        <input id="privpw" type="password" bind:value={privPassword} disabled={mapping || privCipher === "none" || authProtocol === "none"} />
      </div>
    </div>
  {:else}
    <div class="grid">
      <div class="field grow">
        <label for="comm">Community</label>
        <input id="comm" class="mono" bind:value={community} disabled={mapping} spellcheck="false" />
      </div>
    </div>
  {/if}

  <div class="grid">
    <div class="field grow">
      <label for="arp">ARP source (router or L3 switch, optional, same credentials)</label>
      <input id="arp" class="mono" bind:value={arpHost} disabled={mapping} spellcheck="false" placeholder="10.0.0.1" />
    </div>
  </div>

  <div class="row">
    {#if mapping}
      <button class="action stop" onclick={cancel}>Cancel</button>
    {:else}
      <button class="action" onclick={run}>Map ports</button>
    {/if}
    {#if stage}<span class="done muted">{stage}{mapping ? "..." : ""}</span>{/if}
  </div>

  {#if error}
    <div class="error mono">{error}</div>
  {/if}

  {#if map}
    <div class="device">
      <div>
        <span class="mono strong">{map.sysName || host}</span>
        <span class="muted"> · {map.source || "no FDB"} · {map.ports.length} interfaces · {map.macs.length.toLocaleString()} MACs{map.truncated ? " (capped)" : ""}</span>
      </div>
      {#if map.sysDescr}<div class="descr muted">{map.sysDescr}</div>{/if}
    </div>

    {#each map.warnings as w (w)}
      <div class="warn">{w}</div>
    {/each}

    <div class="faceplate">
      {#each groups as g (g.prefix)}
        <div class="group">
          <div class="gname mono muted">{g.prefix || "ports"}</div>
          <div class="ports-scroll">
          <div class="ports">
            {#each g.ports as p (p.ifIndex)}
              <button
                class="tile {tileState(p)}"
                class:uplink={p.uplink}
                class:selected={selectedIf === p.ifIndex}
                title={tileTitle(p)}
                onclick={() => selectPort(p.ifIndex)}
              >
                <span class="num mono">{shortLabel(p)}</span>
                {#if p.macCount > 0}<span class="cnt">{p.macCount}</span>{/if}
              </button>
            {/each}
          </div>
          </div>
        </div>
      {:else}
        <p class="muted">No physical interfaces reported. Enable "all interfaces" to see the rest.</p>
      {/each}
      <div class="legend muted">
        <span><i class="sw up"></i>up</span>
        <span><i class="sw down"></i>down</span>
        <span><i class="sw disabled"></i>admin down</span>
        <span><i class="sw uplinkk"></i>likely uplink</span>
        <label class="check"><input type="checkbox" bind:checked={showAll} /> all interfaces</label>
      </div>
    </div>

    <div class="tabs">
      <button class:active={view === "macs"} onclick={() => (view = "macs")}>MACs</button>
      <button class:active={view === "ports"} onclick={() => (view = "ports")}>Ports</button>
    </div>

    {#if view === "macs"}
      <div class="row filters">
        <input class="mono search" bind:value={search} placeholder="Filter MAC, vendor, IP, VLAN, port" spellcheck="false" />
        {#if selectedPort}
          <span class="chip mono">{selectedPort.name}
            <button class="x" onclick={() => (selectedIf = null)} aria-label="Clear port filter">x</button>
          </span>
        {:else}
          <label class="check muted"><input type="checkbox" bind:checked={hideUplinks} /> hide MACs on uplinks</label>
        {/if}
        <button class="secondary" onclick={copyCsv} disabled={shownMacs.length === 0}>{copied ? "Copied" : "Copy CSV"}</button>
        <button class="secondary" onclick={saveCsv} disabled={shownMacs.length === 0}>Save CSV</button>
      </div>

      {#if shownMacs.length > 0}
        <div class="table-scroll">
          <table>
            <thead>
              <tr><th>MAC</th><th>Vendor</th><th>VLAN</th><th>Port</th><th>IP</th></tr>
            </thead>
            <tbody>
              {#each shownMacs.slice(0, MAX_ROWS) as m, i (i)}
                <tr>
                  <td class="mono">{m.mac}</td>
                  <td>{m.vendor ?? ""}</td>
                  <td class="mono dim">{m.vlan ?? ""}</td>
                  <td class="mono">
                    {#if m.ifIndex !== null}
                      <button class="link mono" onclick={() => selectPort(m.ifIndex!)}>{m.port}</button>
                    {:else}{m.port}{/if}
                    {#if m.onUplink}<span class="tag">uplink</span>{/if}
                  </td>
                  <td class="mono">{m.ips.join(", ")}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
        <p class="count muted">{shownMacs.length.toLocaleString()} of {map.macs.length.toLocaleString()} MACs{#if shownMacs.length > MAX_ROWS} (showing first {MAX_ROWS.toLocaleString()}){/if}</p>
      {:else}
        <p class="muted">
          No MACs match.{#if hideUplinks && selectedIf === null && map.macs.some((m) => m.onUplink)}
            Some are hidden because they were learned on uplinks.{/if}
        </p>
      {/if}
    {:else}
      <div class="row filters">
        <label class="check muted"><input type="checkbox" bind:checked={showPortMacs} /> show MACs</label>
        <span class="spacer"></span>
        <button class="secondary" onclick={copyCsv}>{copied ? "Copied" : "Copy CSV"}</button>
        <button class="secondary" onclick={saveCsv}>Save CSV</button>
      </div>
      <div class="table-scroll">
        <table>
          <thead>
            <tr><th>Port</th><th>Description</th><th>Status</th><th>Speed</th><th>PVID</th><th>VLANs</th><th>MACs</th></tr>
          </thead>
          <tbody>
            {#each sortedPorts as p (p.ifIndex)}
              <tr class:sel={selectedIf === p.ifIndex}>
                <td class="mono"><button class="link mono" onclick={() => selectPort(p.ifIndex)}>{p.name}</button></td>
                <td>{p.alias}</td>
                <td><span class="st {tileState(p)}">{p.adminStatus === "down" ? "admin down" : p.operStatus}</span></td>
                <td class="mono dim">{p.speed}</td>
                <td class="mono dim">{p.pvid ?? ""}</td>
                <td class="mono dim vl">{p.vlans.join(",")}</td>
                <td class="mono">
                  {p.macCount || ""}{#if p.uplink}<span class="tag">uplink</span>{/if}
                  {#if showPortMacs}
                    {#each macsByIf.get(p.ifIndex) ?? [] as m (m.mac + m.vlan)}
                      <div class="pmac">
                        {m.mac}{#if m.vendor}<span class="muted"> {m.vendor}</span>{/if}{#if m.ips.length}<span class="muted"> {m.ips.join(", ")}</span>{/if}
                      </div>
                    {/each}
                  {/if}
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
  {/if}
</div>

<style>
  .panel {
    --st-up: #2ea043;
    --st-down: #6e7681;
    --st-off: #b35454;
    --st-warn: #c69026;
    padding: 1.5rem 2rem 2rem;
    box-sizing: border-box;
    width: 100%;
  }

  header h1 {
    margin: 0 0 0.25rem;
    font-size: 1.3rem;
  }

  .sub {
    margin: 0 0 1.25rem;
    color: var(--muted);
    font-size: 0.85rem;
  }

  .grid {
    display: flex;
    flex-wrap: wrap;
    gap: 0.75rem;
    margin-bottom: 0.75rem;
  }

  .field {
    display: flex;
    flex-direction: column;
    flex: 1 1 130px;
  }

  .field.grow {
    flex: 2 1 220px;
  }

  label {
    font-size: 0.78rem;
    color: var(--muted);
    margin-bottom: 0.3rem;
  }

  input,
  select {
    width: 100%;
    box-sizing: border-box;
    background: var(--input-bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.45rem 0.55rem;
    color: var(--fg);
    font-size: 0.88rem;
  }

  input:focus,
  select:focus {
    outline: none;
    border-color: var(--accent);
  }

  input:disabled,
  select:disabled {
    opacity: 0.55;
  }

  input[type="checkbox"] {
    width: auto;
    margin: 0 0.3rem 0 0;
  }

  .mono {
    font-family: var(--mono);
  }

  .strong {
    font-weight: 600;
  }

  .row {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    margin: 0.3rem 0 1rem;
  }

  .secondary {
    background: var(--btn-bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.45rem 0.9rem;
    color: var(--fg);
    font-size: 0.82rem;
    cursor: pointer;
    white-space: nowrap;
  }

  .secondary:disabled {
    opacity: 0.5;
    cursor: default;
  }

  .action {
    background: var(--accent);
    border: 1px solid var(--accent);
    border-radius: 6px;
    padding: 0.5rem 1.3rem;
    color: var(--accent-fg);
    font-weight: 600;
    font-size: 0.85rem;
    cursor: pointer;
  }

  .action.stop {
    background: var(--btn-bg);
    border-color: var(--error-border);
    color: var(--error-fg);
  }

  .done {
    font-size: 0.82rem;
  }

  .muted {
    color: var(--muted);
  }

  .error {
    background: var(--error-bg);
    border: 1px solid var(--error-border);
    color: var(--error-fg);
    border-radius: 6px;
    padding: 0.6rem 0.8rem;
    font-size: 0.82rem;
    margin-bottom: 0.9rem;
    white-space: pre-wrap;
  }

  .warn {
    border: 1px solid var(--st-warn);
    border-left-width: 3px;
    border-radius: 6px;
    padding: 0.45rem 0.7rem;
    font-size: 0.8rem;
    margin-bottom: 0.6rem;
  }

  .device {
    margin-bottom: 0.8rem;
    font-size: 0.88rem;
  }

  /* Full sysDescr, keeping the device's line breaks. */
  .device .descr {
    font-size: 0.78rem;
    margin-top: 0.3rem;
    white-space: pre-wrap;
    word-break: break-word;
  }

  .faceplate {
    border: 1px solid var(--border);
    border-radius: 8px;
    background: var(--sidebar-bg);
    padding: 0.8rem 0.9rem 0.6rem;
    margin-bottom: 1rem;
  }

  /* Each port group scrolls sideways on its own, so a wide stack never pushes
     a scrollbar over the legend. Padding leaves room for the count badges.
     overflow-y must be hidden: overflow-x alone makes the box a vertical
     scroller too, and on macOS it then latches the wheel so the page will
     not scroll while the pointer is over the faceplate. */
  .ports-scroll {
    overflow-x: auto;
    overflow-y: hidden;
    padding: 0.5rem 0.5rem 0.4rem 0;
  }

  .group {
    margin-bottom: 0.4rem;
  }

  .gname {
    font-size: 0.72rem;
  }

  /* Two rows filled column first: odd ports on top, even below, like a faceplate. */
  /* Columns flex between 1.6rem and 2.5rem so a 48-port row fits the panel
     width; sideways scrolling only kicks in below the minimum. */
  .ports {
    display: grid;
    grid-template-rows: repeat(2, auto);
    grid-auto-flow: column;
    grid-auto-columns: minmax(1.6rem, 2.5rem);
    gap: 0.25rem;
    justify-content: start;
    min-width: min-content;
    width: 100%;
  }

  .tile {
    position: relative;
    height: 2.1rem;
    border-radius: 4px;
    border: 2px solid transparent;
    background: var(--btn-bg);
    color: var(--fg);
    cursor: pointer;
    padding: 0;
    font-size: 0.72rem;
  }

  .tile.up {
    background: color-mix(in srgb, var(--st-up) 30%, var(--btn-bg));
    border-color: var(--st-up);
  }

  .tile.down {
    border-color: var(--st-down);
    color: var(--muted);
  }

  .tile.disabled {
    border-color: var(--st-off);
    border-style: dashed;
    color: var(--muted);
  }

  .tile.uplink {
    box-shadow: inset 0 -4px 0 var(--st-warn);
  }

  .tile.selected {
    outline: 2px solid var(--accent);
    outline-offset: 1px;
  }

  .tile .num {
    display: block;
  }

  .tile .cnt {
    position: absolute;
    top: -0.45rem;
    right: -0.35rem;
    min-width: 1rem;
    padding: 0 0.2rem;
    border-radius: 0.6rem;
    background: var(--accent);
    color: var(--accent-fg);
    font-size: 0.62rem;
    line-height: 1rem;
  }

  .legend {
    border-top: 1px solid var(--border);
    padding-top: 0.6rem;
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 1rem;
    font-size: 0.75rem;
  }

  .legend .check {
    margin: 0 0 0 auto;
  }

  .sw {
    display: inline-block;
    width: 0.8rem;
    height: 0.8rem;
    border-radius: 2px;
    margin-right: 0.3rem;
    vertical-align: -0.1rem;
    border: 2px solid;
  }

  .sw.up {
    border-color: var(--st-up);
    background: color-mix(in srgb, var(--st-up) 30%, transparent);
  }

  .sw.down {
    border-color: var(--st-down);
  }

  .sw.disabled {
    border-color: var(--st-off);
    border-style: dashed;
  }

  .sw.uplinkk {
    border-color: var(--border);
    box-shadow: inset 0 -3px 0 var(--st-warn);
  }

  .check {
    display: inline-flex;
    align-items: center;
    font-size: 0.8rem;
    margin: 0;
    white-space: nowrap;
  }

  .tabs {
    display: flex;
    gap: 0.25rem;
    border-bottom: 1px solid var(--border);
    margin-bottom: 0.8rem;
  }

  .tabs button {
    background: none;
    border: none;
    border-bottom: 2px solid transparent;
    color: var(--muted);
    padding: 0.4rem 0.9rem;
    font-size: 0.85rem;
    cursor: pointer;
  }

  .tabs button.active {
    color: var(--fg);
    border-bottom-color: var(--accent);
  }

  .spacer {
    flex: 1 1 auto;
  }

  .pmac {
    white-space: nowrap;
    font-size: 0.76rem;
    line-height: 1.5;
  }

  .filters .search {
    flex: 1 1 auto;
  }

  .chip {
    display: inline-flex;
    align-items: center;
    gap: 0.4rem;
    border: 1px solid var(--accent);
    border-radius: 1rem;
    padding: 0.2rem 0.4rem 0.2rem 0.7rem;
    font-size: 0.8rem;
    white-space: nowrap;
  }

  .chip .x {
    background: none;
    border: none;
    color: var(--muted);
    cursor: pointer;
    padding: 0 0.2rem;
  }

  /* The table scrolls with the page (no nested scroll box), so the wheel always
     reaches the bottom. clip keeps the rounded border without creating a scroll
     container, so the sticky header pins to the top of the page. */
  .table-scroll {
    border: 1px solid var(--border);
    border-radius: 6px;
    overflow: clip;
  }

  table {
    border-collapse: collapse;
    width: 100%;
    font-size: 0.8rem;
  }

  th {
    text-align: left;
    color: var(--muted);
    font-weight: 500;
    padding: 0.4rem 0.6rem;
    border-bottom: 1px solid var(--border);
    position: sticky;
    top: 0;
    z-index: 1;
    background: var(--sidebar-bg);
    white-space: nowrap;
  }

  td {
    padding: 0.3rem 0.6rem;
    border-bottom: 1px solid var(--border);
    vertical-align: top;
  }

  tr:last-child td {
    border-bottom: none;
  }

  tr.sel td {
    background: var(--active-bg);
  }

  .dim {
    color: var(--muted);
    white-space: nowrap;
  }

  .vl {
    white-space: normal;
    max-width: 200px;
    word-break: break-word;
  }

  .link {
    background: none;
    border: none;
    padding: 0;
    color: var(--accent);
    cursor: pointer;
    font-size: inherit;
  }

  .tag {
    margin-left: 0.4rem;
    font-size: 0.68rem;
    color: var(--st-warn);
    border: 1px solid var(--st-warn);
    border-radius: 3px;
    padding: 0 0.25rem;
  }

  .st.up {
    color: var(--st-up);
  }

  .st.down {
    color: var(--muted);
  }

  .st.disabled {
    color: var(--st-off);
  }

  .count {
    font-size: 0.78rem;
    margin: 0.5rem 0 0;
  }
</style>
