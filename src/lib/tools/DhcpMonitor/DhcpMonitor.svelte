<script lang="ts">
  import { invoke, Channel } from "@tauri-apps/api/core";
  import type { DhcpEvent, DhcpServerRecord, NetInterface } from "$lib/tools/types";

  const MAX_LOG = 300;

  let interfaces = $state<NetInterface[]>([]);
  let iface = $state("");
  let authorized = $state("");
  let listenSecs = $state(5);
  let intervalSecs = $state(30);

  let running = $state<"" | "probe" | "monitor">("");
  let error = $state("");
  let warnings = $state<string[]>([]);
  let servers = $state<DhcpServerRecord[]>([]);
  let log = $state<
    { at: number; type: string; source: string; server: string; mac: string; xid: string; ours: boolean }[]
  >([]);
  let status = $state("");
  let probes = $state(0);
  let finishedProbe = $state(false);
  let runId = 0;

  $effect(() => {
    invoke<NetInterface[]>("dhcp_interfaces")
      .then((list) => (interfaces = list))
      .catch((e) => (error = String(e)));
  });

  const rogues = $derived(servers.filter((s) => s.status === "rogue"));

  function ipKey(ip: string): number {
    return ip.split(".").reduce((a, x) => a * 256 + (Number(x) || 0), 0);
  }

  function fmtLease(secs: number | null): string {
    if (secs === null) return "";
    if (secs === 0xffffffff) return "infinite";
    if (secs % 86400 === 0) return `${secs / 86400}d`;
    if (secs % 3600 === 0) return `${secs / 3600}h`;
    if (secs % 60 === 0) return `${secs / 60}m`;
    return `${secs}s`;
  }

  function fmtTime(ms: number): string {
    return new Date(ms).toLocaleTimeString();
  }

  async function start(mode: "probe" | "monitor") {
    error = "";
    warnings = [];
    servers = [];
    log = [];
    probes = 0;
    finishedProbe = false;
    status = "Opening UDP 68";
    running = mode;
    runId = Math.floor(Math.random() * 0x7fffffff);

    const channel = new Channel<DhcpEvent>();
    channel.onmessage = (ev) => {
      switch (ev.type) {
        case "started":
          status = `Listening on UDP 68 (${ev.interface})`;
          break;
        case "probe":
          probes = ev.n;
          status = `DISCOVER #${ev.n} sent as ${ev.clientMac}, xid ${ev.xid}`;
          break;
        case "reply": {
          const r = ev.record;
          const rest = servers.filter((s) => s.server !== r.server);
          servers = [...rest, r].sort((a, b) => ipKey(a.server) - ipKey(b.server));
          log = [
            {
              at: r.lastSeenMs,
              type: r.last.messageType,
              source: ev.source,
              server: r.server,
              mac: r.last.clientMac,
              xid: r.last.xid,
              ours: ev.ours,
            },
            ...log,
          ].slice(0, MAX_LOG);
          break;
        }
        case "warning":
          if (!warnings.includes(ev.message)) warnings = [...warnings, ev.message];
          break;
        case "stopped":
          if (ev.error) error = ev.error;
          status = `Stopped after ${ev.probes} DISCOVER${ev.probes === 1 ? "" : "s"}, ${ev.servers} server${ev.servers === 1 ? "" : "s"} seen.`;
          finishedProbe = true;
          running = "";
          break;
      }
    };

    const config = { interface: iface, authorized, mode, listenSecs, intervalSecs };
    try {
      await invoke("dhcp_monitor", { runId, config, onEvent: channel });
    } catch (e) {
      error = String(e);
      status = "";
      running = "";
    }
  }

  async function stop() {
    try {
      await invoke("dhcp_stop", { runId });
    } catch {
      // ignore
    }
  }
</script>

<div class="panel">
  <header>
    <h1>DHCP Monitor</h1>
    <p class="sub">
      Broadcast a DHCPDISCOVER and list every server that answers. Uses a random,
      locally administered client MAC, so your own lease is untouched. Add your
      authorized servers to flag rogues.
    </p>
  </header>

  <div class="grid">
    <div class="field grow">
      <label for="iface">Interface</label>
      <select id="iface" bind:value={iface} disabled={running !== ""}>
        <option value="">Default route</option>
        {#each interfaces as i (i.name + i.ip)}
          <option value={i.name}>{i.name} ({i.ip}/{i.prefix})</option>
        {/each}
      </select>
    </div>
    <div class="field grow">
      <label for="auth">Authorized servers (optional)</label>
      <input
        id="auth"
        class="mono"
        bind:value={authorized}
        disabled={running !== ""}
        spellcheck="false"
        placeholder="10.0.0.1, 10.0.0.2"
      />
    </div>
  </div>

  <div class="grid">
    <div class="field">
      <label for="listen">Probe: listen (s)</label>
      <input id="listen" type="number" min="1" max="60" bind:value={listenSecs} disabled={running !== ""} />
    </div>
    <div class="field">
      <label for="interval">Monitor: every (s)</label>
      <input id="interval" type="number" min="5" max="3600" bind:value={intervalSecs} disabled={running !== ""} />
    </div>
  </div>

  <div class="row">
    {#if running}
      <button class="action stop" onclick={stop}>Stop</button>
    {:else}
      <button class="action" onclick={() => start("probe")}>Probe</button>
      <button class="secondary" onclick={() => start("monitor")}>Monitor</button>
    {/if}
    {#if status}<span class="done muted mono">{status}{running ? "..." : ""}</span>{/if}
  </div>

  {#if error}
    <div class="error mono">{error}</div>
  {/if}

  {#each warnings as w (w)}
    <div class="warn">{w}</div>
  {/each}

  {#if rogues.length > 0}
    <div class="verdict bad">
      Rogue DHCP server{rogues.length === 1 ? "" : "s"} detected:
      <span class="mono">{rogues.map((r) => r.server).join(", ")}</span>
    </div>
  {:else if servers.length > 1 && authorized.trim() === ""}
    <div class="verdict warnv">
      {servers.length} DHCP servers are answering on this segment. Add the authorized
      ones above to classify them.
    </div>
  {:else if servers.length > 0 && authorized.trim() !== ""}
    <div class="verdict good">All answering servers are authorized.</div>
  {:else if finishedProbe && servers.length === 0 && !error}
    <div class="verdict warnv">
      No DHCP server answered. Check the interface, that this segment has a server or
      relay, and that a host firewall is not blocking inbound UDP 68.
    </div>
  {/if}

  {#if servers.length > 0}
    <h2>Servers</h2>
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Status</th><th>Server</th><th>Offered</th><th>Mask</th><th>Router</th>
            <th>DNS</th><th>Domain</th><th>Lease</th><th>Replies</th><th>Last seen</th>
          </tr>
        </thead>
        <tbody>
          {#each servers as s (s.server)}
            <tr class:roguerow={s.status === "rogue"}>
              <td><span class="badge {s.status}">{s.status}</span></td>
              <td class="mono">
                {s.server}
                {#if s.source !== s.server}<div class="dim small">via {s.source}</div>{/if}
                {#if s.last.relay}<div class="dim small">relay {s.last.relay}</div>{/if}
                {#if s.last.nextServer}<div class="dim small">next-server {s.last.nextServer}</div>{/if}
              </td>
              <td class="mono">{s.last.offeredIp ?? ""}</td>
              <td class="mono dim">{s.last.subnetMask ?? ""}</td>
              <td class="mono">{s.last.routers.join(", ")}</td>
              <td class="mono">{s.last.dns.join(", ")}</td>
              <td>{s.last.domain ?? ""}</td>
              <td class="mono dim">{fmtLease(s.last.leaseSecs)}</td>
              <td class="mono">{s.replies}</td>
              <td class="dim">{fmtTime(s.lastSeenMs)}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}

  {#if log.length > 0}
    <h2>Replies</h2>
    <div class="table-wrap">
      <table>
        <thead>
          <tr><th>Time</th><th>Type</th><th>From</th><th>Server</th><th>Client MAC</th><th>xid</th><th>For</th></tr>
        </thead>
        <tbody>
          {#each log as l, i (i)}
            <tr>
              <td class="dim">{fmtTime(l.at)}</td>
              <td class="mono">{l.type}</td>
              <td class="mono">{l.source}</td>
              <td class="mono">{l.server}</td>
              <td class="mono">{l.mac}</td>
              <td class="mono dim">{l.xid}</td>
              <td class="dim">{l.ours ? "our probe" : "other client"}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
    <p class="count muted">Last {log.length} replies. Probes sent: {probes}.</p>
  {/if}
</div>

<style>
  .panel {
    --st-ok: #2ea043;
    --st-bad: #d1453b;
    --st-warn: #c69026;
    padding: 1.5rem 2rem 2rem;
    box-sizing: border-box;
    width: 100%;
  }

  header h1 {
    margin: 0 0 0.25rem;
    font-size: 1.3rem;
  }

  h2 {
    font-size: 0.95rem;
    font-weight: 600;
    margin: 1.2rem 0 0.5rem;
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
    flex: 2 1 240px;
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

  .mono {
    font-family: var(--mono);
  }

  .row {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 0.75rem;
    margin: 0.3rem 0 1rem;
  }

  .action {
    background: var(--accent);
    border: 1px solid var(--accent);
    border-radius: 6px;
    padding: 0.5rem 1.3rem;
    color: #fff;
    font-weight: 600;
    font-size: 0.85rem;
    cursor: pointer;
  }

  .action.stop {
    background: var(--btn-bg);
    border-color: var(--error-border);
    color: var(--error-fg);
  }

  .secondary {
    background: var(--btn-bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.5rem 1.1rem;
    color: var(--fg);
    font-size: 0.85rem;
    cursor: pointer;
  }

  .done {
    font-size: 0.8rem;
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

  .verdict {
    border-radius: 6px;
    padding: 0.6rem 0.8rem;
    font-size: 0.85rem;
    margin-bottom: 0.6rem;
    border: 1px solid;
    border-left-width: 4px;
  }

  .verdict.bad {
    border-color: var(--st-bad);
    background: color-mix(in srgb, var(--st-bad) 12%, transparent);
    font-weight: 600;
  }

  .verdict.warnv {
    border-color: var(--st-warn);
  }

  .verdict.good {
    border-color: var(--st-ok);
  }

  /* Tables scroll with the page; clip keeps the rounded border without a
     nested scroll container, so the sticky header pins to the page. */
  .table-wrap {
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
    word-break: break-word;
  }

  tr:last-child td {
    border-bottom: none;
  }

  tr.roguerow td {
    background: color-mix(in srgb, var(--st-bad) 8%, transparent);
  }

  .dim {
    color: var(--muted);
  }

  .small {
    font-size: 0.72rem;
  }

  .badge {
    display: inline-block;
    border: 1px solid;
    border-radius: 3px;
    padding: 0 0.35rem;
    font-size: 0.72rem;
    text-transform: uppercase;
    letter-spacing: 0.03em;
  }

  .badge.authorized {
    color: var(--st-ok);
  }

  .badge.rogue {
    color: var(--st-bad);
    font-weight: 700;
  }

  .badge.unverified {
    color: var(--muted);
  }

  .count {
    font-size: 0.78rem;
    margin: 0.5rem 0 0;
  }
</style>
