<script lang="ts">
  // Throughput tester: drives the user's own iperf3 (never bundled) as a
  // client against an iperf3 server, or as a server for another computer.
  import { Channel, invoke } from "@tauri-apps/api/core";
  import { open } from "@tauri-apps/plugin-dialog";
  import { onDestroy, onMount } from "svelte";
  import ExportMenu from "$lib/components/ExportMenu.svelte";
  import { selectOnFocus } from "$lib/actions/selectOnFocus";
  import {
    buildClientReport,
    buildServerReport,
    dirLabel,
    emptyRun,
    rate,
    shortDir,
    bytes,
    type ClientOpts,
    type Detected,
    type IperfEvent,
    type Point,
    type TestRun,
  } from "./model";

  const PATH_KEY = "net3po.iperf.path";

  let detected = $state<Detected | null>(null);
  let detectError = $state("");
  let detecting = $state(false);
  let customPath = $state("");

  let mode = $state<"client" | "server">("client");
  let opts = $state<ClientOpts>({
    host: "",
    port: 5201,
    protocol: "tcp",
    direction: "upload",
    duration: 10,
    parallel: 1,
    bitrate: "",
    omit: 0,
    family: "auto",
  });
  let serverPort = $state(5201);
  let oneOff = $state(false);

  let running = $state(false);
  let runId = 0;
  let command = $state("");
  let live = $state(true);
  let error = $state("");
  let logs = $state<string[]>([]);
  let clientRun = $state<TestRun>(emptyRun());
  let serverTests = $state<TestRun[]>([]);
  let serverRunning = $state(false);

  const MAX_LOG = 300;

  function loadPath(): string {
    try {
      return localStorage.getItem(PATH_KEY) ?? "";
    } catch {
      return "";
    }
  }

  function savePath(p: string) {
    try {
      if (p) localStorage.setItem(PATH_KEY, p);
      else localStorage.removeItem(PATH_KEY);
    } catch {
      // Storage unavailable: the path is simply detected again next time.
    }
  }

  async function detect(path: string | null) {
    detecting = true;
    detectError = "";
    try {
      detected = await invoke<Detected>("iperf_detect", { path: path || null });
      customPath = path ?? "";
      savePath(path ?? "");
    } catch (e) {
      detected = null;
      detectError = String(e);
    } finally {
      detecting = false;
    }
  }

  onMount(() => {
    const saved = loadPath();
    void detect(saved || null).then(() => {
      // A saved path that stopped working: fall back to the usual places.
      if (!detected && saved) void detect(null);
    });
  });

  onDestroy(() => {
    if (running) void invoke("iperf_stop", { runId });
  });

  async function choose() {
    const p = await open({ multiple: false, title: "Choose the iperf3 program" });
    if (typeof p === "string") await detect(p);
  }

  function addLog(line: string) {
    logs.push(line);
    if (logs.length > MAX_LOG) logs.splice(0, logs.length - MAX_LOG);
  }

  function handle(e: IperfEvent, server: boolean) {
    const current = (): TestRun => {
      if (!server) return clientRun;
      if (!serverTests.length) serverTests.push(emptyRun());
      return serverTests[serverTests.length - 1];
    };
    switch (e.type) {
      case "started":
        command = e.command;
        live = e.live;
        break;
      case "testStart":
        if (server) serverTests.push({ ...emptyRun(), info: e.info });
        else clientRun.info = e.info;
        break;
      case "interval":
        current().points.push(...e.points);
        break;
      case "result":
        current().summary = e.summary;
        break;
      case "error":
        if (server && serverTests.length) current().errors.push(e.message);
        else if (server) error = e.message;
        else clientRun.errors.push(e.message);
        break;
      case "log":
        addLog(e.line);
        break;
      case "done":
        if (e.cancelled) addLog("stopped");
        break;
    }
  }

  async function start() {
    if (!detected) return;
    error = "";
    logs = [];
    command = "";
    runId = Math.floor(Math.random() * 2 ** 31);
    const ch = new Channel<IperfEvent>();
    running = true;
    try {
      if (mode === "client") {
        if (!opts.host.trim()) {
          error = "Enter the iperf3 server's hostname or IP address.";
          running = false;
          return;
        }
        clientRun = emptyRun();
        ch.onmessage = (e) => handle(e, false);
        await invoke("iperf_client", { runId, path: detected.path, opts: { ...opts, host: opts.host.trim() }, onEvent: ch });
      } else {
        serverTests = [];
        serverRunning = true;
        ch.onmessage = (e) => handle(e, true);
        await invoke("iperf_server", { runId, path: detected.path, opts: { port: serverPort, oneOff }, onEvent: ch });
      }
    } catch (e) {
      error = String(e);
    } finally {
      running = false;
      serverRunning = false;
    }
  }

  function stop() {
    void invoke("iperf_stop", { runId });
  }

  // ---- chart
  const W = 640;
  const H = 170;
  const PAD = { l: 64, r: 10, t: 10, b: 22 };

  function chart(points: Point[]) {
    const send = points.filter((p) => p.localSends);
    const recv = points.filter((p) => !p.localSends);
    const maxT = Math.max(1, ...points.map((p) => p.end));
    const maxV = Math.max(1, ...points.map((p) => p.bitsPerSecond)) * 1.1;
    const x = (t: number) => PAD.l + (t / maxT) * (W - PAD.l - PAD.r);
    const y = (v: number) => H - PAD.b - (v / maxV) * (H - PAD.t - PAD.b);
    const line = (ps: Point[]) => ps.map((p) => `${x(p.end).toFixed(1)},${y(p.bitsPerSecond).toFixed(1)}`).join(" ");
    return { send: line(send), recv: line(recv), maxT, maxV, y, x, hasSend: send.length > 0, hasRecv: recv.length > 0 };
  }

  const shownRun = $derived(mode === "client" ? clientRun : serverTests[serverTests.length - 1] ?? null);
  const c = $derived(shownRun && shownRun.points.length ? chart(shownRun.points) : null);
  const latest = $derived.by(() => {
    const pts = shownRun?.points ?? [];
    const last = pts.length ? pts[pts.length - 1].end : 0;
    return pts.filter((p) => p.end === last);
  });
  const reportName = $derived(mode === "client" ? `iperf-${opts.host.trim() || "test"}` : "iperf-server");
</script>

<div class="panel">
  <header>
    <h1>Throughput Tester</h1>
    <p class="sub">
      Measure throughput with iperf3: as a client against an iperf3 server, or as a server so another computer can test
      against this one. Uses your own iperf3 installation (it is not bundled). Traffic is sent only when you click Start.
    </p>
  </header>

  <div class="status" class:bad={!detected && !detecting}>
    {#if detecting}
      <span class="muted">Looking for iperf3...</span>
    {:else if detected}
      <span>iperf3 <strong>{detected.version}</strong> at <span class="mono">{detected.path}</span></span>
      <span class="muted">
        {detected.jsonStream ? "live results" : "results at the end of each test (iperf3 3.17 or later shows them live)"}
        {detected.bidir ? "" : "; no bidirectional tests (needs 3.7)"}
      </span>
    {:else}
      <span>{detectError || "iperf3 not found."}</span>
    {/if}
    <span class="spacer"></span>
    <button class="secondary" onclick={choose} disabled={running}>Choose iperf3...</button>
    {#if customPath}
      <button class="secondary" onclick={() => detect(null)} disabled={running} title="Forget the chosen path and search the usual places">Detect</button>
    {/if}
  </div>

  {#if detected}
    <div class="row">
      <div class="seg" role="tablist">
        <button role="tab" class:on={mode === "client"} aria-selected={mode === "client"} onclick={() => (mode = "client")} disabled={running}>Client</button>
        <button role="tab" class:on={mode === "server"} aria-selected={mode === "server"} onclick={() => (mode = "server")} disabled={running}>Server</button>
      </div>
    </div>

    {#if mode === "client"}
      <div class="grid">
        <label class="field wide">Server
          <input class="mono" bind:value={opts.host} placeholder="hostname or IP of the iperf3 server" spellcheck="false" autocapitalize="off" disabled={running} onkeydown={(e) => e.key === "Enter" && !running && start()} />
        </label>
        <label class="field">Port
          <input class="mono" type="number" min="1" max="65535" bind:value={opts.port} use:selectOnFocus disabled={running} />
        </label>
        <label class="field">Protocol
          <select bind:value={opts.protocol} disabled={running}>
            <option value="tcp">TCP</option>
            <option value="udp">UDP</option>
          </select>
        </label>
        <label class="field">Direction
          <select bind:value={opts.direction} disabled={running}>
            <option value="upload">Upload (this computer sends)</option>
            <option value="download">Download (server sends, -R)</option>
            <option value="both" disabled={!detected.bidir}>Both at once (--bidir)</option>
          </select>
        </label>
        <label class="field">Duration (s)
          <input class="mono" type="number" min="1" max="600" bind:value={opts.duration} use:selectOnFocus disabled={running} />
        </label>
        <label class="field">Parallel streams
          <input class="mono" type="number" min="1" max="128" bind:value={opts.parallel} use:selectOnFocus disabled={running} />
        </label>
        <label class="field">Bitrate
          <input class="mono" bind:value={opts.bitrate} placeholder={opts.protocol === "udp" ? "1M (iperf3 default)" : "unlimited"} spellcheck="false" disabled={running} />
        </label>
        <label class="field">Omit first (s)
          <input class="mono" type="number" min="0" max="60" bind:value={opts.omit} use:selectOnFocus disabled={running} />
        </label>
        <label class="field">IP version
          <select bind:value={opts.family} disabled={running}>
            <option value="auto">Auto</option>
            <option value="v4">IPv4 (-4)</option>
            <option value="v6">IPv6 (-6)</option>
          </select>
        </label>
      </div>
      {#if opts.protocol === "udp"}
        <p class="hint">UDP sends at the bitrate you set (iperf3 defaults to 1 Mbit/s) and reports loss and jitter. Set it near the rate you expect the path to carry.</p>
      {/if}
    {:else}
      <div class="grid">
        <label class="field">Port
          <input class="mono" type="number" min="1" max="65535" bind:value={serverPort} use:selectOnFocus disabled={running} />
        </label>
        <label class="check"><input type="checkbox" bind:checked={oneOff} disabled={running} /> Stop after one test (-1)</label>
      </div>
      <p class="hint">
        Listens on TCP and UDP port {serverPort} while running. On the other computer run
        <span class="mono">iperf3 -c &lt;this computer's address&gt; -p {serverPort}</span>. Allow the port in this computer's
        firewall if prompted. Ports below 1024 need extra rights on macOS and Linux.
      </p>
    {/if}

    <div class="row">
      {#if running}
        <button class="primary" onclick={stop}>{mode === "server" ? "Stop server" : "Stop"}</button>
        <span class="muted">{mode === "server" ? (serverRunning ? "Server running..." : "") : "Testing..."}</span>
      {:else}
        <button class="primary" onclick={start}>{mode === "server" ? "Start server" : "Start"}</button>
      {/if}
      <span class="spacer"></span>
      {#if !running && command && (mode === "client" ? clientRun.summary || clientRun.points.length : serverTests.length)}
        <ExportMenu
          build={() => (mode === "client" ? buildClientReport(clientRun, command, detected?.version ?? "") : buildServerReport(serverTests, command, detected?.version ?? ""))}
          name={reportName}
        />
      {/if}
    </div>
  {/if}

  {#if error}<div class="error">{error}</div>{/if}
  {#if command}<div class="cmd mono">{command}</div>{/if}

  {#if mode === "server" && serverTests.length > 1}
    <div class="tests">
      {#each serverTests as t, i (i)}
        <div class="test-row">
          <span class="mono">#{i + 1} {t.info?.remote || "client"}</span>
          <span class="muted">{t.info?.protocol ?? ""} {t.info?.bidir ? "bidir" : t.info?.reverse ? "reverse" : ""}</span>
          {#each t.summary?.directions ?? [] as d, j (j)}
            <span>{shortDir(d.localSends)} <strong>{rate(d.receivedBps)}</strong></span>
          {/each}
          {#each t.errors as e, j (j)}<span class="err">{e}</span>{/each}
        </div>
      {/each}
      <p class="muted">The chart and table below show the latest test.</p>
    </div>
  {/if}

  {#if shownRun}
    {#if shownRun.info}
      <div class="info">
        <span><span class="muted">Remote</span> <span class="mono">{shownRun.info.remote || "-"}</span></span>
        <span><span class="muted">Local</span> <span class="mono">{shownRun.info.local || "-"}</span></span>
        <span>{shownRun.info.protocol}, {shownRun.info.streams} stream{shownRun.info.streams === 1 ? "" : "s"}, {shownRun.info.duration} s</span>
      </div>
    {/if}

    {#each shownRun.errors as e, i (i)}<div class="error">{e}</div>{/each}

    {#if running && latest.length && !shownRun.summary}
      <div class="now">
        {#each latest as p, i (i)}
          <span>{shortDir(p.localSends)} <strong>{rate(p.bitsPerSecond)}</strong></span>
        {/each}
        <span class="muted">at {latest[0].end.toFixed(0)} s</span>
      </div>
    {/if}

    {#if shownRun.summary}
      <div class="cards">
        {#each shownRun.summary.directions as d, i (i)}
          <div class="card">
            <div class="card-title">{dirLabel(d.localSends, mode === "server")}</div>
            <div class="big">{rate(d.receivedBps)}</div>
            <div class="muted">received · sent {rate(d.sentBps)} · {bytes(d.receivedBytes ?? d.sentBytes)}</div>
            {#if d.retransmits !== null}<div class:warn={d.retransmits > 0}>Retransmits {d.retransmits}</div>{/if}
            {#if d.jitterMs !== null}<div>Jitter {d.jitterMs.toFixed(3)} ms</div>{/if}
            {#if d.lostPercent !== null}
              <div class:warn={d.lostPercent > 0}>Loss {d.lostPackets ?? 0}/{d.packets ?? 0} ({d.lostPercent.toFixed(2)}%)</div>
            {/if}
          </div>
        {/each}
        {#if shownRun.summary.cpuLocal !== null}
          <div class="card">
            <div class="card-title">CPU</div>
            <div>This computer {shownRun.summary.cpuLocal.toFixed(1)}%</div>
            <div>Remote {shownRun.summary.cpuRemote?.toFixed(1) ?? "-"}%</div>
            {#if (shownRun.summary.cpuLocal ?? 0) > 85 || (shownRun.summary.cpuRemote ?? 0) > 85}
              <div class="warn small">High CPU: an end host may be the limit, not the network.</div>
            {/if}
          </div>
        {/if}
      </div>
    {/if}

    {#if c}
      <svg class="chart" viewBox="0 0 {W} {H}" role="img" aria-label="Throughput per second">
        {#each [0, 0.5, 1] as f (f)}
          <line x1={PAD.l} x2={W - PAD.r} y1={c.y(c.maxV * f)} y2={c.y(c.maxV * f)} class="grid-line" />
          <text x={PAD.l - 6} y={c.y(c.maxV * f) + 4} class="axis" text-anchor="end">{rate(c.maxV * f)}</text>
        {/each}
        <text x={PAD.l} y={H - 6} class="axis">0 s</text>
        <text x={W - PAD.r} y={H - 6} class="axis" text-anchor="end">{c.maxT.toFixed(0)} s</text>
        {#if c.hasSend}<polyline points={c.send} class="l-send" />{/if}
        {#if c.hasRecv}<polyline points={c.recv} class="l-recv" />{/if}
      </svg>
      <div class="legend">
        {#if c.hasSend}<span><i class="sw send"></i>{mode === "server" ? "server sends" : "upload"}</span>{/if}
        {#if c.hasRecv}<span><i class="sw recv"></i>{mode === "server" ? "server receives" : "download"}</span>{/if}
      </div>

      <details>
        <summary>Intervals ({shownRun.points.length})</summary>
        <div class="scroll">
          <table>
            <thead><tr><th>Time (s)</th><th>Direction</th><th class="n">Rate</th><th class="n">Retransmits</th><th class="n">Jitter</th><th class="n">Lost / packets</th></tr></thead>
            <tbody>
              {#each shownRun.points as p, i (i)}
                <tr class:omit={p.omitted}>
                  <td class="mono">{p.start.toFixed(1)}-{p.end.toFixed(1)}{p.omitted ? " (omitted)" : ""}</td>
                  <td>{shortDir(p.localSends)}</td>
                  <td class="n mono">{rate(p.bitsPerSecond)}</td>
                  <td class="n mono">{p.retransmits ?? "-"}</td>
                  <td class="n mono">{p.jitterMs === null ? "-" : `${p.jitterMs.toFixed(3)} ms`}</td>
                  <td class="n mono">{p.packets === null ? "-" : `${p.lostPackets ?? 0}/${p.packets}`}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      </details>
    {:else if running && !live}
      <p class="muted">This iperf3 reports results when the test ends.</p>
    {/if}
  {/if}

  {#if logs.length}
    <details class="logs">
      <summary>iperf3 messages ({logs.length})</summary>
      <pre class="mono">{logs.join("\n")}</pre>
    </details>
  {/if}

  {#if !detected && !detecting}
    <div class="install">
      <strong>Install iperf3</strong>
      <ul>
        <li>macOS: <span class="mono">brew install iperf3</span></li>
        <li>Ubuntu / Debian: <span class="mono">sudo apt install iperf3</span></li>
        <li>RHEL / Fedora: <span class="mono">sudo dnf install iperf3</span></li>
        <li>Windows: download an iperf3 build, then use <strong>Choose iperf3...</strong> to select <span class="mono">iperf3.exe</span>.</li>
      </ul>
      <p class="muted">iperf 2 is a different program and is not supported.</p>
    </div>
  {/if}
</div>

<style>
  .panel {
    padding: 1.5rem 2rem;
    max-width: 1080px;
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
  .mono {
    font-family: var(--mono);
  }
  .muted {
    color: var(--muted);
    font-size: 0.78rem;
  }
  .small {
    font-size: 0.76rem;
  }
  .status {
    display: flex;
    align-items: center;
    gap: 0.4rem 0.9rem;
    flex-wrap: wrap;
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 0.5rem 0.75rem;
    font-size: 0.83rem;
  }
  .status.bad {
    border-color: #b7791f;
  }
  .row {
    display: flex;
    align-items: center;
    gap: 0.7rem;
    margin: 0.7rem 0;
    flex-wrap: wrap;
  }
  .spacer {
    flex: 1;
  }
  .grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(150px, 1fr));
    gap: 0.6rem 0.9rem;
    margin-top: 0.4rem;
  }
  .field {
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
    font-size: 0.76rem;
    color: var(--muted);
  }
  .field.wide {
    grid-column: span 2;
  }
  .check {
    display: flex;
    align-items: center;
    gap: 0.4rem;
    font-size: 0.82rem;
    align-self: end;
    padding-bottom: 0.4rem;
  }
  input:not([type="checkbox"]),
  select {
    box-sizing: border-box;
    width: 100%;
    background: var(--input-bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.4rem 0.55rem;
    color: var(--fg);
    font-size: 0.82rem;
  }
  input:focus,
  select:focus {
    outline: none;
    border-color: var(--accent);
  }
  .hint {
    font-size: 0.78rem;
    color: var(--muted);
    margin: 0.5rem 0 0;
  }
  .primary,
  .secondary {
    border-radius: 6px;
    padding: 0.42rem 1rem;
    font-size: 0.82rem;
    cursor: pointer;
    white-space: nowrap;
  }
  .primary {
    background: var(--accent);
    color: var(--accent-fg);
    border: 1px solid var(--accent);
    font-weight: 600;
  }
  .secondary {
    background: transparent;
    color: var(--fg);
    border: 1px solid var(--border);
  }
  button:disabled {
    opacity: 0.55;
    cursor: default;
  }
  .seg {
    display: inline-flex;
    border: 1px solid var(--border);
    border-radius: 6px;
    overflow: hidden;
  }
  .seg button {
    background: transparent;
    border: 0;
    color: var(--fg);
    padding: 0.38rem 1rem;
    font-size: 0.8rem;
    cursor: pointer;
  }
  .seg button.on {
    background: var(--accent);
    color: var(--accent-fg);
  }
  .error,
  .err {
    color: var(--error-fg);
    font-size: 0.84rem;
  }
  .error {
    margin: 0.4rem 0;
  }
  .cmd {
    font-size: 0.76rem;
    color: var(--muted);
    margin: 0.3rem 0 0.6rem;
    word-break: break-all;
  }
  .info,
  .now {
    display: flex;
    flex-wrap: wrap;
    gap: 0.3rem 1.3rem;
    font-size: 0.83rem;
    margin: 0.4rem 0;
  }
  .now strong {
    font-size: 1.05rem;
  }
  .cards {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(210px, 1fr));
    gap: 0.7rem;
    margin: 0.7rem 0;
  }
  .card {
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 0.6rem 0.8rem;
    font-size: 0.82rem;
    display: flex;
    flex-direction: column;
    gap: 0.15rem;
  }
  .card-title {
    font-size: 0.76rem;
    color: var(--muted);
  }
  .big {
    font-size: 1.35rem;
    font-weight: 700;
  }
  .warn {
    color: #b7791f;
  }
  .chart {
    width: 100%;
    height: auto;
    margin-top: 0.4rem;
  }
  .grid-line {
    stroke: var(--border);
    stroke-width: 1;
  }
  .axis {
    fill: var(--muted);
    font-size: 10px;
    font-family: var(--mono);
  }
  .l-send,
  .l-recv {
    fill: none;
    stroke-width: 2;
    stroke-linejoin: round;
  }
  .l-send {
    stroke: var(--accent);
  }
  .l-recv {
    stroke: #15935a;
  }
  .legend {
    display: flex;
    gap: 1rem;
    font-size: 0.76rem;
    color: var(--muted);
  }
  .sw {
    display: inline-block;
    width: 14px;
    height: 3px;
    margin-right: 0.35rem;
    vertical-align: middle;
  }
  .sw.send {
    background: var(--accent);
  }
  .sw.recv {
    background: #15935a;
  }
  details {
    margin-top: 0.8rem;
    font-size: 0.8rem;
  }
  summary {
    cursor: pointer;
    color: var(--muted);
  }
  .scroll {
    max-height: 45vh;
    overflow: auto;
    margin-top: 0.4rem;
  }
  table {
    border-collapse: collapse;
    width: 100%;
    font-size: 0.78rem;
  }
  th,
  td {
    text-align: left;
    padding: 0.2rem 0.8rem 0.2rem 0;
    border-bottom: 1px solid var(--border);
  }
  th {
    color: var(--muted);
    font-weight: 500;
  }
  .n {
    text-align: right;
  }
  tr.omit {
    color: var(--muted);
  }
  .logs pre {
    max-height: 30vh;
    overflow: auto;
    font-size: 0.74rem;
    white-space: pre-wrap;
    word-break: break-all;
  }
  .tests {
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 0.5rem 0.75rem;
    margin: 0.5rem 0;
  }
  .test-row {
    display: flex;
    flex-wrap: wrap;
    gap: 0.3rem 1rem;
    font-size: 0.8rem;
    padding: 0.15rem 0;
  }
  .install {
    margin-top: 1rem;
    font-size: 0.84rem;
  }
  .install ul {
    margin: 0.4rem 0;
    padding-left: 1.2rem;
  }
</style>
