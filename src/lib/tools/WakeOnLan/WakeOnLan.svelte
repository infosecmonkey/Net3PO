<script lang="ts">
  import { invoke, Channel } from "@tauri-apps/api/core";
  import ExportMenu from "$lib/components/ExportMenu.svelte";
  import { selectOnFocus } from "$lib/actions/selectOnFocus";
  import { loadCollection, saveCollection } from "$lib/store";
  import type { WolCheckEvent, WolDevice, WolInterface, WolSendResult } from "$lib/tools/types";
  import { buildWolReport, checkSummary, DELIVERY_NOTE, sentSummary, type LogEntry } from "./report";

  const MAX_LOG = 100;

  let interfaces = $state<WolInterface[]>([]);
  let devices = $state<WolDevice[]>([]);
  let editingId = $state<string | null>(null);

  // Form
  let name = $state("");
  let mac = $state("");
  let destination = $state("");
  let portMode = $state<"9" | "7" | "custom">("9");
  let customPort = $state(9);
  let iface = $state("");
  let repeats = $state(3);
  let password = $state("");
  let doCheck = $state(false);
  let checkHost = $state("");
  let checkPorts = $state("");
  let checkWait = $state(120);
  let notes = $state("");

  let sending = $state(false);
  let error = $state("");
  let message = $state("");
  let log = $state<LogEntry[]>([]);
  let checkRun = $state<{ runId: number; key: number } | null>(null);
  let nextKey = 1;

  const port = $derived(portMode === "custom" ? customPort : Number(portMode));
  const suggestions = $derived([
    ...interfaces.map((i) => ({ value: i.broadcast, label: `${i.name} subnet broadcast` })),
    { value: "255.255.255.255", label: "limited broadcast" },
  ]);

  $effect(() => {
    invoke<WolInterface[]>("wol_interfaces")
      .then((list) => (interfaces = list))
      .catch((e) => (error = String(e)));
    loadCollection<WolDevice>("wol_devices")
      .then((l) => {
        devices = l.items;
        if (l.recoveredTo) error = `Saved devices were unreadable and moved to ${l.recoveredTo}.`;
      })
      .catch((e) => (error = String(e)));
  });

  // Picking an interface fills its broadcast address when the field is empty
  // or still holds another interface's suggestion.
  function onInterface() {
    const i = interfaces.find((x) => x.name === iface);
    const isSuggestion = destination === "" || suggestions.some((s) => s.value === destination);
    if (i && isSuggestion) destination = i.broadcast;
  }

  function formDevice(id: string): WolDevice {
    return {
      id,
      name: name.trim(),
      mac: mac.trim(),
      destination: destination.trim(),
      port,
      interface: iface,
      repeats,
      checkHost: checkHost.trim(),
      checkPorts: checkPorts.trim(),
      notes: notes.trim(),
    };
  }

  function load(d: WolDevice) {
    editingId = d.id;
    name = d.name;
    mac = d.mac;
    destination = d.destination;
    portMode = d.port === 9 ? "9" : d.port === 7 ? "7" : "custom";
    customPort = d.port;
    iface = interfaces.some((i) => i.name === d.interface) ? d.interface : "";
    repeats = d.repeats;
    checkHost = d.checkHost;
    checkPorts = d.checkPorts;
    doCheck = d.checkHost !== "";
    notes = d.notes;
    password = "";
    error = "";
    message = d.interface && iface === "" ? `Interface ${d.interface} is not present; using the OS default.` : "";
  }

  function clearForm() {
    editingId = null;
    name = mac = destination = password = checkHost = checkPorts = notes = "";
    portMode = "9";
    customPort = 9;
    iface = "";
    repeats = 3;
    doCheck = false;
    error = message = "";
  }

  async function persist(next: WolDevice[]) {
    await saveCollection("wol_devices", next);
    devices = next;
  }

  async function saveDevice() {
    error = "";
    if (!name.trim()) {
      error = "Give the device a name to save it.";
      return;
    }
    if (!mac.trim() || !destination.trim()) {
      error = "A saved device needs a MAC address and a destination.";
      return;
    }
    try {
      if (editingId) {
        await persist(devices.map((d) => (d.id === editingId ? formDevice(d.id) : d)));
        message = `Updated ${name.trim()}.`;
      } else {
        const d = formDevice(crypto.randomUUID());
        await persist([...devices, d].sort((a, b) => a.name.localeCompare(b.name)));
        editingId = d.id;
        message = `Saved ${d.name}.`;
      }
    } catch (e) {
      error = String(e);
    }
  }

  async function deleteDevice(d: WolDevice) {
    if (!confirm(`Delete ${d.name}?`)) return;
    try {
      await persist(devices.filter((x) => x.id !== d.id));
      if (editingId === d.id) clearForm();
    } catch (e) {
      error = String(e);
    }
  }

  async function wake(d?: WolDevice) {
    if (d) load(d);
    error = "";
    message = "";
    sending = true;
    try {
      const result = await invoke<WolSendResult>("wol_send", {
        request: { mac, destination, port, interface: iface, repeats, password },
      });
      const key = nextKey++;
      log = [{ key, device: name.trim(), result, check: { state: "none" as const } }, ...log].slice(0, MAX_LOG);
      if (doCheck && checkHost.trim()) await startCheck(key);
    } catch (e) {
      error = String(e);
    } finally {
      sending = false;
    }
  }

  function setCheck(key: number, check: LogEntry["check"]) {
    log = log.map((e) => (e.key === key ? { ...e, check } : e));
  }

  async function startCheck(key: number) {
    const host = checkHost.trim();
    const runId = Math.floor(Math.random() * 0x7fffffff);
    checkRun = { runId, key };
    setCheck(key, { state: "running", host });
    const channel = new Channel<WolCheckEvent>();
    let resolved = host;
    channel.onmessage = (ev) => {
      switch (ev.type) {
        case "started":
          resolved = ev.host;
          setCheck(key, { state: "running", host: resolved });
          break;
        case "up":
          setCheck(key, { state: "up", host: resolved, port: ev.port, answer: ev.answer, elapsedMs: ev.elapsedMs });
          break;
        case "done":
          if (!ev.reachable) {
            setCheck(
              key,
              ev.cancelled
                ? { state: "cancelled", host: resolved, elapsedMs: ev.elapsedMs }
                : { state: "noAnswer", host: resolved, elapsedMs: ev.elapsedMs },
            );
          }
          checkRun = null;
          break;
      }
    };
    try {
      await invoke("wol_check", {
        runId,
        request: { host, ports: checkPorts, timeoutSecs: checkWait },
        onEvent: channel,
      });
    } catch (e) {
      setCheck(key, { state: "error", host, message: String(e) });
      checkRun = null;
    }
  }

  async function stopCheck() {
    if (!checkRun) return;
    await invoke("wol_stop", { runId: checkRun.runId }).catch(() => {});
  }
</script>

<div class="panel">
  <header>
    <h1>Wake-on-LAN</h1>
    <p class="sub">
      Send magic packets to wake a host, from the interface you pick. Save devices for
      one-click wake, and optionally watch for the host to start answering.
    </p>
  </header>

  <div class="grid">
    <div class="field grow">
      <label for="wol-name">Device name (to save)</label>
      <input id="wol-name" bind:value={name} placeholder="Lab server" />
    </div>
    <div class="field grow">
      <label for="wol-mac">MAC address</label>
      <input id="wol-mac" class="mono" bind:value={mac} spellcheck="false" placeholder="aa:bb:cc:dd:ee:ff" />
    </div>
  </div>

  <div class="grid">
    <div class="field grow">
      <label for="wol-iface">Source interface</label>
      <select id="wol-iface" bind:value={iface} onchange={onInterface}>
        <option value="">OS default route</option>
        {#each interfaces as i (i.name + i.ip)}
          <option value={i.name}>{i.name} ({i.ip}/{i.prefix})</option>
        {/each}
      </select>
    </div>
    <div class="field grow">
      <label for="wol-dest">Destination</label>
      <input
        id="wol-dest"
        class="mono"
        list="wol-dest-list"
        bind:value={destination}
        spellcheck="false"
        placeholder="Subnet broadcast, IPv4 or host name"
      />
      <datalist id="wol-dest-list">
        {#each suggestions as s (s.value)}
          <option value={s.value}>{s.label}</option>
        {/each}
      </datalist>
    </div>
  </div>

  <div class="grid">
    <div class="field">
      <label for="wol-port">UDP port</label>
      <select id="wol-port" bind:value={portMode}>
        <option value="9">9 (discard)</option>
        <option value="7">7 (echo)</option>
        <option value="custom">Custom</option>
      </select>
    </div>
    {#if portMode === "custom"}
      <div class="field">
        <label for="wol-cport">Custom port</label>
        <input id="wol-cport" type="number" min="1" max="65535" bind:value={customPort} use:selectOnFocus />
      </div>
    {/if}
    <div class="field">
      <label for="wol-rep">Packets</label>
      <input id="wol-rep" type="number" min="1" max="10" bind:value={repeats} use:selectOnFocus />
    </div>
    <div class="field grow">
      <label for="wol-pw">SecureOn password (optional, not saved)</label>
      <input id="wol-pw" class="mono" bind:value={password} spellcheck="false" placeholder="a.b.c.d or aa:bb:cc:dd:ee:ff" />
    </div>
  </div>

  <label class="check">
    <input type="checkbox" bind:checked={doCheck} />
    Check reachability after sending
  </label>
  {#if doCheck}
    <div class="grid">
      <div class="field grow">
        <label for="wol-chost">Target host (its own IP or name)</label>
        <input id="wol-chost" class="mono" bind:value={checkHost} spellcheck="false" placeholder="10.1.1.50" />
      </div>
      <div class="field grow">
        <label for="wol-cports">TCP ports</label>
        <input id="wol-cports" class="mono" bind:value={checkPorts} spellcheck="false" placeholder="22, 3389, 445, 80, 443" />
      </div>
      <div class="field">
        <label for="wol-cwait">Wait up to (s)</label>
        <input id="wol-cwait" type="number" min="5" max="600" bind:value={checkWait} use:selectOnFocus />
      </div>
    </div>
  {/if}

  <div class="field notes">
    <label for="wol-notes">Notes (saved with the device)</label>
    <input id="wol-notes" bind:value={notes} placeholder="Location, BIOS setting, switch port" />
  </div>

  <div class="row">
    <button class="action" onclick={() => wake()} disabled={sending || !mac.trim() || !destination.trim()}>
      {sending ? "Sending..." : "Wake"}
    </button>
    <button class="secondary" onclick={saveDevice}>{editingId ? "Update device" : "Save device"}</button>
    {#if editingId || mac || destination}
      <button class="secondary" onclick={clearForm}>{editingId ? "New device" : "Clear"}</button>
    {/if}
    {#if checkRun}<button class="secondary stop" onclick={stopCheck}>Stop check</button>{/if}
    {#if message}<span class="muted small">{message}</span>{/if}
  </div>

  {#if error}<div class="error mono">{error}</div>{/if}

  {#if devices.length > 0}
    <h2>Saved devices</h2>
    <div class="table-wrap">
      <table>
        <thead>
          <tr><th>Name</th><th>MAC</th><th>Destination</th><th>Interface</th><th>Check</th><th></th></tr>
        </thead>
        <tbody>
          {#each devices as d (d.id)}
            <tr class:editing={editingId === d.id}>
              <td>
                {d.name}
                {#if d.notes}<div class="dim small">{d.notes}</div>{/if}
              </td>
              <td class="mono">{d.mac}</td>
              <td class="mono">{d.destination}:{d.port}</td>
              <td class="dim">{d.interface || "OS default"}</td>
              <td class="mono dim">{d.checkHost || ""}</td>
              <td class="actions">
                <button class="mini primary" onclick={() => wake(d)} disabled={sending}>Wake</button>
                <button class="mini" onclick={() => load(d)}>Edit</button>
                <button class="mini" onclick={() => deleteDevice(d)}>Delete</button>
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}

  {#if log.length > 0}
    <div class="loghead">
      <h2>Log</h2>
      <ExportMenu build={() => buildWolReport(log)} name="wake-on-lan" />
    </div>
    <div class="entries">
      {#each log as e (e.key)}
        <div class="entry">
          <div class="entry-head">
            <span class="dim">{new Date(e.result.sentAtMs).toLocaleTimeString()}</span>
            <strong>{e.device || e.result.mac}</strong>
            {#if e.device}<span class="mono dim">{e.result.mac}</span>{/if}
          </div>
          <div class="line"><span class="tag sent">Sent</span> {sentSummary(e.result)}</div>
          <div class="line">
            <span
              class="tag"
              class:ok={e.check.state === "up"}
              class:warnc={e.check.state === "noAnswer" || e.check.state === "error"}
            >Woke?</span>
            {checkSummary(e.check)}
          </div>
          <div class="note dim">{DELIVERY_NOTE[e.result.delivery]}</div>
          {#each e.result.warnings as w (w)}<div class="warn">{w}</div>{/each}
        </div>
      {/each}
    </div>
  {/if}
</div>

<style>
  .panel {
    --st-ok: #2ea043;
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
    flex: 1 1 110px;
  }

  .field.grow {
    flex: 2 1 220px;
  }

  .field.notes {
    margin-bottom: 0.75rem;
  }

  label {
    font-size: 0.78rem;
    color: var(--muted);
    margin-bottom: 0.3rem;
  }

  label.check {
    display: flex;
    align-items: center;
    gap: 0.4rem;
    font-size: 0.82rem;
    color: var(--fg);
    margin-bottom: 0.75rem;
  }

  input:not([type="checkbox"]),
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

  .mono {
    font-family: var(--mono);
  }

  .row {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 0.6rem;
    margin: 0.3rem 0 1rem;
  }

  .action {
    background: var(--accent);
    border: 1px solid var(--accent);
    border-radius: 6px;
    padding: 0.5rem 1.4rem;
    color: var(--accent-fg);
    font-weight: 600;
    font-size: 0.85rem;
    cursor: pointer;
  }

  .action:disabled {
    opacity: 0.5;
    cursor: default;
  }

  .secondary,
  .mini {
    background: var(--btn-bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    color: var(--fg);
    cursor: pointer;
  }

  .secondary {
    padding: 0.5rem 1rem;
    font-size: 0.85rem;
  }

  .secondary.stop {
    border-color: var(--error-border);
    color: var(--error-fg);
  }

  .mini {
    padding: 0.15rem 0.5rem;
    font-size: 0.74rem;
  }

  .mini.primary {
    border-color: var(--accent);
    color: var(--accent);
  }

  .muted,
  .dim {
    color: var(--muted);
  }

  .small {
    font-size: 0.75rem;
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
    padding: 0.4rem 0.6rem;
    font-size: 0.78rem;
    margin-top: 0.4rem;
  }

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
    background: var(--sidebar-bg);
  }

  td {
    padding: 0.35rem 0.6rem;
    border-bottom: 1px solid var(--border);
    vertical-align: top;
  }

  tr:last-child td {
    border-bottom: none;
  }

  tr.editing td {
    background: var(--active-bg);
  }

  td.actions {
    white-space: nowrap;
    text-align: right;
  }

  td.actions .mini + .mini {
    margin-left: 0.25rem;
  }

  .loghead {
    display: flex;
    align-items: center;
    justify-content: space-between;
  }

  .entries {
    display: flex;
    flex-direction: column;
    gap: 0.6rem;
  }

  .entry {
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.6rem 0.8rem;
    font-size: 0.82rem;
  }

  .entry-head {
    display: flex;
    gap: 0.6rem;
    align-items: baseline;
    margin-bottom: 0.35rem;
  }

  .line {
    margin: 0.2rem 0;
  }

  .tag {
    display: inline-block;
    min-width: 3.2rem;
    border: 1px solid var(--border);
    border-radius: 3px;
    padding: 0 0.3rem;
    font-size: 0.7rem;
    text-transform: uppercase;
    letter-spacing: 0.03em;
    color: var(--muted);
    text-align: center;
  }

  .tag.sent {
    color: var(--fg);
  }

  .tag.ok {
    color: var(--st-ok);
    border-color: var(--st-ok);
  }

  .tag.warnc {
    color: var(--st-warn);
    border-color: var(--st-warn);
  }

  .note {
    font-size: 0.76rem;
    margin-top: 0.35rem;
  }
</style>
