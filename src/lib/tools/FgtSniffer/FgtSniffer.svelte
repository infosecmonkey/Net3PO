<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import { open, save } from "@tauri-apps/plugin-dialog";
  import type { FgtOptions, FgtParseSummary, FgtSaveSummary } from "$lib/tools/types";

  const PLACEHOLDER = `Paste "diagnose sniffer packet <iface> '<filter>' 3" output here, for example:

interfaces=[port1]
filters=[none]
2.123456 port1 in 10.0.0.1 -> 10.0.0.2: udp 20
0x0000   0011 2233 4455 6677 8899 aabb 0800 4500   ..3DUfw.......E
0x0010   0030 0000 4000 4011 ...`;

  let input = $state("");
  let skipEth0 = $state(true);

  let summary = $state<FgtParseSummary | null>(null);
  let error = $state("");
  let saveMsg = $state("");

  let options = $derived<FgtOptions>({ skipEth0 });

  let debounce: ReturnType<typeof setTimeout> | undefined;
  $effect(() => {
    void input;
    void skipEth0;
    saveMsg = "";
    clearTimeout(debounce);
    debounce = setTimeout(parse, 150);
    return () => clearTimeout(debounce);
  });

  async function parse() {
    if (input.trim().length === 0) {
      summary = null;
      error = "";
      return;
    }
    try {
      summary = await invoke<FgtParseSummary>("fgt_parse", { input, options });
      error = "";
    } catch (e) {
      summary = null;
      error = String(e);
    }
  }

  async function loadFile() {
    error = "";
    saveMsg = "";
    try {
      const path = await open({
        multiple: false,
        filters: [
          { name: "Text", extensions: ["txt", "log"] },
          { name: "All files", extensions: ["*"] },
        ],
      });
      if (typeof path !== "string") return; // cancelled
      input = await invoke<string>("fgt_read_file", { path });
    } catch (e) {
      error = String(e);
    }
  }

  async function savePcap() {
    saveMsg = "";
    error = "";
    try {
      const path = await save({
        defaultPath: "capture.pcap",
        filters: [{ name: "PCAP", extensions: ["pcap"] }],
      });
      if (!path) return; // cancelled
      const res = await invoke<FgtSaveSummary>("fgt_save", { input, options, path });
      saveMsg = `Wrote ${res.packets.toLocaleString()} packets (${res.bytesWritten.toLocaleString()} bytes).`;
    } catch (e) {
      error = String(e);
    }
  }
</script>

<div class="panel">
  <header>
    <h1>FortiGate Sniffer to PCAP</h1>
    <p class="sub">
      Convert `diagnose sniffer packet` verbose output (level 3, with hex) into a
      .pcap. The file is written directly, so Wireshark is not required to create
      it.
    </p>
  </header>

  <textarea
    class="mono"
    bind:value={input}
    placeholder={PLACEHOLDER}
    spellcheck="false"
    autocapitalize="off"
    autocomplete="off"
  ></textarea>

  <div class="controls">
    <button class="secondary" onclick={loadFile}>Load .txt file</button>
    <label class="opt">
      <input type="checkbox" bind:checked={skipEth0} /> Skip eth0 (internal)
    </label>
    <button class="save" onclick={savePcap} disabled={!summary || summary.total === 0}>
      Save .pcap
    </button>
  </div>

  {#if error}
    <div class="error mono">{error}</div>
  {/if}
  {#if saveMsg}
    <div class="ok">{saveMsg}</div>
  {/if}

  {#if summary}
    <div class="stats">
      <span><strong>{summary.total.toLocaleString()}</strong> packets</span>
      <span>{summary.totalBytes.toLocaleString()} bytes</span>
      {#if summary.skippedEth0 > 0}
        <span class="muted">{summary.skippedEth0.toLocaleString()} eth0 skipped</span>
      {/if}
    </div>

    {#if summary.total > 0}
      <div class="table-scroll">
        <table>
          <thead>
            <tr>
              <th>#</th>
              <th>Time (UTC)</th>
              <th>Interface</th>
              <th>Dir</th>
              <th>Bytes</th>
            </tr>
          </thead>
          <tbody>
            {#each summary.packets as p (p.index)}
              <tr>
                <td class="muted">{p.index}</td>
                <td class="mono">{p.time}</td>
                <td class="mono">{p.interface ?? "-"}</td>
                <td>{p.direction ?? "-"}</td>
                <td class="mono num">{p.length}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
      {#if summary.truncated}
        <p class="note">Showing the first {summary.shown.toLocaleString()} packets. The saved .pcap includes all {summary.total.toLocaleString()}.</p>
      {/if}
    {:else}
      <p class="empty">
        No packets recognized. This expects `diagnose sniffer packet` output at a
        verbose level that includes hex (level 3 or 6), with `0x0000 ...` dump
        lines under each packet.
      </p>
    {/if}
  {/if}
</div>

<style>
  .panel {
    padding: 1.5rem 2rem;
    max-width: 900px;
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

  textarea {
    width: 100%;
    box-sizing: border-box;
    min-height: 11rem;
    resize: vertical;
    background: var(--input-bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.6rem 0.7rem;
    color: var(--fg);
    font-size: 0.82rem;
    line-height: 1.45;
  }

  textarea:focus {
    outline: none;
    border-color: var(--accent);
  }

  .controls {
    display: flex;
    align-items: center;
    gap: 1rem;
    margin: 0.9rem 0;
  }

  .opt {
    display: flex;
    align-items: center;
    gap: 0.4rem;
    font-size: 0.85rem;
  }

  .save {
    margin-left: auto;
    background: var(--accent);
    border: 1px solid var(--accent);
    border-radius: 6px;
    padding: 0.5rem 1rem;
    color: #fff;
    font-weight: 600;
    font-size: 0.85rem;
    cursor: pointer;
  }

  .save:disabled {
    opacity: 0.5;
    cursor: default;
  }

  .secondary {
    background: var(--btn-bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.5rem 0.9rem;
    color: var(--fg);
    font-size: 0.85rem;
    cursor: pointer;
  }

  .secondary:hover {
    border-color: var(--accent);
  }

  .empty {
    font-size: 0.85rem;
    color: var(--muted);
    max-width: 620px;
  }

  .error {
    background: var(--error-bg);
    border: 1px solid var(--error-border);
    color: var(--error-fg);
    border-radius: 6px;
    padding: 0.6rem 0.8rem;
    font-size: 0.82rem;
    margin-bottom: 0.6rem;
    white-space: pre-wrap;
  }

  .ok {
    color: var(--accent);
    font-size: 0.85rem;
    margin-bottom: 0.6rem;
  }

  .stats {
    display: flex;
    gap: 1.25rem;
    font-size: 0.85rem;
    margin-bottom: 0.75rem;
  }

  .muted {
    color: var(--muted);
  }

  .table-scroll {
    overflow: auto;
    max-height: 420px;
    border: 1px solid var(--border);
    border-radius: 6px;
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
    padding: 0.4rem 0.75rem;
    border-bottom: 1px solid var(--border);
    position: sticky;
    top: 0;
    background: var(--sidebar-bg);
    white-space: nowrap;
  }

  td {
    padding: 0.3rem 0.75rem;
    border-bottom: 1px solid var(--border);
  }

  tr:last-child td {
    border-bottom: none;
  }

  .num {
    text-align: right;
  }

  .note {
    font-size: 0.78rem;
    color: var(--muted);
    margin: 0.5rem 0 0;
  }
</style>
