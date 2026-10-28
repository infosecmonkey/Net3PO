<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import type { MacDbInfo, MacInfo } from "$lib/tools/types";

  let mac = $state("B8:27:EB:12:34:56");
  let info = $state<MacInfo | null>(null);
  let error = $state("");
  let db = $state<MacDbInfo | null>(null);

  // Load dataset provenance once so we can flag the seed fallback.
  $effect(() => {
    invoke<MacDbInfo>("mac_db_info")
      .then((d) => (db = d))
      .catch(() => (db = null));
  });

  let debounce: ReturnType<typeof setTimeout> | undefined;
  $effect(() => {
    void mac;
    clearTimeout(debounce);
    debounce = setTimeout(lookup, 120);
    return () => clearTimeout(debounce);
  });

  async function lookup() {
    if (mac.trim().length === 0) {
      info = null;
      error = "";
      return;
    }
    try {
      info = await invoke<MacInfo>("mac_lookup", { mac });
      error = "";
    } catch (e) {
      info = null;
      error = String(e);
    }
  }
</script>

<div class="panel">
  <header>
    <h1>MAC Vendor Lookup</h1>
    <p class="sub">
      Resolve a MAC address to its registered vendor using the IEEE OUI
      registry. Accepts any separator style.
    </p>
  </header>

  {#if db}
    <div class="dbline" class:warn={db.source === "seed"}>
      {#if db.source === "seed"}
        Seed dataset ({db.total} entries). Build with network, or set
        OUI_DATA_FILE, to load the full IEEE registry.
      {:else}
        {db.total.toLocaleString()} assignments loaded
        (MA-L {db.maL.toLocaleString()}, MA-M {db.maM.toLocaleString()}, MA-S {db.maS.toLocaleString()}){db.source === "file" ? ", from file" : ""}.
      {/if}
    </div>
  {/if}

  <input
    class="mono addr"
    bind:value={mac}
    spellcheck="false"
    autocapitalize="off"
    autocomplete="off"
    placeholder="00:00:0C:12:34:56"
  />

  {#if error}
    <div class="error">{error}</div>
  {/if}

  {#if info}
    <div class="result">
      <div class="vendor">
        {#if info.vendor}
          {info.vendor}
        {:else}
          <span class="muted">No matching vendor in the dataset</span>
        {/if}
      </div>

      <table>
        <tbody>
          <tr><th>MAC</th><td class="mono">{info.normalized}</td></tr>
          <tr><th>OUI</th><td class="mono">{info.oui}</td></tr>
          {#if info.prefix}
            <tr><th>Assignment</th><td class="mono">{info.prefix} ({info.block})</td></tr>
          {/if}
          <tr>
            <th>Administration</th>
            <td>{info.isLocallyAdministered ? "Locally administered" : "Universally administered (OUI)"}</td>
          </tr>
          <tr>
            <th>Cast</th>
            <td>{info.isMulticast ? "Multicast / group" : "Unicast"}</td>
          </tr>
        </tbody>
      </table>

      {#if info.isLocallyAdministered && !info.vendor}
        <p class="note">
          The locally administered bit is set, so this address was assigned
          locally and has no IEEE vendor.
        </p>
      {/if}
    </div>
  {/if}
</div>

<style>
  .panel {
    padding: 1.5rem 2rem;
    max-width: 760px;
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

  .dbline {
    font-size: 0.78rem;
    color: var(--muted);
    margin-bottom: 0.9rem;
  }

  .dbline.warn {
    color: var(--error-fg);
  }

  .mono {
    font-family: var(--mono);
  }

  .addr {
    width: 100%;
    box-sizing: border-box;
    background: var(--input-bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.6rem 0.7rem;
    color: var(--fg);
    font-size: 1rem;
    letter-spacing: 0.02em;
  }

  .addr:focus {
    outline: none;
    border-color: var(--accent);
  }

  .error {
    background: var(--error-bg);
    border: 1px solid var(--error-border);
    color: var(--error-fg);
    border-radius: 6px;
    padding: 0.6rem 0.8rem;
    font-size: 0.85rem;
    margin-top: 0.9rem;
  }

  .result {
    margin-top: 1.25rem;
  }

  .vendor {
    font-size: 1.15rem;
    font-weight: 600;
    margin-bottom: 0.75rem;
  }

  table {
    border-collapse: collapse;
    width: 100%;
  }

  th {
    text-align: left;
    width: 150px;
    color: var(--muted);
    font-weight: 500;
    font-size: 0.8rem;
    padding: 0.3rem 0.75rem 0.3rem 0;
    vertical-align: top;
  }

  td {
    padding: 0.3rem 0;
    font-size: 0.88rem;
  }

  .muted {
    color: var(--muted);
    font-weight: 400;
  }

  .note {
    margin-top: 0.9rem;
    font-size: 0.8rem;
    color: var(--muted);
    max-width: 560px;
  }
</style>
