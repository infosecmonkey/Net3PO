<script lang="ts">
  import { open } from "@tauri-apps/plugin-dialog";
  import { detectClients, saveSettings, settings, type Protocol } from "$lib/settings.svelte";
  import { recommended } from "./recommended";
  import { checkForUpdates, updates } from "$lib/updater.svelte";

  let detecting = $state(false);
  let saved = $state("");

  const LABELS: Record<Protocol, { title: string; tool: string; placeholders: string }> = {
    rdp: {
      title: "RDP client",
      tool: "RDP",
      placeholders: "{file} is a temporary .rdp file with the host, port, user and screen mode.",
    },
    vnc: {
      title: "VNC client",
      tool: "VNC",
      placeholders: "Most VNC viewers take {host}::{port}.",
    },
  };

  async function redetect() {
    detecting = true;
    await detectClients();
    detecting = false;
  }

  async function persist() {
    await saveSettings();
    if (!settings.error) {
      saved = "Saved";
      setTimeout(() => (saved = ""), 1500);
    }
  }

  async function browse(p: Protocol) {
    const path = await open({ multiple: false, directory: false, title: `Choose the ${LABELS[p].title}` });
    if (typeof path === "string") {
      settings.value.remote[p].path = path;
      await persist();
    }
  }

  let copied = $state("");

  async function copy(command: string) {
    try {
      await navigator.clipboard.writeText(command);
      copied = command;
      setTimeout(() => (copied = ""), 1500);
    } catch {
      copied = "";
    }
  }

  function resetArgs(p: Protocol) {
    const d = settings.detected;
    settings.value.remote[p].args = (p === "rdp" ? d?.rdpTemplate : d?.vncTemplate) ?? (p === "rdp" ? "{file}" : "{host}::{port}");
    void persist();
  }
</script>

<div class="panel">
  <header>
    <h1>Settings</h1>
    <p class="sub">Saved on this computer in the app data folder.</p>
  </header>

  {#if settings.error}<div class="error mono">{settings.error}</div>{/if}

  <section>
    <div class="head">
      <h2>Remote clients</h2>
      <span class="spacer"></span>
      {#if saved}<span class="ok">{saved}</span>{/if}
      <button class="small" onclick={redetect} disabled={detecting}>{detecting ? "Looking..." : "Detect again"}</button>
    </div>
    <p class="hint">
      The RDP and VNC tools open the client installed on this computer, and show in the sidebar under
      Remote only when a client is available here. Passwords are never passed to the client; it asks for
      them itself.
    </p>

    {#each ["rdp", "vnc"] as const as p (p)}
      {@const s = settings.value.remote[p]}
      {@const found = settings.detected?.[p] ?? []}
      {@const recs = recommended(settings.detected?.os, p)}
      <div class="card">
        <h3>{LABELS[p].title}</h3>
        <div class="modes" role="radiogroup" aria-label={LABELS[p].title}>
          <label><input type="radio" name="mode-{p}" value="auto" bind:group={s.mode} onchange={persist} /> Use an installed client</label>
          <label><input type="radio" name="mode-{p}" value="custom" bind:group={s.mode} onchange={persist} /> Custom program</label>
          <label><input type="radio" name="mode-{p}" value="off" bind:group={s.mode} onchange={persist} /> Off (hide the {LABELS[p].tool} tool)</label>
        </div>

        {#if s.mode === "auto"}
          {#if !settings.detected}
            <p class="hint">Looking for clients...</p>
          {:else if found.length === 0}
            <p class="warn-text">
              None found. Install one of the recommended clients below, then click Detect again, or choose a
              custom program.
            </p>
          {:else}
            <div class="choices">
              {#each found as c, i (c.id)}
                <label class="choice">
                  <input
                    type="radio"
                    name="client-{p}"
                    checked={s.id === c.id || (!found.some((x) => x.id === s.id) && i === 0)}
                    onchange={() => {
                      s.id = c.id;
                      void persist();
                    }}
                  />
                  <span>
                    <strong>{c.name}</strong>
                    <span class="path mono">{c.path}</span>
                    {#if c.note}<span class="note">{c.note}</span>{/if}
                  </span>
                </label>
              {/each}
            </div>
          {/if}
        {:else if s.mode === "custom"}
          <label class="field">
            Program
            <span class="inline">
              <input class="mono" bind:value={s.path} onchange={persist} placeholder={p === "rdp" ? "/usr/bin/xfreerdp3" : "/usr/bin/vncviewer"} spellcheck="false" />
              <button class="small" onclick={() => browse(p)}>Browse</button>
            </span>
          </label>
          <label class="field">
            Arguments
            <span class="inline">
              <input class="mono" bind:value={s.args} onchange={persist} spellcheck="false" />
              <button class="small" onclick={() => resetArgs(p)}>Default</button>
            </span>
          </label>
          <p class="hint">
            Placeholders: <code>{"{host}"}</code>, <code>{"{port}"}</code>, <code>{"{user}"}</code>,
            <code>{"{target}"}</code> (host:port){p === "rdp" ? ", " : ""}{#if p === "rdp"}<code>{"{file}"}</code>{/if}.
            {LABELS[p].placeholders} Each space-separated part is one argument; an argument that is only an
            empty {"{user}"} is left out. There is no password placeholder.
          </p>
        {:else}
          <p class="hint">The {LABELS[p].tool} tool is hidden.</p>
        {/if}

        <details class="recs" open={s.mode === "auto" && settings.detected !== null && found.length === 0}>
          <summary>Recommended {LABELS[p].tool} clients for this OS</summary>
          <ul>
            {#each recs as r (r.name)}
              <li>
                <strong>{r.name}</strong>
                <span class="note-text">{r.note}</span>
                {#each r.install as i (i.label)}
                  <span class="cmd">
                    <span class="label">{i.label}</span>
                    <code class="mono">{i.command}</code>
                    <button class="small" onclick={() => copy(i.command)}>{copied === i.command ? "Copied" : "Copy"}</button>
                  </span>
                {/each}
              </li>
            {/each}
          </ul>
          <p class="hint">
            Net3PO does not install or download these. A client installed somewhere Net3PO does not look
            (for example a Flatpak) can be set as a custom program.
          </p>
        </details>
      </div>
    {/each}
  </section>

  <section>
    <div class="head">
      <h2>Updates</h2>
    </div>
    <div class="card">
      <label class="choice">
        <input type="checkbox" bind:checked={settings.value.updates.checkOnStart} onchange={persist} />
        Check for updates when Net3PO starts
      </label>
      <p class="hint">
        Off by default. When on, Net3PO asks GitHub for the latest release each time it starts, and shows a message only
        when there is a newer version. Nothing about you or this computer is sent. Updates are never installed without
        your click, and each one is checked against Net3PO's signing key first.
      </p>
      <button class="small" onclick={() => void checkForUpdates(true)} disabled={updates.status === "checking"}>
        {updates.status === "checking" ? "Checking..." : "Check for updates now"}
      </button>
    </div>
  </section>
</div>

<style>
  .panel {
    padding: 1.5rem 2rem 2rem;
    box-sizing: border-box;
    width: 100%;
    max-width: 52rem;
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

  .head {
    display: flex;
    align-items: center;
    gap: 0.6rem;
  }

  h2 {
    font-size: 1rem;
    margin: 0;
  }

  h3 {
    font-size: 0.9rem;
    margin: 0 0 0.5rem;
  }

  .spacer {
    flex: 1;
  }

  .ok {
    color: #16a34a;
    font-size: 0.78rem;
  }

  .hint {
    color: var(--muted);
    font-size: 0.8rem;
    margin: 0.4rem 0 0.8rem;
  }

  .warn-text {
    font-size: 0.82rem;
    border-left: 3px solid #c69026;
    padding-left: 0.6rem;
  }

  .card {
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 0.8rem 1rem;
    margin-bottom: 0.9rem;
    background: var(--sidebar-bg);
  }

  .modes {
    display: flex;
    flex-wrap: wrap;
    gap: 0.4rem 1.2rem;
    font-size: 0.84rem;
    margin-bottom: 0.6rem;
  }

  .modes label,
  .choice {
    display: flex;
    align-items: flex-start;
    gap: 0.4rem;
    cursor: pointer;
  }

  .choices {
    display: flex;
    flex-direction: column;
    gap: 0.45rem;
    font-size: 0.84rem;
  }

  .choice span {
    display: flex;
    flex-direction: column;
  }

  .path {
    color: var(--muted);
    font-size: 0.74rem;
    overflow-wrap: anywhere;
  }

  .note {
    color: #c69026;
    font-size: 0.74rem;
  }

  .field {
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
    font-size: 0.78rem;
    color: var(--muted);
    margin-bottom: 0.5rem;
  }

  .inline {
    display: flex;
    gap: 0.35rem;
  }

  input:not([type]),
  input.mono {
    flex: 1;
    box-sizing: border-box;
    background: var(--input-bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    color: var(--fg);
    font-size: 0.82rem;
    padding: 0.35rem 0.5rem;
  }

  input:focus {
    outline: none;
    border-color: var(--accent);
  }

  .mono,
  code {
    font-family: var(--mono);
  }

  button.small {
    background: var(--input-bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    color: var(--fg);
    font-size: 0.76rem;
    padding: 0.28rem 0.6rem;
    cursor: pointer;
    white-space: nowrap;
  }

  button.small:hover:not(:disabled) {
    background: var(--hover);
  }

  button:disabled {
    opacity: 0.5;
  }

  .recs {
    margin-top: 0.7rem;
    font-size: 0.82rem;
  }

  .recs summary {
    cursor: pointer;
    color: var(--muted);
    font-size: 0.8rem;
  }

  .recs ul {
    list-style: none;
    padding: 0;
    margin: 0.5rem 0 0;
    display: flex;
    flex-direction: column;
    gap: 0.55rem;
  }

  .recs li {
    display: flex;
    flex-direction: column;
    gap: 0.2rem;
  }

  .note-text {
    color: var(--muted);
    font-size: 0.78rem;
  }

  .cmd {
    display: flex;
    align-items: center;
    gap: 0.45rem;
    flex-wrap: wrap;
  }

  .cmd .label {
    color: var(--muted);
    font-size: 0.74rem;
    min-width: 8.5rem;
  }

  .cmd code {
    font-size: 0.76rem;
    background: var(--input-bg);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 0.1rem 0.35rem;
  }

  .error {
    background: var(--error-bg);
    border: 1px solid var(--error-border);
    color: var(--error-fg);
    border-radius: 6px;
    padding: 0.5rem 0.7rem;
    font-size: 0.8rem;
    margin-bottom: 0.8rem;
    white-space: pre-wrap;
  }
</style>
