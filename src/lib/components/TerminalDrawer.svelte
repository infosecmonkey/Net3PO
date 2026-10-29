<script lang="ts">
  // The active SSH session docked under the current tool, so you can work in
  // a builder and the device side by side. Drag the top edge to resize.
  import TermView from "$lib/tools/Ssh/TermView.svelte";
  import Icon from "./icons/Icon.svelte";
  import { closeTab, ssh } from "$lib/ssh/sessions.svelte";
  import { openTool } from "$lib/nav.svelte";

  const MIN = 120;

  let dragging = $state(false);

  function startDrag(e: PointerEvent) {
    dragging = true;
    (e.currentTarget as HTMLElement).setPointerCapture(e.pointerId);
  }

  function drag(e: PointerEvent) {
    if (!dragging) return;
    const max = Math.max(MIN, window.innerHeight * 0.85);
    ssh.drawerHeight = Math.round(Math.min(max, Math.max(MIN, window.innerHeight - e.clientY)));
  }

  function stopDrag() {
    dragging = false;
  }

  const title = $derived(ssh.tabs.find((t) => t.key === ssh.active)?.title ?? "");
</script>

<div class="drawer" style:height="{ssh.drawerHeight}px">
  <div
    class="handle"
    class:dragging
    role="separator"
    aria-orientation="horizontal"
    aria-label="Resize terminal"
    onpointerdown={startDrag}
    onpointermove={drag}
    onpointerup={stopDrag}
    onpointercancel={stopDrag}
  ></div>
  <div class="head">
    <span class="title mono">{title}</span>
    <button title="Open in the SSH tool" onclick={() => openTool("ssh")}>
      <Icon name="terminal" size={13} /> Expand
    </button>
    {#if ssh.active !== null}
      {@const key = ssh.active}
      <button title="Disconnect and close this session" onclick={() => closeTab(key)}>Close session</button>
    {/if}
    <button title="Hide the docked terminal" onclick={() => (ssh.drawer = false)}>Hide</button>
  </div>
  <div class="body">
    {#key ssh.active}
      {#if ssh.active !== null}
        <TermView tabKey={ssh.active} />
      {/if}
    {/key}
  </div>
</div>

<style>
  .drawer {
    flex: 0 0 auto;
    display: flex;
    flex-direction: column;
    border-top: 1px solid var(--border);
    background: var(--input-bg);
    position: relative;
    min-height: 0;
  }

  .handle {
    position: absolute;
    top: -3px;
    left: 0;
    right: 0;
    height: 6px;
    cursor: ns-resize;
    z-index: 2;
  }

  .handle:hover,
  .handle.dragging {
    background: var(--accent);
    opacity: 0.5;
  }

  .head {
    display: flex;
    align-items: center;
    gap: 0.4rem;
    padding: 0.25rem 0.5rem;
    border-bottom: 1px solid var(--border);
    background: var(--sidebar-bg);
  }

  .title {
    flex: 1 1 auto;
    font-size: 0.76rem;
    color: var(--muted);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .mono {
    font-family: var(--mono);
  }

  button {
    display: flex;
    align-items: center;
    gap: 0.3rem;
    font-size: 0.72rem;
    color: var(--fg);
    background: var(--btn-bg);
    border: 1px solid var(--border);
    border-radius: 5px;
    padding: 0.15rem 0.5rem;
    cursor: pointer;
  }

  button:hover {
    background: var(--hover);
  }

  .body {
    flex: 1 1 auto;
    min-height: 0;
  }
</style>
