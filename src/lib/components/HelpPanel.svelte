<script lang="ts">
  // Help pop-out, docked on the right: the user manual, bundled with the app
  // so it works offline. Opens on the current tool's page (F1 or the ? button).
  // Manual links stay in the panel; web links open in the browser on click.
  import { tick } from "svelte";
  import { openUrl } from "@tauri-apps/plugin-opener";
  import { nav } from "$lib/nav.svelte";
  import { findTool } from "$lib/tools/registry";
  import { back, help, helpForTool, persistHelp, showPage } from "$lib/help/help.svelte";
  import { HOME, loadPage, render, toolPage } from "$lib/help/manual";

  const MIN_W = 320;

  let html = $state("");
  let title = $state("");
  let error = $state("");
  let body = $state<HTMLDivElement | null>(null);
  let dragging = $state(false);

  const tool = $derived(findTool(nav.selected));
  const toolHelp = $derived(toolPage(nav.selected));

  // Follow the tool: when help shows the previous tool's page and another
  // tool is opened, show that tool's page instead.
  let lastTool = nav.selected;
  $effect(() => {
    const id = nav.selected;
    if (id === lastTool) return;
    const was = toolPage(lastTool);
    lastTool = id;
    if (was && help.page === was) helpForTool(id);
  });

  // Load and render whenever the page changes, then scroll to the anchor.
  $effect(() => {
    const page = help.page;
    const anchor = help.anchor;
    error = "";
    loadPage(page)
      .then(async (md) => {
        if (page !== help.page) return;
        const r = render(md, page);
        html = r.html;
        title = r.title;
        await tick();
        scrollTo(anchor);
      })
      .catch((e) => {
        html = "";
        title = "";
        error = String(e);
      });
  });

  function scrollTo(anchor: string) {
    if (!body) return;
    const el = anchor ? body.querySelector(`[id="${CSS.escape(anchor)}"]`) : null;
    if (el) el.scrollIntoView({ block: "start" });
    else body.scrollTop = 0;
  }

  function onClick(e: MouseEvent) {
    const a = (e.target as HTMLElement).closest("a");
    if (!a) return;
    e.preventDefault();
    const ext = a.dataset.external;
    if (ext) {
      void openUrl(ext);
      return;
    }
    const page = a.dataset.page;
    const anchor = a.dataset.anchor ?? "";
    if (page) showPage(page, anchor);
    else if (anchor) scrollTo(anchor);
  }

  function close() {
    help.open = false;
  }

  function startDrag(e: PointerEvent) {
    dragging = true;
    (e.currentTarget as HTMLElement).setPointerCapture(e.pointerId);
  }

  function drag(e: PointerEvent) {
    if (!dragging) return;
    const max = Math.max(MIN_W, Math.min(900, window.innerWidth * 0.7));
    help.width = Math.round(Math.min(max, Math.max(MIN_W, window.innerWidth - e.clientX)));
  }

  function stopDrag() {
    if (!dragging) return;
    dragging = false;
    persistHelp();
  }
</script>

<aside class="help" style:width="{help.width}px" aria-label="Help">
  <div
    class="handle"
    class:dragging
    role="separator"
    aria-orientation="vertical"
    aria-label="Resize help"
    onpointerdown={startDrag}
    onpointermove={drag}
    onpointerup={stopDrag}
    onpointercancel={stopDrag}
  ></div>

  <div class="head">
    <strong>Help</strong>
    <div class="nav">
      <button class="mini" onclick={back} disabled={help.history.length === 0} title="Back">Back</button>
      <button class="mini" onclick={() => showPage(HOME)} disabled={help.page === HOME} title="Manual contents">Contents</button>
      {#if toolHelp && help.page !== toolHelp}
        <button class="mini" onclick={() => helpForTool(nav.selected)} title="Help for the open tool">{tool?.name}</button>
      {/if}
    </div>
    <button class="x" title="Hide help (Esc)" aria-label="Hide help" onclick={close}>
      <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><path d="M18 6 6 18"/><path d="m6 6 12 12"/></svg>
    </button>
  </div>

  {#if error}
    <div class="error">{error}</div>
  {/if}
  <!-- svelte-ignore a11y_click_events_have_key_events, a11y_no_static_element_interactions -->
  <div class="body" bind:this={body} onclick={onClick} aria-label={title}>
    <!-- Rendered from the bundled manual; raw HTML in it is escaped. -->
    <!-- eslint-disable-next-line svelte/no-at-html-tags -->
    {@html html}
  </div>
</aside>

<style>
  .help {
    position: relative;
    flex: 0 0 auto;
    height: 100vh;
    box-sizing: border-box;
    border-left: 1px solid var(--border);
    background: var(--bg);
    display: flex;
    flex-direction: column;
    min-width: 0;
  }

  .handle {
    position: absolute;
    top: 0;
    bottom: 0;
    left: -3px;
    width: 6px;
    cursor: ew-resize;
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
    gap: 0.6rem;
    padding: 0.6rem 0.8rem;
    border-bottom: 1px solid var(--border);
    background: var(--sidebar-bg);
    font-size: 0.85rem;
  }

  .nav {
    display: flex;
    gap: 0.3rem;
    flex: 1;
    min-width: 0;
    flex-wrap: wrap;
  }

  .mini {
    background: var(--btn-bg);
    color: var(--fg);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.15rem 0.55rem;
    font-size: 0.75rem;
    cursor: pointer;
    white-space: nowrap;
  }

  .mini:disabled {
    opacity: 0.45;
    cursor: default;
  }

  .x {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 28px;
    height: 28px;
    margin: -4px -6px -4px 0;
    background: none;
    border: none;
    border-radius: 6px;
    color: var(--muted);
    cursor: pointer;
  }

  .x:hover {
    color: var(--fg);
    background: var(--hover);
  }

  .error {
    margin: 0.8rem;
    padding: 0.5rem 0.7rem;
    border-radius: 6px;
    background: var(--error-bg);
    border: 1px solid var(--error-border);
    color: var(--error-fg);
    font-size: 0.85rem;
  }

  .body {
    flex: 1 1 auto;
    min-height: 0;
    overflow-y: auto;
    padding: 0.4rem 1.1rem 2rem;
    font-size: 0.88rem;
    line-height: 1.55;
    user-select: text;
    overflow-wrap: anywhere;
  }

  .body :global(h1) {
    font-size: 1.35rem;
    margin: 0.8rem 0 0.4rem;
  }

  .body :global(h2) {
    font-size: 1.08rem;
    margin: 1.4rem 0 0.4rem;
    padding-bottom: 0.2rem;
    border-bottom: 1px solid var(--border);
  }

  .body :global(h3) {
    font-size: 0.95rem;
    margin: 1.1rem 0 0.3rem;
  }

  .body :global(p),
  .body :global(ul),
  .body :global(ol) {
    margin: 0.45rem 0;
  }

  .body :global(li) {
    margin: 0.15rem 0;
  }

  .body :global(a) {
    color: var(--accent);
    text-decoration: none;
  }

  .body :global(a:hover) {
    text-decoration: underline;
  }

  .body :global(blockquote) {
    margin: 0.6rem 0;
    padding: 0.3rem 0.8rem;
    border-left: 3px solid var(--accent);
    background: var(--sidebar-bg);
    color: var(--muted);
  }

  .body :global(code) {
    font-family: var(--mono);
    font-size: 0.82em;
    background: var(--btn-bg);
    border-radius: 4px;
    padding: 0.05rem 0.3rem;
  }

  .body :global(pre) {
    background: var(--sidebar-bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.6rem 0.75rem;
    overflow-x: auto;
  }

  .body :global(pre code) {
    background: none;
    padding: 0;
    overflow-wrap: normal;
  }

  .body :global(table) {
    border-collapse: collapse;
    width: 100%;
    margin: 0.6rem 0;
    font-size: 0.82rem;
    display: block;
    overflow-x: auto;
  }

  .body :global(th),
  .body :global(td) {
    border: 1px solid var(--border);
    padding: 0.3rem 0.5rem;
    text-align: left;
    vertical-align: top;
    overflow-wrap: normal;
  }

  .body :global(th) {
    background: var(--sidebar-bg);
  }

  .body :global(hr) {
    border: none;
    border-top: 1px solid var(--border);
    margin: 1.2rem 0;
  }
</style>
