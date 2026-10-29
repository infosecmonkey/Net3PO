<script lang="ts">
  // One xterm.js terminal bound to an SSH tab. Replays the tab's scrollback
  // on mount, so switching tools and back keeps the screen.
  import { onMount } from "svelte";
  import { Terminal } from "@xterm/xterm";
  import { FitAddon } from "@xterm/addon-fit";
  import "@xterm/xterm/css/xterm.css";
  import { attach, detach, resize, write } from "$lib/ssh/sessions.svelte";

  interface Props {
    tabKey: number;
  }
  let { tabKey }: Props = $props();

  let el = $state<HTMLDivElement | null>(null);

  function theme() {
    const css = getComputedStyle(document.documentElement);
    const v = (name: string, fallback: string) => css.getPropertyValue(name).trim() || fallback;
    return {
      background: v("--input-bg", "#1b1d21"),
      foreground: v("--fg", "#e6e8eb"),
      cursor: v("--accent", "#fb923c"),
      selectionBackground: v("--active-bg", "#3a2414"),
    };
  }

  onMount(() => {
    const key = tabKey;
    const term = new Terminal({
      fontFamily: getComputedStyle(document.documentElement).getPropertyValue("--mono") || "monospace",
      fontSize: 13,
      cursorBlink: true,
      scrollback: 5000,
      theme: theme(),
      allowProposedApi: false,
    });
    const fit = new FitAddon();
    term.loadAddon(fit);
    term.open(el!);

    // Cmd/Ctrl+C copies when text is selected; otherwise it goes to the host.
    term.attachCustomKeyEventHandler((e) => {
      if (e.type === "keydown" && (e.metaKey || (e.ctrlKey && e.shiftKey)) && e.key.toLowerCase() === "c" && term.hasSelection()) {
        void navigator.clipboard.writeText(term.getSelection());
        return false;
      }
      return true;
    });

    const sink = (d: Uint8Array) => term.write(d);
    for (const chunk of attach(key, sink)) term.write(chunk);
    const input = term.onData((d) => void write(key, d));

    let timer: ReturnType<typeof setTimeout> | undefined;
    const ro = new ResizeObserver(() => {
      clearTimeout(timer);
      timer = setTimeout(() => {
        try {
          fit.fit();
          void resize(key, term.cols, term.rows);
        } catch {
          // Element not laid out yet.
        }
      }, 60);
    });
    ro.observe(el!);
    fit.fit();
    void resize(key, term.cols, term.rows);
    term.focus();

    return () => {
      clearTimeout(timer);
      ro.disconnect();
      input.dispose();
      detach(key, sink);
      term.dispose();
    };
  });
</script>

<div class="term" bind:this={el}></div>

<style>
  .term {
    width: 100%;
    height: 100%;
    padding: 0.4rem;
    box-sizing: border-box;
    background: var(--input-bg);
  }
</style>
