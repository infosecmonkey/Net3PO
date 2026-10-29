<script lang="ts">
  // Path latency: average RTT per hop as a line, with a best-to-worst band.
  // Silent hops break the line and show "*" on the baseline. A crosshair snaps
  // to the nearest hop; arrow keys move it; click or Enter selects the hop.
  import type { HopView } from "$lib/tools/types";
  import { fmtMs, hopLabel, niceScale } from "./format";

  interface Props {
    hops: HopView[];
    selected: number | null;
    onselect: (ttl: number) => void;
  }
  let { hops, selected, onselect }: Props = $props();

  const HEIGHT = 220;
  const M = { top: 16, right: 48, bottom: 28, left: 44 };

  let width = $state(600);
  let hover = $state<number | null>(null);

  const plotW = $derived(Math.max(width - M.left - M.right, 50));
  const plotH = HEIGHT - M.top - M.bottom;
  const scale = $derived(niceScale(Math.max(0, ...hops.map((h) => h.worstMs ?? 0))));
  const band = $derived(plotW / Math.max(hops.length, 1));

  const x = (i: number) => M.left + (i + 0.5) * band;
  const y = (ms: number) => M.top + plotH - (ms / scale.top) * plotH;

  /** Runs of consecutive answering hops; the line and band break at silent hops. */
  const runs = $derived.by(() => {
    const out: number[][] = [];
    let cur: number[] = [];
    hops.forEach((h, i) => {
      if (h.avgMs !== null) cur.push(i);
      else if (cur.length) {
        out.push(cur);
        cur = [];
      }
    });
    if (cur.length) out.push(cur);
    return out;
  });

  function linePath(run: number[]): string {
    return run.map((i, k) => `${k ? "L" : "M"}${x(i)},${y(hops[i].avgMs!)}`).join("");
  }

  function bandPath(run: number[]): string {
    if (run.length < 2) return "";
    const top = run.map((i) => `${x(i)},${y(hops[i].worstMs!)}`);
    const bottom = [...run].reverse().map((i) => `${x(i)},${y(hops[i].bestMs!)}`);
    return `M${top.join("L")}L${bottom.join("L")}Z`;
  }

  const last = $derived([...hops].reverse().find((h) => h.avgMs !== null) ?? null);
  const lastIndex = $derived(last ? hops.indexOf(last) : -1);

  function nearest(clientX: number, el: HTMLElement): number {
    const rect = el.getBoundingClientRect();
    const i = Math.floor((clientX - rect.left - M.left) / band);
    return Math.min(Math.max(i, 0), hops.length - 1);
  }

  function onKey(e: KeyboardEvent) {
    if (!hops.length) return;
    const cur = hover ?? (selected !== null ? selected - 1 : 0);
    if (e.key === "ArrowRight") hover = Math.min(cur + 1, hops.length - 1);
    else if (e.key === "ArrowLeft") hover = Math.max(cur - 1, 0);
    else if (e.key === "Enter" && hover !== null) onselect(hops[hover].ttl);
    else return;
    e.preventDefault();
  }

  const tip = $derived(hover !== null ? hops[hover] : null);
  const tipLeft = $derived(hover !== null ? Math.min(x(hover) + 12, width - 190) : 0);
</script>

<div
  class="chart"
  bind:clientWidth={width}
  role="slider"
  aria-roledescription="latency chart"
  aria-label="Average round-trip time per hop. Left and right arrows move between hops, Enter opens hop detail."
  aria-valuemin={hops[0]?.ttl ?? 1}
  aria-valuemax={hops[hops.length - 1]?.ttl ?? 1}
  aria-valuenow={tip?.ttl ?? selected ?? hops[0]?.ttl ?? 1}
  aria-valuetext={tip ? `Hop ${tip.ttl}, ${tip.avgMs !== null ? `${fmtMs(tip.avgMs)} ms average` : "no reply"}, ${tip.lossPct.toFixed(0)}% loss` : undefined}
  tabindex="0"
  onpointermove={(e) => (hover = nearest(e.clientX, e.currentTarget))}
  onpointerleave={() => (hover = null)}
  onclick={() => hover !== null && onselect(hops[hover].ttl)}
  onkeydown={onKey}
  onblur={() => (hover = null)}
>
  <svg width={width} height={HEIGHT} aria-hidden="true">
    {#each scale.ticks as t (t)}
      <line class="grid" x1={M.left} x2={M.left + plotW} y1={y(t)} y2={y(t)} />
      <text class="tick" x={M.left - 8} y={y(t) + 4} text-anchor="end">{t}</text>
    {/each}
    <text class="tick unit" x={M.left - 8} y={M.top - 4} text-anchor="end">ms</text>

    {#if selected !== null && selected <= hops.length}
      <rect class="sel" x={M.left + (selected - 1) * band} y={M.top} width={band} height={plotH} />
    {/if}

    {#each runs as run, r (r)}
      <path class="band" d={bandPath(run)} />
      <path class="line" d={linePath(run)} />
    {/each}

    {#each hops as h, i (h.ttl)}
      {#if h.avgMs !== null}
        <circle class="dot" cx={x(i)} cy={y(h.avgMs)} r="4" />
      {:else}
        <text class="silent" x={x(i)} y={M.top + plotH - 4} text-anchor="middle">*</text>
      {/if}
      {#if hops.length <= 32 || i % 2 === 0}
        <text class="tick" x={x(i)} y={HEIGHT - 8} text-anchor="middle">{h.ttl}</text>
      {/if}
    {/each}

    {#if last && lastIndex >= 0}
      <text class="endlabel" x={x(lastIndex) + 8} y={y(last.avgMs!) + 4}>{fmtMs(last.avgMs)} ms</text>
    {/if}

    {#if hover !== null}
      <line class="cross" x1={x(hover)} x2={x(hover)} y1={M.top} y2={M.top + plotH} />
    {/if}
  </svg>

  {#if tip}
    <div class="tooltip" style="left: {tipLeft}px">
      <div class="tv">{tip.avgMs !== null ? `${fmtMs(tip.avgMs)} ms avg` : "no reply"}</div>
      {#if tip.avgMs !== null}
        <div class="tl"><span class="key band-key"></span>{fmtMs(tip.bestMs)} to {fmtMs(tip.worstMs)} ms</div>
      {/if}
      <div class="tl">{tip.lossPct.toFixed(0)}% loss</div>
      <div class="tn">Hop {tip.ttl} · {hopLabel(tip)}</div>
    </div>
  {/if}
</div>

<style>
  .chart {
    position: relative;
    width: 100%;
  }

  svg {
    display: block;
  }

  .chart {
    outline: none;
  }

  .chart:focus-visible {
    outline: 2px solid var(--accent);
    outline-offset: 2px;
    border-radius: 4px;
  }

  .grid {
    stroke: var(--border);
    stroke-width: 1;
  }

  .tick {
    fill: var(--muted);
    font-size: 11px;
    font-variant-numeric: tabular-nums;
  }

  .unit {
    font-size: 10px;
  }

  .sel {
    fill: var(--active-bg);
  }

  .band {
    fill: var(--viz-series);
    opacity: 0.1;
  }

  .line {
    fill: none;
    stroke: var(--viz-series);
    stroke-width: 2;
    stroke-linejoin: round;
    stroke-linecap: round;
  }

  .dot {
    fill: var(--viz-series);
    stroke: var(--bg);
    stroke-width: 2;
  }

  .silent {
    fill: var(--muted);
    font-size: 14px;
  }

  .endlabel {
    fill: var(--fg);
    font-size: 11px;
    font-weight: 600;
  }

  .cross {
    stroke: var(--muted);
    stroke-width: 1;
    pointer-events: none;
  }

  .tooltip {
    position: absolute;
    top: 8px;
    pointer-events: none;
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.4rem 0.6rem;
    font-size: 0.75rem;
    box-shadow: 0 2px 8px rgb(0 0 0 / 0.15);
    max-width: 180px;
  }

  .tv {
    font-weight: 600;
    font-size: 0.85rem;
  }

  .tl {
    color: var(--muted);
  }

  .tn {
    color: var(--muted);
    margin-top: 0.2rem;
    word-break: break-all;
  }

  .key {
    display: inline-block;
    width: 12px;
    height: 8px;
    margin-right: 0.35rem;
    vertical-align: middle;
  }

  .band-key {
    background: var(--viz-series);
    opacity: 0.3;
  }
</style>
