<script lang="ts">
  // RTT over time for one hop: a line of per-cycle RTTs, with lost probes as
  // ticks on the baseline. `top` is shared across hops so small multiples
  // compare honestly. With `axis`, it draws ticks for the larger detail view.
  import { fmtMs, niceScale } from "./format";

  interface Props {
    history: (number | null)[];
    top: number;
    height?: number;
    axis?: boolean;
    label: string;
  }
  let { history, top, height = 44, axis = false, label }: Props = $props();

  const M = $derived(axis ? { top: 10, right: 12, bottom: 22, left: 40 } : { top: 4, right: 4, bottom: 6, left: 4 });

  let width = $state(200);
  let hover = $state<number | null>(null);

  const plotW = $derived(Math.max(width - M.left - M.right, 10));
  const plotH = $derived(height - M.top - M.bottom);
  const scale = $derived(axis ? niceScale(top) : { top: Math.max(top, 1), ticks: [] });
  const n = $derived(history.length);

  const x = (i: number) => M.left + (n <= 1 ? plotW / 2 : (i / (n - 1)) * plotW);
  const y = (ms: number) => M.top + plotH - (Math.min(ms, scale.top) / scale.top) * plotH;

  const path = $derived.by(() => {
    let d = "";
    let pen = false;
    history.forEach((v, i) => {
      if (v === null) {
        pen = false;
        return;
      }
      d += `${pen ? "L" : "M"}${x(i)},${y(v)}`;
      pen = true;
    });
    return d;
  });

  /** Points with no answered neighbor would be invisible as a line; dot them. */
  const isolated = $derived(
    history
      .map((v, i) => ({ v, i }))
      .filter(({ v, i }) => v !== null && (history[i - 1] ?? null) === null && (history[i + 1] ?? null) === null),
  );

  const lost = $derived(history.filter((v) => v === null).length);

  function onMove(e: PointerEvent) {
    if (n === 0) return;
    const rect = (e.currentTarget as SVGSVGElement).getBoundingClientRect();
    const rel = (e.clientX - rect.left - M.left) / plotW;
    hover = Math.min(Math.max(Math.round(rel * (n - 1)), 0), n - 1);
  }

  const tipLeft = $derived(hover !== null ? Math.min(x(hover) + 10, width - 120) : 0);
</script>

<div class="wrap" bind:clientWidth={width}>
  <svg
    {width}
    {height}
    role="img"
    aria-label="{label}: {n} samples, {lost} lost"
    onpointermove={onMove}
    onpointerleave={() => (hover = null)}
  >
    {#if axis}
      {#each scale.ticks as t (t)}
        <line class="grid" x1={M.left} x2={M.left + plotW} y1={y(t)} y2={y(t)} />
        <text class="tick" x={M.left - 6} y={y(t) + 4} text-anchor="end">{t}</text>
      {/each}
      <text class="tick" x={M.left} y={height - 6}>oldest</text>
      <text class="tick" x={M.left + plotW} y={height - 6} text-anchor="end">latest</text>
    {:else}
      <line class="grid" x1={M.left} x2={M.left + plotW} y1={M.top + plotH} y2={M.top + plotH} />
    {/if}

    <path class="line" d={path} />
    {#each isolated as p (p.i)}
      <circle class="dot" cx={x(p.i)} cy={y(p.v!)} r="3" />
    {/each}
    {#each history as v, i (i)}
      {#if v === null}
        <line class="lost" x1={x(i)} x2={x(i)} y1={M.top + plotH - (axis ? 8 : 5)} y2={M.top + plotH} />
      {/if}
    {/each}

    {#if hover !== null}
      <line class="cross" x1={x(hover)} x2={x(hover)} y1={M.top} y2={M.top + plotH} />
    {/if}
  </svg>

  {#if hover !== null}
    <div class="tooltip" style="left: {tipLeft}px">
      <span class="tv">{history[hover] === null ? "lost" : `${fmtMs(history[hover])} ms`}</span>
      <span class="tl">sample {hover + 1} of {n}</span>
    </div>
  {/if}
</div>

<style>
  .wrap {
    position: relative;
    width: 100%;
  }

  svg {
    display: block;
  }

  .grid {
    stroke: var(--border);
    stroke-width: 1;
  }

  .tick {
    fill: var(--muted);
    font-size: 10px;
    font-variant-numeric: tabular-nums;
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
  }

  .lost {
    stroke: var(--viz-critical);
    stroke-width: 2;
    stroke-linecap: round;
  }

  .cross {
    stroke: var(--muted);
    stroke-width: 1;
    pointer-events: none;
  }

  .tooltip {
    position: absolute;
    top: 0;
    pointer-events: none;
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.2rem 0.45rem;
    font-size: 0.72rem;
    white-space: nowrap;
    box-shadow: 0 2px 8px rgb(0 0 0 / 0.15);
    z-index: 2;
  }

  .tv {
    font-weight: 600;
  }

  .tl {
    color: var(--muted);
    margin-left: 0.3rem;
  }
</style>
