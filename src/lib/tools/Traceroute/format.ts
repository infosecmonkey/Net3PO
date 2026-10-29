// Shared number formatting and scales for the traceroute panel and charts.

/** Milliseconds: one decimal under 10 ms, whole numbers above. */
export function fmtMs(v: number | null | undefined): string {
  if (v === null || v === undefined) return "";
  return v < 10 ? v.toFixed(1) : Math.round(v).toString();
}

/** A clean axis maximum and ticks covering `max` (ms). */
export function niceScale(max: number, count = 4): { top: number; ticks: number[] } {
  const raw = Math.max(max, 1) / count;
  const mag = 10 ** Math.floor(Math.log10(raw));
  const step = [1, 2, 2.5, 5, 10].map((m) => m * mag).find((s) => s >= raw) ?? raw;
  const top = step * Math.ceil(Math.max(max, 1) / step);
  const ticks: number[] = [];
  for (let t = 0; t <= top + step / 2; t += step) ticks.push(Math.round(t * 100) / 100);
  return { top, ticks };
}

/** Primary display name for a hop. */
export function hopLabel(h: { hostname: string | null; ip: string | null }): string {
  return h.hostname ?? h.ip ?? "*";
}
