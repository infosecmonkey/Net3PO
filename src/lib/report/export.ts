// Save a report through the native save dialog and the Rust renderers.

import { invoke } from "@tauri-apps/api/core";
import { save } from "@tauri-apps/plugin-dialog";
import type { Report, ReportFormat } from "./types";

export const FORMATS: { id: ReportFormat; label: string; ext: string }[] = [
  { id: "html", label: "HTML", ext: "html" },
  { id: "pdf", label: "PDF", ext: "pdf" },
  { id: "markdown", label: "Markdown", ext: "md" },
  { id: "text", label: "Plain text", ext: "txt" },
];

/** Timestamp in the user's locale, for the report header. */
export function generatedNow(): string {
  return new Date().toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

/** `yyyyMMdd-HHmm`, for default file names. */
function fileStamp(d = new Date()): string {
  const p = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}-${p(d.getHours())}${p(d.getMinutes())}`;
}

/** A file-name-safe version of `s`. */
export function safeName(s: string): string {
  return s.replace(/[^A-Za-z0-9._-]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 80) || "report";
}

/**
 * Ask where to save, then render and write. Returns the saved path, or null
 * when the user cancelled.
 */
export async function exportReport(
  report: Report,
  format: ReportFormat,
  baseName: string,
): Promise<string | null> {
  const f = FORMATS.find((x) => x.id === format)!;
  const path = await save({
    defaultPath: `${safeName(baseName)}-${fileStamp()}.${f.ext}`,
    filters: [{ name: f.label, extensions: [f.ext] }],
  });
  if (!path) return null;
  await invoke<number>("report_export", {
    report: { generated: generatedNow(), ...report },
    format,
    path,
  });
  return path;
}
