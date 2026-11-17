// Report redaction settings and helpers. The Rust side does the redaction
// (`report::redact`); this file holds the saved settings and the rule syntax.

import { invoke } from "@tauri-apps/api/core";
import { loadCollection, saveCollection } from "$lib/store";
import type { Report } from "./types";

export interface RedactRule {
  find: string;
  replace: string;
  regex: boolean;
}

export interface RedactOptions {
  ips: boolean;
  hostnames: boolean;
  emails: boolean;
  usernames: boolean;
  secrets: boolean;
  /** Text tools only; report export leaves these off. */
  macs?: boolean;
  serials?: boolean;
  certificates?: boolean;
  fakeAddresses?: boolean;
  rules: RedactRule[];
  exclusions: string[];
}

export type RedactKind = "custom" | "secret" | "ip" | "host" | "user" | "mac" | "serial";

export interface MappingEntry {
  kind: RedactKind;
  original: string;
  token: string;
  count: number;
}

export interface RedactPreview {
  title: string;
  mapping: MappingEntry[];
  mappingTruncated: boolean;
  replacements: number;
  emails: number;
  privateKeys: number;
}

/** Saved form: checkboxes plus the rule and exclusion text as typed. */
export interface RedactSettings {
  ips: boolean;
  hostnames: boolean;
  emails: boolean;
  usernames: boolean;
  secrets: boolean;
  rulesText: string;
  exclusionsText: string;
}

export const DEFAULT_SETTINGS: RedactSettings = {
  ips: true,
  hostnames: true,
  emails: true,
  usernames: true,
  secrets: true,
  rulesText: "",
  exclusionsText: "",
};

/**
 * One rule per line: `find` or `find => replacement`. A `re:` prefix makes
 * `find` a regular expression. Blank lines and `#` comments are skipped.
 */
export function parseRules(text: string): RedactRule[] {
  const rules: RedactRule[] = [];
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const regex = line.startsWith("re:");
    const body = regex ? line.slice(3).trim() : line;
    const at = body.lastIndexOf("=>");
    const find = (at >= 0 ? body.slice(0, at) : body).trim();
    const replace = at >= 0 ? body.slice(at + 2).trim() : "";
    if (find) rules.push({ find, replace, regex });
  }
  return rules;
}

export function parseExclusions(text: string): string[] {
  return text
    .split(/[\r\n]+/)
    .map((s) => s.trim())
    .filter((s) => s && !s.startsWith("#"));
}

export function toOptions(s: RedactSettings): RedactOptions {
  return {
    ips: s.ips,
    hostnames: s.hostnames,
    emails: s.emails,
    usernames: s.usernames,
    secrets: s.secrets,
    rules: parseRules(s.rulesText),
    exclusions: parseExclusions(s.exclusionsText),
  };
}

export async function loadRedactSettings(): Promise<RedactSettings> {
  try {
    const { items } = await loadCollection<RedactSettings>("report_redaction");
    return { ...DEFAULT_SETTINGS, ...(items[0] ?? {}) };
  } catch {
    return { ...DEFAULT_SETTINGS };
  }
}

export async function saveRedactSettings(s: RedactSettings): Promise<void> {
  await saveCollection("report_redaction", [s]);
}

export const previewReport = (report: Report, opts: RedactOptions) =>
  invoke<RedactPreview>("report_redact_preview", { report, opts });

export const KIND_LABEL: Record<RedactKind, string> = {
  custom: "Rule",
  secret: "Secret",
  ip: "IP",
  host: "Host",
  user: "User",
  mac: "MAC",
  serial: "Serial",
};
