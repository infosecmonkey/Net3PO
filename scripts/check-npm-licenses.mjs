// Fails when an npm dependency uses a license outside the allowlist in
// CLAUDE.md. The Rust side is checked by cargo-deny (src-tauri/deny.toml).
// Usage: pnpm licenses:check

import { execFileSync } from "node:child_process";

const ALLOW = new Set([
  "MIT",
  "MIT-0",
  "Apache-2.0",
  "BSD-2-Clause",
  "BSD-3-Clause",
  "0BSD",
  "ISC",
  "Zlib",
  "MPL-2.0",
]);

/** True when an SPDX expression is satisfied by the allowlist. Handles
 * OR (any side), AND (every side) and parentheses. */
export function allowed(expr) {
  const tokens = expr.replace(/[()]/g, (p) => ` ${p} `).trim().split(/\s+/);
  let i = 0;
  function or() {
    let ok = and();
    while (tokens[i] === "OR") {
      i++;
      ok = and() || ok;
    }
    return ok;
  }
  function and() {
    let ok = atom();
    while (tokens[i] === "AND") {
      i++;
      ok = atom() && ok;
    }
    return ok;
  }
  function atom() {
    const t = tokens[i++];
    if (t === "(") {
      const ok = or();
      i++; // ")"
      return ok;
    }
    return ALLOW.has(t);
  }
  return or();
}

const out = execFileSync("pnpm", ["licenses", "list", "--json"], {
  encoding: "utf8",
  shell: process.platform === "win32",
});
const byLicense = JSON.parse(out);

const bad = [];
for (const [license, pkgs] of Object.entries(byLicense)) {
  if (allowed(license)) continue;
  for (const p of pkgs) bad.push(`${p.name}@${p.versions?.join(",") ?? "?"}: ${license}`);
}

if (bad.length > 0) {
  console.error("Disallowed npm licenses:");
  for (const b of bad) console.error(`  ${b}`);
  process.exit(1);
}
const count = Object.values(byLicense).reduce((n, p) => n + p.length, 0);
console.log(`npm licenses ok (${count} packages)`);
