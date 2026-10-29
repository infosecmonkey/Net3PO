// Generates static/third-party-notices.txt: the license texts of every Rust
// crate and npm package that ships in the app, as MIT, BSD, Apache and
// friends require. Shown in the app's About dialog.
// Usage: pnpm notices   (needs cargo-about: cargo install cargo-about --features cli)

import { execFileSync } from "node:child_process";
import { existsSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const OUT = "static/third-party-notices.txt";
const RULE = "=".repeat(78);
const win = process.platform === "win32";

function run(cmd, args, cwd) {
  return execFileSync(cmd, args, {
    cwd,
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
    env: { ...process.env, OUI_OFFLINE: "1" },
    stdio: ["ignore", "pipe", "inherit"],
    shell: win,
  });
}

/** Unique license texts mapped to the packages that use them. */
const groups = new Map();
function add(id, text, pkg) {
  const body = text.replace(/\r\n/g, "\n").trim();
  const key = `${id}\n${body}`;
  if (!groups.has(key)) groups.set(key, { id, body, pkgs: new Set() });
  groups.get(key).pkgs.add(pkg);
}

// Rust: cargo-about resolves each crate's license files for all targets.
const about = JSON.parse(run("cargo", ["about", "generate", "--format", "json"], "src-tauri"));
for (const lic of about.licenses) {
  for (const u of lic.used_by) {
    if (u.crate.name === "omnipacket") continue;
    add(lic.id, lic.text, `${u.crate.name} ${u.crate.version}`);
  }
}

// npm: production packages only; dev tooling is not shipped.
const LICENSE_FILE = /^(licen[cs]e|copying)(\..*)?$/i;
const npm = JSON.parse(run("pnpm", ["licenses", "list", "--prod", "--json", "--long"], "."));
for (const [id, pkgs] of Object.entries(npm)) {
  for (const p of pkgs) {
    for (const [i, version] of p.versions.entries()) {
      const dir = p.paths[i] ?? p.paths[0];
      const file = existsSync(dir) && readdirSync(dir).find((f) => LICENSE_FILE.test(f));
      if (!file) throw new Error(`no license file for ${p.name}@${version} in ${dir}`);
      add(id, readFileSync(join(dir, file), "utf8"), `${p.name} ${version} (npm)`);
    }
  }
}

// Bundled assets outside any package manager.
add("ISC", readFileSync("src/lib/components/icons/LICENSE-lucide.txt", "utf8"), "Lucide icons");

const sorted = [...groups.values()].sort(
  (a, b) => a.id.localeCompare(b.id) || b.pkgs.size - a.pkgs.size,
);
let out =
  "OmniPacket third-party notices\n\n" +
  "OmniPacket is licensed under the Apache License 2.0. It includes the\n" +
  "following third-party software, each under the license shown.\n";
for (const g of sorted) {
  out += `\n${RULE}\n${g.id}\nUsed by: ${[...g.pkgs].sort().join(", ")}\n${RULE}\n\n${g.body}\n`;
}
writeFileSync(OUT, out);
const count = sorted.reduce((n, g) => n + g.pkgs.size, 0);
console.log(`wrote ${OUT}: ${count} packages, ${sorted.length} license texts`);
