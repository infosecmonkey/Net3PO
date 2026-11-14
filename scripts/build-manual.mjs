// Build the user manual (docs/manual/**/*.md) into static HTML pages for the
// project website. Output goes to <out>/manual/ and uses the site's own
// stylesheet (../assets/style.css) plus assets/manual.css, written next to it.
// No scripts and no inline styles, so the site's strict CSP keeps working.
//
// Usage: node scripts/build-manual.mjs <site-dir>

import { readFileSync, writeFileSync, mkdirSync, readdirSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { Marked, Renderer } from "marked";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const src = join(root, "docs", "manual");
const site = process.argv[2];
if (!site) {
  console.error("usage: node scripts/build-manual.mjs <site-dir>");
  process.exit(1);
}
const out = join(site, "manual");
const version = JSON.parse(readFileSync(join(root, "package.json"), "utf8")).version;

const esc = (s) =>
  s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
const slug = (s) =>
  s
    .toLowerCase()
    .replace(/<[^>]+>/g, "")
    .replace(/&[a-z]+;/g, "")
    .replace(/[^a-z0-9\s-]/g, "")
    .trim()
    .replace(/\s+/g, "-");

// Shared pages, in sidebar order: [file stem, title].
const GUIDES = [
  ["README", "Overview"],
  ["installing", "Installing"],
  ["getting-started", "Getting started"],
  ["projects-and-notes", "Projects and notes"],
  ["export-and-redaction", "Export and redaction"],
  ["privacy", "Privacy and data"],
  ["troubleshooting", "Troubleshooting and FAQ"],
];

// Tool groups come from the README: "**Group:** [Name](tools/id.md) · ...".
const readme = readFileSync(join(src, "README.md"), "utf8");
const GROUPS = [];
for (const line of readme.split("\n")) {
  const m = line.match(/^\*\*(.+?):\*\*\s+(.*)$/);
  if (!m) continue;
  const tools = [...m[2].matchAll(/\[([^\]]+)\]\(tools\/([a-z0-9-]+)\.md\)/g)].map((t) => ({
    name: t[1],
    id: t[2],
  }));
  if (tools.length) GROUPS.push({ name: m[1], tools });
}

/** Output path (relative to manual/) for a source path relative to docs/manual. */
const outPath = (rel) => (rel === "README.md" ? "index.html" : rel.replace(/\.md$/, ".html"));

function render(md, depth) {
  const marked = new Marked({ gfm: true });
  marked.use({
    renderer: {
      heading({ tokens, depth: level }) {
        const text = this.parser.parseInline(tokens);
        const id = slug(text);
        return level === 1
          ? `<h1>${text}</h1>\n`
          : `<h${level} id="${id}"><a class="anchor" href="#${id}">${text}</a></h${level}>\n`;
      },
      link({ href, title, tokens }) {
        const text = this.parser.parseInline(tokens);
        let url = href;
        const external = /^[a-z]+:/i.test(url);
        if (!external) {
          url = url.replace(/(^|\/)README\.md(#|$)/, "$1index.html$2").replace(/\.md(#|$)/, ".html$1");
        }
        const t = title ? ` title="${esc(title)}"` : "";
        const rel = external ? ' rel="noopener"' : "";
        return `<a href="${esc(url)}"${t}${rel}>${text}</a>`;
      },
      table(token) {
        // Wrap tables so wide ones scroll instead of widening the page.
        return `<div class="table-wrap">${Renderer.prototype.table.call(this, token)}</div>`;
      },
    },
  });
  return marked.parse(md);
}

function sidebar(current, prefix) {
  const item = (href, label, rel) =>
    `<li><a href="${prefix}${href}"${rel === current ? ' aria-current="page"' : ""}>${esc(label)}</a></li>`;
  let html = `<nav class="m-side" id="contents" aria-label="Manual"><div class="m-group">Guide</div><ul>`;
  for (const [stem, title] of GUIDES) html += item(outPath(`${stem}.md`), title, `${stem}.md`);
  html += "</ul>";
  for (const g of GROUPS) {
    html += `<div class="m-group">${esc(g.name)}</div><ul>`;
    for (const t of g.tools) html += item(`tools/${t.id}.html`, t.name, `tools/${t.id}.md`);
    html += "</ul>";
  }
  return html + "</nav>";
}

function page(rel, md) {
  const depth = rel.split("/").length - 1;
  const prefix = "../".repeat(depth); // to manual/
  const assets = `${prefix}../assets/`;
  const home = `${prefix}../index.html`;
  const title = (md.match(/^#\s+(.+)$/m)?.[1] ?? "Manual").replace(/[*`]/g, "");
  const descr = (md.match(/^>\s+(.+)$/m)?.[1] ?? "Net3PO user manual.").replace(/[*`[\]]/g, "");
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${esc(title)} | Net3PO Manual</title>
  <meta name="description" content="${esc(descr)}">
  <meta name="theme-color" content="#111318">
  <link rel="icon" type="image/png" href="${assets}logo.png">
  <link rel="stylesheet" href="${assets}style.css">
  <link rel="stylesheet" href="${assets}manual.css">
</head>
<body class="manual">
<header class="nav">
  <div class="wrap nav-inner">
    <a class="brand" href="${home}" aria-label="Net3PO home">
      <img src="${assets}logo.png" alt="" width="34" height="34">
      <span class="wordmark">Net<span>3PO</span></span>
    </a>
    <nav class="m-top">
      <a href="${prefix}index.html">Manual</a>
      <a href="${home}#download">Download</a>
      <a class="btn btn-ghost btn-sm" href="https://github.com/infosecmonkey/Net3PO" rel="noopener">GitHub</a>
    </nav>
  </div>
</header>
<div class="wrap m-layout">
  ${sidebar(rel, prefix)}
  <main class="m-doc">
<a class="m-jump" href="#contents">Contents</a>
${render(md, depth)}
  </main>
</div>
<footer class="footer">
  <div class="wrap copyright">Net3PO manual for version ${esc(version)} &middot; <a href="${home}">net3po.com</a> &middot; Apache-2.0</div>
</footer>
</body>
</html>
`;
}

const files = [];
(function walk(dir) {
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, e.name);
    if (e.isDirectory()) walk(p);
    else if (e.name.endsWith(".md") && e.name !== "TEMPLATE.md") files.push(relative(src, p));
  }
})(src);

for (const rel of files) {
  const dest = join(out, outPath(rel));
  mkdirSync(dirname(dest), { recursive: true });
  writeFileSync(dest, page(rel.split("\\").join("/"), readFileSync(join(src, rel), "utf8")));
}
mkdirSync(join(site, "assets"), { recursive: true });
writeFileSync(join(site, "assets", "manual.css"), readFileSync(join(src, "manual.css"), "utf8"));
console.log(`wrote ${files.length} pages to ${out}`);
