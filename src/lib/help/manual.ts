// The user manual (docs/manual), bundled into the app so help works offline.
// Pages are loaded on demand and rendered with marked. The Markdown is our
// own, but raw HTML in it is still escaped rather than injected.

import { Marked, Renderer, type Tokens } from "marked";

const files = import.meta.glob("../../../docs/manual/**/*.md", {
  query: "?raw",
  import: "default",
}) as Record<string, () => Promise<string>>;

const PREFIX = "../../../docs/manual/";

/** Page paths relative to docs/manual, e.g. "README.md", "tools/dig.md". */
export const PAGES: string[] = Object.keys(files)
  .map((k) => k.slice(PREFIX.length))
  .filter((p) => p !== "TEMPLATE.md")
  .sort();

export const HOME = "README.md";

export function toolPage(toolId: string): string | null {
  const p = `tools/${toolId}.md`;
  return PAGES.includes(p) ? p : null;
}

export async function loadPage(path: string): Promise<string> {
  const load = files[PREFIX + path];
  if (!load || path === "TEMPLATE.md") throw new Error(`no manual page ${path}`);
  return load();
}

/** Resolve a relative link against the page it appears on. */
export function resolve(from: string, href: string): string {
  const parts = from.split("/").slice(0, -1);
  for (const seg of href.split("/")) {
    if (seg === "..") parts.pop();
    else if (seg !== "." && seg !== "") parts.push(seg);
  }
  return parts.join("/");
}

export const slug = (s: string) =>
  s
    .toLowerCase()
    .replace(/<[^>]+>/g, "")
    .replace(/&[a-z#0-9]+;/g, "")
    .replace(/[^a-z0-9\s-]/g, "")
    .trim()
    .replace(/\s+/g, "-");

const esc = (s: string) =>
  s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

export interface Rendered {
  title: string;
  html: string;
}

/** Render a page. Links become data attributes the panel handles: manual
 * pages and anchors stay in the panel, web links open in the browser. */
export function render(md: string, path: string): Rendered {
  let title = "";
  const renderer = new Renderer();
  renderer.html = ({ text }: Tokens.HTML | Tokens.Tag) => esc(text);
  renderer.heading = function ({ tokens, depth }: Tokens.Heading) {
    const inner = this.parser.parseInline(tokens);
    if (depth === 1 && !title) title = inner.replace(/<[^>]+>/g, "");
    return `<h${depth} id="${slug(inner)}">${inner}</h${depth}>\n`;
  };
  renderer.link = function ({ href, title: t, tokens }: Tokens.Link) {
    const inner = this.parser.parseInline(tokens);
    const tip = t ? ` title="${esc(t)}"` : "";
    if (/^https?:\/\//i.test(href)) {
      return `<a href="#" data-external="${esc(href)}"${tip}>${inner}</a>`;
    }
    if (href.startsWith("#")) {
      return `<a href="#" data-anchor="${esc(href.slice(1))}"${tip}>${inner}</a>`;
    }
    const [file, anchor = ""] = href.split("#");
    if (file.endsWith(".md")) {
      const target = resolve(path, file);
      return `<a href="#" data-page="${esc(target)}" data-anchor="${esc(anchor)}"${tip}>${inner}</a>`;
    }
    return `<span>${inner}</span>`;
  };
  // Images are not used in the manual; show alt text rather than load files.
  renderer.image = ({ text }: Tokens.Image) => esc(text);
  const html = new Marked({ renderer, gfm: true }).parse(md, { async: false }) as string;
  return { title: title || path, html };
}
