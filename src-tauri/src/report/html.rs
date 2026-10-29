//! Self-contained HTML report: one file, inline CSS, no scripts or external
//! resources, print friendly. Every piece of report text is escaped.

use super::core::{Block, DiffKind, Report, Severity, footer};

const CSS: &str = r#"
:root { color-scheme: light; }
body { font: 14px/1.5 -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; color: #1a1a1a; margin: 0; background: #fff; }
main { max-width: 960px; margin: 0 auto; padding: 32px 24px 48px; }
h1 { font-size: 24px; margin: 0 0 4px; }
.subtitle { color: #6b7280; margin: 0 0 4px; }
.meta { color: #6b7280; font-size: 12px; margin: 0 0 24px; }
h2 { font-size: 18px; margin: 32px 0 4px; padding-bottom: 4px; border-bottom: 2px solid #c2410c; }
.section-sub { color: #6b7280; margin: 0 0 12px; font-size: 13px; }
h2.part { font-size: 22px; margin: 48px 0 4px; border-bottom: 4px solid #c2410c; }
h3 { font-size: 16px; margin: 28px 0 4px; padding-bottom: 3px; border-bottom: 1px solid #e2e5e9; }
p { margin: 8px 0; }
table { border-collapse: collapse; width: 100%; margin: 12px 0; font-size: 13px; }
th, td { text-align: left; padding: 6px 10px; border: 1px solid #e2e5e9; vertical-align: top; }
th { background: #f6f7f9; font-weight: 600; }
table.kv th { width: 30%; }
td { overflow-wrap: anywhere; }
.finding { border: 1px solid #e2e5e9; border-left-width: 4px; border-radius: 4px; padding: 8px 12px; margin: 8px 0; }
.finding .badge { display: inline-block; font-size: 11px; font-weight: 700; padding: 1px 6px; border-radius: 3px; margin-right: 8px; color: #fff; }
.finding .cat { color: #6b7280; font-size: 12px; margin-right: 6px; }
.finding .detail { color: #374151; margin-top: 4px; white-space: pre-wrap; }
.pass { border-left-color: #15803d; } .pass .badge { background: #15803d; }
.info { border-left-color: #2563eb; } .info .badge { background: #2563eb; }
.warn { border-left-color: #b45309; } .warn .badge { background: #b45309; }
.fail { border-left-color: #b91c1c; } .fail .badge { background: #b91c1c; }
pre { font: 12px/1.45 "SF Mono", Menlo, Consolas, monospace; background: #f6f7f9; border: 1px solid #e2e5e9; border-radius: 4px; padding: 10px 12px; overflow-x: auto; white-space: pre-wrap; overflow-wrap: anywhere; }
pre.diff { padding: 6px 0; }
pre.diff span { display: block; padding: 0 12px; }
pre.diff .add { background: #e9f7ee; }
pre.diff .del { background: #fdecec; }
pre.diff .hunk { background: #eef0f3; color: #6b7280; }
footer { margin-top: 40px; color: #6b7280; font-size: 12px; border-top: 1px solid #e2e5e9; padding-top: 8px; }
@media print { main { padding: 0; } h2, h3 { break-after: avoid; } h2.part { break-before: page; } .finding, tr { break-inside: avoid; } }
"#;

/// Escape text for HTML element content and attribute values.
pub fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

fn severity_class(s: Severity) -> &'static str {
    match s {
        Severity::Pass => "pass",
        Severity::Info => "info",
        Severity::Warn => "warn",
        Severity::Fail => "fail",
    }
}

/// Render a report as a standalone HTML document.
pub fn render(report: &Report) -> String {
    let mut o = String::new();
    o.push_str("<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n");
    o.push_str("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n");
    o.push_str(&format!("<title>{}</title>\n", esc(&report.title)));
    o.push_str(&format!("<style>{CSS}</style>\n</head>\n<body>\n<main>\n"));
    o.push_str(&format!("<h1>{}</h1>\n", esc(&report.title)));
    if !report.subtitle.is_empty() {
        o.push_str(&format!(
            "<p class=\"subtitle\">{}</p>\n",
            esc(&report.subtitle)
        ));
    }
    let mut meta = Vec::new();
    if !report.tool.is_empty() {
        meta.push(esc(&report.tool));
    }
    if !report.generated.is_empty() {
        meta.push(esc(&report.generated));
    }
    if !meta.is_empty() {
        o.push_str(&format!("<p class=\"meta\">{}</p>\n", meta.join(" | ")));
    }

    // With parts, parts take h2 and plain sections drop to h3.
    let parts = report.has_parts();
    for s in &report.sections {
        let tag = if s.part || !parts { "h2" } else { "h3" };
        let class = if s.part { " class=\"part\"" } else { "" };
        o.push_str(&format!(
            "<section>\n<{tag}{class}>{}</{tag}>\n",
            esc(&s.title)
        ));
        if !s.subtitle.is_empty() {
            o.push_str(&format!(
                "<p class=\"section-sub\">{}</p>\n",
                esc(&s.subtitle)
            ));
        }
        for b in &s.blocks {
            render_block(&mut o, b);
        }
        o.push_str("</section>\n");
    }

    o.push_str(&format!("<footer>{}</footer>\n", esc(&footer(report))));
    o.push_str("</main>\n</body>\n</html>\n");
    o
}

fn render_block(o: &mut String, b: &Block) {
    match b {
        Block::Paragraph { text } => o.push_str(&format!("<p>{}</p>\n", esc(text))),
        Block::KeyValues { items } => {
            o.push_str("<table class=\"kv\">\n");
            for kv in items {
                o.push_str(&format!(
                    "<tr><th>{}</th><td>{}</td></tr>\n",
                    esc(&kv.key),
                    esc(&kv.value)
                ));
            }
            o.push_str("</table>\n");
        }
        Block::Table { headers, rows } => {
            o.push_str("<table>\n");
            if !headers.is_empty() {
                o.push_str("<thead><tr>");
                for h in headers {
                    o.push_str(&format!("<th>{}</th>", esc(h)));
                }
                o.push_str("</tr></thead>\n");
            }
            o.push_str("<tbody>\n");
            for row in rows {
                o.push_str("<tr>");
                for cell in row {
                    o.push_str(&format!("<td>{}</td>", esc(cell)));
                }
                o.push_str("</tr>\n");
            }
            o.push_str("</tbody>\n</table>\n");
        }
        Block::Findings { items } => {
            for f in items {
                o.push_str(&format!(
                    "<div class=\"finding {}\"><span class=\"badge\">{}</span>",
                    severity_class(f.severity),
                    f.severity.label()
                ));
                if !f.category.is_empty() {
                    o.push_str(&format!("<span class=\"cat\">{}</span>", esc(&f.category)));
                }
                o.push_str(&format!("<strong>{}</strong>", esc(&f.title)));
                if !f.detail.is_empty() {
                    o.push_str(&format!("<div class=\"detail\">{}</div>", esc(&f.detail)));
                }
                o.push_str("</div>\n");
            }
        }
        Block::Code { text } => o.push_str(&format!("<pre>{}</pre>\n", esc(text))),
        Block::Diff { lines } => {
            o.push_str("<pre class=\"diff\">");
            for l in lines {
                let class = match l.kind {
                    DiffKind::Context => "",
                    DiffKind::Add => "add",
                    DiffKind::Del => "del",
                    DiffKind::Hunk => "hunk",
                };
                o.push_str(&format!(
                    "<span class=\"{class}\">{}{}</span>",
                    l.marker(),
                    esc(&l.text)
                ));
            }
            o.push_str("</pre>\n");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::core::sample;
    use super::*;

    #[test]
    fn escapes_report_text() {
        let html = render(&sample());
        assert!(html.contains("Checks &lt;SPF&gt; &amp; DMARC."));
        assert!(!html.contains("<SPF>"));
    }

    #[test]
    fn has_structure_and_no_scripts() {
        let html = render(&sample());
        assert!(html.starts_with("<!doctype html>"));
        assert!(html.contains("<h2>Records</h2>"));
        assert!(html.contains("<span class=\"badge\">FAIL</span>"));
        assert!(html.contains("<span class=\"del\">-set action accept</span>"));
        assert!(!html.contains("<script"));
        assert!(!html.contains("http://") && !html.contains("https://"));
    }

    #[test]
    fn esc_quotes() {
        assert_eq!(esc(r#"a"b'c"#), "a&quot;b&#39;c");
    }
}
