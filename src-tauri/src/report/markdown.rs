//! GitHub-flavored Markdown report. Table cells escape pipes and fold
//! newlines; code fences are chosen longer than any backtick run inside.

use super::core::{Block, Report, footer};

/// Make text safe inside a table cell.
fn cell(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('|', "\\|")
        .replace("\r\n", "<br>")
        .replace('\n', "<br>")
}

/// A backtick fence longer than any run of backticks in `text`.
fn fence(text: &str) -> String {
    let mut longest = 0;
    let mut run = 0;
    for c in text.chars() {
        if c == '`' {
            run += 1;
            longest = longest.max(run);
        } else {
            run = 0;
        }
    }
    "`".repeat((longest + 1).max(3))
}

/// Render a report as Markdown.
pub fn render(report: &Report) -> String {
    let mut o = format!("# {}\n\n", report.title.trim());
    if !report.subtitle.is_empty() {
        o.push_str(&format!("{}\n\n", report.subtitle.trim()));
    }
    let mut meta = Vec::new();
    if !report.tool.is_empty() {
        meta.push(report.tool.clone());
    }
    if !report.generated.is_empty() {
        meta.push(report.generated.clone());
    }
    if !meta.is_empty() {
        o.push_str(&format!("_{}_\n\n", meta.join(" | ")));
    }

    for s in &report.sections {
        o.push_str(&format!("## {}\n\n", s.title.trim()));
        if !s.subtitle.is_empty() {
            o.push_str(&format!("{}\n\n", s.subtitle.trim()));
        }
        for b in &s.blocks {
            render_block(&mut o, b);
        }
    }
    o.push_str(&format!("---\n\n{}\n", footer(report)));
    o
}

fn render_block(o: &mut String, b: &Block) {
    match b {
        Block::Paragraph { text } => o.push_str(&format!("{}\n\n", text.trim())),
        Block::KeyValues { items } => {
            o.push_str("| Field | Value |\n| --- | --- |\n");
            for kv in items {
                o.push_str(&format!("| {} | {} |\n", cell(&kv.key), cell(&kv.value)));
            }
            o.push('\n');
        }
        Block::Table { headers, rows } => {
            let cols = headers
                .len()
                .max(rows.iter().map(Vec::len).max().unwrap_or(0));
            if cols == 0 {
                return;
            }
            let head: Vec<String> = (0..cols)
                .map(|i| headers.get(i).map(|h| cell(h)).unwrap_or_default())
                .collect();
            o.push_str(&format!("| {} |\n", head.join(" | ")));
            o.push_str(&format!("|{}\n", " --- |".repeat(cols)));
            for row in rows {
                let cells: Vec<String> = (0..cols)
                    .map(|i| row.get(i).map(|c| cell(c)).unwrap_or_default())
                    .collect();
                o.push_str(&format!("| {} |\n", cells.join(" | ")));
            }
            o.push('\n');
        }
        Block::Findings { items } => {
            for f in items {
                o.push_str(&format!("- **{}**", f.severity.label()));
                if !f.category.is_empty() {
                    o.push_str(&format!(" {}:", f.category));
                }
                o.push_str(&format!(" {}\n", f.title));
                if !f.detail.is_empty() {
                    for line in f.detail.lines() {
                        o.push_str(&format!("  {line}\n"));
                    }
                }
            }
            o.push('\n');
        }
        Block::Code { text } => {
            let f = fence(text);
            o.push_str(&format!("{f}\n{}\n{f}\n\n", text.trim_end_matches('\n')));
        }
        Block::Diff { lines } => {
            let body: String = lines
                .iter()
                .map(|l| format!("{}{}\n", l.marker(), l.text))
                .collect();
            let f = fence(&body);
            o.push_str(&format!("{f}diff\n{body}{f}\n\n"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::core::sample;
    use super::*;

    #[test]
    fn renders_headings_and_tables() {
        let md = render(&sample());
        assert!(md.starts_with("# DNS audit: example.com\n"));
        assert!(md.contains("## Records\n"));
        assert!(md.contains("| Type | Value \\| data |\n| --- | --- |\n"));
        assert!(md.contains("- **FAIL** SPF: No SPF record\n  Add v=spf1 ... -all\n"));
    }

    #[test]
    fn code_fence_outgrows_inner_backticks() {
        let md = render(&sample());
        assert!(md.contains("````\ndig +short example.com\n```fence```\n````"));
    }

    #[test]
    fn diff_block() {
        let md = render(&sample());
        assert!(md.contains(
            "```diff\n@@ -1,2 +1,2 @@\n-set action accept\n+set action deny\n next\n```"
        ));
    }

    #[test]
    fn cell_escaping() {
        assert_eq!(cell("a|b\nc"), "a\\|b<br>c");
    }
}
