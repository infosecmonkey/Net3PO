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

/// Escape user text so Markdown shows it literally: inline markup is
/// backslash-escaped, and line starts that would form headings, lists or
/// quotes are neutralized.
fn literal(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if matches!(
            c,
            '\\' | '`' | '*' | '_' | '[' | ']' | '<' | '>' | '#' | '|' | '~'
        ) {
            out.push('\\');
        }
        out.push(c);
    }
    let t = out.trim_start();
    let lead = &out[..out.len() - t.len()];
    let starts_list = t.starts_with("- ") || t.starts_with("+ ") || t == "-" || t == "+";
    let starts_num = t
        .find(|c: char| !c.is_ascii_digit())
        .is_some_and(|i| i > 0 && (t[i..].starts_with('.') || t[i..].starts_with(')')));
    if starts_list || starts_num || t.starts_with("===") {
        format!("{lead}\\{t}")
    } else {
        out
    }
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

    // With parts, parts take ## and plain sections drop to ###.
    let parts = report.has_parts();
    for s in &report.sections {
        let level = if s.part || !parts { "##" } else { "###" };
        o.push_str(&format!("{level} {}\n\n", s.title.trim()));
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
        Block::Notes { items } => {
            for n in items {
                o.push_str(&format!("**{}**\n\n", literal(&n.heading)));
                for line in n.text.trim_end().lines() {
                    // Trailing double space keeps the user's line breaks.
                    o.push_str(&format!("> {}  \n", literal(line)));
                }
                o.push('\n');
            }
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
    fn notes_render_literally() {
        let md = render(&sample());
        assert!(md.contains("> \\# not a heading  \n"));
        assert!(md.contains("> \\- not a list  \n"));
        assert!(md.contains("> \\<b\\>raw\\</b\\> & \\*\\*stars\\*\\*  \n"));
        assert_eq!(literal("1. one"), "\\1. one");
        assert_eq!(literal("é. ok"), "é. ok");
        assert_eq!(literal("plain"), "plain");
    }

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
