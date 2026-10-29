//! Plain text report for terminals, tickets and email. Tables are aligned with
//! wrapped cells; widths are counted in characters.

use super::core::{Block, Report, footer};

/// Total line width the text layout aims for.
const WIDTH: usize = 100;

/// Widest a table column may grow before its cells wrap.
const MAX_COL: usize = 48;

fn char_len(s: &str) -> usize {
    s.chars().count()
}

/// Greedy word wrap to `width` characters. Words longer than the width are
/// split. Existing newlines are kept.
pub fn wrap(text: &str, width: usize) -> Vec<String> {
    let width = width.max(1);
    let mut out = Vec::new();
    for para in text.split('\n') {
        let mut line = String::new();
        let mut len = 0;
        for word in para.split(' ') {
            let mut word: Vec<char> = word.chars().collect();
            loop {
                let wlen = word.len();
                let need = if len == 0 { wlen } else { len + 1 + wlen };
                if need <= width {
                    if len > 0 {
                        line.push(' ');
                    }
                    line.extend(word.iter());
                    len = need;
                    break;
                }
                if len > 0 {
                    out.push(std::mem::take(&mut line));
                    len = 0;
                    continue;
                }
                // A single word wider than the line: hard split it.
                let rest = word.split_off(width);
                out.push(word.iter().collect());
                word = rest;
            }
        }
        out.push(line);
    }
    out
}

fn pad(s: &str, n: usize) -> String {
    let len = char_len(s);
    if len >= n {
        s.to_string()
    } else {
        format!("{s}{}", " ".repeat(n - len))
    }
}

fn heading(o: &mut String, text: &str, underline: char) {
    o.push_str(text);
    o.push('\n');
    o.push_str(&underline.to_string().repeat(char_len(text).clamp(3, WIDTH)));
    o.push('\n');
}

/// Render a report as plain text.
pub fn render(report: &Report) -> String {
    let mut o = String::new();
    heading(&mut o, &report.title, '=');
    if !report.subtitle.is_empty() {
        o.push_str(&report.subtitle);
        o.push('\n');
    }
    let mut meta = Vec::new();
    if !report.tool.is_empty() {
        meta.push(report.tool.clone());
    }
    if !report.generated.is_empty() {
        meta.push(report.generated.clone());
    }
    if !meta.is_empty() {
        o.push_str(&meta.join(" | "));
        o.push('\n');
    }

    for s in &report.sections {
        o.push('\n');
        if s.part {
            o.push('\n');
            heading(&mut o, &s.title, '#');
        } else {
            heading(&mut o, &s.title, '-');
        }
        if !s.subtitle.is_empty() {
            o.push_str(&s.subtitle);
            o.push('\n');
        }
        for b in &s.blocks {
            o.push('\n');
            render_block(&mut o, b);
        }
    }
    o.push('\n');
    o.push_str(&footer(report));
    o.push('\n');
    o
}

fn render_block(o: &mut String, b: &Block) {
    match b {
        Block::Paragraph { text } => {
            for line in wrap(text, WIDTH) {
                o.push_str(&line);
                o.push('\n');
            }
        }
        Block::KeyValues { items } => {
            let kw = items
                .iter()
                .map(|kv| char_len(&kv.key))
                .max()
                .unwrap_or(0)
                .min(MAX_COL);
            for kv in items {
                let lines = wrap(&kv.value, WIDTH.saturating_sub(kw + 2).max(20));
                for (i, line) in lines.iter().enumerate() {
                    let key = if i == 0 { kv.key.as_str() } else { "" };
                    o.push_str(&format!("{}  {line}\n", pad(key, kw)));
                }
            }
        }
        Block::Table { headers, rows } => table(o, headers, rows),
        Block::Findings { items } => {
            for f in items {
                let mut head = format!("[{}] ", f.severity.label());
                if !f.category.is_empty() {
                    head.push_str(&format!("{}: ", f.category));
                }
                head.push_str(&f.title);
                for (i, line) in wrap(&head, WIDTH).iter().enumerate() {
                    o.push_str(if i == 0 { "" } else { "       " });
                    o.push_str(line);
                    o.push('\n');
                }
                if !f.detail.is_empty() {
                    for line in wrap(&f.detail, WIDTH - 7) {
                        o.push_str(&format!("       {line}\n"));
                    }
                }
            }
        }
        Block::Code { text } => {
            for line in text.lines() {
                o.push_str(&format!("    {line}\n"));
            }
        }
        Block::Diff { lines } => {
            for l in lines {
                o.push_str(&format!("{}{}\n", l.marker(), l.text));
            }
        }
    }
}

/// Aligned table with wrapped cells and a header rule.
fn table(o: &mut String, headers: &[String], rows: &[Vec<String>]) {
    let cols = headers
        .len()
        .max(rows.iter().map(Vec::len).max().unwrap_or(0));
    if cols == 0 {
        return;
    }
    let get = |row: &[String], i: usize| row.get(i).cloned().unwrap_or_default();
    let mut widths: Vec<usize> = (0..cols)
        .map(|i| {
            let h = headers.get(i).map(|h| char_len(h)).unwrap_or(0);
            let body = rows.iter().map(|r| char_len(&get(r, i))).max().unwrap_or(0);
            h.max(body).clamp(1, MAX_COL)
        })
        .collect();
    // Shrink the widest columns until the table fits the line width.
    let sep = 2 * (cols - 1);
    while widths.iter().sum::<usize>() + sep > WIDTH {
        let (i, w) = widths
            .iter()
            .enumerate()
            .max_by_key(|(_, w)| **w)
            .map(|(i, w)| (i, *w))
            .unwrap_or((0, 0));
        if w <= 8 {
            break;
        }
        widths[i] = w - 1;
    }

    let emit = |o: &mut String, cells: &[String]| {
        let wrapped: Vec<Vec<String>> =
            (0..cols).map(|i| wrap(&get(cells, i), widths[i])).collect();
        let height = wrapped.iter().map(Vec::len).max().unwrap_or(1);
        for line in 0..height {
            let parts: Vec<String> = (0..cols)
                .map(|i| {
                    pad(
                        wrapped[i].get(line).map(String::as_str).unwrap_or(""),
                        widths[i],
                    )
                })
                .collect();
            o.push_str(parts.join("  ").trim_end());
            o.push('\n');
        }
    };

    if !headers.is_empty() {
        emit(o, headers);
        let rule: Vec<String> = widths.iter().map(|w| "-".repeat(*w)).collect();
        o.push_str(&rule.join("  "));
        o.push('\n');
    }
    for row in rows {
        emit(o, row);
    }
}

#[cfg(test)]
mod tests {
    use super::super::core::sample;
    use super::*;

    #[test]
    fn wrap_basic() {
        assert_eq!(wrap("aa bb cc", 5), ["aa bb", "cc"]);
        assert_eq!(wrap("abcdefgh", 3), ["abc", "def", "gh"]);
        assert_eq!(wrap("a\nb", 10), ["a", "b"]);
        assert_eq!(wrap("", 10), [""]);
    }

    #[test]
    fn renders_sample() {
        let t = render(&sample());
        assert!(t.starts_with("DNS audit: example.com\n======================\n"));
        assert!(t.contains("Records\n-------\n"));
        assert!(t.contains("[FAIL] SPF: No SPF record\n       Add v=spf1 ... -all\n"));
        assert!(t.contains("-set action accept\n+set action deny\n next\n"));
        assert!(t.ends_with("Generated by OmniPacket | DNS Analyzer | Oct 29, 2026 9:00 AM\n"));
    }

    #[test]
    fn table_aligns_columns() {
        let mut o = String::new();
        table(
            &mut o,
            &["Port".to_string(), "Service".to_string()],
            &[
                vec!["22".to_string(), "ssh".to_string()],
                vec!["443".to_string(), "https".to_string()],
            ],
        );
        assert_eq!(o, "Port  Service\n----  -------\n22    ssh\n443   https\n");
    }

    #[test]
    fn table_wraps_wide_cells_within_width() {
        let mut o = String::new();
        let long = "word ".repeat(60);
        table(
            &mut o,
            &["A".to_string(), "B".to_string(), "C".to_string()],
            &[vec![long.clone(), long.clone(), long]],
        );
        assert!(o.lines().all(|l| char_len(l) <= WIDTH), "{o}");
        assert!(o.lines().count() > 3);
    }
}
