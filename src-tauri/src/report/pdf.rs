//! PDF report on US Letter using the standard PDF base fonts (Helvetica,
//! Helvetica-Bold, Courier), so no font data is embedded. Text is encoded as
//! WinAnsi; characters outside it print as `?`.
//!
//! Layout is a simple top-down flow: each block measures and wraps its text
//! with Helvetica metrics, starts a new page when it runs out of room, and
//! tables repeat their header row after a page break.

use pdf_writer::{Content, Name, Pdf, Rect, Ref, Str, TextStr};

use super::core::{Block, DiffKind, Report, Severity, footer};

const PAGE_W: f32 = 612.0;
const PAGE_H: f32 = 792.0;
const MARGIN: f32 = 54.0;
/// Lowest baseline for body content; the footer sits below it.
const BOTTOM: f32 = MARGIN + 6.0;
const CONTENT_W: f32 = PAGE_W - 2.0 * MARGIN;

type Rgb = (f32, f32, f32);
const TEXT: Rgb = (0.10, 0.10, 0.10);
const MUTED: Rgb = (0.42, 0.45, 0.50);
const ACCENT: Rgb = (0.76, 0.25, 0.05);
const RULE: Rgb = (0.89, 0.90, 0.91);
const HEADER_BG: Rgb = (0.965, 0.969, 0.976);
const CODE_BG: Rgb = (0.965, 0.969, 0.976);
const ADD_BG: Rgb = (0.914, 0.969, 0.933);
const DEL_BG: Rgb = (0.992, 0.925, 0.925);
const HUNK_BG: Rgb = (0.933, 0.941, 0.953);
const WHITE: Rgb = (1.0, 1.0, 1.0);

#[derive(Clone, Copy, PartialEq, Eq)]
enum Font {
    Regular,
    Bold,
    Mono,
}

impl Font {
    fn name(self) -> Name<'static> {
        match self {
            Font::Regular => Name(b"F1"),
            Font::Bold => Name(b"F2"),
            Font::Mono => Name(b"F3"),
        }
    }
}

/// Helvetica advance widths (1/1000 em) for ASCII 32..=126, from the
/// standard Adobe font metrics.
const HELVETICA: [u16; 95] = [
    278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278,
    278, // ' ' to '/'
    556, 556, 556, 556, 556, 556, 556, 556, 556, 556, // '0' to '9'
    278, 278, 584, 584, 584, 556, 1015, // ':' to '@'
    667, 667, 722, 722, 667, 611, 778, 722, 278, 500, 667, 556, 833, // 'A' to 'M'
    722, 778, 667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, // 'N' to 'Z'
    278, 278, 278, 469, 556, 333, // '[' to '`'
    556, 556, 500, 556, 556, 278, 556, 556, 222, 222, 500, 222, 833, // 'a' to 'm'
    556, 556, 556, 556, 333, 500, 278, 556, 500, 722, 500, 500, 500, // 'n' to 'z'
    334, 260, 334, 584, // '{' to '~'
];

/// Bold glyphs run a little wider than regular; used only for wrapping.
const BOLD_FACTOR: f32 = 1.06;

fn glyph_width(c: char, font: Font) -> f32 {
    if font == Font::Mono {
        return 600.0;
    }
    let base = match c as u32 {
        32..=126 => HELVETICA[(c as u32 - 32) as usize] as f32,
        _ => 556.0,
    };
    if font == Font::Bold {
        base * BOLD_FACTOR
    } else {
        base
    }
}

fn text_width(s: &str, font: Font, size: f32) -> f32 {
    s.chars().map(|c| glyph_width(c, font)).sum::<f32>() * size / 1000.0
}

/// Encode text as WinAnsi bytes. Latin-1 maps directly; common typographic
/// characters map to their WinAnsi slots; anything else becomes `?`. Tabs
/// become spaces and other control characters are dropped.
pub fn encode(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len());
    for c in s.chars() {
        let b = match c {
            '\t' => b' ',
            c if (c as u32) < 32 => continue,
            c if (c as u32) < 127 => c as u8,
            c if (0xA0..=0xFF).contains(&(c as u32)) => c as u32 as u8,
            '\u{20AC}' => 0x80,
            '\u{2026}' => 0x85,
            '\u{2018}' => 0x91,
            '\u{2019}' => 0x92,
            '\u{201C}' => 0x93,
            '\u{201D}' => 0x94,
            '\u{2022}' => 0x95,
            '\u{2013}' => 0x96,
            '\u{2014}' => 0x97,
            '\u{2122}' => 0x99,
            _ => b'?',
        };
        out.push(b);
    }
    out
}

/// Greedy word wrap by measured width. Words wider than the line are split by
/// character. Existing newlines are kept.
fn wrap(text: &str, font: Font, size: f32, max_w: f32) -> Vec<String> {
    let space = text_width(" ", font, size);
    let mut out = Vec::new();
    for para in text.split('\n') {
        let mut line = String::new();
        let mut w = 0.0;
        for word in para.split(' ') {
            let ww = text_width(word, font, size);
            let need = if line.is_empty() { ww } else { w + space + ww };
            if need <= max_w {
                if !line.is_empty() {
                    line.push(' ');
                }
                line.push_str(word);
                w = need;
                continue;
            }
            if !line.is_empty() {
                out.push(std::mem::take(&mut line));
                w = 0.0;
            }
            // Place the word on fresh lines, splitting it if too wide.
            for c in word.chars() {
                let cw = glyph_width(c, font) * size / 1000.0;
                if w + cw > max_w && !line.is_empty() {
                    out.push(std::mem::take(&mut line));
                    w = 0.0;
                }
                line.push(c);
                w += cw;
            }
        }
        out.push(line);
    }
    out
}

/// Page content under construction, with a top-down cursor.
struct Layout {
    pages: Vec<Content>,
    /// Current baseline position, measured from the bottom of the page.
    y: f32,
}

impl Layout {
    fn new() -> Self {
        let mut l = Self {
            pages: Vec::new(),
            y: 0.0,
        };
        l.new_page();
        l
    }

    fn new_page(&mut self) {
        self.pages.push(Content::new());
        self.y = PAGE_H - MARGIN;
    }

    /// Start a new page unless `h` more points fit above the bottom margin.
    /// Returns true when a page break happened.
    fn ensure(&mut self, h: f32) -> bool {
        if self.y - h < BOTTOM {
            self.new_page();
            true
        } else {
            false
        }
    }

    fn page(&mut self) -> &mut Content {
        self.pages.last_mut().expect("layout always has a page")
    }

    fn text(&mut self, font: Font, size: f32, x: f32, y: f32, s: &str, color: Rgb) {
        let bytes = encode(s);
        let c = self.page();
        c.begin_text();
        c.set_font(font.name(), size);
        c.set_fill_rgb(color.0, color.1, color.2);
        c.next_line(x, y);
        c.show(Str(&bytes));
        c.end_text();
    }

    fn fill(&mut self, x: f32, y: f32, w: f32, h: f32, color: Rgb) {
        let c = self.page();
        c.set_fill_rgb(color.0, color.1, color.2);
        c.rect(x, y, w, h);
        c.fill_nonzero();
    }

    fn hline(&mut self, x: f32, y: f32, w: f32, width: f32, color: Rgb) {
        let c = self.page();
        c.set_stroke_rgb(color.0, color.1, color.2);
        c.set_line_width(width);
        c.move_to(x, y);
        c.line_to(x + w, y);
        c.stroke();
    }

    /// Wrapped lines, one per baseline, breaking pages as needed.
    fn lines(&mut self, lines: &[String], font: Font, size: f32, leading: f32, x: f32, color: Rgb) {
        for line in lines {
            self.ensure(leading);
            self.y -= leading;
            self.text(font, size, x, self.y + leading * 0.25, line, color);
        }
    }

    fn paragraph(&mut self, text: &str, font: Font, size: f32, leading: f32, x: f32, color: Rgb) {
        let w = CONTENT_W - (x - MARGIN);
        let lines = wrap(text, font, size, w);
        self.lines(&lines, font, size, leading, x, color);
    }

    fn gap(&mut self, h: f32) {
        self.y -= h;
    }
}

/// Render a report as PDF bytes.
pub fn render(report: &Report) -> Vec<u8> {
    let mut l = Layout::new();

    l.paragraph(&report.title, Font::Bold, 18.0, 23.0, MARGIN, TEXT);
    if !report.subtitle.is_empty() {
        l.paragraph(&report.subtitle, Font::Regular, 11.0, 15.0, MARGIN, MUTED);
    }
    let mut meta = Vec::new();
    if !report.tool.is_empty() {
        meta.push(report.tool.as_str());
    }
    if !report.generated.is_empty() {
        meta.push(report.generated.as_str());
    }
    if !meta.is_empty() {
        l.paragraph(&meta.join(" | "), Font::Regular, 9.0, 13.0, MARGIN, MUTED);
    }

    for s in &report.sections {
        // Keep a heading with at least a few lines of its content.
        l.gap(16.0);
        l.ensure(60.0);
        l.paragraph(&s.title, Font::Bold, 13.0, 17.0, MARGIN, TEXT);
        l.hline(MARGIN, l.y, CONTENT_W, 1.5, ACCENT);
        l.gap(6.0);
        if !s.subtitle.is_empty() {
            l.paragraph(&s.subtitle, Font::Regular, 9.5, 13.0, MARGIN, MUTED);
        }
        for b in &s.blocks {
            l.gap(6.0);
            block(&mut l, b);
        }
    }

    finish(report, l)
}

fn block(l: &mut Layout, b: &Block) {
    match b {
        Block::Paragraph { text } => l.paragraph(text, Font::Regular, 10.0, 13.5, MARGIN, TEXT),
        Block::KeyValues { items } => {
            let kw = 150.0;
            for kv in items {
                let keys = wrap(&kv.key, Font::Bold, 9.5, kw - 8.0);
                let vals = wrap(&kv.value, Font::Regular, 9.5, CONTENT_W - kw);
                let n = keys.len().max(vals.len());
                for i in 0..n {
                    l.ensure(13.0);
                    l.y -= 13.0;
                    let base = l.y + 3.0;
                    if let Some(k) = keys.get(i) {
                        l.text(Font::Bold, 9.5, MARGIN, base, k, TEXT);
                    }
                    if let Some(v) = vals.get(i) {
                        l.text(Font::Regular, 9.5, MARGIN + kw, base, v, TEXT);
                    }
                }
            }
        }
        Block::Table { headers, rows } => table(l, headers, rows),
        Block::Findings { items } => {
            for f in items {
                let x = MARGIN + 40.0;
                let mut title = String::new();
                if !f.category.is_empty() {
                    title.push_str(&f.category);
                    title.push_str(": ");
                }
                title.push_str(&f.title);
                let tl = wrap(&title, Font::Bold, 9.5, CONTENT_W - 40.0);
                let dl = if f.detail.is_empty() {
                    Vec::new()
                } else {
                    wrap(&f.detail, Font::Regular, 9.0, CONTENT_W - 40.0)
                };
                l.ensure(13.0 + 12.0 * dl.len().min(2) as f32);
                l.y -= 13.0;
                let base = l.y + 3.0;
                l.fill(MARGIN, base - 2.5, 32.0, 11.0, severity_color(f.severity));
                let label = f.severity.label();
                let lw = text_width(label, Font::Bold, 7.5);
                l.text(
                    Font::Bold,
                    7.5,
                    MARGIN + (32.0 - lw) / 2.0,
                    base,
                    label,
                    WHITE,
                );
                l.text(Font::Bold, 9.5, x, base, &tl[0], TEXT);
                l.lines(&tl[1..], Font::Bold, 9.5, 13.0, x, TEXT);
                l.lines(&dl, Font::Regular, 9.0, 12.0, x, MUTED);
                l.gap(4.0);
            }
        }
        Block::Code { text } => {
            let lines: Vec<(String, Rgb)> = text
                .lines()
                .map(|line| (line.to_string(), CODE_BG))
                .collect();
            mono(l, &lines);
        }
        Block::Diff { lines } => {
            let lines: Vec<(String, Rgb)> = lines
                .iter()
                .map(|d| {
                    let bg = match d.kind {
                        DiffKind::Context => CODE_BG,
                        DiffKind::Add => ADD_BG,
                        DiffKind::Del => DEL_BG,
                        DiffKind::Hunk => HUNK_BG,
                    };
                    (format!("{}{}", d.marker(), d.text), bg)
                })
                .collect();
            mono(l, &lines);
        }
    }
}

fn severity_color(s: Severity) -> Rgb {
    match s {
        Severity::Pass => (0.08, 0.50, 0.24),
        Severity::Info => (0.15, 0.39, 0.92),
        Severity::Warn => (0.71, 0.33, 0.04),
        Severity::Fail => (0.73, 0.11, 0.11),
    }
}

/// Monospace lines on a tinted background, wrapped by character count.
fn mono(l: &mut Layout, lines: &[(String, Rgb)]) {
    let size = 8.0;
    let leading = 10.0;
    let pad = 6.0;
    let cols = ((CONTENT_W - 2.0 * pad) / (0.6 * size)).floor() as usize;
    for (line, bg) in lines {
        let chars: Vec<char> = line.chars().collect();
        let pieces: Vec<String> = if chars.is_empty() {
            vec![String::new()]
        } else {
            chars
                .chunks(cols.max(1))
                .map(|c| c.iter().collect())
                .collect()
        };
        for p in pieces {
            l.ensure(leading);
            l.y -= leading;
            l.fill(MARGIN, l.y, CONTENT_W, leading, *bg);
            l.text(Font::Mono, size, MARGIN + pad, l.y + 2.5, &p, TEXT);
        }
    }
}

/// Table with measured columns, wrapped cells and a header row repeated after
/// page breaks.
fn table(l: &mut Layout, headers: &[String], rows: &[Vec<String>]) {
    let cols = headers
        .len()
        .max(rows.iter().map(Vec::len).max().unwrap_or(0));
    if cols == 0 {
        return;
    }
    let size = 8.5;
    let leading = 11.0;
    let pad = 4.0;
    let get = |row: &[String], i: usize| row.get(i).cloned().unwrap_or_default();

    // Natural widths, capped, then scaled to the content width.
    let mut widths: Vec<f32> = (0..cols)
        .map(|i| {
            let h = headers
                .get(i)
                .map(|h| text_width(h, Font::Bold, size))
                .unwrap_or(0.0);
            let body = rows
                .iter()
                .map(|r| text_width(&get(r, i), Font::Regular, size))
                .fold(0.0, f32::max);
            h.max(body).min(CONTENT_W * 0.6) + 2.0 * pad
        })
        .collect();
    // Scale to the full content width, shrinking or growing every column.
    let total: f32 = widths.iter().sum();
    let scale = CONTENT_W / total;
    for w in &mut widths {
        *w *= scale;
    }

    // Wrap a row's cells and measure its height.
    let measure = |cells: &[String], font: Font| {
        let wrapped: Vec<Vec<String>> = (0..cols)
            .map(|i| wrap(&get(cells, i), font, size, (widths[i] - 2.0 * pad).max(4.0)))
            .collect();
        let n = wrapped.iter().map(Vec::len).max().unwrap_or(1);
        (wrapped, n as f32 * leading + 2.0 * pad)
    };
    let table_w: f32 = widths.iter().sum();
    let draw = |l: &mut Layout, wrapped: &[Vec<String>], h: f32, font: Font, fill: Option<Rgb>| {
        let top = l.y;
        if let Some(bg) = fill {
            l.fill(MARGIN, top - h, table_w, h, bg);
        }
        let mut x = MARGIN;
        for (i, lines) in wrapped.iter().enumerate() {
            for (k, line) in lines.iter().enumerate() {
                let base = top - pad - (k as f32 + 1.0) * leading + 2.5;
                l.text(font, size, x + pad, base, line, TEXT);
            }
            x += widths[i];
        }
        l.y = top - h;
        l.hline(MARGIN, l.y, table_w, 0.5, RULE);
    };

    let header = (!headers.is_empty()).then(|| measure(headers, Font::Bold));
    let body: Vec<_> = rows.iter().map(|r| measure(r, Font::Regular)).collect();

    // Keep the header with the first row.
    if let Some((hw, hh)) = &header {
        let first = body.first().map(|b| b.1).unwrap_or(0.0);
        l.ensure(hh + first);
        draw(l, hw, *hh, Font::Bold, Some(HEADER_BG));
    }
    for (wrapped, h) in &body {
        if l.ensure(*h)
            && let Some((hw, hh)) = &header
        {
            draw(l, hw, *hh, Font::Bold, Some(HEADER_BG));
        }
        draw(l, wrapped, *h, Font::Regular, None);
    }
}

/// Add footers and assemble the PDF objects.
fn finish(report: &Report, mut l: Layout) -> Vec<u8> {
    let foot = footer(report);
    let total = l.pages.len();
    for (i, page) in l.pages.iter_mut().enumerate() {
        let num = format!("Page {} of {total}", i + 1);
        let nw = text_width(&num, Font::Regular, 8.0);
        for (text, x) in [
            (foot.as_str(), MARGIN),
            (num.as_str(), PAGE_W - MARGIN - nw),
        ] {
            let bytes = encode(text);
            page.begin_text();
            page.set_font(Font::Regular.name(), 8.0);
            page.set_fill_rgb(MUTED.0, MUTED.1, MUTED.2);
            page.next_line(x, MARGIN - 24.0);
            page.show(Str(&bytes));
            page.end_text();
        }
    }

    let mut pdf = Pdf::new();
    let catalog = Ref::new(1);
    let tree = Ref::new(2);
    let info = Ref::new(3);
    let fonts = [
        (Font::Regular, Ref::new(4), "Helvetica"),
        (Font::Bold, Ref::new(5), "Helvetica-Bold"),
        (Font::Mono, Ref::new(6), "Courier"),
    ];
    let first = 7;
    let page_ids: Vec<Ref> = (0..total).map(|i| Ref::new(first + 2 * i as i32)).collect();

    pdf.catalog(catalog).pages(tree);
    pdf.pages(tree)
        .kids(page_ids.iter().copied())
        .count(total as i32);
    pdf.document_info(info)
        .title(TextStr(&report.title))
        .producer(TextStr(super::core::PRODUCT));

    for (_, id, base) in fonts {
        pdf.type1_font(id)
            .base_font(Name(base.as_bytes()))
            .encoding_predefined(Name(b"WinAnsiEncoding"));
    }

    for (i, content) in l.pages.into_iter().enumerate() {
        let page_id = page_ids[i];
        let content_id = Ref::new(page_id.get() + 1);
        let mut page = pdf.page(page_id);
        page.media_box(Rect::new(0.0, 0.0, PAGE_W, PAGE_H));
        page.parent(tree);
        page.contents(content_id);
        {
            let mut res = page.resources();
            let mut f = res.fonts();
            for (font, id, _) in fonts {
                f.pair(font.name(), id);
            }
        }
        drop(page);
        pdf.stream(content_id, &content.finish());
    }

    pdf.finish()
}

#[cfg(test)]
mod tests {
    use super::super::core::{Block, Section, sample};
    use super::*;

    #[test]
    fn produces_a_pdf() {
        let out = render(&sample());
        assert!(out.starts_with(b"%PDF-"));
        let s = String::from_utf8_lossy(&out);
        assert!(s.contains("/BaseFont /Helvetica"));
        assert!(s.contains("/WinAnsiEncoding"));
        assert!(s.contains("/Count 1"));
        assert!(s.trim_end().ends_with("%%EOF"));
    }

    #[test]
    fn long_content_breaks_pages() {
        let mut r = sample();
        let rows: Vec<Vec<String>> = (0..400)
            .map(|i| {
                vec![
                    format!("10.0.0.{}", i % 255),
                    "open".to_string(),
                    "https".to_string(),
                ]
            })
            .collect();
        r.sections.push(Section {
            title: "Ports".to_string(),
            subtitle: String::new(),
            blocks: vec![Block::Table {
                headers: vec!["Host".into(), "State".into(), "Service".into()],
                rows,
            }],
        });
        let s = String::from_utf8_lossy(&render(&r)).into_owned();
        let count: usize = s
            .split("/Count ")
            .nth(1)
            .and_then(|t| t.split(|c: char| !c.is_ascii_digit()).next())
            .and_then(|n| n.parse().ok())
            .unwrap();
        assert!(count >= 5, "only {count} pages");
    }

    #[test]
    fn encode_winansi() {
        assert_eq!(encode("a(b)"), b"a(b)");
        assert_eq!(encode("caf\u{e9}"), [b'c', b'a', b'f', 0xE9]);
        assert_eq!(encode("\u{2013}\u{2019}"), [0x96, 0x92]);
        assert_eq!(encode("\u{65e5}"), b"?");
        assert_eq!(encode("a\tb\x07"), b"a b");
    }

    #[test]
    fn wrap_respects_width() {
        let lines = wrap(&"network ".repeat(50), Font::Regular, 10.0, 200.0);
        assert!(lines.len() > 5);
        for line in &lines {
            assert!(
                text_width(line, Font::Regular, 10.0) <= 200.0 + 0.01,
                "{line}"
            );
        }
    }

    #[test]
    fn wrap_splits_long_words() {
        let lines = wrap(&"x".repeat(200), Font::Mono, 10.0, 60.0);
        assert!(lines.iter().all(|l| l.chars().count() <= 10));
    }

    #[test]
    fn helvetica_table_lines_up() {
        assert_eq!(glyph_width(' ', Font::Regular), 278.0);
        assert_eq!(glyph_width('0', Font::Regular), 556.0);
        assert_eq!(glyph_width('W', Font::Regular), 944.0);
        assert_eq!(glyph_width('i', Font::Regular), 222.0);
        assert_eq!(glyph_width('~', Font::Regular), 584.0);
    }
}
