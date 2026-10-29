//! Format-independent report model shared by every tool that exports results,
//! plus validation and the render dispatcher. Ported from FortiDebug Builder's
//! ReportExport. Tools build a [`Report`] from their results; the renderers in
//! the sibling modules turn it into HTML, Markdown, plain text or PDF.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::{html, markdown, pdf, text};

/// Cap on the total text in a report, to bound memory and render time.
pub const MAX_REPORT_BYTES: usize = 20_000_000;

/// Product name shown in report footers.
pub const PRODUCT: &str = "Net3PO";

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", default)]
pub struct Report {
    pub title: String,
    pub subtitle: String,
    /// Human-readable timestamp, set by the caller in the user's locale.
    pub generated: String,
    /// Tool that produced the report, such as "DNS Analyzer".
    pub tool: String,
    pub sections: Vec<Section>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", default)]
pub struct Section {
    pub title: String,
    pub subtitle: String,
    pub blocks: Vec<Block>,
    /// A part heading that groups the sections after it, used when a project
    /// combines several results into one report. Rendered more prominently;
    /// in PDF each part starts a new page.
    pub part: bool,
}

impl Report {
    /// True when any section is a part heading, so plain sections render one
    /// level down.
    pub fn has_parts(&self) -> bool {
        self.sections.iter().any(|s| s.part)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum Block {
    Paragraph {
        text: String,
    },
    KeyValues {
        items: Vec<KeyValue>,
    },
    Table {
        headers: Vec<String>,
        rows: Vec<Vec<String>>,
    },
    Findings {
        items: Vec<Finding>,
    },
    /// Preformatted monospace text.
    Code {
        text: String,
    },
    /// Unified diff lines.
    Diff {
        lines: Vec<DiffLine>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeyValue {
    pub key: String,
    pub value: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Pass,
    Info,
    Warn,
    Fail,
}

impl Severity {
    /// Short label used in every format.
    pub fn label(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Info => "INFO",
            Self::Warn => "WARN",
            Self::Fail => "FAIL",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    pub severity: Severity,
    #[serde(default)]
    pub category: String,
    pub title: String,
    #[serde(default)]
    pub detail: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum DiffKind {
    Context,
    Add,
    Del,
    /// `@@` hunk header.
    Hunk,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiffLine {
    pub kind: DiffKind,
    pub text: String,
}

impl DiffLine {
    /// The unified diff marker for this line.
    pub fn marker(&self) -> &'static str {
        match self.kind {
            DiffKind::Context => " ",
            DiffKind::Add => "+",
            DiffKind::Del => "-",
            DiffKind::Hunk => "",
        }
    }
}

/// Output format.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Format {
    Html,
    Markdown,
    Text,
    Pdf,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ReportError {
    #[error("report has no sections")]
    Empty,
    #[error("report is too large ({got} bytes of text, limit {limit})")]
    TooLarge { got: usize, limit: usize },
}

/// Total bytes of text in the report.
pub fn text_size(report: &Report) -> usize {
    let mut n =
        report.title.len() + report.subtitle.len() + report.generated.len() + report.tool.len();
    for s in &report.sections {
        n += s.title.len() + s.subtitle.len();
        for b in &s.blocks {
            n += match b {
                Block::Paragraph { text } | Block::Code { text } => text.len(),
                Block::KeyValues { items } => {
                    items.iter().map(|kv| kv.key.len() + kv.value.len()).sum()
                }
                Block::Table { headers, rows } => {
                    headers.iter().map(String::len).sum::<usize>()
                        + rows.iter().flatten().map(String::len).sum::<usize>()
                }
                Block::Findings { items } => items
                    .iter()
                    .map(|f| f.category.len() + f.title.len() + f.detail.len())
                    .sum(),
                Block::Diff { lines } => lines.iter().map(|l| l.text.len() + 1).sum(),
            };
        }
    }
    n
}

/// Check a report is renderable.
pub fn validate(report: &Report) -> Result<(), ReportError> {
    if report.sections.is_empty() {
        return Err(ReportError::Empty);
    }
    let got = text_size(report);
    if got > MAX_REPORT_BYTES {
        return Err(ReportError::TooLarge {
            got,
            limit: MAX_REPORT_BYTES,
        });
    }
    Ok(())
}

/// Render a report to bytes in the given format.
pub fn render(report: &Report, format: Format) -> Result<Vec<u8>, ReportError> {
    validate(report)?;
    Ok(match format {
        Format::Html => html::render(report).into_bytes(),
        Format::Markdown => markdown::render(report).into_bytes(),
        Format::Text => text::render(report).into_bytes(),
        Format::Pdf => pdf::render(report),
    })
}

/// Footer line used by every format.
pub fn footer(report: &Report) -> String {
    let mut parts = vec![format!("Generated by {PRODUCT}")];
    if !report.tool.is_empty() {
        parts.push(report.tool.clone());
    }
    if !report.generated.is_empty() {
        parts.push(report.generated.clone());
    }
    parts.join(" | ")
}

/// A small report touching every block type, for renderer tests.
#[cfg(test)]
pub fn sample() -> Report {
    Report {
        title: "DNS audit: example.com".to_string(),
        subtitle: "Resolver 1.1.1.1".to_string(),
        generated: "Oct 29, 2026 9:00 AM".to_string(),
        tool: "DNS Analyzer".to_string(),
        sections: vec![
            Section {
                title: "Summary".to_string(),
                subtitle: String::new(),
                part: false,
                blocks: vec![
                    Block::Paragraph {
                        text: "Checks <SPF> & DMARC.".to_string(),
                    },
                    Block::KeyValues {
                        items: vec![KeyValue {
                            key: "Domain".to_string(),
                            value: "example.com".to_string(),
                        }],
                    },
                    Block::Findings {
                        items: vec![Finding {
                            severity: Severity::Fail,
                            category: "SPF".to_string(),
                            title: "No SPF record".to_string(),
                            detail: "Add v=spf1 ... -all".to_string(),
                        }],
                    },
                ],
            },
            Section {
                title: "Records".to_string(),
                subtitle: "Answers".to_string(),
                part: false,
                blocks: vec![
                    Block::Table {
                        headers: vec!["Type".to_string(), "Value | data".to_string()],
                        rows: vec![vec!["TXT".to_string(), "v=DMARC1; p=reject".to_string()]],
                    },
                    Block::Code {
                        text: "dig +short example.com\n```fence```".to_string(),
                    },
                    Block::Diff {
                        lines: vec![
                            DiffLine {
                                kind: DiffKind::Hunk,
                                text: "@@ -1,2 +1,2 @@".to_string(),
                            },
                            DiffLine {
                                kind: DiffKind::Del,
                                text: "set action accept".to_string(),
                            },
                            DiffLine {
                                kind: DiffKind::Add,
                                text: "set action deny".to_string(),
                            },
                            DiffLine {
                                kind: DiffKind::Context,
                                text: "next".to_string(),
                            },
                        ],
                    },
                ],
            },
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_report_errors() {
        assert_eq!(
            render(&Report::default(), Format::Html),
            Err(ReportError::Empty)
        );
    }

    #[test]
    fn too_large_errors() {
        let mut r = sample();
        r.sections[0].blocks.push(Block::Code {
            text: "x".repeat(MAX_REPORT_BYTES),
        });
        assert!(matches!(
            render(&r, Format::Text),
            Err(ReportError::TooLarge { .. })
        ));
    }

    #[test]
    fn every_format_renders_sample() {
        for f in [Format::Html, Format::Markdown, Format::Text, Format::Pdf] {
            let out = render(&sample(), f).unwrap();
            assert!(!out.is_empty(), "{f:?}");
        }
    }

    #[test]
    fn json_shape_matches_ui() {
        let json = r#"{"title":"t","sections":[{"title":"s","blocks":[
            {"type":"keyValues","items":[{"key":"k","value":"v"}]},
            {"type":"findings","items":[{"severity":"warn","title":"x"}]},
            {"type":"diff","lines":[{"kind":"add","text":"a"}]}
        ]}]}"#;
        let r: Report = serde_json::from_str(json).unwrap();
        assert_eq!(r.sections[0].blocks.len(), 3);
        assert!(r.subtitle.is_empty());
    }

    /// The sample with a part heading in front.
    fn with_part() -> Report {
        let mut r = sample();
        r.sections.insert(
            0,
            Section {
                title: "1. Port scan".to_string(),
                subtitle: "Port Scanner".to_string(),
                blocks: Vec::new(),
                part: true,
            },
        );
        r
    }

    #[test]
    fn parts_shift_section_levels() {
        let r = with_part();
        assert!(r.has_parts() && !sample().has_parts());
        let html = String::from_utf8(render(&r, Format::Html).unwrap()).unwrap();
        assert!(html.contains("<h2 class=\"part\">1. Port scan</h2>"));
        assert!(html.contains("<h3>Records</h3>"));
        let md = String::from_utf8(render(&r, Format::Markdown).unwrap()).unwrap();
        assert!(md.contains("## 1. Port scan\n") && md.contains("### Records\n"));
        let txt = String::from_utf8(render(&r, Format::Text).unwrap()).unwrap();
        assert!(txt.contains("1. Port scan\n############\n"));
    }

    #[test]
    fn pdf_part_starts_a_page() {
        let mut r = sample();
        let plain = String::from_utf8_lossy(&render(&r, Format::Pdf).unwrap()).into_owned();
        r.sections.push(Section {
            title: "2. Next".to_string(),
            part: true,
            ..Default::default()
        });
        let parted = String::from_utf8_lossy(&render(&r, Format::Pdf).unwrap()).into_owned();
        assert!(plain.contains("/Count 1"));
        assert!(parted.contains("/Count 2"));
    }

    #[test]
    fn footer_joins_parts() {
        assert_eq!(
            footer(&sample()),
            "Generated by Net3PO | DNS Analyzer | Oct 29, 2026 9:00 AM"
        );
    }
}
