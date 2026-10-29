//! Projects: named collections of tool results (reports) that export together
//! as one combined report. Each project is one JSON file, `<id>.json`, in a
//! directory the caller chooses (normally `<app data>/projects`).
//!
//! Ids are generated here and validated as short lowercase hex before any path
//! is built, so the UI cannot name arbitrary files. Writes are atomic and
//! sizes are capped. Time is passed in by the caller so tests are
//! deterministic.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use serde::de::IgnoredAny;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::report::core::{self as report, Block, KeyValue, Report, Section};
use crate::store::core::write_atomic;

/// Largest project file accepted, on load and on save.
pub const MAX_PROJECT_BYTES: usize = 25_000_000;
/// Most results in one project.
pub const MAX_ITEMS: usize = 500;
/// Most projects kept.
pub const MAX_PROJECTS: usize = 1000;
/// Longest project or result name, in characters.
pub const MAX_NAME: usize = 200;
/// Longest notes field, in characters.
pub const MAX_NOTE: usize = 20_000;
/// Longest id accepted.
const MAX_ID: usize = 32;
/// On-disk format version.
const VERSION: u32 = 1;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProjectError {
    #[error("invalid project or item id")]
    InvalidId,
    #[error("project not found")]
    NotFound,
    #[error("name is too long (limit {MAX_NAME} characters)")]
    NameTooLong,
    #[error("notes are too long (limit {MAX_NOTE} characters)")]
    NoteTooLong,
    #[error("project is full (limit {MAX_ITEMS} results)")]
    TooManyItems,
    #[error("too many projects (limit {MAX_PROJECTS}); delete some first")]
    TooManyProjects,
    #[error("project would be too large ({0} bytes; limit {MAX_PROJECT_BYTES})")]
    TooLarge(usize),
    #[error("project file is unreadable: {0}")]
    Corrupt(String),
    #[error("{0}")]
    Report(#[from] report::ReportError),
    #[error("{0}")]
    Io(String),
}

/// One saved result: a tool's report plus the user's title and note.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Item {
    pub id: String,
    pub tool: String,
    pub title: String,
    #[serde(default)]
    pub note: String,
    /// Unix seconds.
    pub added: u64,
    /// When it was added, in the user's locale, for reports.
    #[serde(default)]
    pub added_label: String,
    pub report: Report,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Project {
    pub version: u32,
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub notes: String,
    /// Unix seconds.
    pub created: u64,
    pub updated: u64,
    pub items: Vec<Item>,
}

/// List entry, without the item contents.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ProjectSummary {
    pub id: String,
    pub name: String,
    pub created: u64,
    pub updated: u64,
    pub items: usize,
}

/// An item as the panel shows it: metadata and section titles only.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ItemView {
    pub id: String,
    pub tool: String,
    pub title: String,
    pub note: String,
    pub added: u64,
    pub added_label: String,
    pub sections: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ProjectView {
    pub id: String,
    pub name: String,
    pub notes: String,
    pub created: u64,
    pub updated: u64,
    pub items: Vec<ItemView>,
}

/// The panel's edit of one item. The order of edits is the new item order;
/// items left out are removed.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ItemEdit {
    pub id: String,
    pub title: String,
    #[serde(default)]
    pub note: String,
}

/// Just enough of a project file to list it, skipping item contents.
#[derive(Deserialize)]
struct Head {
    id: String,
    name: String,
    created: u64,
    updated: u64,
    items: Vec<IgnoredAny>,
}

/// Lowercase hex, 1 to 32 characters.
pub fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_ID
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

static COUNTER: AtomicU32 = AtomicU32::new(0);

/// A new id from a nanosecond timestamp and a process-wide counter.
pub fn new_id(now_nanos: u128) -> String {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed) & 0xffff;
    format!("{:x}{n:04x}", now_nanos & 0xffff_ffff_ffff_ffff)
}

fn clean_name(name: &str, fallback: &str) -> Result<String, ProjectError> {
    let name = name.trim();
    if name.chars().count() > MAX_NAME {
        return Err(ProjectError::NameTooLong);
    }
    Ok(if name.is_empty() {
        fallback.to_string()
    } else {
        name.to_string()
    })
}

fn check_note(note: &str) -> Result<(), ProjectError> {
    if note.chars().count() > MAX_NOTE {
        Err(ProjectError::NoteTooLong)
    } else {
        Ok(())
    }
}

impl Project {
    fn summary(&self) -> ProjectSummary {
        ProjectSummary {
            id: self.id.clone(),
            name: self.name.clone(),
            created: self.created,
            updated: self.updated,
            items: self.items.len(),
        }
    }

    fn view(&self) -> ProjectView {
        ProjectView {
            id: self.id.clone(),
            name: self.name.clone(),
            notes: self.notes.clone(),
            created: self.created,
            updated: self.updated,
            items: self
                .items
                .iter()
                .map(|i| ItemView {
                    id: i.id.clone(),
                    tool: i.tool.clone(),
                    title: i.title.clone(),
                    note: i.note.clone(),
                    added: i.added,
                    added_label: i.added_label.clone(),
                    sections: i.report.sections.iter().map(|s| s.title.clone()).collect(),
                })
                .collect(),
        }
    }
}

/// Project files in one directory.
pub struct ProjectStore {
    dir: PathBuf,
}

impl ProjectStore {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    fn path(&self, id: &str) -> PathBuf {
        self.dir.join(format!("{id}.json"))
    }

    /// Ids of every project file present.
    fn ids(&self) -> Result<Vec<String>, ProjectError> {
        let entries = match fs::read_dir(&self.dir) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => {
                return Err(ProjectError::Io(format!(
                    "could not read {}: {e}",
                    self.dir.display()
                )));
            }
        };
        Ok(entries
            .filter_map(|e| e.ok())
            .filter_map(|e| {
                let name = e.file_name().into_string().ok()?;
                let id = name.strip_suffix(".json")?;
                valid_id(id).then(|| id.to_string())
            })
            .collect())
    }

    fn read_bytes(&self, id: &str) -> Result<Vec<u8>, ProjectError> {
        if !valid_id(id) {
            return Err(ProjectError::InvalidId);
        }
        let path = self.path(id);
        let meta = match fs::metadata(&path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(ProjectError::NotFound);
            }
            Err(e) => {
                return Err(ProjectError::Io(format!(
                    "could not read {}: {e}",
                    path.display()
                )));
            }
        };
        if meta.len() > MAX_PROJECT_BYTES as u64 {
            return Err(ProjectError::TooLarge(meta.len() as usize));
        }
        fs::read(&path)
            .map_err(|e| ProjectError::Io(format!("could not read {}: {e}", path.display())))
    }

    fn read(&self, id: &str) -> Result<Project, ProjectError> {
        let bytes = self.read_bytes(id)?;
        serde_json::from_slice(&bytes).map_err(|e| ProjectError::Corrupt(e.to_string()))
    }

    fn write(&self, p: &Project) -> Result<(), ProjectError> {
        let bytes = serde_json::to_vec(p).map_err(|e| ProjectError::Io(e.to_string()))?;
        if bytes.len() > MAX_PROJECT_BYTES {
            return Err(ProjectError::TooLarge(bytes.len()));
        }
        write_atomic(&self.dir, &format!("{}.json", p.id), &bytes).map_err(ProjectError::Io)
    }

    /// Every readable project, most recently updated first. Unreadable files
    /// are skipped, not deleted.
    pub fn list(&self) -> Result<Vec<ProjectSummary>, ProjectError> {
        let mut out = Vec::new();
        for id in self.ids()? {
            let Ok(bytes) = self.read_bytes(&id) else {
                continue;
            };
            let Ok(h) = serde_json::from_slice::<Head>(&bytes) else {
                continue;
            };
            if h.id != id {
                continue;
            }
            out.push(ProjectSummary {
                id: h.id,
                name: h.name,
                created: h.created,
                updated: h.updated,
                items: h.items.len(),
            });
        }
        out.sort_by(|a, b| b.updated.cmp(&a.updated).then_with(|| a.name.cmp(&b.name)));
        Ok(out)
    }

    pub fn create(&self, name: &str, id: String, now: u64) -> Result<ProjectSummary, ProjectError> {
        if !valid_id(&id) {
            return Err(ProjectError::InvalidId);
        }
        if self.ids()?.len() >= MAX_PROJECTS {
            return Err(ProjectError::TooManyProjects);
        }
        let p = Project {
            version: VERSION,
            id,
            name: clean_name(name, "Untitled project")?,
            notes: String::new(),
            created: now,
            updated: now,
            items: Vec::new(),
        };
        self.write(&p)?;
        Ok(p.summary())
    }

    pub fn get(&self, id: &str) -> Result<ProjectView, ProjectError> {
        Ok(self.read(id)?.view())
    }

    /// Apply the panel's edits: name, notes, and item order, titles and notes.
    pub fn update(
        &self,
        id: &str,
        name: &str,
        notes: &str,
        edits: &[ItemEdit],
        now: u64,
    ) -> Result<ProjectView, ProjectError> {
        let mut p = self.read(id)?;
        p.name = clean_name(name, "Untitled project")?;
        check_note(notes)?;
        p.notes = notes.to_string();

        let mut old = std::mem::take(&mut p.items);
        for edit in edits {
            check_note(&edit.note)?;
            let Some(pos) = old.iter().position(|i| i.id == edit.id) else {
                continue;
            };
            let mut item = old.swap_remove(pos);
            item.title = clean_name(&edit.title, &item.report.title)?;
            item.note = edit.note.clone();
            p.items.push(item);
        }
        p.updated = now;
        self.write(&p)?;
        Ok(p.view())
    }

    pub fn delete(&self, id: &str) -> Result<(), ProjectError> {
        if !valid_id(id) {
            return Err(ProjectError::InvalidId);
        }
        match fs::remove_file(self.path(id)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(ProjectError::NotFound),
            Err(e) => Err(ProjectError::Io(e.to_string())),
        }
    }

    /// Add a tool's report to a project.
    pub fn add(
        &self,
        id: &str,
        item_id: String,
        tool: &str,
        added_label: &str,
        report: Report,
        now: u64,
    ) -> Result<ProjectSummary, ProjectError> {
        if !valid_id(&item_id) {
            return Err(ProjectError::InvalidId);
        }
        report::validate(&report)?;
        let mut p = self.read(id)?;
        if p.items.len() >= MAX_ITEMS {
            return Err(ProjectError::TooManyItems);
        }
        let title = clean_name(&report.title, "Untitled result")
            .unwrap_or_else(|_| report.title.chars().take(MAX_NAME).collect());
        p.items.push(Item {
            id: item_id,
            tool: tool.to_string(),
            title,
            note: String::new(),
            added: now,
            added_label: added_label.to_string(),
            report,
        });
        p.updated = now;
        self.write(&p)?;
        Ok(p.summary())
    }

    /// The combined report for a project.
    pub fn report(&self, id: &str, generated: &str) -> Result<Report, ProjectError> {
        Ok(combined_report(&self.read(id)?, generated))
    }
}

/// Build one report from every item: optional notes, a contents table, then a
/// part heading per item followed by that item's sections.
pub fn combined_report(p: &Project, generated: &str) -> Report {
    let mut sections = Vec::new();

    let mut overview = vec![Block::KeyValues {
        items: vec![
            KeyValue {
                key: "Project".to_string(),
                value: p.name.clone(),
            },
            KeyValue {
                key: "Results".to_string(),
                value: p.items.len().to_string(),
            },
        ],
    }];
    if !p.notes.trim().is_empty() {
        overview.push(Block::Paragraph {
            text: p.notes.trim().to_string(),
        });
    }
    if !p.items.is_empty() {
        overview.push(Block::Table {
            headers: vec!["#".into(), "Result".into(), "Tool".into(), "Added".into()],
            rows: p
                .items
                .iter()
                .enumerate()
                .map(|(n, i)| {
                    vec![
                        (n + 1).to_string(),
                        i.title.clone(),
                        i.tool.clone(),
                        i.added_label.clone(),
                    ]
                })
                .collect(),
        });
    }
    sections.push(Section {
        title: "Overview".to_string(),
        blocks: overview,
        ..Default::default()
    });

    for (n, item) in p.items.iter().enumerate() {
        let mut sub = vec![item.tool.clone()];
        if !item.added_label.is_empty() {
            sub.push(item.added_label.clone());
        }
        let mut blocks = Vec::new();
        if !item.report.subtitle.is_empty() {
            blocks.push(Block::Paragraph {
                text: item.report.subtitle.clone(),
            });
        }
        if !item.note.trim().is_empty() {
            blocks.push(Block::Paragraph {
                text: format!("Note: {}", item.note.trim()),
            });
        }
        sections.push(Section {
            title: format!("{}. {}", n + 1, item.title),
            subtitle: sub.join(" | "),
            blocks,
            part: true,
        });
        sections.extend(item.report.sections.iter().cloned().map(|mut s| {
            s.part = false;
            s
        }));
    }

    Report {
        title: p.name.clone(),
        subtitle: format!(
            "{} result{}",
            p.items.len(),
            if p.items.len() == 1 { "" } else { "s" }
        ),
        generated: generated.to_string(),
        tool: "Projects".to_string(),
        sections,
    }
}

/// Directory for project files under the app data dir.
pub fn projects_dir(app_data: &Path) -> PathBuf {
    app_data.join("projects")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::core::Format;

    fn temp_dir(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let d = std::env::temp_dir().join(format!(
            "omnipacket-projects-{tag}-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn rep(title: &str) -> Report {
        Report {
            title: title.to_string(),
            subtitle: "sub".to_string(),
            tool: "Port Scanner".to_string(),
            sections: vec![Section {
                title: "Summary".to_string(),
                blocks: vec![Block::Paragraph {
                    text: "x".to_string(),
                }],
                ..Default::default()
            }],
            ..Default::default()
        }
    }

    fn store(tag: &str) -> ProjectStore {
        ProjectStore::new(temp_dir(tag))
    }

    #[test]
    fn id_validation() {
        assert!(valid_id("0af9"));
        assert!(!valid_id(""));
        assert!(!valid_id("../etc"));
        assert!(!valid_id("ABC"));
        assert!(!valid_id(&"a".repeat(33)));
        let a = new_id(123);
        let b = new_id(123);
        assert!(valid_id(&a) && valid_id(&b) && a != b);
    }

    #[test]
    fn create_list_get_delete() {
        let s = store("crud");
        assert!(s.list().unwrap().is_empty());
        s.create("  Branch audit  ", "a1".into(), 10).unwrap();
        s.create("", "b2".into(), 20).unwrap();
        let list = s.list().unwrap();
        assert_eq!(list.len(), 2);
        // Most recently updated first; empty name gets a default.
        assert_eq!(list[0].name, "Untitled project");
        assert_eq!(list[1].name, "Branch audit");
        assert_eq!(s.get("a1").unwrap().name, "Branch audit");
        s.delete("a1").unwrap();
        assert_eq!(s.get("a1"), Err(ProjectError::NotFound));
        assert_eq!(s.delete("a1"), Err(ProjectError::NotFound));
    }

    #[test]
    fn rejects_bad_ids_before_touching_disk() {
        let s = store("ids");
        assert_eq!(s.get("../x"), Err(ProjectError::InvalidId));
        assert_eq!(s.delete("x/y"), Err(ProjectError::InvalidId));
        assert_eq!(s.create("p", "Z".into(), 1), Err(ProjectError::InvalidId));
    }

    #[test]
    fn add_and_view_items() {
        let s = store("add");
        s.create("P", "a1".into(), 1).unwrap();
        let sum = s
            .add(
                "a1",
                "c1".into(),
                "Port Scanner",
                "Oct 29",
                rep("Port scan: 10.0.0.0/24"),
                5,
            )
            .unwrap();
        assert_eq!(sum.items, 1);
        assert_eq!(sum.updated, 5);
        let v = s.get("a1").unwrap();
        assert_eq!(v.items[0].title, "Port scan: 10.0.0.0/24");
        assert_eq!(v.items[0].sections, ["Summary"]);
        assert_eq!(s.list().unwrap()[0].items, 1);
    }

    #[test]
    fn add_rejects_empty_report() {
        let s = store("empty");
        s.create("P", "a1".into(), 1).unwrap();
        let r = Report::default();
        assert!(matches!(
            s.add("a1", "c1".into(), "t", "", r, 2),
            Err(ProjectError::Report(_))
        ));
    }

    #[test]
    fn update_reorders_renames_and_removes() {
        let s = store("update");
        s.create("P", "a1".into(), 1).unwrap();
        for (i, t) in ["one", "two", "three"].iter().enumerate() {
            s.add("a1", format!("c{i}"), "t", "", rep(t), 2).unwrap();
        }
        let edits = vec![
            ItemEdit {
                id: "c2".into(),
                title: "Third first".into(),
                note: "check this".into(),
            },
            ItemEdit {
                id: "c0".into(),
                title: "".into(),
                note: String::new(),
            },
            ItemEdit {
                id: "zz".into(),
                title: "ignored".into(),
                note: String::new(),
            },
        ];
        let v = s.update("a1", "Renamed", "notes", &edits, 9).unwrap();
        let titles: Vec<_> = v.items.iter().map(|i| i.title.as_str()).collect();
        // c1 was left out, so it is removed; an empty title falls back to the report title.
        assert_eq!(titles, ["Third first", "one"]);
        assert_eq!(v.items[0].note, "check this");
        assert_eq!(v.name, "Renamed");
        assert_eq!(v.updated, 9);
    }

    #[test]
    fn limits() {
        let s = store("limits");
        assert_eq!(
            s.create(&"n".repeat(MAX_NAME + 1), "a1".into(), 1),
            Err(ProjectError::NameTooLong)
        );
        s.create("P", "a1".into(), 1).unwrap();
        assert_eq!(
            s.update("a1", "P", &"n".repeat(MAX_NOTE + 1), &[], 2),
            Err(ProjectError::NoteTooLong)
        );
    }

    #[test]
    fn corrupt_files_are_skipped_in_list() {
        let s = store("corrupt");
        s.create("Good", "a1".into(), 1).unwrap();
        fs::write(s.dir.join("b2.json"), b"{not json").unwrap();
        fs::write(s.dir.join("notes.txt"), b"ignored").unwrap();
        let list = s.list().unwrap();
        assert_eq!(list.len(), 1);
        assert!(matches!(s.get("b2"), Err(ProjectError::Corrupt(_))));
    }

    #[test]
    fn combined_report_structure() {
        let s = store("combined");
        s.create("Site audit", "a1".into(), 1).unwrap();
        s.add(
            "a1",
            "c1".into(),
            "Port Scanner",
            "Oct 29, 9:00 AM",
            rep("Port scan"),
            2,
        )
        .unwrap();
        s.add(
            "a1",
            "c2".into(),
            "DNS Analyzer",
            "Oct 29, 9:05 AM",
            rep("DNS audit"),
            3,
        )
        .unwrap();
        s.update(
            "a1",
            "Site audit",
            "Quarterly review",
            &[
                ItemEdit {
                    id: "c1".into(),
                    title: "Port scan".into(),
                    note: "two hosts down".into(),
                },
                ItemEdit {
                    id: "c2".into(),
                    title: "DNS audit".into(),
                    note: String::new(),
                },
            ],
            4,
        )
        .unwrap();
        let r = s.report("a1", "now").unwrap();
        assert_eq!(r.title, "Site audit");
        assert_eq!(r.subtitle, "2 results");
        let titles: Vec<_> = r
            .sections
            .iter()
            .map(|s| (s.title.as_str(), s.part))
            .collect();
        assert_eq!(
            titles,
            [
                ("Overview", false),
                ("1. Port scan", true),
                ("Summary", false),
                ("2. DNS audit", true),
                ("Summary", false),
            ]
        );
        assert_eq!(r.sections[1].subtitle, "Port Scanner | Oct 29, 9:00 AM");
        assert!(
            matches!(&r.sections[1].blocks[1], Block::Paragraph { text } if text == "Note: two hosts down")
        );
        for f in [Format::Html, Format::Pdf, Format::Markdown, Format::Text] {
            assert!(!report::render(&r, f).unwrap().is_empty());
        }
    }
}
