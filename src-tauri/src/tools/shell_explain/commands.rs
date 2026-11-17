//! Tauri command for the shell explainer.

use super::core::{self, Explanation};
use super::man::SystemMan;

/// Most new man pages read for one explanation.
const MAN_LIMIT: usize = 30;

/// Explain a shell command line. Runs `man` locally for commands the built-in
/// list does not cover; never runs the command itself.
#[tauri::command]
pub async fn shell_explain(text: String) -> Result<Explanation, String> {
    tokio::task::spawn_blocking(move || core::explain(&text, &SystemMan::new(MAN_LIMIT)))
        .await
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Print the explanation of `SHELL_EXPLAIN_TEXT` using local man pages.
    #[test]
    #[ignore = "manual: set SHELL_EXPLAIN_TEXT"]
    fn dump() {
        let text = std::env::var("SHELL_EXPLAIN_TEXT").unwrap_or_default();
        let e = core::explain(&text, &SystemMan::new(MAN_LIMIT));
        if let Ok(path) = std::env::var("SHELL_EXPLAIN_JSON") {
            std::fs::write(path, serde_json::to_string(&e).unwrap_or_default()).unwrap_or_default();
        }
        fn show(e: &Explanation, depth: usize) {
            let pad = "  ".repeat(depth);
            for n in &e.notes {
                println!("{pad}NOTE {n}");
            }
            for i in &e.items {
                println!(
                    "{pad}[{:?}{}] {}",
                    i.kind,
                    if i.warn { " WARN" } else { "" },
                    i.label
                );
                for en in &i.entries {
                    println!("{pad}    {:?} {} :: {}", en.source, en.term, en.text);
                }
                for n in &i.nested {
                    println!("{pad}  >> {}", n.label);
                    show(&n.explanation, depth + 2);
                }
            }
        }
        show(&e, 0);
    }
}
