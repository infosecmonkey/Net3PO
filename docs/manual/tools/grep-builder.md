# Grep Builder

> Build a correctly quoted `grep` command or pipeline from match and exclude patterns, and preview which sample lines it keeps.

**Sidebar group:** Utilities · **Works offline:** yes · **Needs admin rights:** no

## When to use it

- Write a one-liner to pull denied sessions for one subnet out of a large firewall or syslog file on a jump host.
- Combine several conditions (this AND that, NOT the other) without getting the pipe order or quoting wrong.
- Check that a pattern works in BSD grep on macOS as well as GNU grep on Linux, or find out it needs `-P`.
- Hand a colleague a command that searches a config tree recursively while skipping `.git` and compressed files.

## Quick start

1. Open **Grep Builder**. If you came from [Regex Builder](regex-builder.md) with **Open in Grep Builder**, the pattern and mode are already filled in.
2. Pick a **Mode** (Basic, Extended, Perl or Fixed) and a **Target** (GNU grep or BSD grep).
3. Type the first pattern. Add more with **+ Match** or **+ Exclude**. With two or more match patterns, choose **All (AND)** or **Any (OR)**.
4. Enter the file or directory in **Files or paths**.
5. Set flags, context lines and include or exclude globs as needed.
6. Paste sample lines into the **Preview** box and check what is kept.
7. Read any warnings, then click **Copy** to copy the command.

## Inputs and options

| Field | What it means | Default / accepted values |
|---|---|---|
| Mode | **Basic (-G)**: BRE, grep's default, no flag written. **Extended (-E)**: ERE. **Perl (-P)**: PCRE, lookaround and backrefs. **Fixed (-F)**: literal text, no regex. | Extended |
| Target | **GNU grep (Linux)** or **BSD grep (macOS)**. Drives compatibility warnings only. | GNU grep |
| Patterns | Each row is **Match** (keep lines that match) or **Exclude** (drop lines that match). The x button removes a row. Empty rows are ignored. | One empty Match row |
| All (AND) / Any (OR) | Shown with two or more match patterns. AND builds one grep stage per pattern, joined with pipes. OR puts all match patterns in one grep with repeated `-e`. | All (AND) |
| Files or paths | Files or directories, separated by spaces. Each is quoted for the shell only when needed. | Empty (reads stdin) |
| ignore case (-i) | Case-insensitive. Applied to every stage. | Off |
| word match (-w) | Pattern must match a whole word. Every stage. | Off |
| whole line (-x) | Pattern must match the whole line. Every stage. | Off |
| only matching (-o) | Print only the matched text. First stage only. | Off |
| line numbers (-n) | Prefix line numbers. First stage only. | On |
| count (-c) | Print a count instead of lines. Last stage only. | Off |
| files only (-l) | Print file names that match. First stage only. | Off |
| recursive (-r) | Search directories. With no path given, `.` is added. | Off |
| skip binary (-I) | Ignore binary files. First stage. | Off |
| color | Adds `--color=auto` on the last stage. | Off |
| file names | **auto** (grep default), **always (-H)**, **never (-h)**. First stage. | auto |
| before (-B), after (-A), context (-C) | Context lines around matches. If context is set, it replaces before and after. First stage. | 0 |
| --include, --exclude, --exclude-dir | Globs or directory names, separated by commas or spaces. Each becomes its own `--include=...` (and so on) option, quoted when needed. | Empty |

Excludes always run last, in one `grep -v -e A -e B` stage. A single pattern is written bare and single-quoted. A pattern starting with `-` gets `-e` so grep does not read it as an option.

## Reading the results

1. **Command box**: the full command or pipeline, with a **Copy** button.
2. **Warnings** (when a pattern is present), for example:
   - "BSD grep (macOS default) has no -P. Install GNU grep (brew install grep, run as ggrep) or use -E."
   - "Pattern 1 uses \d (use [0-9]), which grep -E does not support. Switch to Perl (-P)." Similar warnings flag lookahead, lookbehind, named groups, non-capturing groups, lazy quantifiers, `\K` and other inline `(?...)` syntax in Basic or Extended mode.
   - "Excludes apply after the OR: (A or B) and not C."
   - "Later stages see the file:line: prefix the first stage adds, so ^ anchors and -x there will not line up."
   - Notes that `-l`, `-o`, context lines and `-c` change what later pipeline stages see.
3. **Preview**: "N of M lines kept", the sample box with match patterns highlighted in kept lines, and an **Output** list of kept lines (with line numbers if **line numbers** is on). Up to 500 output lines are listed.

### Worked example

Mode Extended, target GNU, line numbers on, path `/var/log/fortigate.log`, and three patterns:

- Match `deny`
- Match `srcip=192\.0\.2\.`
- Exclude `dstport=53`

With **All (AND)** the command is:

```
grep -En 'deny' /var/log/fortigate.log | grep -E 'srcip=192\.0\.2\.' | grep -Ev 'dstport=53'
```

The warning about the `file:line:` prefix appears because `-n` adds `123:` to each line before the later stages see it. That is harmless here, but a later `^srcip` anchor would fail.

With **Any (OR)** the command becomes:

```
grep -En -e 'deny' -e 'srcip=192\.0\.2\.' /var/log/fortigate.log | grep -Ev 'dstport=53'
```

and the "Excludes apply after the OR" warning appears.

Preview sample:

```
action="deny" srcip=192.0.2.10 dstip=198.51.100.20 dstport=443
action="deny" srcip=192.0.2.11 dstip=198.51.100.53 dstport=53
action="accept" srcip=192.0.2.12 dstip=198.51.100.20 dstport=443
```

With AND, the preview shows "1 of 3 lines kept" (line 1). With OR, it shows "2 of 3 lines kept" (lines 1 and 3; line 2 is dropped by the exclude).

## What the results do and do not tell you

- The preview runs the same engines as [Regex Builder](regex-builder.md), line by line. Basic mode is translated to extended syntax for the preview; Fixed mode is matched literally. Real grep implementations can still differ on edge cases.
- `-o`, `-c`, `-l` and context lines are not simulated. The preview shows which lines the patterns keep, not grep's exact output.
- The tool builds a command; it does not run grep or read your files.
- Paths are split on spaces, so a path that contains a space cannot be entered as one path. Edit the copied command by hand in that case.
- Sample text is limited to 1,000,000 bytes, and up to 1,000 highlights are shown.

## Online activity and privacy

None. Nothing is sent anywhere, and patterns and sample text are not saved. See [Privacy](../privacy.md).

## Export and projects

This tool has no Export menu and no "Add to project". Copy the command with **Copy**. You can keep notes about the work in the project notes panel docked beside every tool; see [Projects and notes](../projects-and-notes.md).

## Platform notes

The app works the same on every OS, but the command is for a POSIX shell with GNU or BSD grep. macOS ships BSD grep (no `-P`); Linux ships GNU grep. Windows has no grep by default; run the command in WSL or another environment that provides grep. Shell quoting uses single quotes, which `cmd.exe` and PowerShell do not treat the same way.

## Troubleshooting

**"Add a pattern to build a command."** All pattern rows are empty.

**"pattern N: invalid pattern: ..."** Pattern N does not compile in the preview engine for this mode. Fix the syntax, or switch to Perl (-P) if it uses lookaround or backreferences.

**"pattern N: backtrack limit exceeded ..."** A Perl-mode pattern backtracked too much on the sample. Make it more specific.

**"sample text is too large ..."** Paste a smaller sample.

**The command works on Linux but not on a Mac.** Set **Target** to BSD grep and read the warnings. `-P` is not available in BSD grep.

## Related tools

- [Regex Builder](regex-builder.md)
- [Filter Builder](filter-builder.md)
- [Syslog Server](syslog-server.md)
- [Event Log](event-log.md)
- [SSH](ssh.md)
