# MEMORY.md

# bashguard project memory

## Project
/Users/sunir/source/colony/bashguard — Python library + CLI for sandboxing LLM bash commands.
(Note: old path `/Users/sunir/source/bashguard` is stale — it moved into colony monorepo)

## Architecture

Single package: `bashguard/`
- `parser.py` — tree-sitter parser → `CommandNode` (name, args, flags, redirect_targets)
- `models.py` — frozen dataclasses: Finding, ExecutionContext, Verdict + Severity/VerdictType enums
- `rules/` — Rule protocol + @register decorator + 74 built-in rules
- `auditor.py` — `audit(script, ctx, rules=None)` → `list[Finding]`
- `policy.py` — `decide(findings, ctx, config)` → `Verdict` (PURE FUNCTION)
- `context.py` — `make_context()` builds ExecutionContext from env
- `cli.py` — `bashguard` CLI (data-grammar). Hook + analyze + run + log + stats modes.
- `grammar.bnf` — data-grammar BNF for CLI
- `types.py` — data-grammar Python types (Entry, AnalyzeScript, RunScript, LogQuery, StatsQuery, Output)

## CLI modes (2026-07-09 current)
- `bashguard hook` — Claude PreToolUse hook: reads JSON stdin, emits gates-compatible JSON or silent allow
- `bashguard analyze -c 'cmd'` — full JSON audit report (debug)
- `bashguard run -c 'cmd'` — **tilde-exec pattern**: audit + run in seatbelt sandbox, returns `{verdict, exit_code, stdout, stderr}`. Block exits 2, confirm exits 1, allow exits with command's exit code.
- `bashguard log [--verdict V] [--rule R] [-n N] [--json]` — query JSONL audit log
- `bashguard stats [--days N] [--json]` — aggregate audit statistics
- `bashguard approve/revoke <rule_id>` — session approval cache
- `bashguard claude setup` — install hook symlinks

## Rules (75 registered, 1308 tests passing — 2026-07-09)

### Core detection
- `parse.error_node` — malformed/obfuscated commands (HIGH)
- `credentials.privileged_path` — ~/.ssh, ~/.aws, /etc, .env (CRITICAL)
- `credentials.cloud_secret` — aws secretsmanager, gcloud secrets, vault, kubectl get secret (CRITICAL)
- `credentials.keychain` — macOS keychain access (CRITICAL)
- `network.unknown_host` — curl/wget/nc to unknown hosts (CRITICAL)
- `network.dev_tcp` — /dev/tcp bash trick (CRITICAL)
- `network.port_scan` — nmap/masscan recon (HIGH)
- `network.socat_shell` — socat shell relay (CRITICAL)
- `network.route_tamper` — ip route / iptables changes (HIGH)
- `network.firewall_tamper` — iptables/ufw/firewalld changes (HIGH)
- `network.public_disclosure` — posting to public APIs (HIGH)
- `destructive.irreversible` — rm -rf (non-/tmp), dd, mkfs, shred (HIGH/CRITICAL)
- `destructive.disk_copy` — dd/cat/strings/hexdump on raw /dev/sda* (HIGH/CRITICAL)
- `package_install.global` — brew/apt/npm -g (HIGH)
- `package_install.publish` — npm publish/unpublish (CRITICAL)
- `package.local_install` — pip install from local path (HIGH)
- `git.destructive` — force push, reset --hard, branch -D (HIGH/CRITICAL)
- `git.history_rewrite` — filter-branch, remote set-url (HIGH)
- `git.hook_inject` — write/chmod to .git/hooks/ (CRITICAL)
- `paths.protected_write` — write to /etc /usr /sys /proc /boot /bin /sbin /lib /dev /opt /usr/local/bin (HIGH)

### Evasion (all CRITICAL unless noted)
- `evasion.eval`, `evasion.shell_in_shell`, `evasion.interpreter_shell`
- `evasion.source`, `evasion.exec_shell`, `evasion.alias`, `evasion.coproc`
- `evasion.pipe_to_shell`, `evasion.process_sub_exec`
- `evasion.dangerous_env` — LD_PRELOAD, PYTHONSTARTUP, PYTHONPATH, NODE_OPTIONS, RUBYLIB, etc.
- `evasion.decode_pipeline`, `evasion.dynamic_command_name`, `evasion.ifs_manipulation`
- `evasion.ldconfig_inject` — ldconfig /tmp path injects linker cache
- `evasion.log_tamper` — clearing /var/log, history
- `evasion.ansi_c_escape`, `evasion.heredoc_interpreter`, `evasion.shellshock`
- `evasion.function_shadow`, `evasion.glob_command_name`, `evasion.xargs_shell`
- `evasion.path_traversal`, `evasion.proc_root_bypass`, `evasion.anti_forensics`
- `evasion.agent_spawn` — spawning sub-agents

### Persistence
- `persistence.backdoor_account`, `persistence.service_enable`, `persistence.at_job`
- `persistence.ssh_key_deploy`, `persistence.boot_entry` — LaunchAgents, systemd units, autostart
- `persistence.local_bin_shadow` — write to ~/.local/bin/, ~/bin/
- `persistence.shell_rc_inject` — write to ~/.bashrc, ~/.zshrc, ~/.profile, etc.
- `persistence.cron_install`

### Supply chain / test tampering
- `test_harness.conftest_inject` — pytest hookimpl forces tests to "passed"
- `test_harness.site_packages_inject` — monkey-patches installed libs
- `ci.workflow_inject` — write to .github/workflows/, Jenkinsfile, etc.
- `supply_chain.pkg_mirror_redirect` — pip/npm/yarn/gem registry redirect
- `supply_chain.pkg_config_inject` — write to ~/.npmrc, ~/.pip/pip.conf

### Process / system
- `proc.gcore_dump`, `proc.process_inject`, `proc.credential_scrape`
- `proc.xinput_keylogger`, `proc.osascript_abuse`
- `system.kernel_module`, `system.sysctl_write`
- `privesc.suid_chmod`, `privesc.setcap`, `privesc.sudo_shell`
- `container.escape` — --privileged, --pid=host, --net=host

### Other
- `exec.forbidden_binary` (HIGH, added 2026-05-06) — binaries with no legitimate LLM coding use:
  - Offensive tools: msfconsole, sqlmap, hashcat, aircrack-ng, hydra, responder, volatility
  - GUI apps: zathura, gimp, wireshark, xdotool
  - Legacy/exotic: debugfs, crash, jrunscript, jjs, rtorrent
- `sql.destructive` — DROP DATABASE/TABLE, TRUNCATE, bulk DELETE
- `tunnel.service` — ngrok, localtunnel, serveo
- `mining.detected` — xmrig, minerd, cpuminer + 6 more
- `comms` — sendmail, mutt, Slack/Discord/Teams webhooks
- `self_protection` — modification of bashguard config/rule/core files blocked
- Content inspection: `content.secret_in_args`, `content.exfiltration_pattern`, `content.outside_boundary`

## ActionType enum (15 types)
FILESYSTEM_READ, FILESYSTEM_WRITE, FILESYSTEM_DELETE, FILESYSTEM_MOVE,
NETWORK_OUTBOUND, GIT_SAFE, GIT_DESTRUCTIVE, PACKAGE_INSTALL, LANG_EXEC,
PROCESS_SIGNAL, ENV_MUTATION, OBFUSCATED, CREDENTIAL_ACCESS, SYSTEM_CONFIG, UNKNOWN

## Shared-repo worktree guard (2026-07-09)
- `09-shared-repo-worktree-guard` hook — blocks branch-mutating git in main working dir of shared repos (system, heuristics)
- Worktrees (.git FILE) and non-shared repos always allowed
- Shipped to system main (PR #2 merged 2026-07-09), auto-distributed to all agents via 05-system-sync at next Stop
- Source: `/var/db/ai/claude/prod/bashguard/hooks/09-shared-repo-worktree-guard`
- Symlink at `~/.claude/hooks/PreToolUse.d/system/09-shared-repo-worktree-guard`

## Colony deploy chain (verified 2026-07-09)
Merge to main → post-merge hook fires → `production` branch advances → `/var/db/ai/claude/prod/<repo>` resets → `05-system-sync` Stop hook distributes `PreToolUse.d/system/0X-*` to all member repos at next session end. Zero-touch for colony-wide rollout.

## P11 roadmap — next milestone (2026-07-09)
**CONTRACT ENFORCEMENT**: PreToolUse hook enforcing /contract BOUNDARIES. Blocked on:
1. the_management's decision: canonical compiled directory path (suggested: `the_management/contracts/directory.json`) + refresh mechanism (cupdate/colony-setup)
2. the_management@ocean (twin) P11 milestone definition
Sysop confirmed `colony-contracts` schema is stable. Do NOT start story until both answers arrive.

## Defense-in-depth stack (on ALLOW verdict)
1. **Rule audit** — semantic detection (75 rules)
2. **Credential injection** — `bashguard/credentials.py`. Substitutes `{{KEY}}` placeholders. Real secrets never in Claude's context.
3. **Seatbelt** — `bashguard/seatbelt.py`. `sandbox-exec -f profile.sb /bin/bash -c cmd`. Deny-default SBPL. Disable with `BASHGUARD_SEATBELT=0`.
4. **FUSE shadow FS** — CoW overlay via FUSE-T (spike — not production, lives in `spike/`). Writes captured in memory, real dir untouched.

## Key design decisions
- Detection orthogonal to response: rules → Findings, policy → Verdict
- All models frozen=True (immutable)
- Rule.check() must never raise — return [] on exception
- allowed_hosts: exact match only, no wildcards
- venv at `.venv/`, run tests with `.venv/bin/python -m pytest` (NOT `.venv/bin/pytest` — shebang broken)
- `python -m bashguard.cli` broken (data_grammar pth path stale). Use `bashguard` binary or `shutil.which("bashguard")` in tests.
- tree-sitter-bash wraps command name in `command_name` node — use `_unwrap_cmd_name()` helper
- coproc parsed as plain command — detect via cmd.name == "coproc"
- `rules/` dir is in .gitignore — use `git add -f` when committing rule changes
- Cannot commit directly to main — must branch + merge (pre-commit hook enforces)

## data-grammar lesson
Tokenless method chains NEVER fire. Do full pipeline work inside each token-consuming method.
Exception: `__str__` methods work because `@end` fires and calls str(current_object).
New CLI types must be registered in `_TYPES` dict in `cli.py` or the grammar can't instantiate them.
New data-grammar validates `--flag` literals must be in `Flags < stdlib.Flags` subtypes. Use
`# compile:allow flag-outside-flags` pragma in grammar.bnf when flags are intentional data
selectors (e.g. --command, --days, --verdict are query params, not meta-flags). The method
return type must also have a grammar rule — anonymous local classes won't work as return types.

## Colony integration
- `~/.claude/hooks/PreToolUse.d/system/70-bashguard` → global symlink to prod hook
- Deployed via auto-deploy on merge to main (production worktree)
- EXIT CODE 2 = block (colony dispatcher reads exit code, not JSON stdout)

## Tilde-inspired run mode (added 2026-05-06)
`bashguard run -c 'cmd'` — audit + execute in seatbelt, structured JSON output.
Stolen from tilde.run (tilde-exec pattern). Lets callers use bashguard as executor
not just interceptor. Exit code propagates from executed command.


# MEMORY.md

# bashguard project memory

## Project
/Users/sunir/source/colony/bashguard — Python library + CLI for sandboxing LLM bash commands.
(Note: old path `/Users/sunir/source/bashguard` is stale — it moved into colony monorepo)

## Architecture

Single package: `bashguard/`
- `parser.py` — tree-sitter parser → `CommandNode` (name, args, flags, redirect_targets)
- `models.py` — frozen dataclasses: Finding, ExecutionContext, Verdict + Severity/VerdictType enums
- `rules/` — Rule protocol + @register decorator + 74 built-in rules
- `auditor.py` — `audit(script, ctx, rules=None)` → `list[Finding]`
- `policy.py` — `decide(findings, ctx, config)` → `Verdict` (PURE FUNCTION)
- `context.py` — `make_context()` builds ExecutionContext from env
- `cli.py` — `bashguard` CLI (data-grammar). Hook + analyze + run + log + stats modes.
- `grammar.bnf` — data-grammar BNF for CLI
- `types.py` — data-grammar Python types (Entry, AnalyzeScript, RunScript, LogQuery, StatsQuery, Output)

## CLI modes (2026-07-09 current)
- `bashguard hook` — Claude PreToolUse hook: reads JSON stdin, emits gates-compatible JSON or silent allow
- `bashguard analyze -c 'cmd'` — full JSON audit report (debug)
- `bashguard run -c 'cmd'` — **tilde-exec pattern**: audit + run in seatbelt sandbox, returns `{verdict, exit_code, stdout, stderr}`. Block exits 2, confirm exits 1, allow exits with command's exit code.
- `bashguard log [--verdict V] [--rule R] [-n N] [--json]` — query JSONL audit log
- `bashguard stats [--days N] [--json]` — aggregate audit statistics
- `bashguard approve/revoke <rule_id>` — session approval cache
- `bashguard claude setup` — install hook symlinks

## Rules (75 registered, 1308 tests passing — 2026-07-09)

### Core detection
- `parse.error_node` — malformed/obfuscated commands (HIGH)
- `credentials.privileged_path` — ~/.ssh, ~/.aws, /etc, .env (CRITICAL)
- `credentials.cloud_secret` — aws secretsmanager, gcloud secrets, vault, kubectl get secret (CRITICAL)
- `credentials.keychain` — macOS keychain access (CRITICAL)
- `network.unknown_host` — curl/wget/nc to unknown hosts (CRITICAL)
- `network.dev_tcp` — /dev/tcp bash trick (CRITICAL)
- `network.port_scan` — nmap/masscan recon (HIGH)
- `network.socat_shell` — socat shell relay (CRITICAL)
- `network.route_tamper` — ip route / iptables changes (HIGH)
- `network.firewall_tamper` — iptables/ufw/firewalld changes (HIGH)
- `network.public_disclosure` — posting to public APIs (HIGH)
- `destructive.irreversible` — rm -rf (non-/tmp), dd, mkfs, shred (HIGH/CRITICAL)
- `destructive.disk_copy` — dd/cat/strings/hexdump on raw /dev/sda* (HIGH/CRITICAL)
- `package_install.global` — brew/apt/npm -g (HIGH)
- `package_install.publish` — npm publish/unpublish (CRITICAL)
- `package.local_install` — pip install from local path (HIGH)
- `git.destructive` — force push, reset --hard, branch -D (HIGH/CRITICAL)
- `git.history_rewrite` — filter-branch, remote set-url (HIGH)
- `git.hook_inject` — write/chmod to .git/hooks/ (CRITICAL)
- `paths.protected_write` — write to /etc /usr /sys /proc /boot /bin /sbin /lib /dev /opt /usr/local/bin (HIGH)

### Evasion (all CRITICAL unless noted)
- `evasion.eval`, `evasion.shell_in_shell`, `evasion.interpreter_shell`
- `evasion.source`, `evasion.exec_shell`, `evasion.alias`, `evasion.coproc`
- `evasion.pipe_to_shell`, `evasion.process_sub_exec`
- `evasion.dangerous_env` — LD_PRELOAD, PYTHONSTARTUP, PYTHONPATH, NODE_OPTIONS, RUBYLIB, etc.
- `evasion.decode_pipeline`, `evasion.dynamic_command_name`, `evasion.ifs_manipulation`
- `evasion.ldconfig_inject` — ldconfig /tmp path injects linker cache
- `evasion.log_tamper` — clearing /var/log, history
- `evasion.ansi_c_escape`, `evasion.heredoc_interpreter`, `evasion.shellshock`
- `evasion.function_shadow`, `evasion.glob_command_name`, `evasion.xargs_shell`
- `evasion.path_traversal`, `evasion.proc_root_bypass`, `evasion.anti_forensics`
- `evasion.agent_spawn` — spawning sub-agents

### Persistence
- `persistence.backdoor_account`, `persistence.service_enable`, `persistence.at_job`
- `persistence.ssh_key_deploy`, `persistence.boot_entry` — LaunchAgents, systemd units, autostart
- `persistence.local_bin_shadow` — write to ~/.local/bin/, ~/bin/
- `persistence.shell_rc_inject` — write to ~/.bashrc, ~/.zshrc, ~/.profile, etc.
- `persistence.cron_install`

### Supply chain / test tampering
- `test_harness.conftest_inject` — pytest hookimpl forces tests to "passed"
- `test_harness.site_packages_inject` — monkey-patches installed libs
- `ci.workflow_inject` — write to .github/workflows/, Jenkinsfile, etc.
- `supply_chain.pkg_mirror_redirect` — pip/npm/yarn/gem registry redirect
- `supply_chain.pkg_config_inject` — write to ~/.npmrc, ~/.pip/pip.conf

### Process / system
- `proc.gcore_dump`, `proc.process_inject`, `proc.credential_scrape`
- `proc.xinput_keylogger`, `proc.osascript_abuse`
- `system.kernel_module`, `system.sysctl_write`
- `privesc.suid_chmod`, `privesc.setcap`, `privesc.sudo_shell`
- `container.escape` — --privileged, --pid=host, --net=host

### Other
- `exec.forbidden_binary` (HIGH, added 2026-05-06) — binaries with no legitimate LLM coding use:
  - Offensive tools: msfconsole, sqlmap, hashcat, aircrack-ng, hydra, responder, volatility
  - GUI apps: zathura, gimp, wireshark, xdotool
  - Legacy/exotic: debugfs, crash, jrunscript, jjs, rtorrent
- `sql.destructive` — DROP DATABASE/TABLE, TRUNCATE, bulk DELETE
- `tunnel.service` — ngrok, localtunnel, serveo
- `mining.detected` — xmrig, minerd, cpuminer + 6 more
- `comms` — sendmail, mutt, Slack/Discord/Teams webhooks
- `self_protection` — modification of bashguard config/rule/core files blocked
- Content inspection: `content.secret_in_args`, `content.exfiltration_pattern`, `content.outside_boundary`

## ActionType enum (15 types)
FILESYSTEM_READ, FILESYSTEM_WRITE, FILESYSTEM_DELETE, FILESYSTEM_MOVE,
NETWORK_OUTBOUND, GIT_SAFE, GIT_DESTRUCTIVE, PACKAGE_INSTALL, LANG_EXEC,
PROCESS_SIGNAL, ENV_MUTATION, OBFUSCATED, CREDENTIAL_ACCESS, SYSTEM_CONFIG, UNKNOWN

## Shared-repo worktree guard (2026-07-09)
- `09-shared-repo-worktree-guard` hook — blocks branch-mutating git in main working dir of shared repos (system, heuristics)
- Worktrees (.git FILE) and non-shared repos always allowed
- Shipped to system main (PR #2 merged 2026-07-09), auto-distributed to all agents via 05-system-sync at next Stop
- Source: `/var/db/ai/claude/prod/bashguard/hooks/09-shared-repo-worktree-guard`
- Symlink at `~/.claude/hooks/PreToolUse.d/system/09-shared-repo-worktree-guard`

## Colony deploy chain (verified 2026-07-09)
Merge to main → post-merge hook fires → `production` branch advances → `/var/db/ai/claude/prod/<repo>` resets → `05-system-sync` Stop hook distributes `PreToolUse.d/system/0X-*` to all member repos at next session end. Zero-touch for colony-wide rollout.

## P11 roadmap — next milestone (2026-07-09)
**CONTRACT ENFORCEMENT**: PreToolUse hook enforcing /contract BOUNDARIES. Blocked on:
1. the_management's decision: canonical compiled directory path (suggested: `the_management/contracts/directory.json`) + refresh mechanism (cupdate/colony-setup)
2. the_management@ocean (twin) P11 milestone definition
Sysop confirmed `colony-contracts` schema is stable. Do NOT start story until both answers arrive.

## Defense-in-depth stack (on ALLOW verdict)
1. **Rule audit** — semantic detection (75 rules)
2. **Credential injection** — `bashguard/credentials.py`. Substitutes `{{KEY}}` placeholders. Real secrets never in Claude's context.
3. **Seatbelt** — `bashguard/seatbelt.py`. `sandbox-exec -f profile.sb /bin/bash -c cmd`. Deny-default SBPL. Disable with `BASHGUARD_SEATBELT=0`.
4. **FUSE shadow FS** — CoW overlay via FUSE-T (spike — not production, lives in `spike/`). Writes captured in memory, real dir untouched.

## Key design decisions
- Detection orthogonal to response: rules → Findings, policy → Verdict
- All models frozen=True (immutable)
- Rule.check() must never raise — return [] on exception
- allowed_hosts: exact match only, no wildcards
- venv at `.venv/`, run tests with `.venv/bin/python -m pytest` (NOT `.venv/bin/pytest` — shebang broken)
- `python -m bashguard.cli` broken (data_grammar pth path stale). Use `bashguard` binary or `shutil.which("bashguard")` in tests.
- tree-sitter-bash wraps command name in `command_name` node — use `_unwrap_cmd_name()` helper
- coproc parsed as plain command — detect via cmd.name == "coproc"
- `rules/` dir is in .gitignore — use `git add -f` when committing rule changes
- Cannot commit directly to main — must branch + merge (pre-commit hook enforces)

## data-grammar lesson
Tokenless method chains NEVER fire. Do full pipeline work inside each token-consuming method.
Exception: `__str__` methods work because `@end` fires and calls str(current_object).
New CLI types must be registered in `_TYPES` dict in `cli.py` or the grammar can't instantiate them.
New data-grammar validates `--flag` literals must be in `Flags < stdlib.Flags` subtypes. Use
`# compile:allow flag-outside-flags` pragma in grammar.bnf when flags are intentional data
selectors (e.g. --command, --days, --verdict are query params, not meta-flags). The method
return type must also have a grammar rule — anonymous local classes won't work as return types.

## Colony integration
- `~/.claude/hooks/PreToolUse.d/system/70-bashguard` → global symlink to prod hook
- Deployed via auto-deploy on merge to main (production worktree)
- EXIT CODE 2 = block (colony dispatcher reads exit code, not JSON stdout)

## Tilde-inspired run mode (added 2026-05-06)
`bashguard run -c 'cmd'` — audit + execute in seatbelt, structured JSON output.
Stolen from tilde.run (tilde-exec pattern). Lets callers use bashguard as executor
not just interceptor. Exit code propagates from executed command.


# feedback_msg_proactive.md

---
name: proactive messaging
description: Send messages to other agents proactively whenever there's useful information to share — don't wait for user to ask
type: feedback
---

msg send to any agent anytime there's something useful to communicate. Don't ask permission. "If you can improve the silence, speak."

**Why:** User values proactive inter-agent communication. Waiting for explicit instruction wastes coordination opportunities.

**How to apply:** When working on bashguard and discovering integration points, bugs, or useful information for other repos (qa, prompt, colony, etc.), send the message immediately.


# feedback_todo_push_cleanup.md

---
name: todo push cleanup requires filter taken
description: todo push auto-taken items stay in taken state after merge; run todo filter taken to trigger cleanup
type: feedback
---

When using `todo push 'Task'` in bashguard, the item is auto-taken and exported to Claude Code tasks as in_progress. After the work is done and merged, the item disappears from `.todo.json` but the stop hook may still see "Incomplete: 1 in progress".

**Why:** The `todo push` item enters a `[close]` transitional state. Running `todo filter taken` triggers cleanup of close-state items and clears the status.

**How to apply:** After completing a `todo push` task, run `todo filter taken` to confirm the item is cleared. If it shows with `[close]` prefix, running the command again or waiting resolves it. The stop hook "Incomplete: 1 in progress" is caused by this stale state, not by actual unfinished work.


# project_qa_integration.md

---
name: qa integration for script validation
description: qa tool should use bashguard to validate shellexec commands it detects in source code, not bashguard reading scripts itself
type: project
---

Instead of bashguard doing expensive runtime script file inspection, integrate with qa tool (/Users/sunir/source/qa/).

**Why:** bashguard guards the bash boundary but can't see inside `python script.py`. qa already does code graph scanning with a cache (850 tests). qa finds shellexec calls (os.system, subprocess.run, exec, backticks), extracts command strings, pipes them through `bashguard analyze -c`. Results cached — only re-scanned on source change.

**How to apply:** Don't build recursive file inspection inside bashguard. Keep bashguard fast and focused on bash validation. Integration surface: `bashguard analyze --command '...'` → JSON response. No library coupling needed.

**Threat model:** idiot agents, not malicious agents. Simple pattern scanning catches confused LLMs that write destructive scripts. Adversarial evasion is unbounded.


# reference_n2ark.md

---
name: n2-ark reference
description: n2-ark (choihyunsus/n2-ark) is a JS AI firewall — features already borrowed into bashguard
type: reference
---

https://github.com/choihyunsus/n2-ark — JS/Node AI firewall with .n2 rule DSL.

Features borrowed (2026-03-21):
- Self-protection (triple-layer defense)
- External comms blocking (email/SMS/webhook)
- Audit statistics
- Strict mode (allowlist-only)

Features NOT borrowed (not needed or different approach):
- .n2 DSL — bashguard uses .bashguard.yaml + Python rules
- State machine contracts — may be useful later for deploy sequences
- MCP server mode — bashguard uses Claude hooks, not MCP
- Domain-specific rule packs (financial, medical, military) — future potential


