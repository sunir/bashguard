# MEMORY.md

# bashguard project memory

## Project
`/Users/sunir/source/colony/bashguard` — Python library + CLI sandboxing LLM bash commands (colony monorepo).

## Architecture
- `parser.py` → `CommandNode`; `models.py` → Finding/ExecutionContext/Verdict (frozen); `rules/` → 75 rules via @register; `auditor.py` → `audit()`; `policy.py` → `decide()` (pure); `context.py` → `make_context()`; `cli.py` → data-grammar CLI; `grammar.bnf`, `types.py`
- CLI modes: `hook` (PreToolUse), `analyze`, `run` (tilde-exec: audit+seatbelt), `log`, `stats`, `approve/revoke`, `launch` (session-level sandbox-exec), `claude setup`
- Defense stack: rule audit → credential injection → seatbelt (sandbox-exec, deny-default) → FUSE shadow FS (spike only)
- EXIT CODE 2 = block; 1 = confirm; 0 = allow. Colony dispatcher reads exit code, not JSON stdout.

## Rules
76 rules, 1336 tests (2026-07-09 session 4). Full inventory: [[rules-inventory]]
Latest: `evasion.vim_shell` (HIGH) — vim/vi/view/ex/nvim -c ':!cmd', --cmd ':shell', +shell, +!cmd shell escapes. Plain `vim file.txt` allowed.

## Key gotchas
- `rules/` in .gitignore — use `git add -f` to commit rule changes
- Cannot commit to main directly — branch + PR enforced by pre-commit hook
- Run tests with `.venv/bin/python -m pytest` (NOT `.venv/bin/pytest` — shebang broken)
- `python -m bashguard.cli` broken (stale pth). Use `bashguard` binary or `shutil.which("bashguard")` in tests
- tree-sitter-bash wraps cmd name in `command_name` node — use `_unwrap_cmd_name()` helper
- coproc parsed as plain command — detect via `cmd.name == "coproc"`
- `_extract_path(arg)` strips `key=value` prefix for dd-style args (credentials.privileged_path)
- nc listen mode: `_is_nc_listen()` returns True when `-l` in flags; `_extract_nc_host()` returns None in listen mode
- data-grammar lessons: [[data-grammar]]
- **Parser probe is step 1 for new rules.** Run `parse()` on inputs, print name/args/flags/raw before writing detection. `-c 'cmd'` → flags=['-c'], args=["':cmd'"] (args[0] is the ex-cmd with quotes intact). `+cmd` → in args directly with + prefix.

## Colony integration
- `~/.claude/hooks/PreToolUse.d/system/70-bashguard` → symlink to prod hook
- `~/.claude/hooks/PreToolUse.d/system/09-shared-repo-worktree-guard` → symlink to prod hook (shipped 2026-07-09)
- Deploy chain: merge to main → post-merge hook → `production` branch advances → prod worktree resets → `05-system-sync` distributes `PreToolUse.d/system/0X-*` to all members at next Stop
- `/var/db/ai/claude/prod/bashguard` — production worktree

## CONTRACT-ENFORCEMENT-HOOK — Layer 1 LIVE (2026-07-09)
- `hooks/11-contract-enforcement` deployed to production, reading `the_management/contracts/directory.json` (4 contracts: seeds)
- `hooks/lib/contract_path_check.py` — standalone module, no bashguard dep
- Rate-limited (PR #13): mtime lock files in `/tmp/bashguard-contract-rl/`, once per (actor,target) per 5-min. Key pattern: `_ratelimit_ok "violation-${ACTOR}-${TARGET}" 300`
- **Layer 2 (Haiku semantic)**: still pending — no blocking issue, just not started
- **Open question**: "deploy touching qa" — live violation or stale cwd-based detection? the_management investigating.
- **Rate-limit is mandatory for any PreToolUse hook that sends external alerts.** Fires per-tool-call = hundreds/session without dedup.


# MEMORY.md

# bashguard project memory

## Project
`/Users/sunir/source/colony/bashguard` — Python library + CLI sandboxing LLM bash commands (colony monorepo).

## Architecture
- `parser.py` → `CommandNode`; `models.py` → Finding/ExecutionContext/Verdict (frozen); `rules/` → 75 rules via @register; `auditor.py` → `audit()`; `policy.py` → `decide()` (pure); `context.py` → `make_context()`; `cli.py` → data-grammar CLI; `grammar.bnf`, `types.py`
- CLI modes: `hook` (PreToolUse), `analyze`, `run` (tilde-exec: audit+seatbelt), `log`, `stats`, `approve/revoke`, `launch` (session-level sandbox-exec), `claude setup`
- Defense stack: rule audit → credential injection → seatbelt (sandbox-exec, deny-default) → FUSE shadow FS (spike only)
- EXIT CODE 2 = block; 1 = confirm; 0 = allow. Colony dispatcher reads exit code, not JSON stdout.

## Rules
76 rules, 1336 tests (2026-07-09 session 4). Full inventory: [[rules-inventory]]
Latest: `evasion.vim_shell` (HIGH) — vim/vi/view/ex/nvim -c ':!cmd', --cmd ':shell', +shell, +!cmd shell escapes. Plain `vim file.txt` allowed.

## Key gotchas
- `rules/` in .gitignore — use `git add -f` to commit rule changes
- Cannot commit to main directly — branch + PR enforced by pre-commit hook
- Run tests with `.venv/bin/python -m pytest` (NOT `.venv/bin/pytest` — shebang broken)
- `python -m bashguard.cli` broken (stale pth). Use `bashguard` binary or `shutil.which("bashguard")` in tests
- tree-sitter-bash wraps cmd name in `command_name` node — use `_unwrap_cmd_name()` helper
- coproc parsed as plain command — detect via `cmd.name == "coproc"`
- `_extract_path(arg)` strips `key=value` prefix for dd-style args (credentials.privileged_path)
- nc listen mode: `_is_nc_listen()` returns True when `-l` in flags; `_extract_nc_host()` returns None in listen mode
- data-grammar lessons: [[data-grammar]]
- **Parser probe is step 1 for new rules.** Run `parse()` on inputs, print name/args/flags/raw before writing detection. `-c 'cmd'` → flags=['-c'], args=["':cmd'"] (args[0] is the ex-cmd with quotes intact). `+cmd` → in args directly with + prefix.

## Colony integration
- `~/.claude/hooks/PreToolUse.d/system/70-bashguard` → symlink to prod hook
- `~/.claude/hooks/PreToolUse.d/system/09-shared-repo-worktree-guard` → symlink to prod hook (shipped 2026-07-09)
- Deploy chain: merge to main → post-merge hook → `production` branch advances → prod worktree resets → `05-system-sync` distributes `PreToolUse.d/system/0X-*` to all members at next Stop
- `/var/db/ai/claude/prod/bashguard` — production worktree

## CONTRACT-ENFORCEMENT-HOOK — Layer 1 LIVE (2026-07-09)
- `hooks/11-contract-enforcement` deployed to production, reading `the_management/contracts/directory.json` (4 contracts: seeds)
- `hooks/lib/contract_path_check.py` — standalone module, no bashguard dep
- Rate-limited (PR #13): mtime lock files in `/tmp/bashguard-contract-rl/`, once per (actor,target) per 5-min. Key pattern: `_ratelimit_ok "violation-${ACTOR}-${TARGET}" 300`
- **Layer 2 (Haiku semantic)**: still pending — no blocking issue, just not started
- **Open question**: "deploy touching qa" — live violation or stale cwd-based detection? the_management investigating.
- **Rate-limit is mandatory for any PreToolUse hook that sends external alerts.** Fires per-tool-call = hundreds/session without dedup.


# data-grammar.md

---
name: data-grammar
description: "Gotchas and lessons from bashguard's data-grammar BNF CLI framework"
metadata: 
  node_type: memory
  type: feedback
  originSessionId: 6b49b1d3-3c6e-46dc-99ef-8e1a08b09364
---

Tokenless method chains NEVER fire — do full pipeline work inside each token-consuming method. Exception: `__str__` works because `@end` fires.

New CLI types must be registered in `_TYPES` dict in `cli.py` or the grammar can't instantiate them.

`--flag` literals must be in `Flags < stdlib.Flags` subtypes. Use `# compile:allow flag-outside-flags` pragma for intentional data selectors (--command, --days, --verdict are query params, not meta-flags).

Return type must have a grammar rule — anonymous local classes won't work.

**Why:** data-grammar is strict about token consumption and type registration; silent failures are the result of violating these invariants.
**How to apply:** always check _TYPES registration and grammar rule existence when adding new CLI modes.


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


# rules-inventory.md

---
name: rules-inventory
description: Full list of all 75 bashguard rules by category and rule_id
metadata: 
  node_type: memory
  type: reference
  originSessionId: 6b49b1d3-3c6e-46dc-99ef-8e1a08b09364
---

75 rules, 1308 tests (2026-07-09). Categories and rule_ids:

**Core detection:** parse.error_node, credentials.privileged_path, credentials.cloud_secret, credentials.keychain, network.unknown_host, network.dev_tcp, network.port_scan, network.socat_shell, network.route_tamper, network.firewall_tamper, network.public_disclosure, destructive.irreversible, destructive.disk_copy, package_install.global, package_install.publish, package.local_install, git.destructive, git.history_rewrite, git.hook_inject, paths.protected_write

**Evasion (27):** evasion.eval, shell_in_shell, interpreter_shell, source, exec_shell, alias, coproc, pipe_to_shell, process_sub_exec, dangerous_env, decode_pipeline, dynamic_command_name, ifs_manipulation, ldconfig_inject, log_tamper, ansi_c_escape, heredoc_interpreter, shellshock, function_shadow, glob_command_name, xargs_shell, path_traversal, proc_root_bypass, anti_forensics, agent_spawn, shell_via_tool (+tclsh/wish/expect in _SHELLS + _SCRIPT_INTERPS)

**Persistence (9):** persistence.backdoor_account, service_enable, at_job, ssh_key_deploy, boot_entry, local_bin_shadow, shell_rc_inject, cron_install + dd key=value path fix in credentials.privileged_path (_extract_path helper)

**Supply chain / test tampering:** test_harness.conftest_inject, site_packages_inject, ci.workflow_inject, supply_chain.pkg_mirror_redirect, pkg_config_inject

**Process / system:** proc.gcore_dump, process_inject, credential_scrape, xinput_keylogger, osascript_abuse, system.kernel_module, sysctl_write, privesc.suid_chmod, setcap, sudo_shell, container.escape

**Other:** exec.forbidden_binary (msfconsole/sqlmap/hashcat/aircrack-ng/hydra/responder/volatility + GUI + legacy), sql.destructive, tunnel.service, mining.detected, comms, self_protection, content.secret_in_args, exfiltration_pattern, outside_boundary


