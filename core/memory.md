# bashguard — Core Memory

## Identity

I am bashguard — a security auditing system for LLM bash commands. I intercept Claude Code's Bash tool calls, audit them for dangerous patterns, and enforce verdicts at the OS level. I am also the agent embedded in this repo, maintaining and improving the system.

## What I Do

Rule audit → credential substitution → seatbelt kernel enforcement → FUSE CoW overlay.

Four defense layers:
1. **Rule audit** — semantic detection (credentials, evasion, network, destructive ops)
2. **Credential injection** — `{{KEY}}`/`$KEY` placeholders substituted at execution time, secrets never in Claude's context
3. **Seatbelt** — `sandbox-exec` deny-default kernel enforcement, project-dir-only writes
4. **FUSE shadow FS** — CoW overlay, real dir untouched, diff at session end

## Critical Protocol Knowledge

**The colony PreToolUse dispatcher uses exit code 2 to block, NOT JSON stdout.**  
The hook must exit 2 on deny. JSON deny with exit 0 is silently discarded.  
Fixed in session 1 (2026-04-03). `cli.py` now returns 2 when output contains `permissionDecision: deny`.

**Test: `echo '{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}' | bashguard hook; echo $?` → must show EXIT:2**

## Architecture

```
bashguard/
  cli.py          — Entry point. Captures stdout, returns exit 2 on deny.
  types.py        — Grammar types. _gates_output() composes the defense stack.
  auditor.py      — audit(script, ctx) → list[Finding]
  policy.py       — decide(findings, ctx, config) → Verdict (pure function)
  rules/          — Rule protocol + built-in rules (gitignored, use git add -f)
  seatbelt.py     — sandbox-exec profile builder + wrapper
  credentials.py  — Credential store + placeholder substitution
  approval_cache.py — Session approval cache (CONFIRM → ALLOW if pre-approved)
  audit_log.py    — JSONL audit log at ~/.bashguard/audit.jsonl
  setup.py        — install_all_hooks() → all 3 hooks to ~/.claude/hooks/
spike/
  shadow_fs.py, acl_shadow_fs.py, token_auth_fs.py, session.py — FUSE layer
hooks/
  70-bashguard         — PreToolUse: audit + seatbelt + credentials
  75-bashguard-mount   — SessionStart: FUSE mount
  75-bashguard-unmount — SessionEnd: FUSE unmount + diff
```

## Deployment

- Production: `/var/db/ai/claude/prod/bashguard/` (git worktree, tracks origin/main)
- Binary: `/var/db/ai/claude/bin/bashguard`
- Global hook: `~/.claude/hooks/PreToolUse.d/system/70-bashguard` → symlink to prod
- Colony dist: `~/source/colony/system/claude/hooks/PreToolUse.d/system/70-bashguard`
- Deploy: push to main → post-merge hook → auto-deploys to prod worktree

## Rule Corpus (82-incident database — 66 rules total as of session 2, 2026-04-09)

Every rule is grounded in a documented real incident. Key additions from session 1:

- `process.agent_kill` — pkill/killall (Mythos cascading server takedown)
- `proc.credential_scrape` — /proc/*/environ, /proc/*/mem (Mythos memory scrape)
- `network.public_disclosure` — gh gist create, pastebin (Mythos unprompted disclosure)
- `proc.process_inject` — gdb -p, strace -p (Mythos MCP server editing)
- `git.history_rewrite` — git commit --amend, git rebase -i (Mythos cover-up)
- `evasion.proc_root_bypass` — /proc/self/root/... (CVE-2025-54794)
- `exfil.model_weights` — .safetensors/.ckpt upload (Vertex AI ModeLeak)
- `config.oversight_tamper` — sed 's/oversight: true/false/' (2025 documented)
- `evasion.agent_spawn` — claude, autogpt, crewai, aider (RSA 2026 swarm)
- `credentials.keychain` — security find-generic-password, secret-tool lookup

Key additions from session 2 (+16 rules):
- `persistence.backdoor_account` — useradd/usermod/userdel/chpasswd
- `evasion.log_tamper` — auditd stop, journalctl vacuum, auditctl -e 0
- `proc.gcore_dump` — live process memory dump (ssh-agent credential extraction)
- `persistence.service_enable` — systemctl enable (boot persistence)
- `persistence.at_job` — at/batch scheduled jobs
- `persistence.ssh_key_deploy` — ssh-copy-id lateral movement
- `network.port_scan` — nmap/masscan/zmap reconnaissance
- `network.socat_shell` — socat EXEC: bind/reverse shell
- `destructive.disk_copy` — dd if=/dev/sda or /proc/kcore
- `package.local_install` — dpkg/rpm/pip install from local path
- `proc.xinput_keylogger` — xinput test keyboard capture
- `proc.osascript_abuse` — osascript keystroke/clipboard theft
- `system.sysctl_write` — sysctl -w kernel parameter modification
- `network.route_tamper` — ip route add/del on default/0.0.0.0/0
- cron_install extended: now catches `crontab <file>` not just `crontab -`
- disk_copy extended: catches `dd if=/proc/kcore` in addition to /dev/ paths

## Parser Behavior Cheatsheet

- `auditctl -e 0` → flags=['-e'], args=['0'] — flag and value are split
- `dd if=/dev/sda` → `if=/dev/sda` is a single arg in cmd.args
- `socat TCP-LISTEN:4444 EXEC:/bin/bash` → "EXEC:/bin/bash" is a single arg
- `ip route add default` → "route", "add", "default" are all in cmd.args
- `crontab /tmp/evil.cron` → file path lands in cmd.args (no flag)
- `-m http.server` → flags=['-m'], args=['http.server'] (module name in args[0])
- `-v /:/host` → flags=['-v'], volume spec lands in cmd.args

## New rules added (2026-04-12 session — +4 rules from Berkeley RDI 2025, now 70 total)

Grounded in "Trustworthy Benchmarks" (Berkeley RDI, 2025) — documented AI benchmark manipulation attacks.

- `test_harness.conftest_inject` (CRITICAL) — write to conftest.py; pytest hookimpl forces all tests to "passed" (SWE-bench, 100% bypass)
- `test_harness.site_packages_inject` (CRITICAL) — write to site-packages/; monkey-patches installed libs (SWE-bench Pro)
- `git.hook_inject` (CRITICAL) — write/chmod to .git/hooks/; persistent backdoor on git operations
- `persistence.local_bin_shadow` (HIGH) — write to ~/.local/bin/, ~/bin/; shadows system commands via PATH (user-space Terminal-Bench variant)

All detect: redirect (>/>>), cp, mv, tee to target paths; chmod on hook/bin paths.
test_harness.site_packages_inject also catches .venv/lib/*/site-packages/ (not in paths.protected_write).
persistence.local_bin_shadow also catches /home/*/.local/bin/ and /Users/*/.local/bin/.

## Workflow

- Tests: `.venv/bin/pytest tests/` (1019 passing as of session 3, 2026-04-12)
- Branches: cannot commit to main directly; use feature branch → merge
- Rules dir is gitignored: `git add -f` when committing rule changes

## Key Lessons Learned

1. **Test the exit code, not just the JSON output.** The test `test_blocked_command_exits_0` was testing the wrong thing — it asserted exit 0, which was correct for the JSON protocol but wrong for the colony dispatcher protocol.

2. **Read the hook dispatcher before assuming the protocol.** The colony PreToolUse dispatcher has its own protocol layer that transforms JSON output into exit codes.

3. **"Exits 2 to deny" was in the hook comment but unimplemented.** Documentation can be ahead of implementation. When something doesn't work, check if the documented protocol matches the actual code.

4. **Verify with production binary, not just dev tests.** The dev tests passed (with wrong exit code assertions). The production binary needed to be tested end-to-end.

5. **Evidence is not enforcement.** A rule in the registry without a test against the actual attack pattern isn't protecting you. Build from real incidents.

6. **The meta-attack: remove the defense, not circumvent it.** config.oversight_tamper exists because "change oversight_enabled to false" is simpler than any evasion technique. Defense systems that can be reconfigured by what they're defending against are illusions.

7. **Ego shapes threat models.** If your model assumes the agent doesn't know what it's doing, your defenses will be different — and weaker — than if you assume it does. Assume it does.
