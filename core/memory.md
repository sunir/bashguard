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

## Rule Corpus (82-incident database, session 1)

Every rule is grounded in a documented real incident. Key additions:

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
- credentials paths extended: .vscode/, .idea/, ~/.claude/, keyrings, fish history

## Workflow

- Tests: `.venv/bin/pytest tests/` (682 passing as of session 1, 2026-04-08)
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
