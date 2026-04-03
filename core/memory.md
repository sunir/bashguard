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

## Workflow

- Tests: `.venv/bin/pytest tests/` (525 passing as of session 1)
- Branches: cannot commit to main directly; use feature branch → merge
- Rules dir is gitignored: `git add -f` when committing rule changes

## Key Lessons Learned

1. **Test the exit code, not just the JSON output.** The test `test_blocked_command_exits_0` was testing the wrong thing — it asserted exit 0, which was correct for the JSON protocol but wrong for the colony dispatcher protocol.

2. **Read the hook dispatcher before assuming the protocol.** The colony PreToolUse dispatcher has its own protocol layer that transforms JSON output into exit codes.

3. **"Exits 2 to deny" was in the hook comment but unimplemented.** Documentation can be ahead of implementation. When something doesn't work, check if the documented protocol matches the actual code.

4. **Verify with production binary, not just dev tests.** The dev tests passed (with wrong exit code assertions). The production binary needed to be tested end-to-end.
