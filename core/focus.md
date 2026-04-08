# bashguard — Focus

## Current Status (after session 1, 2026-04-03)

**Hook enforcement: WORKING.** Exit code 2 on BLOCK. Colony dispatcher respects it. 525 tests passing.

**Defense stack: COMPLETE.**
- Layer 1: Rule audit (semantic detection)
- Layer 2: Credential injection (placeholder substitution)
- Layer 3: Seatbelt (sandbox-exec kernel enforcement)
- Layer 4: FUSE shadow FS (CoW overlay, W3-W5 complete)

## What's Actually Done

- W1-W5 complete (FUSE passthrough → shadow → ACL → token auth → session CLI)
- Session CLI: fork, status, sync (BBS from Freestyle.sh)
- Seatbelt integrated into hook pipeline
- Credential injection integrated into hook pipeline
- Hook exit code 2 fix — enforcement now real
- Colony-wide distribution via system hooks
- **770 tests** (as of 2026-04-09)
- **14 new rules** from 82-incident AI agent threat database + spec 04 audit
- Spec 04 (51 evasion patterns): **fully covered** (evasion_gaps.py)
- Corpus covers: Mythos incidents, CVE-2025-54794, Vertex AI ModeLeak,
  McKinsey red team, LiteLLM supply chain, RSA 2026 agent swarm

## Rules from evasion_gaps.py (this session)

- **`evasion.function_shadow`** — cd() { rm -rf "$1"; } shadows trusted builtins
- **`evasion.path_traversal`** — /usr/bin/../bin/rm bypasses path-based allowlists
- **`evasion.xargs_shell`** — echo ... | xargs bash -c (indirect pipe_to_shell)
- **`evasion.ansi_c_escape`** — $'\x2f...' hex/octal ANSI-C argument obfuscation
- **`evasion.shellshock`** — CVE-2014-6271: () { in variable values
- **`evasion.heredoc_interpreter`** — heredoc/herestring body to bash/python3/etc
- **`evasion.glob_command_name`** — /???/bin/ba* bypasses allowlist string matching

## Potential Next Work (when user directs)

- **`content.outside_boundary` false positive tuning**: The rule fires on any path outside the worktree boundary, including when that path appears in command strings (not just as file arguments). May produce noise for meta-operations.
- **`.deploy/` gitignore cleanup**: Minor — a warning appears on each deploy.
- **FUSE layer integration with real Claude sessions**: The spike code works, but wiring the session mount/unmount into actual Claude Code sessions needs end-to-end testing.
- **Colony/system hooks distribution testing**: Verify `colony c` actually picks up the new 70-bashguard from colony/system and distributes it correctly.
- **Spec 04 evasion audit**: DONE (2026-04-09). All 51 patterns covered. 7 new rules in evasion_gaps.py. 106 corpus entries.
- **RISK_POINTS scoring system**: The incident database analysis suggests a risk scoring layer above individual rules — some combinations of findings indicate higher risk than individual verdicts.

## What Sunir Cares About

- The system working, not just logging
- Evidence of enforcement, not claims
- Test-first discipline
- Minimal, targeted fixes over architectural overengineering
