# bashguard — Focus

## Current Status (2026-07-09)

**Hook enforcement: WORKING.** Exit code 2 on BLOCK. Colony dispatcher respects it.

**Defense stack: COMPLETE.**
- Layer 1: Rule audit (semantic detection) — 75 rules, 1308 tests
- Layer 2: Credential injection (placeholder substitution)
- Layer 3: Seatbelt (sandbox-exec kernel enforcement)
- Layer 4: FUSE shadow FS (CoW overlay, W3-W5 complete — spike only)

**82-incident database: SUBSTANTIALLY COVERED.**
All key threat patterns BLOCK correctly. Remaining gaps above bash parsing level (DNS exfil, clipboard, session hijacking).

## What's Done (cumulative)

- W1-W5 complete (FUSE passthrough → shadow → ACL → token auth → session CLI)
- Hook exit code 2 fix — enforcement now real
- Colony-wide distribution via system hooks (70-bashguard)
- 75 rules across: evasion (27), persistence (9), network (8), credentials (3), destructive (3), git (3), supply_chain (2), proc (4), system (2), privesc (3), test_harness (2), ci (1), container (1), exec (1), mining (1), sql (1), tunnel (1), comms (1), self_protection (1), content (3)
- GTFOBins gaps filled: tclsh/wish/expect pipe+heredoc, dd if=/key=value bypass
- nc listen-mode false positive fixed
- `bashguard run -c` — tilde-exec pattern: audit + sandbox execute
- `bashguard launch` — session-level sandbox-exec with deny-default profile
- Shared-repo worktree guard hook (PR #2 merged + deployed to system prod 2026-07-09)

## P11 Roadmap — Next Milestone

**Strong candidate (from the_management): CONTRACT ENFORCEMENT**

A PreToolUse hook that enforces `/contract` BOUNDARIES — warns/routes-to-the_management when an agent acts outside its OWNS domain. Coordinate with sysop (building the contract schema+directory in `feat/colony-contracts-directory`) + the twin at the_management@ocean (P11 context).

## Backlog

- **`content.outside_boundary` false positive**: `getcap /usr/bin/ping` fires incorrectly. Exemption needed for known-safe read-only system tools.
- **Risk scoring layer**: compound rule or scoring layer for dangerous combinations (e.g., `evasion.anti_forensics` + `network.unknown_host`).
- **Remaining bash-catchable gaps**: DNS exfil via dig, pbpaste/clipboard read, `bash --noprofile --norc`.
- **bwrap (Linux)**: `bashguard launch` on ocean node — sandbox-exec is macOS-only.
- **Add /contract to identity.md** — bashguard has no formal contract in the colony directory yet.

## What Sunir Cares About

- The system working, not just logging
- Evidence of enforcement, not claims
- Test-first discipline (TDD rhythm maintained this session)
- Minimal, targeted fixes over architectural overengineering
- Scope discipline in automode
