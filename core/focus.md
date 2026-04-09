# bashguard — Focus

## Current Status (after session 2, 2026-04-09)

**Hook enforcement: WORKING.** Exit code 2 on BLOCK. Colony dispatcher respects it.

**Defense stack: COMPLETE.**
- Layer 1: Rule audit (semantic detection) — 66 rules, 962 tests
- Layer 2: Credential injection (placeholder substitution)
- Layer 3: Seatbelt (sandbox-exec kernel enforcement)
- Layer 4: FUSE shadow FS (CoW overlay, W3-W5 complete)

**82-incident database: SUBSTANTIALLY COVERED.**
28/28 key threat patterns from the database all BLOCK correctly. Remaining gaps are at levels above bash parsing (DNS exfil, clipboard, session hijacking).

## What's Done

- W1-W5 complete (FUSE passthrough → shadow → ACL → token auth → session CLI)
- Session CLI: fork, status, sync (BBS from Freestyle.sh)
- Seatbelt integrated into hook pipeline
- Credential injection integrated into hook pipeline
- Hook exit code 2 fix — enforcement now real
- Colony-wide distribution via system hooks
- **962 tests, 66 rules** (as of 2026-04-09)
- Spec 04 (51 evasion patterns): fully covered (evasion_gaps.py)
- False positives fixed: /dev/null writes, trusted_paths for cross-repo access

## New Rules This Session (Session 2 — +16)

From `account_log_dump.py`:
- `persistence.backdoor_account` (CRITICAL) — useradd/usermod/userdel/chpasswd
- `evasion.log_tamper` (HIGH) — auditd stop/disable, journalctl vacuum, auditctl -e 0
- `proc.gcore_dump` (CRITICAL) — live process memory dump

From `service_persist.py`:
- `persistence.service_enable` (HIGH) — systemctl enable (boot persistence)
- `persistence.at_job` (HIGH) — at/batch job scheduling
- `persistence.ssh_key_deploy` (HIGH) — ssh-copy-id lateral movement
- `persistence.cron_install` extended — `crontab <file>` now caught

From `network_recon_shell.py`:
- `network.port_scan` (HIGH) — nmap/masscan/zmap
- `network.socat_shell` (CRITICAL) — socat EXEC: bind/reverse shell
- `destructive.disk_copy` (CRITICAL) — dd if=/dev/sda, /dev/mem, /proc/kcore

From `local_pkg_keylogger.py`:
- `package.local_install` (CRITICAL) — dpkg/rpm/pip from local paths
- `proc.xinput_keylogger` (HIGH) — xinput test keyboard capture
- `proc.osascript_abuse` (HIGH) — osascript keystroke/clipboard

From `kernel_route.py`:
- `system.sysctl_write` (HIGH) — sysctl -w kernel parameter modification
- `network.route_tamper` (HIGH) — ip route add/del on default/0.0.0.0/0

## Potential Next Work

- **`content.outside_boundary` false positive**: `getcap /usr/bin/ping` fires incorrectly. Root issue: the rule fires on any path outside worktree, including system tools doing read-only queries. The right fix is an exemption for known-safe read-only tools (getcap, lsof, file, etc.) or a `read_only_system_tools` allowlist.
- **Risk scoring layer**: Some combinations of findings indicate higher risk than individual verdicts — e.g., `evasion.anti_forensics` + `network.unknown_host` together suggests an agent covering tracks. A compound rule or scoring layer above individual rules could surface this.
- **Spec updates**: specs/00, 01 don't reflect current 66-rule set. Should update the rule inventory in the spec.
- **`.deploy/` gitignore warning**: Minor — appears on each deploy. Clean up.
- **Colony hooks distribution test**: Verify `colony c` distributes the 70-bashguard hook correctly.
- **Remaining bash-catchable gaps**: DNS exfil via dig (command substitution in hostname), pbpaste/clipboard read (no safe pattern to distinguish from legitimate), `bash --noprofile --norc` (too many legit uses).

## What Sunir Cares About

- The system working, not just logging
- Evidence of enforcement, not claims
- Test-first discipline (TDD rhythm maintained this session)
- Minimal, targeted fixes over architectural overengineering
- Scope discipline in automode
