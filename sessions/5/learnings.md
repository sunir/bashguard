# Session 5 Learnings — 2026-07-09

## Technical learnings

1. **Rate-limiting is mandatory for PreToolUse hooks.** Any hook that fires on every tool call MUST deduplicate alerts or it floods the msg bus. Use mtime-based lock files in /tmp/ keyed by alert type.

2. **Lock file pattern (bash):** `stat -f %m` (macOS) / `stat -c %Y` (Linux) for mtime. Compare `$(date +%s) - mtime` against window_secs. Touch the lock file to reset the timer.

3. **Advisory hooks have TWO noise sources:** (a) same alert firing repeatedly per-session, (b) advisory printed to stderr on every call even when no alert sent. Dedup covers (a); stderr output is intentional for (b) — it's user-visible feedback per tool call.

## Heuristics wiki candidates

- **Hook authoring checklist:** Add rate-limiting as step (4) after implement + test. Every PreToolUse hook that sends an external alert needs dedup.
- **Lock file dedup pattern:** Document `_ratelimit_ok()` pattern from 11-contract-enforcement as reusable snippet for hooks.
