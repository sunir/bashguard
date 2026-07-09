# Learnings — 2026-07-09

1. **Colony deploy chain is automated end-to-end.** Merge to `main` on any repo with the post-merge hook installed: branch advances → prod worktree resets → `05-system-sync` Stop hook fans out to all members. No manual intervention needed for colony-wide rollout.

2. **`05-system-sync` distributes `PreToolUse.d/system/0X-*` to all member repos.** Adding a new `0X-` prefixed hook to system prod means it auto-deploys to every agent at their next session end. Source of truth: `/var/db/ai/claude/prod/system/claude/hooks/`.

3. **git pull fails if untracked files would be overwritten.** Had to `mv .todo.json .todo.json.bak` before pulling system main because the remote added `.todo.json` as a tracked file while a local untracked version existed. The pull brought the authoritative version; the backup was discarded.

4. **colony-contracts schema is stable.** `[{repo, role, owns:[{item,detail}], boundaries:[{item,detail}], collaborates:[{item,detail}]}]`. Parser/schema reference is `system/scripts/colony-contracts`. No separate spec doc needed.

5. **Runtime path for compiled directory is unsolved.** The CONTRACT ENFORCEMENT hook can't recompile `colony-contracts` on every PreToolUse invocation — it's a subprocess call over markdown files. The right approach: a canonical cached path refreshed by cupdate/colony-setup. Decision deferred to the_management.

6. **Stop when blocked by a design decision you don't own.** Got tempted to pre-build the "where the JSON lives" answer. Correctly escalated to the_management instead. Building a competing answer would have wasted work.
