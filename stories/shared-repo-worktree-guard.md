---
id: SHARED-REPO-WORKTREE
---
# Shared-repo worktree guard: block in-place git mutations on shared repos

Agents were colliding in shared repos (system, heuristics) by doing branch-mutating
git operations (checkout/merge/rebase/reset --hard) in the MAIN working directory.
A checkout or merge racing another agent's in-progress work fanned broken state
colony-wide (2026-07-08 incident). Telling agents to "use a worktree" does not stick.

The guard makes in-place mutation impossible via a PreToolUse hook. It targets only
the operations that actually cause collisions; read-only git (status/log/diff/fetch)
is allowed. A worktree `.git` FILE (vs directory) is always permitted — that IS the
sanctioned path.

## Contract

Hook: `system/claude/hooks/PreToolUse.d/system/09-shared-repo-worktree-guard`
Bash hook, exit 2 = block. Fail-open (any error → exit 0).

Blocks when ALL conditions hold:
1. Tool is Bash
2. Command matches `git ... (checkout|switch|merge|rebase|cherry-pick|reset --hard|branch -[DfM])`
3. CWD is inside a repo whose name is in SHARED_REPOS (default: "system heuristics")
4. That repo's `.git` is a DIRECTORY (main checkout, not a worktree)

Shared repos configurable via `COLONY_SHARED_REPOS` env var.

## Deploy

Written via worktree — dogfoods the rule.
Install: `system/claude/hooks/PreToolUse.d/system/09-shared-repo-worktree-guard`
Owned by bashguard; tested in `tests/test_worktree_guard.py`.

## Tests

`tests/test_worktree_guard.py`
- Blocked: git merge in system repo main dir
- Blocked: git checkout -b in system main dir
- Blocked: git reset --hard in system main dir
- Blocked: git branch -D in system main dir
- Allowed: git status / git log / git diff (read-only ops)
- Allowed: any git op in a worktree (.git is a file)
- Allowed: git merge in a NON-shared repo
- Allowed: non-Bash tools
- Allowed: non-git commands
