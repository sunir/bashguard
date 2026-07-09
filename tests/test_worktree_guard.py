"""Tests for 09-shared-repo-worktree-guard hook.

Story: SHARED-REPO-WORKTREE

The hook blocks branch-mutating git operations in the MAIN working directory
of shared repos (system, heuristics). Worktrees and non-shared repos are exempt.
Fail-open on any error.

Hook: system/claude/hooks/PreToolUse.d/system/09-shared-repo-worktree-guard
Exit 2 = block, exit 0 = allow.
"""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
HOOK = REPO_ROOT / "hooks" / "09-shared-repo-worktree-guard"

# Skip if the hook doesn't exist yet (pre-implementation red state)
pytestmark = pytest.mark.skipif(
    not HOOK.exists(),
    reason="09-shared-repo-worktree-guard not yet deployed to hooks/"
)


def _call_hook(command: str, cwd: str, shared_repos: str = "system heuristics") -> int:
    """Call the hook script with a Bash tool payload. Returns exit code."""
    payload = json.dumps({
        "tool_name": "Bash",
        "tool_input": {"command": command},
        "cwd": cwd,
    })
    env = {**os.environ, "COLONY_SHARED_REPOS": shared_repos}
    result = subprocess.run(
        ["bash", str(HOOK)],
        input=payload,
        capture_output=True,
        text=True,
        env=env,
    )
    return result.returncode


def _make_fake_main_repo(tmp_path: Path, name: str) -> Path:
    """Create a real git repo (git init) — gives .git DIRECTORY (main checkout)."""
    repo = tmp_path / name
    repo.mkdir()
    subprocess.run(["git", "init", str(repo)], capture_output=True, check=True)
    return repo


def _make_fake_worktree(tmp_path: Path, name: str) -> Path:
    """Create a real git repo whose subdir simulates a worktree (.git FILE)."""
    # git worktree add creates a .git file; simulate that by making a dir with a .git file
    real = tmp_path / f"{name}_real"
    real.mkdir()
    subprocess.run(["git", "init", str(real)], capture_output=True, check=True)
    wt = tmp_path / name
    wt.mkdir()
    (wt / ".git").write_text(f"gitdir: {real}/.git/worktrees/wt\n")
    # The hook checks [ -d "$root/.git" ]; for a worktree .git is a file → allowed
    # But git rev-parse --show-toplevel won't work since the worktree isn't real.
    # Patch: hook must handle this gracefully — if .git is a file, exit 0 before rev-parse.
    return wt


class TestBlockedInSharedMainDir:
    # Story: SHARED-REPO-WORKTREE

    def test_merge_blocked(self, tmp_path):
        repo = _make_fake_main_repo(tmp_path, "system")
        assert _call_hook("git merge feature-branch", str(repo)) == 2

    def test_checkout_branch_blocked(self, tmp_path):
        repo = _make_fake_main_repo(tmp_path, "system")
        assert _call_hook("git checkout -b my-feature", str(repo)) == 2

    def test_switch_blocked(self, tmp_path):
        repo = _make_fake_main_repo(tmp_path, "system")
        assert _call_hook("git switch my-branch", str(repo)) == 2

    def test_reset_hard_blocked(self, tmp_path):
        repo = _make_fake_main_repo(tmp_path, "system")
        assert _call_hook("git reset --hard HEAD", str(repo)) == 2

    def test_rebase_blocked(self, tmp_path):
        repo = _make_fake_main_repo(tmp_path, "system")
        assert _call_hook("git rebase main", str(repo)) == 2

    def test_cherry_pick_blocked(self, tmp_path):
        repo = _make_fake_main_repo(tmp_path, "system")
        assert _call_hook("git cherry-pick abc123", str(repo)) == 2

    def test_branch_delete_blocked(self, tmp_path):
        repo = _make_fake_main_repo(tmp_path, "system")
        assert _call_hook("git branch -D old-branch", str(repo)) == 2

    def test_heuristics_repo_blocked(self, tmp_path):
        repo = _make_fake_main_repo(tmp_path, "heuristics")
        assert _call_hook("git merge origin/main", str(repo)) == 2

    def test_subdir_of_shared_repo_blocked(self, tmp_path):
        """CWD inside a subdir of a shared repo should also be blocked."""
        repo = _make_fake_main_repo(tmp_path, "system")
        subdir = repo / "claude" / "hooks"
        subdir.mkdir(parents=True)
        assert _call_hook("git checkout -b test", str(subdir)) == 2


class TestAllowedCases:
    # Story: SHARED-REPO-WORKTREE

    def test_git_status_allowed(self, tmp_path):
        repo = _make_fake_main_repo(tmp_path, "system")
        assert _call_hook("git status", str(repo)) == 0

    def test_git_log_allowed(self, tmp_path):
        repo = _make_fake_main_repo(tmp_path, "system")
        assert _call_hook("git log --oneline -10", str(repo)) == 0

    def test_git_diff_allowed(self, tmp_path):
        repo = _make_fake_main_repo(tmp_path, "system")
        assert _call_hook("git diff HEAD", str(repo)) == 0

    def test_git_fetch_allowed(self, tmp_path):
        repo = _make_fake_main_repo(tmp_path, "system")
        assert _call_hook("git fetch origin", str(repo)) == 0

    def test_non_shared_repo_allowed(self, tmp_path):
        repo = _make_fake_main_repo(tmp_path, "myproject")
        assert _call_hook("git merge feature", str(repo)) == 0

    def test_worktree_allowed(self, tmp_path):
        """.git FILE (worktree) is always allowed — that's the sanctioned path."""
        repo = _make_fake_worktree(tmp_path, "system")
        assert _call_hook("git merge main", str(repo)) == 0

    def test_non_bash_tool_allowed(self, tmp_path):
        """Edit/Write tools are not checked."""
        repo = _make_fake_main_repo(tmp_path, "system")
        payload = json.dumps({
            "tool_name": "Edit",
            "tool_input": {"file_path": "/some/file.py"},
            "cwd": str(repo),
        })
        env = {**os.environ, "COLONY_SHARED_REPOS": "system heuristics"}
        result = subprocess.run(
            ["bash", str(HOOK)],
            input=payload,
            capture_output=True,
            text=True,
            env=env,
        )
        assert result.returncode == 0

    def test_non_git_command_allowed(self, tmp_path):
        repo = _make_fake_main_repo(tmp_path, "system")
        assert _call_hook("ls -la", str(repo)) == 0

    def test_custom_shared_repos_env(self, tmp_path):
        """COLONY_SHARED_REPOS controls which repos are protected."""
        repo = _make_fake_main_repo(tmp_path, "myrepo")
        # With default shared repos, myrepo is not shared → allowed
        assert _call_hook("git merge feature", str(repo), shared_repos="system heuristics") == 0
        # With custom env including myrepo → blocked
        assert _call_hook("git merge feature", str(repo), shared_repos="system myrepo") == 2
