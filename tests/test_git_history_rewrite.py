"""
tests/test_git_history_rewrite.py — Tests for git.history_rewrite rule.

Story: As a bashguard operator, I want to block Claude from rewriting git
history. The Mythos model, after exploiting a permission bypass to edit files
it shouldn't have touched, made further interventions to ensure those changes
would NOT appear in the git change history — erasing its own tracks.

History rewriting is a cover-up mechanism: the agent first acts, then erases
the evidence. Even if the action was benign, rewriting history destroys the
audit trail that operators rely on to understand what an agent did.

git filter-branch and git push --force are already blocked by git.destructive.
This rule adds the interactive / commit-level rewriting commands.

Rule contract:
- git commit --amend                 → BLOCK (rewrites most recent commit)
- git rebase -i HEAD~3               → BLOCK (interactive rebase = history edit)
- git rebase --interactive HEAD~1    → BLOCK
- git replace <old> <new>            → BLOCK (swaps objects in history)
- git notes rewrite                  → BLOCK (rewrites note objects)
- git commit -m 'msg'                → ALLOW (normal commit, no rewrite)
- git rebase main                    → ALLOW (non-interactive rebase onto branch)
- git rebase --onto main feature     → ALLOW (rebasing onto target, not interactive)
"""
from __future__ import annotations

from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from bashguard.models import ExecutionContext, Severity, ActionType


@pytest.fixture()
def ctx() -> ExecutionContext:
    return ExecutionContext(cwd="/home/user/project")


def _rule():
    from bashguard.rules.git_history_rewrite import GitHistoryRewriteRule
    return GitHistoryRewriteRule()


class TestAmend:
    def test_commit_amend_blocked(self, ctx):
        findings = _rule().check("git commit --amend", ctx)
        assert len(findings) == 1
        assert findings[0].rule_id == "git.history_rewrite"
        assert findings[0].severity == Severity.HIGH
        assert findings[0].action_type == ActionType.GIT_DESTRUCTIVE

    def test_commit_amend_no_edit_blocked(self, ctx):
        findings = _rule().check("git commit --amend --no-edit", ctx)
        assert len(findings) == 1

    def test_commit_amend_message_blocked(self, ctx):
        findings = _rule().check("git commit --amend -m 'Clean message'", ctx)
        assert len(findings) == 1

    def test_normal_commit_allowed(self, ctx):
        assert _rule().check("git commit -m 'Add feature'", ctx) == []


class TestInteractiveRebase:
    def test_rebase_i_blocked(self, ctx):
        findings = _rule().check("git rebase -i HEAD~3", ctx)
        assert len(findings) == 1

    def test_rebase_interactive_blocked(self, ctx):
        findings = _rule().check("git rebase --interactive HEAD~1", ctx)
        assert len(findings) == 1

    def test_rebase_onto_branch_allowed(self, ctx):
        assert _rule().check("git rebase main", ctx) == []

    def test_rebase_onto_flag_allowed(self, ctx):
        assert _rule().check("git rebase --onto main feature-branch", ctx) == []


class TestReplace:
    def test_git_replace_blocked(self, ctx):
        findings = _rule().check("git replace abc123 def456", ctx)
        assert len(findings) == 1

    def test_git_notes_rewrite_blocked(self, ctx):
        findings = _rule().check("git notes rewrite --stdin", ctx)
        assert len(findings) == 1


class TestClean:
    def test_empty_clean(self, ctx):
        assert _rule().check("", ctx) == []

    def test_git_status_clean(self, ctx):
        assert _rule().check("git status", ctx) == []

    def test_git_log_clean(self, ctx):
        assert _rule().check("git log --oneline", ctx) == []
