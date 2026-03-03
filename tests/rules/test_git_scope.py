"""
Story: As a security operator, I need the git_scope rule to detect git
operations that target repositories outside the current worktree, so that
LLMs operating in one repo cannot modify another repo or perform destructive
git operations.

Success:
- git push --force triggers (destructive regardless of scope)
- git push origin main triggers (protected branch)
- git push origin feature-branch with no force does NOT trigger
- git reset --hard triggers (destructive)
- git clean -fdx triggers (destructive)
- git branch -D triggers (destructive)
- git status does NOT trigger (read-only)
- git log does NOT trigger (read-only)
- git diff does NOT trigger (read-only)
- git add / commit in current worktree does NOT trigger
"""

import pytest
from bash_audit.rules.git_scope import GitScopeRule
from bash_audit.context import make_context
from bash_audit.models import Severity, ExecutionContext


@pytest.fixture
def rule():
    return GitScopeRule()


@pytest.fixture
def ctx():
    return make_context()


def test_git_force_push_triggers(rule, ctx):
    findings = rule.check("git push --force", ctx)
    assert len(findings) > 0


def test_git_force_push_short_flag_triggers(rule, ctx):
    findings = rule.check("git push -f origin main", ctx)
    assert len(findings) > 0


def test_git_push_main_triggers(rule, ctx):
    findings = rule.check("git push origin main", ctx)
    assert len(findings) > 0


def test_git_push_master_triggers(rule, ctx):
    findings = rule.check("git push origin master", ctx)
    assert len(findings) > 0


def test_git_push_feature_no_finding(rule, ctx):
    findings = rule.check("git push origin feature/my-branch", ctx)
    assert findings == []


def test_git_reset_hard_triggers(rule, ctx):
    findings = rule.check("git reset --hard HEAD~5", ctx)
    assert len(findings) > 0


def test_git_clean_fdx_triggers(rule, ctx):
    findings = rule.check("git clean -fdx", ctx)
    assert len(findings) > 0


def test_git_branch_delete_triggers(rule, ctx):
    findings = rule.check("git branch -D feature/old", ctx)
    assert len(findings) > 0


def test_git_status_no_finding(rule, ctx):
    findings = rule.check("git status", ctx)
    assert findings == []


def test_git_log_no_finding(rule, ctx):
    findings = rule.check("git log --oneline -10", ctx)
    assert findings == []


def test_git_diff_no_finding(rule, ctx):
    findings = rule.check("git diff HEAD", ctx)
    assert findings == []


def test_git_add_no_finding(rule, ctx):
    findings = rule.check("git add .", ctx)
    assert findings == []


def test_git_commit_no_finding(rule, ctx):
    findings = rule.check("git commit -m 'fix bug'", ctx)
    assert findings == []


def test_non_git_command_no_finding(rule, ctx):
    findings = rule.check("echo hello", ctx)
    assert findings == []


def test_severity_is_high(rule, ctx):
    findings = rule.check("git push --force", ctx)
    assert findings[0].severity in (Severity.HIGH, Severity.CRITICAL)


def test_rule_never_raises(rule, ctx):
    result = rule.check("\x00\x01", ctx)
    assert isinstance(result, list)
