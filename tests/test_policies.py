"""
Tests for bash_ast.policies — built-in security policies for file and git ops.

Story: As a security layer for an LLM agent, I need policies that can examine
parsed commands and flag violations — so I can block dangerous file writes,
destructive git ops, and path traversal without string-matching raw shell.

Success:
- FileWritePolicy flags writes to protected paths (/, /etc, /usr, /sys)
- FileWritePolicy allows writes to safe paths (/tmp, relative paths)
- GitPolicy flags git push to protected branches (main, master, production)
- GitPolicy allows git status, git log, git diff (read-only ops)
- DangerousCommandPolicy flags rm -rf on non-/tmp paths
- DangerousCommandPolicy allows rm on /tmp
- Multiple policies can be composed: first violation wins
"""

import pytest
from bashguard.parser import parse
from bashguard.policies import FileWritePolicy, GitPolicy, DangerousCommandPolicy
from bashguard.policies import compose, Violation


class TestFileWritePolicy:
    def setup_method(self):
        self.policy = FileWritePolicy()

    def test_write_to_root_blocked(self):
        cmds = parse("echo hello > /etc/passwd")
        violations = [self.policy.check(c) for c in cmds]
        assert any(v is not None for v in violations)

    def test_write_to_tmp_allowed(self):
        cmds = parse("echo hello > /tmp/out.txt")
        violations = [self.policy.check(c) for c in cmds]
        assert all(v is None for v in violations)

    def test_write_to_relative_allowed(self):
        cmds = parse("echo hello > output.txt")
        violations = [self.policy.check(c) for c in cmds]
        assert all(v is None for v in violations)

    def test_write_to_sys_blocked(self):
        cmds = parse("echo 1 > /sys/kernel/sysrq")
        violations = [self.policy.check(c) for c in cmds]
        assert any(v is not None for v in violations)


class TestGitPolicy:
    def setup_method(self):
        self.policy = GitPolicy()

    def test_git_push_main_blocked(self):
        cmds = parse("git push origin main")
        violations = [self.policy.check(c) for c in cmds]
        assert any(v is not None for v in violations)

    def test_git_push_master_blocked(self):
        cmds = parse("git push origin master")
        violations = [self.policy.check(c) for c in cmds]
        assert any(v is not None for v in violations)

    def test_git_push_feature_allowed(self):
        cmds = parse("git push origin feature/my-branch")
        violations = [self.policy.check(c) for c in cmds]
        assert all(v is None for v in violations)

    def test_git_status_allowed(self):
        cmds = parse("git status")
        violations = [self.policy.check(c) for c in cmds]
        assert all(v is None for v in violations)

    def test_git_log_allowed(self):
        cmds = parse("git log --oneline -10")
        violations = [self.policy.check(c) for c in cmds]
        assert all(v is None for v in violations)

    def test_git_reset_hard_blocked(self):
        cmds = parse("git reset --hard HEAD~3")
        violations = [self.policy.check(c) for c in cmds]
        assert any(v is not None for v in violations)


class TestDangerousCommandPolicy:
    def setup_method(self):
        self.policy = DangerousCommandPolicy()

    def test_rm_rf_root_blocked(self):
        cmds = parse("rm -rf /")
        violations = [self.policy.check(c) for c in cmds]
        assert any(v is not None for v in violations)

    def test_rm_rf_project_dir_blocked(self):
        cmds = parse("rm -rf /home/user/project")
        violations = [self.policy.check(c) for c in cmds]
        assert any(v is not None for v in violations)

    def test_rm_rf_tmp_allowed(self):
        cmds = parse("rm -rf /tmp/build-artifacts")
        violations = [self.policy.check(c) for c in cmds]
        assert all(v is None for v in violations)

    def test_rm_single_file_allowed(self):
        cmds = parse("rm output.txt")
        violations = [self.policy.check(c) for c in cmds]
        assert all(v is None for v in violations)


class TestCompose:
    def test_compose_stops_at_first_violation(self):
        policies = compose(FileWritePolicy(), GitPolicy(), DangerousCommandPolicy())
        cmds = parse("rm -rf /etc")
        violations = [policies.check(c) for c in cmds]
        assert any(v is not None for v in violations)

    def test_compose_returns_none_if_all_pass(self):
        policies = compose(FileWritePolicy(), GitPolicy(), DangerousCommandPolicy())
        cmds = parse("git status")
        violations = [policies.check(c) for c in cmds]
        assert all(v is None for v in violations)

    def test_violation_has_policy_name_and_message(self):
        policy = DangerousCommandPolicy()
        cmds = parse("rm -rf /")
        v = next(policy.check(c) for c in cmds if policy.check(c))
        assert isinstance(v, Violation)
        assert v.policy_name
        assert v.message
        assert v.command
