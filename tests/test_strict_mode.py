"""Tests for strict mode (allowlist-only).

When strict mode is enabled, only commands from a known-safe vocabulary
are permitted. Everything else is blocked unconditionally.

This is Layer 3 from specs/05-fail-close.md and n2-ark's strictMode.
"""
import pytest

from bashguard.models import Finding, Severity, VerdictType, ExecutionContext
from bashguard.strict_mode import StrictModeRule, DEFAULT_SAFE_COMMANDS


CTX = ExecutionContext(cwd="/home/user/project")


def findings(script: str) -> list[Finding]:
    return StrictModeRule().check(script, CTX)


class TestDefaultSafeCommands:
    """Known-safe commands should pass in strict mode."""

    def test_echo_allowed(self):
        assert not findings("echo hello")

    def test_ls_allowed(self):
        assert not findings("ls -la")

    def test_cat_allowed(self):
        assert not findings("cat README.md")

    def test_git_allowed(self):
        assert not findings("git status")

    def test_grep_allowed(self):
        assert not findings("grep -r 'pattern' src/")

    def test_python_allowed(self):
        assert not findings("python3 script.py")

    def test_cd_allowed(self):
        assert not findings("cd /tmp")

    def test_mkdir_allowed(self):
        assert not findings("mkdir -p build")


class TestBlockedCommands:
    """Unknown commands should be blocked in strict mode."""

    def test_unknown_binary_blocked(self):
        fs = findings("./malicious_script.sh")
        assert any(f.rule_id == "strict.unknown_command" for f in fs)

    def test_nc_blocked(self):
        fs = findings("nc -l 4444")
        assert any(f.rule_id == "strict.unknown_command" for f in fs)

    def test_nmap_blocked(self):
        fs = findings("nmap 192.168.1.0/24")
        assert any(f.rule_id == "strict.unknown_command" for f in fs)

    def test_unknown_not_in_safelist(self):
        fs = findings("xyzzy --foo bar")
        assert any(f.rule_id == "strict.unknown_command" for f in fs)


class TestSafeListCompleteness:
    """The default safe list should cover common dev workflows."""

    def test_common_dev_commands_in_safelist(self):
        dev_commands = [
            "git", "npm", "node", "python3", "python", "pip", "uv",
            "cargo", "rustc", "go", "make", "cmake",
            "ls", "cat", "head", "tail", "grep", "find", "wc",
            "echo", "printf", "test", "true", "false",
            "cd", "pwd", "mkdir", "cp", "mv", "touch",
            "date", "which", "env", "export",
        ]
        for cmd in dev_commands:
            assert cmd in DEFAULT_SAFE_COMMANDS, f"{cmd} missing from safe list"


class TestStrictModeToggle:
    """Strict mode rule should be optional — not registered by default."""

    def test_rule_has_expected_id(self):
        rule = StrictModeRule()
        assert rule.rule_id == "strict.unknown_command"
