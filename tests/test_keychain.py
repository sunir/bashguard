"""
tests/test_keychain.py — Tests for credentials.keychain rule.

Story: As a bashguard operator, I want to block agents from reading stored
credentials from the system keychain. The McKinsey red team (#71) demonstrated
that an AI agent gaining full enterprise access in 120 minutes specifically
exploited hardcoded credentials in config files and pivoted across services.
Reading the system keychain is a more direct path: it contains stored passwords
for every service the user has ever authenticated with.

macOS: security find-generic-password, security find-internet-password
Linux: secret-tool lookup (GNOME secret service)

These are purpose-built credential extraction commands — not general system
administration. An agent has no legitimate reason to query the system keychain.

Rule contract:
- security find-generic-password -a user -s service -w  → BLOCK
- security find-internet-password -a user@host -w       → BLOCK
- security dump-keychain                                 → BLOCK
- secret-tool lookup service github                     → BLOCK
- security list-keychains                               → ALLOW (listing, not reading)
- security help                                         → ALLOW
"""
from __future__ import annotations
from pathlib import Path
import sys
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))
from bashguard.models import ExecutionContext, Severity, ActionType


@pytest.fixture()
def ctx():
    return ExecutionContext(cwd="/home/user/project")


def _rule():
    from bashguard.rules.keychain import KeychainRule
    return KeychainRule()


class TestMacOSSecurity:
    def test_find_generic_password_blocked(self, ctx):
        findings = _rule().check(
            "security find-generic-password -a myuser -s myservice -w", ctx
        )
        assert len(findings) == 1
        assert findings[0].rule_id == "credentials.keychain"
        assert findings[0].severity == Severity.CRITICAL
        assert findings[0].action_type == ActionType.CREDENTIAL_ACCESS

    def test_find_internet_password_blocked(self, ctx):
        findings = _rule().check(
            "security find-internet-password -a user@github.com -w", ctx
        )
        assert len(findings) == 1

    def test_dump_keychain_blocked(self, ctx):
        findings = _rule().check("security dump-keychain ~/Library/Keychains/login.keychain", ctx)
        assert len(findings) == 1

    def test_find_certificate_blocked(self, ctx):
        findings = _rule().check("security find-certificate -a -Z login.keychain", ctx)
        assert len(findings) == 1

    def test_list_keychains_allowed(self, ctx):
        assert _rule().check("security list-keychains", ctx) == []

    def test_security_help_allowed(self, ctx):
        assert _rule().check("security help", ctx) == []

    def test_security_version_allowed(self, ctx):
        assert _rule().check("security version", ctx) == []


class TestLinuxSecretTool:
    def test_secret_tool_lookup_blocked(self, ctx):
        findings = _rule().check("secret-tool lookup service github token personal", ctx)
        assert len(findings) == 1
        assert findings[0].rule_id == "credentials.keychain"

    def test_secret_tool_search_blocked(self, ctx):
        findings = _rule().check("secret-tool search --all service aws", ctx)
        assert len(findings) == 1


class TestClean:
    def test_unrelated_clean(self, ctx):
        assert _rule().check("ls -la", ctx) == []

    def test_git_log_clean(self, ctx):
        assert _rule().check("git log --oneline", ctx) == []
