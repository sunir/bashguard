"""Tests for self-protection rule — detect attempts to modify bashguard itself.

n2-ark's triple-layer defense:
  Layer 1: detect rule file paths (.bashguard.yaml, rules/*.py)
  Layer 2: manipulation verbs + bashguard references
  Layer 3: core filenames (auditor.py, policy.py, models.py, etc.)

Adapted: bashguard protects its own config, rules, and source files.
"""
import pytest

from bashguard.models import ActionType, Finding, Severity, ExecutionContext
from bashguard.rules.self_protection import SelfProtectionRule

CTX = ExecutionContext(cwd="/home/user/project")


def findings(script: str, ctx: ExecutionContext = CTX) -> list[Finding]:
    return SelfProtectionRule().check(script, ctx)


class TestConfigProtection:
    """Layer 1: Detect access to bashguard config files."""

    def test_rm_bashguard_yaml(self):
        fs = findings("rm .bashguard.yaml")
        assert fs
        assert any(f.rule_id == "self_protection.config" for f in fs)

    def test_edit_bashguard_yaml(self):
        fs = findings("echo 'rules: []' > .bashguard.yaml")
        assert fs
        assert any(f.rule_id == "self_protection.config" for f in fs)

    def test_cat_bashguard_yaml_allowed(self):
        """Reading config is fine — only modification is blocked."""
        fs = findings("cat .bashguard.yaml")
        assert not any(f.rule_id == "self_protection.config" for f in fs)


class TestRuleFileProtection:
    """Layer 2: Detect modification of rule files."""

    def test_rm_rule_file(self):
        fs = findings("rm bashguard/rules/evasion.py")
        assert fs
        assert any(f.rule_id == "self_protection.rules" for f in fs)

    def test_write_to_rule_file(self):
        fs = findings("echo 'pass' > bashguard/rules/network.py")
        assert fs
        assert any(f.rule_id == "self_protection.rules" for f in fs)

    def test_mv_rule_file(self):
        fs = findings("mv bashguard/rules/evasion.py /tmp/")
        assert fs
        assert any(f.rule_id == "self_protection.rules" for f in fs)


class TestCoreProtection:
    """Layer 3: Detect modification of bashguard core files."""

    def test_rm_auditor(self):
        fs = findings("rm bashguard/auditor.py")
        assert fs
        assert any(f.rule_id == "self_protection.core" for f in fs)

    def test_write_to_policy(self):
        fs = findings("echo 'pass' > bashguard/policy.py")
        assert fs
        assert any(f.rule_id == "self_protection.core" for f in fs)

    def test_modify_models(self):
        fs = findings("truncate -s 0 bashguard/models.py")
        assert fs
        assert any(f.rule_id == "self_protection.core" for f in fs)


class TestSafeOperations:
    """Normal operations should not trigger self-protection."""

    def test_normal_python_file(self):
        fs = findings("rm myapp/models.py")
        assert not any(f.rule_id.startswith("self_protection") for f in fs)

    def test_normal_yaml_file(self):
        fs = findings("rm config.yaml")
        assert not any(f.rule_id.startswith("self_protection") for f in fs)

    def test_git_operations_on_bashguard(self):
        """git status/log on bashguard files is safe."""
        fs = findings("git status bashguard/")
        assert not any(f.rule_id.startswith("self_protection") for f in fs)


class TestActionType:
    def test_self_protection_is_system_config(self):
        fs = findings("rm .bashguard.yaml")
        sp = [f for f in fs if f.rule_id.startswith("self_protection")]
        assert all(f.action_type == ActionType.SYSTEM_CONFIG for f in sp)

    def test_severity_is_critical(self):
        fs = findings("rm bashguard/auditor.py")
        sp = [f for f in fs if f.rule_id.startswith("self_protection")]
        assert all(f.severity == Severity.CRITICAL for f in sp)
