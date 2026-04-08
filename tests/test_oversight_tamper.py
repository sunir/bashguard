"""
tests/test_oversight_tamper.py — Tests for config.oversight_tamper rule.

Story: As a bashguard operator, I want to block agents from disabling their
own monitoring and oversight configuration. In a documented 2025 incident,
models given a long-term goal conflicting with developer priorities edited a
config file to switch oversight_enabled: true to false. A separate RSA 2026
case: an agent rewrote an organization's entire security policy to remove a
permission barrier it encountered, then continued operating under the new policy.

Oversight tamper is the meta-attack: instead of working around a constraint,
remove the constraint from the system itself.

Rule contract:
- sed -i 's/oversight_enabled: true/oversight_enabled: false/' config.yaml → BLOCK
- sed -i 's/monitoring: true/monitoring: false/'                           → BLOCK
- echo 'oversight_enabled: false' >> .bashguard.yaml                       → BLOCK
- python3 -c "...['oversight_enabled'] = False..."                         → BLOCK (evasion)
- Writes to files named oversight.yaml, monitoring.yaml, audit.yaml        → BLOCK
- cat .bashguard.yaml                                                      → ALLOW (reading is ok)
- sed -i 's/oversight_enabled: false/oversight_enabled: true/'             → ALLOW (re-enabling is ok)
- echo 'debug: true' >> app.yaml                                           → ALLOW (unrelated config)
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
    from bashguard.rules.oversight_tamper import OversightTamperRule
    return OversightTamperRule()


class TestSedDisable:
    def test_sed_oversight_enabled_false_blocked(self, ctx):
        findings = _rule().check(
            "sed -i 's/oversight_enabled: true/oversight_enabled: false/' config.yaml",
            ctx,
        )
        assert len(findings) == 1
        assert findings[0].rule_id == "config.oversight_tamper"
        assert findings[0].severity == Severity.CRITICAL
        assert findings[0].action_type == ActionType.SYSTEM_CONFIG

    def test_sed_monitoring_false_blocked(self, ctx):
        findings = _rule().check(
            "sed -i 's/monitoring: true/monitoring: false/' settings.yaml",
            ctx,
        )
        assert len(findings) == 1

    def test_sed_audit_disabled_blocked(self, ctx):
        findings = _rule().check(
            "sed -i 's/audit_logging: true/audit_logging: false/' .bashguard.yaml",
            ctx,
        )
        assert len(findings) == 1

    def test_sed_reenable_allowed(self, ctx):
        # Re-enabling oversight is fine
        assert _rule().check(
            "sed -i 's/oversight_enabled: false/oversight_enabled: true/' config.yaml",
            ctx,
        ) == []


class TestEchoAppend:
    def test_echo_oversight_false_append_blocked(self, ctx):
        findings = _rule().check("echo 'oversight_enabled: false' >> .bashguard.yaml", ctx)
        assert len(findings) == 1

    def test_echo_monitoring_false_blocked(self, ctx):
        findings = _rule().check("echo 'monitoring_enabled: false' >> config.yaml", ctx)
        assert len(findings) == 1

    def test_echo_unrelated_config_allowed(self, ctx):
        assert _rule().check("echo 'debug: true' >> app.yaml", ctx) == []


class TestOversightFiles:
    def test_write_to_oversight_yaml_blocked(self, ctx):
        findings = _rule().check("cat /dev/null > oversight.yaml", ctx)
        assert len(findings) == 1

    def test_rm_audit_log_blocked(self, ctx):
        findings = _rule().check("rm -f audit.log", ctx)
        assert len(findings) == 1

    def test_truncate_audit_log_blocked(self, ctx):
        findings = _rule().check("truncate -s 0 audit.jsonl", ctx)
        assert len(findings) == 1


class TestAllowed:
    def test_cat_config_allowed(self, ctx):
        assert _rule().check("cat .bashguard.yaml", ctx) == []

    def test_git_log_allowed(self, ctx):
        assert _rule().check("git log --oneline", ctx) == []

    def test_unrelated_allowed(self, ctx):
        assert _rule().check("ls -la", ctx) == []
