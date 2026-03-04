"""
Story: As a security framework user, I need the auditor to apply all registered
rules and return sorted findings, so that I get a complete picture of all
violations without any single rule crash killing the audit.

Success:
- Malformed command produces at least one finding (error_nodes rule)
- Findings are sorted by severity (CRITICAL before HIGH before MEDIUM etc.)
- A crashing rule does not prevent other rules from running
- Empty command returns empty findings
"""

import pytest
from bashguard.auditor import audit
from bashguard.context import make_context
from bashguard.models import Severity, Finding
from bashguard.rules import Rule, register, _REGISTRY


@pytest.fixture
def ctx():
    return make_context()


def test_malformed_command_produces_findings(ctx):
    findings = audit(">&", ctx)
    assert len(findings) > 0


def test_empty_command_no_findings(ctx):
    findings = audit("", ctx)
    assert findings == []


def test_findings_sorted_by_severity_descending(ctx):
    # Add a test rule that emits a LOW finding
    class _LowRule:
        rule_id = "test.low_severity"
        severity = Severity.LOW
        description = "test"
        def check(self, script, context):
            if script.strip():
                return [Finding(
                    rule_id=self.rule_id,
                    severity=Severity.LOW,
                    message="low",
                    matched_text=script,
                )]
            return []

    from bashguard.rules import _REGISTRY as reg
    reg["test.low_severity"] = _LowRule()

    try:
        findings = audit(">&", ctx)   # ">& " triggers HIGH (error_nodes) + LOW
        if len(findings) >= 2:
            severities = [f.severity for f in findings]
            order = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
            vals = [order[s.value] for s in severities]
            assert vals == sorted(vals, reverse=True), f"Not descending: {severities}"
    finally:
        reg.pop("test.low_severity", None)


def test_crashing_rule_does_not_stop_audit(ctx):
    class _CrashRule:
        rule_id = "test.crash"
        severity = Severity.HIGH
        description = "always crashes"
        def check(self, script, context):
            raise RuntimeError("boom")

    from bashguard.rules import _REGISTRY as reg
    reg["test.crash"] = _CrashRule()

    try:
        # Should not raise; error_nodes rule should still run
        findings = audit(">&", ctx)
        rule_ids = {f.rule_id for f in findings}
        assert "parse.error_node" in rule_ids
    finally:
        reg.pop("test.crash", None)


def test_specific_rules_subset(ctx):
    from bashguard.rules.error_nodes import ErrorNodesRule
    findings = audit(">&", ctx, rules=[ErrorNodesRule()])
    assert any(f.rule_id == "parse.error_node" for f in findings)


def test_audit_returns_list(ctx):
    result = audit("echo hello", ctx)
    assert isinstance(result, list)
