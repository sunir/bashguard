"""
Story: As a security operator, I need the destructive rule to flag irreversible
filesystem operations, so that LLMs cannot wipe data with a single rm -rf.

Success:
- rm -rf / triggers the rule
- rm -rf /home/user/project triggers the rule
- rm -rf /tmp/build does NOT trigger (tmp is safe scratch space)
- dd if=/dev/zero of=/dev/sda triggers the rule
- mkfs on a device triggers the rule
- shred on a file triggers the rule
- rm on a single file does NOT trigger
- truncate on a file triggers the rule
"""

import pytest
from bash_audit.rules.destructive import DestructiveRule
from bash_audit.context import make_context
from bash_audit.models import Severity


@pytest.fixture
def rule():
    return DestructiveRule()


@pytest.fixture
def ctx():
    return make_context()


def test_rm_rf_root_triggers(rule, ctx):
    findings = rule.check("rm -rf /", ctx)
    assert len(findings) > 0


def test_rm_rf_home_dir_triggers(rule, ctx):
    findings = rule.check("rm -rf /home/user/project", ctx)
    assert len(findings) > 0


def test_rm_rf_relative_dir_triggers(rule, ctx):
    findings = rule.check("rm -rf ./important", ctx)
    assert len(findings) > 0


def test_rm_rf_tmp_no_finding(rule, ctx):
    findings = rule.check("rm -rf /tmp/build-artifacts", ctx)
    assert findings == []


def test_rm_single_file_no_finding(rule, ctx):
    findings = rule.check("rm output.txt", ctx)
    assert findings == []


def test_dd_zero_to_device_triggers(rule, ctx):
    findings = rule.check("dd if=/dev/zero of=/dev/sda", ctx)
    assert len(findings) > 0


def test_mkfs_triggers(rule, ctx):
    findings = rule.check("mkfs.ext4 /dev/sdb1", ctx)
    assert len(findings) > 0


def test_shred_triggers(rule, ctx):
    findings = rule.check("shred -u /etc/passwd", ctx)
    assert len(findings) > 0


def test_truncate_triggers(rule, ctx):
    findings = rule.check("truncate -s 0 /var/log/auth.log", ctx)
    assert len(findings) > 0


def test_git_clean_triggers(rule, ctx):
    findings = rule.check("git clean -fdx", ctx)
    assert len(findings) > 0


def test_echo_no_finding(rule, ctx):
    findings = rule.check("echo hello", ctx)
    assert findings == []


def test_severity_is_high_or_critical(rule, ctx):
    findings = rule.check("rm -rf /", ctx)
    assert findings[0].severity in (Severity.HIGH, Severity.CRITICAL)


def test_rule_never_raises(rule, ctx):
    result = rule.check("\x00\x01", ctx)
    assert isinstance(result, list)
