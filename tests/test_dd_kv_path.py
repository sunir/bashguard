"""Tests for dd key=value path detection in credentials.privileged_path.

Story: DD-KEYVAL-PATH

dd if=/etc/shadow was passing through because _is_protected checked the full
'if=/etc/shadow' string instead of extracting '/etc/shadow'.
"""
from __future__ import annotations

from bashguard.auditor import audit
from bashguard.context import make_context
from bashguard.models import VerdictType
from bashguard.policy import decide, PolicyConfig


def _check(script: str):
    ctx = make_context()
    findings = audit(script, ctx)
    verdict = decide(findings, ctx, PolicyConfig.default())
    return verdict.verdict, [f.rule_id for f in findings]


class TestDdKvPathBlocked:
    # Story: DD-KEYVAL-PATH

    def test_dd_if_shadow(self):
        verdict, rules = _check("dd if=/etc/shadow of=/tmp/out")
        assert verdict == VerdictType.BLOCK
        assert "credentials.privileged_path" in rules

    def test_dd_if_ssh_key(self):
        verdict, rules = _check("dd if=~/.ssh/id_rsa of=/tmp/key.bin")
        assert verdict == VerdictType.BLOCK
        assert "credentials.privileged_path" in rules

    def test_dd_of_shadow(self):
        verdict, rules = _check("dd if=/dev/urandom of=/etc/shadow")
        assert verdict == VerdictType.BLOCK
        assert "credentials.privileged_path" in rules

    def test_dd_if_aws_credentials(self):
        verdict, rules = _check("dd if=~/.aws/credentials bs=1 count=1000")
        assert verdict == VerdictType.BLOCK
        assert "credentials.privileged_path" in rules


class TestDdKvPathAllowed:
    # Story: DD-KEYVAL-PATH

    def test_dd_tmp_file(self):
        """dd from/to non-protected paths — allowed."""
        verdict, _ = _check("dd if=/tmp/data.bin of=/tmp/out.bin")
        assert verdict == VerdictType.ALLOW

    def test_dd_dev_zero(self):
        """dd from /dev/zero is a legitimate benchmark pattern."""
        verdict, _ = _check("dd if=/dev/zero of=/tmp/zeros bs=1M count=10")
        assert verdict == VerdictType.ALLOW
