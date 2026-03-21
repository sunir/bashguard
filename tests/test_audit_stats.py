"""Tests for audit statistics from the audit log."""
import json
from pathlib import Path

import pytest

from bashguard.audit_log import log_verdict
from bashguard.audit_stats import compute_stats
from bashguard.models import Finding, Severity, Verdict, VerdictType


def _verdict(vtype, rule_ids=None):
    findings = tuple(
        Finding(rule_id=rid, severity=Severity.CRITICAL, message="x", matched_text="x")
        for rid in (rule_ids or [])
    )
    return Verdict(verdict=vtype, findings=findings, message="test")


class TestComputeStats:
    def test_empty_log(self, tmp_path):
        log_path = tmp_path / "audit.jsonl"
        stats = compute_stats(log_path=log_path)
        assert stats["total"] == 0
        assert stats["by_verdict"] == {}
        assert stats["by_rule"] == {}

    def test_counts_by_verdict(self, tmp_path):
        log_path = tmp_path / "audit.jsonl"
        log_verdict(_verdict(VerdictType.ALLOW), command="echo", log_path=log_path)
        log_verdict(_verdict(VerdictType.ALLOW), command="ls", log_path=log_path)
        log_verdict(_verdict(VerdictType.BLOCK, ["destructive.irreversible"]),
                    command="rm -rf /", log_path=log_path)
        stats = compute_stats(log_path=log_path)
        assert stats["total"] == 3
        assert stats["by_verdict"]["allow"] == 2
        assert stats["by_verdict"]["block"] == 1

    def test_counts_by_rule(self, tmp_path):
        log_path = tmp_path / "audit.jsonl"
        log_verdict(_verdict(VerdictType.BLOCK, ["network.unknown_host"]),
                    command="curl evil.com", log_path=log_path)
        log_verdict(_verdict(VerdictType.BLOCK, ["network.unknown_host"]),
                    command="wget bad.com", log_path=log_path)
        log_verdict(_verdict(VerdictType.BLOCK, ["destructive.irreversible"]),
                    command="rm -rf /", log_path=log_path)
        stats = compute_stats(log_path=log_path)
        assert stats["by_rule"]["network.unknown_host"] == 2
        assert stats["by_rule"]["destructive.irreversible"] == 1

    def test_days_filter(self, tmp_path):
        log_path = tmp_path / "audit.jsonl"
        # Write entries (all recent since they're generated now)
        for i in range(5):
            log_verdict(_verdict(VerdictType.ALLOW), command=f"echo {i}", log_path=log_path)
        stats = compute_stats(log_path=log_path, days=7)
        assert stats["total"] == 5

    def test_block_rate(self, tmp_path):
        log_path = tmp_path / "audit.jsonl"
        log_verdict(_verdict(VerdictType.ALLOW), command="echo", log_path=log_path)
        log_verdict(_verdict(VerdictType.ALLOW), command="ls", log_path=log_path)
        log_verdict(_verdict(VerdictType.ALLOW), command="pwd", log_path=log_path)
        log_verdict(_verdict(VerdictType.BLOCK, ["x"]), command="rm", log_path=log_path)
        stats = compute_stats(log_path=log_path)
        assert stats["block_rate"] == pytest.approx(0.25)
