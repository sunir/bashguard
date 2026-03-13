"""Tests for audit log (JSONL append + query)."""
import json
import tempfile
from pathlib import Path

import pytest

from bashguard.audit_log import log_verdict, read_log
from bashguard.models import Finding, Severity, Verdict, VerdictType


def _make_verdict(vtype: VerdictType, findings=()) -> Verdict:
    return Verdict(
        verdict=vtype,
        findings=findings,
        message="test message",
    )


def _finding(rule_id: str, sev: Severity = Severity.HIGH) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=sev,
        message="test",
        span=(0, 4),
        matched_text="test",
    )


class TestLogVerdict:
    def test_creates_file_on_first_write(self, tmp_path):
        log_path = tmp_path / "audit.jsonl"
        verdict = _make_verdict(VerdictType.ALLOW)
        log_verdict(verdict, command="echo hello", log_path=log_path)
        assert log_path.exists()

    def test_appends_jsonl_line(self, tmp_path):
        log_path = tmp_path / "audit.jsonl"
        verdict = _make_verdict(VerdictType.BLOCK)
        log_verdict(verdict, command="rm -rf /", log_path=log_path)

        lines = log_path.read_text().strip().splitlines()
        assert len(lines) == 1
        entry = json.loads(lines[0])
        assert entry["verdict"] == "block"
        assert entry["command"] == "rm -rf /"

    def test_multiple_appends(self, tmp_path):
        log_path = tmp_path / "audit.jsonl"
        log_verdict(_make_verdict(VerdictType.ALLOW), command="echo", log_path=log_path)
        log_verdict(_make_verdict(VerdictType.BLOCK), command="rm -rf /", log_path=log_path)
        lines = log_path.read_text().strip().splitlines()
        assert len(lines) == 2

    def test_entry_has_timestamp(self, tmp_path):
        log_path = tmp_path / "audit.jsonl"
        log_verdict(_make_verdict(VerdictType.ALLOW), command="x", log_path=log_path)
        entry = json.loads(log_path.read_text())
        assert "timestamp" in entry
        assert "T" in entry["timestamp"]  # ISO 8601

    def test_findings_serialized(self, tmp_path):
        log_path = tmp_path / "audit.jsonl"
        f = _finding("destructive.irreversible", Severity.CRITICAL)
        verdict = Verdict(
            verdict=VerdictType.BLOCK,
            findings=(f,),
            message="blocked",
        )
        log_verdict(verdict, command="rm -rf /", log_path=log_path)
        entry = json.loads(log_path.read_text())
        assert len(entry["findings"]) == 1
        assert entry["findings"][0]["rule_id"] == "destructive.irreversible"
        assert entry["findings"][0]["severity"] == "critical"

    def test_creates_parent_dirs(self, tmp_path):
        log_path = tmp_path / "deep" / "nested" / "audit.jsonl"
        log_verdict(_make_verdict(VerdictType.ALLOW), command="echo", log_path=log_path)
        assert log_path.exists()


class TestReadLog:
    def _write_entries(self, log_path: Path, entries: list[dict]):
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with log_path.open("a") as f:
            for e in entries:
                f.write(json.dumps(e) + "\n")

    def test_read_all(self, tmp_path):
        log_path = tmp_path / "audit.jsonl"
        log_verdict(_make_verdict(VerdictType.ALLOW), command="echo", log_path=log_path)
        log_verdict(_make_verdict(VerdictType.BLOCK), command="rm", log_path=log_path)
        entries = list(read_log(log_path=log_path))
        assert len(entries) == 2

    def test_filter_by_verdict(self, tmp_path):
        log_path = tmp_path / "audit.jsonl"
        log_verdict(_make_verdict(VerdictType.ALLOW), command="echo", log_path=log_path)
        log_verdict(_make_verdict(VerdictType.BLOCK), command="rm", log_path=log_path)
        log_verdict(_make_verdict(VerdictType.BLOCK), command="dd", log_path=log_path)

        blocked = list(read_log(log_path=log_path, decision="block"))
        assert len(blocked) == 2
        for e in blocked:
            assert e["verdict"] == "block"

    def test_filter_by_rule_id(self, tmp_path):
        log_path = tmp_path / "audit.jsonl"
        f = _finding("network.unknown_host", Severity.CRITICAL)
        verdict = Verdict(verdict=VerdictType.BLOCK, findings=(f,), message="blocked")
        log_verdict(verdict, command="curl evil.com", log_path=log_path)
        log_verdict(_make_verdict(VerdictType.ALLOW), command="echo", log_path=log_path)

        network_entries = list(read_log(log_path=log_path, rule_id="network.unknown_host"))
        assert len(network_entries) == 1
        assert network_entries[0]["command"] == "curl evil.com"

    def test_limit(self, tmp_path):
        log_path = tmp_path / "audit.jsonl"
        for i in range(10):
            log_verdict(_make_verdict(VerdictType.ALLOW), command=f"echo {i}", log_path=log_path)

        entries = list(read_log(log_path=log_path, limit=3))
        assert len(entries) == 3

    def test_empty_log_returns_empty(self, tmp_path):
        log_path = tmp_path / "nonexistent.jsonl"
        entries = list(read_log(log_path=log_path))
        assert entries == []

    def test_limit_returns_most_recent(self, tmp_path):
        """With limit N, return the LAST N entries (most recent)."""
        log_path = tmp_path / "audit.jsonl"
        for i in range(5):
            log_verdict(_make_verdict(VerdictType.ALLOW), command=f"cmd{i}", log_path=log_path)

        entries = list(read_log(log_path=log_path, limit=2))
        assert entries[0]["command"] == "cmd3"
        assert entries[1]["command"] == "cmd4"
