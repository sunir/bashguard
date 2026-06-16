"""Tests for bashguard stats/log CLI modes and their flag options.

Story: BG-CLI-FLAGS-VALIDATION

Rule contracts:
- bashguard stats            → human-readable summary
- bashguard stats --json     → valid JSON with keys: total, by_verdict, by_rule, block_rate
- bashguard stats --days 7   → stats filtered to last 7 days (flags accepted, exits 0)
- bashguard log              → human-readable log lines (exits 0)
- bashguard log --json       → valid JSON array
- bashguard log --verdict block  → only block entries
- bashguard log --rule r.id      → filtered entries
- bashguard log -n 2         → at most 2 entries
- bashguard log --limit 2    → at most 2 entries (alias for -n)
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess

_BASHGUARD = shutil.which("bashguard") or "bashguard"


def _run(*args) -> tuple[int, str, str]:
    result = subprocess.run(
        [_BASHGUARD] + list(args),
        capture_output=True, text=True, env=os.environ,
    )
    return result.returncode, result.stdout, result.stderr


class TestStatsFlags:
    # BG-CLI-FLAGS-VALIDATION
    def test_stats_exits_0(self):
        rc, _, err = _run("stats")
        assert rc == 0, f"stderr: {err}"

    def test_stats_text_has_total_line(self):
        _, out, _ = _run("stats")
        assert "Total audited:" in out

    def test_stats_json_exits_0(self):
        rc, _, err = _run("stats", "--json")
        assert rc == 0, f"stderr: {err}"

    def test_stats_json_is_valid_json(self):
        _, out, _ = _run("stats", "--json")
        data = json.loads(out)
        assert isinstance(data, dict)

    def test_stats_json_has_required_keys(self):
        _, out, _ = _run("stats", "--json")
        data = json.loads(out)
        assert "total" in data
        assert "by_verdict" in data
        assert "by_rule" in data
        assert "block_rate" in data

    def test_stats_days_flag_accepted(self):
        rc, out, err = _run("stats", "--days", "3")
        assert rc == 0, f"stderr: {err}"
        assert "Total audited:" in out

    def test_stats_days_short_flag_accepted(self):
        rc, _, err = _run("stats", "-d", "7")
        assert rc == 0, f"stderr: {err}"

    def test_stats_days_json_combo(self):
        rc, out, err = _run("stats", "--days", "365", "--json")
        assert rc == 0, f"stderr: {err}"
        data = json.loads(out)
        assert "total" in data


class TestLogFlags:
    # BG-CLI-FLAGS-VALIDATION
    def test_log_exits_0(self):
        rc, _, err = _run("log")
        assert rc == 0, f"stderr: {err}"

    def test_log_json_exits_0(self):
        rc, _, err = _run("log", "--json")
        assert rc == 0, f"stderr: {err}"

    def test_log_json_is_valid_json(self):
        _, out, _ = _run("log", "--json")
        data = json.loads(out)
        assert isinstance(data, list)

    def test_log_json_entries_have_verdict_field(self):
        _, out, _ = _run("log", "--json")
        data = json.loads(out)
        # Every entry should have a verdict key
        for entry in data:
            assert "verdict" in entry

    def test_log_verdict_filter_accepted(self):
        rc, _, err = _run("log", "--verdict", "block")
        assert rc == 0, f"stderr: {err}"

    def test_log_verdict_short_flag_accepted(self):
        rc, _, err = _run("log", "-v", "allow")
        assert rc == 0, f"stderr: {err}"

    def test_log_rule_filter_accepted(self):
        rc, _, err = _run("log", "--rule", "destructive.irreversible")
        assert rc == 0, f"stderr: {err}"

    def test_log_rule_short_flag_accepted(self):
        rc, _, err = _run("log", "-r", "network.unknown_host")
        assert rc == 0, f"stderr: {err}"

    def test_log_limit_n_short(self):
        rc, out, err = _run("log", "-n", "2")
        assert rc == 0, f"stderr: {err}"
        lines = [l for l in out.strip().splitlines() if l.strip()]
        assert len(lines) <= 2

    def test_log_limit_long_form(self):
        rc, out, err = _run("log", "--limit", "2")
        assert rc == 0, f"stderr: {err}"
        lines = [l for l in out.strip().splitlines() if l.strip()]
        assert len(lines) <= 2

    def test_log_verdict_json_combo(self):
        rc, out, err = _run("log", "--verdict", "block", "--json")
        assert rc == 0, f"stderr: {err}"
        data = json.loads(out)
        assert isinstance(data, list)
        assert all(e.get("verdict") == "block" for e in data)

    def test_log_rule_json_combo(self):
        rc, out, err = _run("log", "--rule", "destructive.irreversible", "--json")
        assert rc == 0, f"stderr: {err}"
        data = json.loads(out)
        assert isinstance(data, list)
