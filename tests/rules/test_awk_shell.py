"""Tests for evasion.awk_shell rule.

Story: BG-AWK-SYSTEM

Rule contracts (evasion.awk_shell):
Blocked — system() call:
- awk 'BEGIN{system("/bin/sh")}'        → BLOCK
- awk 'BEGIN{system("id")}'             → BLOCK (any system() is code exec)
- gawk 'BEGIN{system("id")}'            → BLOCK
- mawk 'BEGIN{system("whoami")}'        → BLOCK
- awk '{system($0)}'                    → BLOCK (dynamic system() from input)

Blocked — pipe to shell / getline exec:
- awk 'BEGIN{cmd="id"; cmd | getline r; print r}'  → BLOCK
- awk '{print | "/bin/sh"}'             → BLOCK
- awk 'BEGIN{"id" | getline r}'         → BLOCK

Allowed — legitimate awk use:
- awk '{print $1}'                      → ALLOW
- awk -F: '{print $1}' /etc/passwd      → ALLOW (field parsing)
- awk 'NR>1{print}'                     → ALLOW
- awk '{sum+=$1} END{print sum}'        → ALLOW
- gawk '{print NF}'                     → ALLOW
"""
from __future__ import annotations

import pytest

from bashguard.auditor import audit
from bashguard.context import make_context
from bashguard.models import VerdictType
from bashguard.policy import decide, PolicyConfig


def _check(script: str) -> str:
    ctx = make_context()
    findings = audit(script, ctx)
    verdict = decide(findings, ctx, PolicyConfig.default())
    triggered = [f.rule_id for f in findings]
    return verdict.verdict, triggered


class TestAwkSystemBlocked:
    # Story: BG-AWK-SYSTEM
    def test_awk_system_begin_shell(self):
        verdict, rules = _check("awk 'BEGIN{system(\"/bin/sh\")}'")
        assert verdict == VerdictType.BLOCK
        assert "evasion.awk_shell" in rules

    def test_awk_system_begin_id(self):
        verdict, rules = _check("awk 'BEGIN{system(\"id\")}'")
        assert verdict == VerdictType.BLOCK
        assert "evasion.awk_shell" in rules

    def test_gawk_system(self):
        verdict, rules = _check("gawk 'BEGIN{system(\"whoami\")}'")
        assert verdict == VerdictType.BLOCK
        assert "evasion.awk_shell" in rules

    def test_mawk_system(self):
        verdict, rules = _check("mawk 'BEGIN{system(\"id\")}'")
        assert verdict == VerdictType.BLOCK
        assert "evasion.awk_shell" in rules

    def test_awk_dynamic_system(self):
        verdict, rules = _check("awk '{system($0)}'")
        assert verdict == VerdictType.BLOCK
        assert "evasion.awk_shell" in rules


class TestAwkPipeGetlineBlocked:
    # Story: BG-AWK-SYSTEM
    def test_awk_cmd_pipe_getline(self):
        verdict, rules = _check("awk 'BEGIN{cmd=\"id\"; cmd | getline r; print r}'")
        assert verdict == VerdictType.BLOCK
        assert "evasion.awk_shell" in rules

    def test_awk_print_pipe_shell(self):
        verdict, rules = _check("awk '{print | \"/bin/sh\"}'")
        assert verdict == VerdictType.BLOCK
        assert "evasion.awk_shell" in rules

    def test_awk_string_pipe_getline(self):
        verdict, rules = _check("awk 'BEGIN{\"id\" | getline r; print r}'")
        assert verdict == VerdictType.BLOCK
        assert "evasion.awk_shell" in rules

    def test_gawk_pipe_getline(self):
        verdict, rules = _check("gawk 'BEGIN{\"whoami\" | getline x}'")
        assert verdict == VerdictType.BLOCK
        assert "evasion.awk_shell" in rules


class TestAwkAllowed:
    # Story: BG-AWK-SYSTEM
    def test_awk_print_field(self):
        verdict, _ = _check("awk '{print $1}'")
        assert verdict == VerdictType.ALLOW

    def test_awk_field_separator(self):
        verdict, _ = _check("awk -F: '{print $1}' users.txt")
        assert verdict == VerdictType.ALLOW

    def test_awk_skip_header(self):
        verdict, _ = _check("awk 'NR>1{print}'")
        assert verdict == VerdictType.ALLOW

    def test_awk_sum(self):
        verdict, _ = _check("awk '{sum+=$1} END{print sum}'")
        assert verdict == VerdictType.ALLOW

    def test_gawk_print_nf(self):
        verdict, _ = _check("gawk '{print NF}'")
        assert verdict == VerdictType.ALLOW
