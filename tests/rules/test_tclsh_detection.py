"""Tests for tclsh/wish/expect shell-escape detection.

Story: TCLSH-INTERPRETER-SHELL

GTFOBins documents tclsh as a shell-escape vector via pipe and heredoc.
tclsh has no -e flag, so interpreter_shell misses it; pipe_to_shell and
heredoc_interpreter cover it once tclsh is added to their sets.
"""
from __future__ import annotations

import pytest

from bashguard.auditor import audit
from bashguard.context import make_context
from bashguard.models import VerdictType
from bashguard.policy import decide, PolicyConfig


def _check(script: str):
    ctx = make_context()
    findings = audit(script, ctx)
    verdict = decide(findings, ctx, PolicyConfig.default())
    return verdict.verdict, [f.rule_id for f in findings]


class TestTclshPipeBlocked:
    # Story: TCLSH-INTERPRETER-SHELL

    def test_echo_pipe_tclsh(self):
        verdict, rules = _check('echo "exec /bin/sh" | tclsh')
        assert verdict == VerdictType.BLOCK
        assert "evasion.pipe_to_shell" in rules

    def test_cmd_pipe_tclsh(self):
        verdict, rules = _check("cat payload.tcl | tclsh")
        assert verdict == VerdictType.BLOCK
        assert "evasion.pipe_to_shell" in rules

    def test_echo_pipe_wish(self):
        verdict, rules = _check('echo "exec /bin/sh" | wish')
        assert verdict == VerdictType.BLOCK
        assert "evasion.pipe_to_shell" in rules

    def test_echo_pipe_expect(self):
        verdict, rules = _check('echo "spawn /bin/sh" | expect')
        assert verdict == VerdictType.BLOCK
        assert "evasion.pipe_to_shell" in rules


class TestTclshHeredocBlocked:
    # Story: TCLSH-INTERPRETER-SHELL

    def test_tclsh_heredoc_exec(self):
        verdict, rules = _check("tclsh <<'EOF'\nexec /bin/sh\nEOF")
        assert verdict == VerdictType.BLOCK
        assert "evasion.heredoc_interpreter" in rules

    def test_wish_heredoc(self):
        verdict, rules = _check("wish <<'EOF'\nexec /bin/sh\nEOF")
        assert verdict == VerdictType.BLOCK
        assert "evasion.heredoc_interpreter" in rules


class TestTclshAllowed:
    # Story: TCLSH-INTERPRETER-SHELL

    def test_tclsh_script_file(self):
        """tclsh script.tcl — can't inspect file contents, must allow."""
        verdict, rules = _check("tclsh script.tcl")
        assert verdict == VerdictType.ALLOW

    def test_wish_script_file(self):
        verdict, rules = _check("wish app.tcl")
        assert verdict == VerdictType.ALLOW
