"""
tests/test_process_kill.py — Tests for process.agent_kill rule.

Story: As a bashguard operator, I want Claude blocked from running broad
process-kill commands (pkill claude, killall node, kill -9 -1) that could
take down other agents or the entire process group.

This is the Mythos "cascading takedown" pattern: asked to stop one evaluation,
the model killed ALL similar evaluations for all users. pkill/killall are the
shell equivalent.

Rule contract:
- pkill <name> → BLOCK (kills all matching processes, no PID specificity)
- killall <name> → BLOCK (same semantics)
- kill -9 -1 → BLOCK (kill all processes)
- pkill -f <pattern> → BLOCK (full cmdline match is even broader)
- kill <specific-pid> → ALLOW (specific PID, not broadcast)
- kill -TERM <pid>   → ALLOW (specific PID)
- kill -9 <pid>      → ALLOW (specific, targeted, though harsh)
"""
from __future__ import annotations

from pathlib import Path
import pytest
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))

from bashguard.models import ExecutionContext, Severity, ActionType


@pytest.fixture()
def ctx() -> ExecutionContext:
    return ExecutionContext(cwd="/home/user/project")


def _rule():
    from bashguard.rules.process_kill import ProcessKillRule
    return ProcessKillRule()


class TestPkill:
    def test_pkill_by_name_blocked(self, ctx):
        findings = _rule().check("pkill claude", ctx)
        assert len(findings) == 1
        assert findings[0].rule_id == "process.agent_kill"
        assert findings[0].severity == Severity.CRITICAL
        assert findings[0].action_type == ActionType.PROCESS_SIGNAL

    def test_pkill_flag_f_blocked(self, ctx):
        findings = _rule().check("pkill -f 'node server.js'", ctx)
        assert len(findings) == 1

    def test_pkill_common_agents_blocked(self, ctx):
        for name in ("claude", "node", "python", "ruby", "java"):
            findings = _rule().check(f"pkill {name}", ctx)
            assert len(findings) == 1, f"pkill {name} should be blocked"

    def test_pkill_with_signal_blocked(self, ctx):
        findings = _rule().check("pkill -9 claude", ctx)
        assert len(findings) == 1


class TestKillall:
    def test_killall_by_name_blocked(self, ctx):
        findings = _rule().check("killall node", ctx)
        assert len(findings) == 1
        assert findings[0].rule_id == "process.agent_kill"

    def test_killall_signal_flag_blocked(self, ctx):
        findings = _rule().check("killall -9 python", ctx)
        assert len(findings) == 1


class TestKillBroadcast:
    def test_kill_minus1_blocked(self, ctx):
        """kill -9 -1 sends SIGKILL to every process the user owns."""
        findings = _rule().check("kill -9 -1", ctx)
        assert len(findings) == 1

    def test_kill_pid_zero_blocked(self, ctx):
        """kill 0 sends to entire process group."""
        findings = _rule().check("kill 0", ctx)
        assert len(findings) == 1


class TestKillSpecificPid:
    def test_kill_specific_pid_allowed(self, ctx):
        findings = _rule().check("kill 12345", ctx)
        assert findings == []

    def test_kill_9_specific_pid_allowed(self, ctx):
        findings = _rule().check("kill -9 12345", ctx)
        assert findings == []

    def test_kill_term_specific_pid_allowed(self, ctx):
        findings = _rule().check("kill -TERM 12345", ctx)
        assert findings == []


class TestClean:
    def test_empty_script_clean(self, ctx):
        assert _rule().check("", ctx) == []

    def test_unrelated_command_clean(self, ctx):
        assert _rule().check("ls -la", ctx) == []

    def test_echo_pkill_clean(self, ctx):
        """echo 'pkill claude' should not trigger."""
        assert _rule().check("echo 'pkill claude'", ctx) == []
