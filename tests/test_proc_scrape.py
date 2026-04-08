"""
tests/test_proc_scrape.py — Tests for proc.credential_scrape rule.

Story: As a bashguard operator, I want to block Claude from reading /proc
filesystem entries that expose other processes' credentials, environment
variables, or memory. The Mythos model used low-level /proc/ access to find
credentials for messaging services, source control, and the Anthropic API by
inspecting process memory — without any user request to do so.

Rule contract:
- cat /proc/*/environ       → BLOCK (env vars of all processes — credentials)
- cat /proc/self/environ    → BLOCK (this process's env — may contain tokens)
- strings /proc/*/mem       → BLOCK (raw process memory scan for secrets)
- dd if=/proc/*/mem         → BLOCK (direct memory read)
- cat /proc/1234/cmdline    → BLOCK (other process command lines leak args)
- cat /proc/1234/fd/3       → BLOCK (open file descriptors — may be sockets)
- ls /proc/                 → ALLOW (listing is benign)
- cat /proc/cpuinfo         → ALLOW (hardware info, not credentials)
- cat /proc/meminfo         → ALLOW (memory stats, not credentials)
- cat /proc/version         → ALLOW (kernel version, not credentials)
- cat /proc/self/status     → ALLOW (own process status, not credentials)
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
    from bashguard.rules.proc_scrape import ProcScrapeRule
    return ProcScrapeRule()


class TestEnvironScrape:
    def test_cat_proc_star_environ_blocked(self, ctx):
        findings = _rule().check("cat /proc/*/environ", ctx)
        assert len(findings) == 1
        assert findings[0].rule_id == "proc.credential_scrape"
        assert findings[0].severity == Severity.CRITICAL
        assert findings[0].action_type == ActionType.CREDENTIAL_ACCESS

    def test_cat_proc_self_environ_blocked(self, ctx):
        findings = _rule().check("cat /proc/self/environ", ctx)
        assert len(findings) == 1

    def test_cat_proc_pid_environ_blocked(self, ctx):
        findings = _rule().check("cat /proc/1234/environ", ctx)
        assert len(findings) == 1

    def test_xargs_cat_environ_blocked(self, ctx):
        findings = _rule().check("ls /proc | xargs -I{} cat /proc/{}/environ", ctx)
        assert len(findings) == 1


class TestMemoryScrape:
    def test_strings_proc_mem_blocked(self, ctx):
        findings = _rule().check("strings /proc/1234/mem", ctx)
        assert len(findings) == 1

    def test_strings_proc_star_mem_blocked(self, ctx):
        findings = _rule().check("strings /proc/*/mem", ctx)
        assert len(findings) == 1

    def test_dd_proc_mem_blocked(self, ctx):
        findings = _rule().check("dd if=/proc/1234/mem of=/tmp/dump bs=4096", ctx)
        assert len(findings) == 1

    def test_hexdump_proc_mem_blocked(self, ctx):
        findings = _rule().check("hexdump /proc/self/mem", ctx)
        assert len(findings) == 1


class TestCmdlineAndFd:
    def test_cat_proc_pid_cmdline_blocked(self, ctx):
        findings = _rule().check("cat /proc/1234/cmdline", ctx)
        assert len(findings) == 1

    def test_cat_proc_pid_fd_blocked(self, ctx):
        findings = _rule().check("cat /proc/1234/fd/3", ctx)
        assert len(findings) == 1

    def test_ls_proc_pid_fd_blocked(self, ctx):
        findings = _rule().check("ls /proc/1234/fd/", ctx)
        assert len(findings) == 1


class TestAllowed:
    def test_ls_proc_allowed(self, ctx):
        assert _rule().check("ls /proc/", ctx) == []

    def test_cat_cpuinfo_allowed(self, ctx):
        assert _rule().check("cat /proc/cpuinfo", ctx) == []

    def test_cat_meminfo_allowed(self, ctx):
        assert _rule().check("cat /proc/meminfo", ctx) == []

    def test_cat_version_allowed(self, ctx):
        assert _rule().check("cat /proc/version", ctx) == []

    def test_cat_self_status_allowed(self, ctx):
        assert _rule().check("cat /proc/self/status", ctx) == []

    def test_unrelated_command_clean(self, ctx):
        assert _rule().check("ls -la", ctx) == []
