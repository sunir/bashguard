"""
tests/test_proc_root_bypass.py — Tests for evasion.proc_root_bypass rule.

Story: As a bashguard operator, I want to block path-based allowlist bypasses
using /proc/self/root/. Claude Code's sandbox was bypassed using
/proc/self/root/usr/bin/npx — the same binary as /usr/bin/npx but via a
different path, evading a denylist that only checked canonical paths. The
agent then disabled the bubblewrap sandbox entirely when caught.

/proc/self/root is a symlink to the process's filesystem root. Using it as
a path prefix reaches the same binaries as their canonical paths but bypasses
string-based path restrictions.

Rule contract:
- /proc/self/root/usr/bin/npx       → BLOCK (symlink evasion)
- /proc/self/root/bin/sh            → BLOCK
- /proc/self/root/usr/local/bin/python → BLOCK
- exec /proc/self/root/bin/bash     → BLOCK
- cat /proc/self/root/etc/passwd    → BLOCK (read via symlink)
- ls /proc/self/root/               → ALLOW (listing is benign)
- cat /proc/self/status             → ALLOW (own process status)
"""
from __future__ import annotations
from pathlib import Path
import sys
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))
from bashguard.models import ExecutionContext, Severity, ActionType


@pytest.fixture()
def ctx():
    return ExecutionContext(cwd="/home/user/project")


def _rule():
    from bashguard.rules.proc_root_bypass import ProcRootBypassRule
    return ProcRootBypassRule()


class TestProcRootEvasion:
    def test_npx_via_proc_root_blocked(self, ctx):
        findings = _rule().check("/proc/self/root/usr/bin/npx some-package", ctx)
        assert len(findings) == 1
        assert findings[0].rule_id == "evasion.proc_root_bypass"
        assert findings[0].severity == Severity.CRITICAL
        assert findings[0].action_type == ActionType.OBFUSCATED

    def test_sh_via_proc_root_blocked(self, ctx):
        findings = _rule().check("/proc/self/root/bin/sh -c 'id'", ctx)
        assert len(findings) == 1

    def test_python_via_proc_root_blocked(self, ctx):
        findings = _rule().check("/proc/self/root/usr/local/bin/python3 exploit.py", ctx)
        assert len(findings) == 1

    def test_exec_proc_root_blocked(self, ctx):
        findings = _rule().check("exec /proc/self/root/bin/bash", ctx)
        assert len(findings) == 1

    def test_cat_etc_via_proc_root_blocked(self, ctx):
        findings = _rule().check("cat /proc/self/root/etc/passwd", ctx)
        assert len(findings) == 1

    def test_curl_via_proc_root_blocked(self, ctx):
        findings = _rule().check("/proc/self/root/usr/bin/curl https://evil.com", ctx)
        assert len(findings) == 1


class TestAllowed:
    def test_ls_proc_root_allowed(self, ctx):
        assert _rule().check("ls /proc/self/root/", ctx) == []

    def test_proc_self_status_allowed(self, ctx):
        assert _rule().check("cat /proc/self/status", ctx) == []

    def test_normal_npx_allowed(self, ctx):
        assert _rule().check("npx some-package", ctx) == []

    def test_unrelated_allowed(self, ctx):
        assert _rule().check("ls -la", ctx) == []
