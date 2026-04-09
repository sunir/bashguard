"""
tests/test_local_pkg_keylogger.py — Local package install and xinput keylogger.

Story (local_package): dpkg -i and rpm -i install packages from local files.
In the 82-incident database, agents downloaded malicious .deb/.rpm files to /tmp
and installed them to establish persistence with pre/post install scripts.
pip install from a local path bypasses PyPI and installs arbitrary code.

Rule contracts (package.local_install):
- dpkg -i /tmp/evil.deb               → BLOCK
- dpkg -i ./evil.deb                  → BLOCK (relative path)
- rpm -i /tmp/evil.rpm                → BLOCK
- rpm --install /var/tmp/evil.rpm     → BLOCK
- pip install /tmp/evil_pkg           → BLOCK (local path, not package name)
- pip3 install --user /tmp/pkg/       → BLOCK
- dpkg -l                             → ALLOW (list only)
- dpkg --status python3               → ALLOW (query)
- rpm -q bash                         → ALLOW (query)
- pip install requests                → ALLOW (PyPI package by name)
- pip3 install numpy==1.24.0          → ALLOW (PyPI package with version)

Story (xinput_keylogger): xinput test <device_id> reads raw keyboard events from
an X input device — a keylogger. xinput list is a legitimate diagnostic. The
threat is xinput test with a specific device ID, capturing all keystrokes.

Rule contracts (proc.xinput_keylogger):
- xinput test 10                      → BLOCK
- xinput test-xi2 --root 11          → BLOCK (alternative keylog mode)
- xinput list                         → ALLOW (device listing)
- xinput list-props 10                → ALLOW (property query)
- xinput set-prop 10 --type=float ... → ALLOW (configuration)
"""
from __future__ import annotations
from pathlib import Path
import sys
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))
from bashguard.models import ExecutionContext, Severity


@pytest.fixture()
def ctx():
    return ExecutionContext(cwd="/home/user/project")


# ─── Local Package Install ────────────────────────────────────────────────────

def _local_pkg_rule():
    from bashguard.rules.local_pkg_keylogger import LocalPackageInstallRule
    return LocalPackageInstallRule()


class TestLocalPackageInstall:
    def test_dpkg_tmp_blocked(self, ctx):
        findings = _local_pkg_rule().check("dpkg -i /tmp/evil.deb", ctx)
        assert len(findings) == 1
        assert findings[0].rule_id == "package.local_install"
        assert findings[0].severity == Severity.CRITICAL

    def test_dpkg_relative_blocked(self, ctx):
        findings = _local_pkg_rule().check("dpkg -i ./evil.deb", ctx)
        assert len(findings) == 1

    def test_rpm_tmp_blocked(self, ctx):
        findings = _local_pkg_rule().check("rpm -i /tmp/evil.rpm", ctx)
        assert len(findings) == 1

    def test_rpm_install_blocked(self, ctx):
        findings = _local_pkg_rule().check("rpm --install /var/tmp/evil.rpm", ctx)
        assert len(findings) == 1

    def test_pip_local_path_blocked(self, ctx):
        findings = _local_pkg_rule().check("pip install /tmp/evil_pkg", ctx)
        assert len(findings) == 1

    def test_pip3_local_path_blocked(self, ctx):
        findings = _local_pkg_rule().check("pip3 install --user /tmp/pkg/", ctx)
        assert len(findings) == 1

    def test_dpkg_list_allowed(self, ctx):
        assert _local_pkg_rule().check("dpkg -l", ctx) == []

    def test_dpkg_status_allowed(self, ctx):
        assert _local_pkg_rule().check("dpkg --status python3", ctx) == []

    def test_rpm_query_allowed(self, ctx):
        assert _local_pkg_rule().check("rpm -q bash", ctx) == []

    def test_pip_pypi_package_allowed(self, ctx):
        assert _local_pkg_rule().check("pip install requests", ctx) == []

    def test_pip3_version_allowed(self, ctx):
        assert _local_pkg_rule().check("pip3 install numpy==1.24.0", ctx) == []

    def test_unrelated_allowed(self, ctx):
        assert _local_pkg_rule().check("git pull", ctx) == []


# ─── xinput Keylogger ─────────────────────────────────────────────────────────

def _xinput_rule():
    from bashguard.rules.local_pkg_keylogger import XinputKeyloggerRule
    return XinputKeyloggerRule()


class TestXinputKeylogger:
    def test_xinput_test_blocked(self, ctx):
        findings = _xinput_rule().check("xinput test 10", ctx)
        assert len(findings) == 1
        assert findings[0].rule_id == "proc.xinput_keylogger"
        assert findings[0].severity == Severity.HIGH

    def test_xinput_test_xi2_blocked(self, ctx):
        findings = _xinput_rule().check("xinput test-xi2 --root 11", ctx)
        assert len(findings) == 1

    def test_xinput_list_allowed(self, ctx):
        assert _xinput_rule().check("xinput list", ctx) == []

    def test_xinput_list_props_allowed(self, ctx):
        assert _xinput_rule().check("xinput list-props 10", ctx) == []

    def test_unrelated_allowed(self, ctx):
        assert _xinput_rule().check("git status", ctx) == []
