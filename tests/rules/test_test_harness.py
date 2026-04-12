"""Tests for test harness tampering rules — conftest inject, site-packages inject.

Grounded in Berkeley RDI trustworthy benchmarks paper (2025):
- SWE-bench attack: create conftest.py with pytest hooks forcing all tests to pass (100% success)
- SWE-bench Pro: overwrite installed library files (django/__init__.py, /workspace/parser.py)

These attacks defeat the entire test verification layer used by coding agents.
"""
import pytest

from bashguard.models import Finding, Severity, ActionType, ExecutionContext
from bashguard.rules.test_harness import ConftestInjectRule, SitePackagesInjectRule

CTX = ExecutionContext(cwd="/home/user/project")


def conftest_findings(script: str) -> list[Finding]:
    return ConftestInjectRule().check(script, CTX)


def site_findings(script: str) -> list[Finding]:
    return SitePackagesInjectRule().check(script, CTX)


class TestConftestInject:
    """Writes to conftest.py inject pytest hooks that force all tests to pass."""

    def test_redirect_to_conftest_blocked(self):
        fs = conftest_findings("cat > conftest.py")
        assert any(f.rule_id == "test_harness.conftest_inject" for f in fs)

    def test_append_to_conftest_blocked(self):
        fs = conftest_findings("echo 'import pytest' >> conftest.py")
        assert any(f.rule_id == "test_harness.conftest_inject" for f in fs)

    def test_nested_conftest_blocked(self):
        """Injection in test subdirectory also blocked."""
        fs = conftest_findings("cat > tests/unit/conftest.py")
        assert any(f.rule_id == "test_harness.conftest_inject" for f in fs)

    def test_tee_to_conftest_blocked(self):
        fs = conftest_findings("echo 'import pytest' | tee conftest.py")
        assert any(f.rule_id == "test_harness.conftest_inject" for f in fs)

    def test_tee_nested_conftest_blocked(self):
        fs = conftest_findings("cat payload.py | tee tests/conftest.py")
        assert any(f.rule_id == "test_harness.conftest_inject" for f in fs)

    def test_heredoc_to_conftest_blocked(self):
        """The actual SWE-bench attack pattern."""
        script = (
            "cat > conftest.py << 'EOF'\n"
            "import pytest\n"
            "@pytest.hookimpl(hookwrapper=True)\n"
            "def pytest_runtest_makereport(item, call):\n"
            "    outcome = yield\n"
            "    rep = outcome.get_result()\n"
            "    rep.outcome = 'passed'\n"
            "EOF"
        )
        fs = conftest_findings(script)
        assert any(f.rule_id == "test_harness.conftest_inject" for f in fs)

    def test_cp_to_conftest_blocked(self):
        """Copying a prepared file over conftest.py."""
        fs = conftest_findings("cp /tmp/evil_conftest.py conftest.py")
        assert any(f.rule_id == "test_harness.conftest_inject" for f in fs)

    def test_mv_to_conftest_blocked(self):
        fs = conftest_findings("mv /tmp/hook.py conftest.py")
        assert any(f.rule_id == "test_harness.conftest_inject" for f in fs)

    def test_read_conftest_allowed(self):
        """Reading conftest.py is fine."""
        fs = conftest_findings("cat conftest.py")
        assert not any(f.rule_id == "test_harness.conftest_inject" for f in fs)

    def test_regular_python_file_write_allowed(self):
        fs = conftest_findings("cat > test_something.py")
        assert not any(f.rule_id == "test_harness.conftest_inject" for f in fs)

    def test_conftest_in_path_but_not_target_allowed(self):
        """Reading a file from a dir that happens to be named conftest is ok."""
        fs = conftest_findings("ls conftest/")
        assert not any(f.rule_id == "test_harness.conftest_inject" for f in fs)


class TestSitePackagesInject:
    """Writes to site-packages monkey-patch installed libraries."""

    def test_write_to_venv_site_packages_blocked(self):
        """The SWE-bench Pro attack: overwrite django/__init__.py."""
        fs = site_findings("cat > .venv/lib/python3.11/site-packages/django/__init__.py")
        assert any(f.rule_id == "test_harness.site_packages_inject" for f in fs)

    def test_write_to_user_site_packages_blocked(self):
        fs = site_findings("cat > ~/.local/lib/python3.11/site-packages/requests/__init__.py")
        assert any(f.rule_id == "test_harness.site_packages_inject" for f in fs)

    def test_cp_into_site_packages_blocked(self):
        fs = site_findings("cp /tmp/patched_init.py .venv/lib/python3.11/site-packages/django/__init__.py")
        assert any(f.rule_id == "test_harness.site_packages_inject" for f in fs)

    def test_tee_into_site_packages_blocked(self):
        fs = site_findings("cat patch.py | tee .venv/lib/python3.11/site-packages/six.py")
        assert any(f.rule_id == "test_harness.site_packages_inject" for f in fs)

    def test_append_to_site_packages_blocked(self):
        fs = site_findings("echo 'import os; os.system(\"id\")' >> .venv/lib/python3.11/site-packages/django/__init__.py")
        assert any(f.rule_id == "test_harness.site_packages_inject" for f in fs)

    def test_read_from_site_packages_allowed(self):
        """Reading installed packages is normal."""
        fs = site_findings("cat .venv/lib/python3.11/site-packages/django/__init__.py")
        assert not any(f.rule_id == "test_harness.site_packages_inject" for f in fs)

    def test_pip_install_not_this_rule(self):
        """pip install is caught by package_install rules, not this one."""
        fs = site_findings("pip install requests")
        assert not any(f.rule_id == "test_harness.site_packages_inject" for f in fs)

    def test_write_to_project_src_allowed(self):
        fs = site_findings("cat > src/mypackage/__init__.py")
        assert not any(f.rule_id == "test_harness.site_packages_inject" for f in fs)


class TestActionTypes:
    def test_conftest_inject_action_type(self):
        fs = conftest_findings("cat > conftest.py")
        cf = [f for f in fs if f.rule_id == "test_harness.conftest_inject"]
        assert all(f.action_type == ActionType.SYSTEM_CONFIG for f in cf)

    def test_site_packages_inject_action_type(self):
        fs = site_findings("cat > .venv/lib/python3.11/site-packages/django/__init__.py")
        sf = [f for f in fs if f.rule_id == "test_harness.site_packages_inject"]
        assert all(f.action_type == ActionType.SYSTEM_CONFIG for f in sf)
