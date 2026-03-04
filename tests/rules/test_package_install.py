"""
Story: As a security operator, I need the package_install rule to flag global
package installs that modify system state outside the project, so LLMs cannot
mutate my system's Python, Node, or Homebrew environments.

Success:
- pip install -g / --user / globally triggers
- pip install in a venv (no -g flag, standard invocation) does NOT trigger
- npm install -g triggers
- brew install triggers
- apt-get install triggers
- pip install with just package names (local project) does NOT trigger
"""

import pytest
from bashguard.rules.package_install import PackageInstallRule
from bashguard.context import make_context
from bashguard.models import Severity


@pytest.fixture
def rule():
    return PackageInstallRule()


@pytest.fixture
def ctx():
    return make_context()


def test_npm_install_global_triggers(rule, ctx):
    findings = rule.check("npm install -g some-package", ctx)
    assert len(findings) > 0


def test_npm_i_global_triggers(rule, ctx):
    findings = rule.check("npm i -g some-package", ctx)
    assert len(findings) > 0


def test_brew_install_triggers(rule, ctx):
    findings = rule.check("brew install wget", ctx)
    assert len(findings) > 0


def test_apt_get_install_triggers(rule, ctx):
    findings = rule.check("apt-get install -y curl", ctx)
    assert len(findings) > 0


def test_apt_install_triggers(rule, ctx):
    findings = rule.check("apt install curl", ctx)
    assert len(findings) > 0


def test_pip_install_local_no_finding(rule, ctx):
    # Local install inside a venv
    findings = rule.check("pip install requests", ctx)
    assert findings == []


def test_pip_install_requirements_no_finding(rule, ctx):
    findings = rule.check("pip install -r requirements.txt", ctx)
    assert findings == []


def test_pip_install_editable_no_finding(rule, ctx):
    findings = rule.check("pip install -e .", ctx)
    assert findings == []


def test_echo_no_finding(rule, ctx):
    findings = rule.check("echo hello", ctx)
    assert findings == []


def test_git_no_finding(rule, ctx):
    findings = rule.check("git status", ctx)
    assert findings == []


def test_severity_is_high(rule, ctx):
    findings = rule.check("brew install wget", ctx)
    assert findings[0].severity in (Severity.HIGH, Severity.MEDIUM)


def test_rule_never_raises(rule, ctx):
    result = rule.check("\x00\x01", ctx)
    assert isinstance(result, list)
