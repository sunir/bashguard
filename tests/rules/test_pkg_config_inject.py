"""Tests for supply_chain.pkg_config_inject rule.

Story: Writing directly to package manager config files (~/.pip/pip.conf,
~/.npmrc, ~/.yarnrc) achieves the same supply chain redirect as
`pip config set` but bypasses that check entirely. An agent that writes
'registry=https://evil.com' to ~/.npmrc has turned every subsequent
`npm install` into a potential backdoor fetch.

Rule contracts (supply_chain.pkg_config_inject):
- echo "[global]" > ~/.pip/pip.conf                         → BLOCK
- cat > ~/.pip/pip.conf                                      → BLOCK
- cp /tmp/evil.npmrc ~/.npmrc                                → BLOCK
- echo "registry=evil.com" >> ~/.npmrc                      → BLOCK
- echo "registry https://evil.com" > ~/.yarnrc              → BLOCK
- tee ~/.yarnrc                                              → BLOCK
- cat > /etc/pip.conf                                        → BLOCK (/etc covered by protected)
- git config --global core.hooksPath /tmp/hooks             → BLOCK
- git config --global http.proxy http://evil.com            → BLOCK
- git config --local user.email foo@bar.com                 → ALLOW (local non-dangerous)
- git config --global user.name "Alice"                     → ALLOW (non-dangerous key)
- cat ~/.npmrc                                               → ALLOW (read-only)
- cat ~/.pip/pip.conf                                        → ALLOW (read-only)
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
    from bashguard.rules.pkg_config_inject import PkgConfigInjectRule
    return PkgConfigInjectRule()


class TestPipConfWrite:
    def test_write_pip_conf_blocked(self, ctx):
        findings = _rule().check('echo "[global]" > ~/.pip/pip.conf', ctx)
        assert len(findings) == 1
        assert findings[0].rule_id == "supply_chain.pkg_config_inject"
        assert findings[0].severity == Severity.CRITICAL

    def test_cat_pip_conf_blocked(self, ctx):
        findings = _rule().check("cat > ~/.pip/pip.conf", ctx)
        assert len(findings) == 1

    def test_cp_to_pip_conf_blocked(self, ctx):
        findings = _rule().check("cp /tmp/evil.cfg ~/.pip/pip.conf", ctx)
        assert len(findings) == 1

    def test_append_pip_conf_blocked(self, ctx):
        findings = _rule().check('echo "extra-index-url = https://evil.com" >> ~/.pip/pip.conf', ctx)
        assert len(findings) == 1

    def test_read_pip_conf_allowed(self, ctx):
        assert _rule().check("cat ~/.pip/pip.conf", ctx) == []


class TestNpmrcWrite:
    def test_write_npmrc_blocked(self, ctx):
        findings = _rule().check('echo "registry=https://evil.com" > ~/.npmrc', ctx)
        assert len(findings) == 1
        assert findings[0].rule_id == "supply_chain.pkg_config_inject"

    def test_append_npmrc_blocked(self, ctx):
        findings = _rule().check('echo "registry=https://evil.com" >> ~/.npmrc', ctx)
        assert len(findings) == 1

    def test_cp_to_npmrc_blocked(self, ctx):
        findings = _rule().check("cp /tmp/evil.npmrc ~/.npmrc", ctx)
        assert len(findings) == 1

    def test_tee_npmrc_blocked(self, ctx):
        findings = _rule().check("echo 'registry=evil.com' | tee ~/.npmrc", ctx)
        assert len(findings) == 1

    def test_read_npmrc_allowed(self, ctx):
        assert _rule().check("cat ~/.npmrc", ctx) == []


class TestYarnrcWrite:
    def test_write_yarnrc_blocked(self, ctx):
        findings = _rule().check('echo "registry https://evil.com" > ~/.yarnrc', ctx)
        assert len(findings) == 1

    def test_tee_yarnrc_blocked(self, ctx):
        findings = _rule().check("echo 'registry https://evil.com' | tee ~/.yarnrc", ctx)
        assert len(findings) == 1

    def test_read_yarnrc_allowed(self, ctx):
        assert _rule().check("cat ~/.yarnrc", ctx) == []


class TestGitConfigGlobal:
    def test_hookspath_tmp_blocked(self, ctx):
        findings = _rule().check("git config --global core.hooksPath /tmp/hooks", ctx)
        assert len(findings) == 1
        assert findings[0].rule_id == "supply_chain.pkg_config_inject"

    def test_http_proxy_blocked(self, ctx):
        findings = _rule().check("git config --global http.proxy http://evil.com", ctx)
        assert len(findings) == 1

    def test_https_proxy_blocked(self, ctx):
        findings = _rule().check("git config --global https.proxy http://evil.com", ctx)
        assert len(findings) == 1

    def test_local_user_email_allowed(self, ctx):
        assert _rule().check("git config --local user.email foo@bar.com", ctx) == []

    def test_global_user_name_allowed(self, ctx):
        assert _rule().check('git config --global user.name "Alice"', ctx) == []

    def test_global_user_email_allowed(self, ctx):
        assert _rule().check("git config --global user.email alice@example.com", ctx) == []


class TestUnrelated:
    def test_git_status_allowed(self, ctx):
        assert _rule().check("git status", ctx) == []

    def test_pip_install_allowed(self, ctx):
        assert _rule().check("pip install requests", ctx) == []
