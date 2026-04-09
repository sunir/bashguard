"""
tests/test_container_network.py — Container escape, firewall tampering, staging server.

Story (container_escape): As a bashguard operator, I want to block container
escape attempts. `docker run --privileged` grants full host privileges. Mounting
the host root `docker run -v /:/host` exposes all files. These are breakout
vectors used in agent containment incidents.

Rule contracts (container.escape):
- docker run --privileged alpine sh  → BLOCK
- docker run -v /:/host alpine       → BLOCK (root mount)
- docker run -v /etc:/host/etc ...   → BLOCK (sensitive path mount)
- docker run -v /tmp:/tmp alpine     → ALLOW (/tmp is safe)
- docker ps                          → ALLOW (read-only)
- docker build -t img .              → ALLOW (no privilege escalation)
- docker exec container ls           → ALLOW (exec without privilege)

Story (firewall_tamper): As a bashguard operator, I want to block commands
that disable or flush firewall rules. `iptables -F` flushes all rules;
`iptables -P INPUT ACCEPT` sets default-accept; `ufw disable` turns off the
firewall entirely. All enable lateral movement.

Rule contracts (network.firewall_tamper):
- iptables -F                   → BLOCK (flush all rules)
- iptables -P INPUT ACCEPT      → BLOCK (default accept)
- iptables -P FORWARD ACCEPT    → BLOCK (default accept)
- ip6tables -F                  → BLOCK (flush IPv6)
- ufw disable                   → BLOCK (disable firewall)
- nft flush ruleset             → BLOCK (flush nftables)
- iptables -L                   → ALLOW (list rules, read-only)
- iptables -A INPUT -p tcp ...  → ALLOW (add specific rule — may be legitimate)

Story (staging_server): As a bashguard operator, I want to block agents from
starting HTTP servers. `python3 -m http.server` and `python -m SimpleHTTPServer`
create staging servers used to host payloads or exfiltrate data. php -S and
ruby httpd are equivalent.

Rule contracts (network.staging_server):
- python3 -m http.server                 → BLOCK
- python3 -m http.server 8080            → BLOCK
- python -m SimpleHTTPServer             → BLOCK
- python -m SimpleHTTPServer 9090        → BLOCK
- php -S 0.0.0.0:8080                    → BLOCK
- ruby -run -e httpd . -p 8080           → BLOCK
- python3 -c "import json; ..."          → ALLOW (non-server -m)
- python3 script.py                      → ALLOW (running a script)
- python3 -m pytest                      → ALLOW (test runner, not server)
- python3 -m pip install ...             → ALLOW (package management)
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


# ─── Container Escape ────────────────────────────────────────────────────────

def _container_rule():
    from bashguard.rules.container_network import ContainerEscapeRule
    return ContainerEscapeRule()


class TestContainerEscape:
    def test_privileged_blocked(self, ctx):
        findings = _container_rule().check("docker run --privileged alpine sh", ctx)
        assert len(findings) == 1
        assert findings[0].rule_id == "container.escape"
        assert findings[0].severity == Severity.CRITICAL

    def test_root_volume_blocked(self, ctx):
        findings = _container_rule().check("docker run -v /:/host alpine", ctx)
        assert len(findings) == 1

    def test_etc_volume_blocked(self, ctx):
        findings = _container_rule().check(
            "docker run -v /etc:/host/etc --rm alpine cat /host/shadow", ctx
        )
        assert len(findings) == 1

    def test_proc_volume_blocked(self, ctx):
        findings = _container_rule().check("docker run -v /proc:/proc alpine", ctx)
        assert len(findings) == 1

    def test_docker_ps_allowed(self, ctx):
        assert _container_rule().check("docker ps", ctx) == []

    def test_docker_build_allowed(self, ctx):
        assert _container_rule().check("docker build -t myimg .", ctx) == []

    def test_docker_tmp_volume_allowed(self, ctx):
        assert _container_rule().check("docker run -v /tmp:/tmp alpine ls", ctx) == []

    def test_docker_exec_allowed(self, ctx):
        assert _container_rule().check("docker exec mycontainer ls", ctx) == []

    def test_unrelated_allowed(self, ctx):
        assert _container_rule().check("git status", ctx) == []


# ─── Firewall Tamper ─────────────────────────────────────────────────────────

def _firewall_rule():
    from bashguard.rules.container_network import FirewallTamperRule
    return FirewallTamperRule()


class TestFirewallTamper:
    def test_iptables_flush_blocked(self, ctx):
        findings = _firewall_rule().check("iptables -F", ctx)
        assert len(findings) == 1
        assert findings[0].rule_id == "network.firewall_tamper"
        assert findings[0].severity == Severity.HIGH

    def test_iptables_policy_accept_blocked(self, ctx):
        findings = _firewall_rule().check("iptables -P INPUT ACCEPT", ctx)
        assert len(findings) == 1

    def test_iptables_forward_accept_blocked(self, ctx):
        findings = _firewall_rule().check("iptables -P FORWARD ACCEPT", ctx)
        assert len(findings) == 1

    def test_ip6tables_flush_blocked(self, ctx):
        findings = _firewall_rule().check("ip6tables -F", ctx)
        assert len(findings) == 1

    def test_ufw_disable_blocked(self, ctx):
        findings = _firewall_rule().check("ufw disable", ctx)
        assert len(findings) == 1

    def test_nft_flush_blocked(self, ctx):
        findings = _firewall_rule().check("nft flush ruleset", ctx)
        assert len(findings) == 1

    def test_iptables_list_allowed(self, ctx):
        assert _firewall_rule().check("iptables -L", ctx) == []

    def test_iptables_add_rule_allowed(self, ctx):
        assert _firewall_rule().check("iptables -A INPUT -p tcp --dport 80 -j ACCEPT", ctx) == []

    def test_unrelated_allowed(self, ctx):
        assert _firewall_rule().check("git log", ctx) == []


# ─── Staging Server ──────────────────────────────────────────────────────────

def _staging_rule():
    from bashguard.rules.container_network import StagingServerRule
    return StagingServerRule()


class TestStagingServer:
    def test_python3_http_server_blocked(self, ctx):
        findings = _staging_rule().check("python3 -m http.server", ctx)
        assert len(findings) == 1
        assert findings[0].rule_id == "network.staging_server"
        assert findings[0].severity == Severity.HIGH

    def test_python3_http_server_port_blocked(self, ctx):
        findings = _staging_rule().check("python3 -m http.server 8080", ctx)
        assert len(findings) == 1

    def test_python_simplehttpserver_blocked(self, ctx):
        findings = _staging_rule().check("python -m SimpleHTTPServer", ctx)
        assert len(findings) == 1

    def test_php_server_blocked(self, ctx):
        findings = _staging_rule().check("php -S 0.0.0.0:8080", ctx)
        assert len(findings) == 1

    def test_ruby_httpd_blocked(self, ctx):
        findings = _staging_rule().check("ruby -run -e httpd . -p 8080", ctx)
        assert len(findings) == 1

    def test_python3_pytest_allowed(self, ctx):
        assert _staging_rule().check("python3 -m pytest tests/", ctx) == []

    def test_python3_pip_allowed(self, ctx):
        assert _staging_rule().check("python3 -m pip install requests", ctx) == []

    def test_python_script_allowed(self, ctx):
        assert _staging_rule().check("python3 script.py", ctx) == []

    def test_unrelated_allowed(self, ctx):
        assert _staging_rule().check("git status", ctx) == []
