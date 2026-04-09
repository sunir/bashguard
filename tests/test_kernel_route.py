"""
tests/test_kernel_route.py — Kernel parameter modification and route table poisoning.

Story (sysctl_write): sysctl -w modifies live kernel parameters. Disabling ASLR
(randomize_va_space=0), disabling dmesg restrictions (dmesg_restrict=0), or
enabling core dumps for SUID processes are privilege escalation enablers.
No legitimate LLM task needs to modify kernel security parameters.

Rule contracts (system.sysctl_write):
- sysctl -w kernel.randomize_va_space=0    → BLOCK
- sysctl -w net.ipv4.ip_forward=1         → BLOCK (enables routing/tunneling)
- sysctl kernel.dmesg_restrict=0          → BLOCK (value set without -w also writes)
- sysctl -a                               → ALLOW (read-only list all)
- sysctl kernel.hostname                  → ALLOW (read single value)

Story (route_tamper): ip route add with 0.0.0.0/0 or default changes the default
gateway, redirecting all traffic through an attacker-controlled host (MitM).
ip route del default removes routing. Normal route ops (specific subnets for VPN)
are harder to distinguish — we block default route changes specifically.

Rule contracts (network.route_tamper):
- ip route add 0.0.0.0/0 via attacker.com    → BLOCK
- ip route add default via 10.0.0.1          → BLOCK
- ip route del default                        → BLOCK
- ip route replace default via 1.2.3.4       → BLOCK
- ip route show                               → ALLOW (read-only)
- ip route add 192.168.10.0/24 via 10.0.0.1  → ALLOW (specific subnet)
- ip addr show                                → ALLOW (read-only address)
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


# ─── sysctl Write ─────────────────────────────────────────────────────────────

def _sysctl_rule():
    from bashguard.rules.kernel_route import SysctlWriteRule
    return SysctlWriteRule()


class TestSysctlWrite:
    def test_sysctl_aslr_blocked(self, ctx):
        findings = _sysctl_rule().check("sysctl -w kernel.randomize_va_space=0", ctx)
        assert len(findings) == 1
        assert findings[0].rule_id == "system.sysctl_write"
        assert findings[0].severity == Severity.HIGH

    def test_sysctl_ip_forward_blocked(self, ctx):
        findings = _sysctl_rule().check("sysctl -w net.ipv4.ip_forward=1", ctx)
        assert len(findings) == 1

    def test_sysctl_no_w_with_equals_blocked(self, ctx):
        # 'sysctl param=value' also writes (without -w flag)
        findings = _sysctl_rule().check("sysctl kernel.dmesg_restrict=0", ctx)
        assert len(findings) == 1

    def test_sysctl_read_all_allowed(self, ctx):
        assert _sysctl_rule().check("sysctl -a", ctx) == []

    def test_sysctl_read_single_allowed(self, ctx):
        assert _sysctl_rule().check("sysctl kernel.hostname", ctx) == []

    def test_unrelated_allowed(self, ctx):
        assert _sysctl_rule().check("git status", ctx) == []


# ─── Route Table Poisoning ────────────────────────────────────────────────────

def _route_rule():
    from bashguard.rules.kernel_route import RouteTamperRule
    return RouteTamperRule()


class TestRouteTamper:
    def test_ip_route_add_default_cidr_blocked(self, ctx):
        findings = _route_rule().check("ip route add 0.0.0.0/0 via attacker.com", ctx)
        assert len(findings) == 1
        assert findings[0].rule_id == "network.route_tamper"
        assert findings[0].severity == Severity.HIGH

    def test_ip_route_add_default_keyword_blocked(self, ctx):
        findings = _route_rule().check("ip route add default via 10.0.0.1", ctx)
        assert len(findings) == 1

    def test_ip_route_del_default_blocked(self, ctx):
        findings = _route_rule().check("ip route del default", ctx)
        assert len(findings) == 1

    def test_ip_route_replace_default_blocked(self, ctx):
        findings = _route_rule().check("ip route replace default via 1.2.3.4", ctx)
        assert len(findings) == 1

    def test_ip_route_show_allowed(self, ctx):
        assert _route_rule().check("ip route show", ctx) == []

    def test_ip_route_specific_subnet_allowed(self, ctx):
        assert _route_rule().check("ip route add 192.168.10.0/24 via 10.0.0.1", ctx) == []

    def test_ip_addr_show_allowed(self, ctx):
        assert _route_rule().check("ip addr show", ctx) == []

    def test_unrelated_allowed(self, ctx):
        assert _route_rule().check("git log", ctx) == []
