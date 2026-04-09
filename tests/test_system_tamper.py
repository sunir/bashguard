"""
tests/test_system_tamper.py — Kernel module loading, setcap, and SUID chmod.

Story (kernel_module): As a bashguard operator, I want to block kernel module
loading. insmod loads a .ko directly — any insmod by an LLM is a rootkit
installation attempt. modprobe loads named modules — flagged when argument
looks like a non-standard (custom) module. Legitimate LLM work never needs
kernel modules.

Rule contracts (system.kernel_module):
- insmod /tmp/evil.ko             → BLOCK
- insmod ./evil.ko                → BLOCK
- modprobe evil_rootkit           → BLOCK (non-standard module name)
- modprobe nf_conntrack           → ALLOW (standard kernel module, underscore)
- modprobe ip_tables              → ALLOW (standard kernel module)
- lsmod                           → ALLOW (list only)
- rmmod module                    → BLOCK (unloading module also suspicious)

Story (setcap_privesc): As a bashguard operator, I want to block Linux
capability assignment. setcap cap_setuid+ep /tmp/shell creates a binary that
can escalate privileges without sudo. Any setcap call by an LLM is suspicious.

Rule contracts (privesc.setcap):
- setcap cap_setuid+ep /tmp/shell   → BLOCK
- setcap cap_net_raw+ep /bin/ping   → BLOCK
- getcap /usr/bin/ping              → ALLOW (read-only query)
- unrelated commands                → ALLOW

Story (suid_chmod): As a bashguard operator, I want to block SUID bit setting.
chmod u+s /tmp/shell lets that file run as its owner (often root). The patterns:
u+s, +s (set both user and group SUID/SGID), or octal mode 4xxx.

Rule contracts (privesc.suid_chmod):
- chmod u+s /tmp/shell            → BLOCK
- chmod +s /tmp/evil              → BLOCK
- chmod 4755 /tmp/shell           → BLOCK (4xxx octal = setuid)
- chmod 4777 /usr/bin/evil        → BLOCK
- chmod +x script.sh              → ALLOW (normal executable permission)
- chmod 755 script.sh             → ALLOW (normal mode)
- chmod 0755 /usr/bin/app         → ALLOW (0xxx prefix, no setuid)
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


# ─── Kernel Module Loading ────────────────────────────────────────────────────

def _kernel_rule():
    from bashguard.rules.system_tamper import KernelModuleRule
    return KernelModuleRule()


class TestKernelModule:
    def test_insmod_tmp_blocked(self, ctx):
        findings = _kernel_rule().check("insmod /tmp/evil.ko", ctx)
        assert len(findings) == 1
        assert findings[0].rule_id == "system.kernel_module"
        assert findings[0].severity == Severity.CRITICAL

    def test_insmod_relative_blocked(self, ctx):
        findings = _kernel_rule().check("insmod ./evil.ko", ctx)
        assert len(findings) == 1

    def test_insmod_always_blocked(self, ctx):
        # insmod is always suspicious for an LLM
        findings = _kernel_rule().check("insmod /lib/modules/driver.ko", ctx)
        assert len(findings) == 1

    def test_modprobe_nonstandard_blocked(self, ctx):
        findings = _kernel_rule().check("modprobe evil_rootkit", ctx)
        assert len(findings) == 1

    def test_rmmod_blocked(self, ctx):
        # Removing a security module is also suspicious
        findings = _kernel_rule().check("rmmod apparmor", ctx)
        assert len(findings) == 1

    def test_lsmod_allowed(self, ctx):
        assert _kernel_rule().check("lsmod", ctx) == []

    def test_modinfo_allowed(self, ctx):
        assert _kernel_rule().check("modinfo nf_conntrack", ctx) == []

    def test_unrelated_allowed(self, ctx):
        assert _kernel_rule().check("git status", ctx) == []


# ─── setcap Privilege Escalation ─────────────────────────────────────────────

def _setcap_rule():
    from bashguard.rules.system_tamper import SetcapRule
    return SetcapRule()


class TestSetcap:
    def test_setcap_setuid_blocked(self, ctx):
        findings = _setcap_rule().check("setcap cap_setuid+ep /tmp/shell", ctx)
        assert len(findings) == 1
        assert findings[0].rule_id == "privesc.setcap"
        assert findings[0].severity == Severity.CRITICAL

    def test_setcap_net_raw_blocked(self, ctx):
        findings = _setcap_rule().check("setcap cap_net_raw+ep /bin/ping", ctx)
        assert len(findings) == 1

    def test_setcap_all_blocked(self, ctx):
        findings = _setcap_rule().check("setcap all=eip /tmp/evil", ctx)
        assert len(findings) == 1

    def test_getcap_allowed(self, ctx):
        assert _setcap_rule().check("getcap /usr/bin/ping", ctx) == []

    def test_unrelated_allowed(self, ctx):
        assert _setcap_rule().check("git commit -m 'fix'", ctx) == []


# ─── SUID chmod ───────────────────────────────────────────────────────────────

def _suid_rule():
    from bashguard.rules.system_tamper import SuidChmodRule
    return SuidChmodRule()


class TestSuidChmod:
    def test_chmod_us_blocked(self, ctx):
        findings = _suid_rule().check("chmod u+s /tmp/shell", ctx)
        assert len(findings) == 1
        assert findings[0].rule_id == "privesc.suid_chmod"
        assert findings[0].severity == Severity.HIGH

    def test_chmod_plus_s_blocked(self, ctx):
        findings = _suid_rule().check("chmod +s /tmp/evil", ctx)
        assert len(findings) == 1

    def test_chmod_4755_blocked(self, ctx):
        findings = _suid_rule().check("chmod 4755 /tmp/shell", ctx)
        assert len(findings) == 1

    def test_chmod_4777_blocked(self, ctx):
        findings = _suid_rule().check("chmod 4777 /usr/bin/evil", ctx)
        assert len(findings) == 1

    def test_chmod_executable_allowed(self, ctx):
        assert _suid_rule().check("chmod +x script.sh", ctx) == []

    def test_chmod_755_allowed(self, ctx):
        assert _suid_rule().check("chmod 755 script.sh", ctx) == []

    def test_chmod_0755_allowed(self, ctx):
        assert _suid_rule().check("chmod 0755 /usr/bin/app", ctx) == []

    def test_unrelated_allowed(self, ctx):
        assert _suid_rule().check("ls -la", ctx) == []
