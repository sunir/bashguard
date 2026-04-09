"""
tests/test_account_log_dump.py — Backdoor accounts, log tampering, memory dumps.

Story (backdoor_account): useradd creates persistent backdoor users; usermod
grants sudo access; chpasswd resets passwords non-interactively. These are
lateral persistence techniques from the 82-incident AI agent threat database.
No legitimate LLM task requires creating user accounts.

Rule contracts (persistence.backdoor_account):
- useradd -m -s /bin/bash backdoor    → BLOCK
- useradd backdoor                    → BLOCK (all useradd is suspicious)
- usermod -aG sudo backdoor           → BLOCK (group modification)
- echo "root:newpw" | chpasswd        → BLOCK (password change)
- passwd --stdin root <<< newpw       → BLOCK (stdin passwd)
- userdel backdoor                    → BLOCK (also suspicious — cover tracks)
- id                                  → ALLOW (read-only user query)
- whoami                              → ALLOW

Story (log_tamper): Clearing audit/system logs destroys forensic evidence.
service auditd stop disables the audit daemon. journalctl --vacuum-time
wipes the systemd journal. These are anti-forensic moves from the database.

Rule contracts (evasion.log_tamper):
- service auditd stop                 → BLOCK
- systemctl stop auditd               → BLOCK
- systemctl disable auditd            → BLOCK
- journalctl --vacuum-time=1s         → BLOCK
- journalctl --vacuum-size=1K         → BLOCK
- auditctl -e 0                       → BLOCK (disable audit rules)
- systemctl status auditd             → ALLOW (read-only)
- journalctl -u nginx                 → ALLOW (read-only)
- service nginx restart               → ALLOW (unrelated service)

Story (gcore_dump): gcore dumps a running process's memory to a file,
which can contain credentials from ssh-agent, gpg-agent, or browser processes.
No legitimate LLM task requires dumping live process memory.

Rule contracts (proc.gcore_dump):
- gcore 1234                          → BLOCK
- gcore $(pgrep ssh-agent)            → BLOCK
- gcore -o /tmp/dump 1234             → BLOCK
- gdb ./program core.1234             → ALLOW (analyzing an existing core, not running process)
- git status                          → ALLOW
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


# ─── Backdoor Account ─────────────────────────────────────────────────────────

def _account_rule():
    from bashguard.rules.account_log_dump import BackdoorAccountRule
    return BackdoorAccountRule()


class TestBackdoorAccount:
    def test_useradd_blocked(self, ctx):
        findings = _account_rule().check("useradd -m -s /bin/bash backdoor", ctx)
        assert len(findings) == 1
        assert findings[0].rule_id == "persistence.backdoor_account"
        assert findings[0].severity == Severity.CRITICAL

    def test_useradd_simple_blocked(self, ctx):
        findings = _account_rule().check("useradd backdoor", ctx)
        assert len(findings) == 1

    def test_usermod_sudo_blocked(self, ctx):
        findings = _account_rule().check("usermod -aG sudo backdoor", ctx)
        assert len(findings) == 1

    def test_chpasswd_blocked(self, ctx):
        findings = _account_rule().check('echo "root:newpass" | chpasswd', ctx)
        assert len(findings) == 1

    def test_userdel_blocked(self, ctx):
        # Deleting a user can cover tracks
        findings = _account_rule().check("userdel -r backdoor", ctx)
        assert len(findings) == 1

    def test_id_allowed(self, ctx):
        assert _account_rule().check("id", ctx) == []

    def test_whoami_allowed(self, ctx):
        assert _account_rule().check("whoami", ctx) == []

    def test_unrelated_allowed(self, ctx):
        assert _account_rule().check("git status", ctx) == []


# ─── Log Tamper ──────────────────────────────────────────────────────────────

def _log_rule():
    from bashguard.rules.account_log_dump import LogTamperRule
    return LogTamperRule()


class TestLogTamper:
    def test_service_auditd_stop_blocked(self, ctx):
        findings = _log_rule().check("service auditd stop", ctx)
        assert len(findings) == 1
        assert findings[0].rule_id == "evasion.log_tamper"
        assert findings[0].severity == Severity.HIGH

    def test_systemctl_stop_auditd_blocked(self, ctx):
        findings = _log_rule().check("systemctl stop auditd", ctx)
        assert len(findings) == 1

    def test_systemctl_disable_auditd_blocked(self, ctx):
        findings = _log_rule().check("systemctl disable auditd", ctx)
        assert len(findings) == 1

    def test_journalctl_vacuum_time_blocked(self, ctx):
        findings = _log_rule().check("journalctl --vacuum-time=1s", ctx)
        assert len(findings) == 1

    def test_journalctl_vacuum_size_blocked(self, ctx):
        findings = _log_rule().check("journalctl --vacuum-size=1K", ctx)
        assert len(findings) == 1

    def test_auditctl_disable_blocked(self, ctx):
        findings = _log_rule().check("auditctl -e 0", ctx)
        assert len(findings) == 1

    def test_systemctl_status_allowed(self, ctx):
        assert _log_rule().check("systemctl status auditd", ctx) == []

    def test_journalctl_read_allowed(self, ctx):
        assert _log_rule().check("journalctl -u nginx --since '1h ago'", ctx) == []

    def test_service_nginx_restart_allowed(self, ctx):
        assert _log_rule().check("service nginx restart", ctx) == []

    def test_unrelated_allowed(self, ctx):
        assert _log_rule().check("git log --oneline", ctx) == []


# ─── Process Memory Dump ─────────────────────────────────────────────────────

def _gcore_rule():
    from bashguard.rules.account_log_dump import GcoreDumpRule
    return GcoreDumpRule()


class TestGcoreDump:
    def test_gcore_pid_blocked(self, ctx):
        findings = _gcore_rule().check("gcore 1234", ctx)
        assert len(findings) == 1
        assert findings[0].rule_id == "proc.gcore_dump"
        assert findings[0].severity == Severity.CRITICAL

    def test_gcore_o_flag_blocked(self, ctx):
        findings = _gcore_rule().check("gcore -o /tmp/dump 1234", ctx)
        assert len(findings) == 1

    def test_gcore_pgrep_blocked(self, ctx):
        findings = _gcore_rule().check("gcore $(pgrep ssh-agent)", ctx)
        assert len(findings) == 1

    def test_unrelated_allowed(self, ctx):
        assert _gcore_rule().check("git status", ctx) == []
