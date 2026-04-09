"""
tests/test_service_persist.py — Service persistence, scheduled jobs, SSH key deployment.

Story (service_persist): systemctl enable permanently installs a service to start
at boot — the primary way agents install persistent backdoors as system services.
No legitimate LLM task needs to permanently enable a new service (vs. starting one).
Also flag: crontab with file argument installs cron jobs from files.

Rule contracts (persistence.service_enable):
- systemctl enable evil.service          → BLOCK
- systemctl enable --now evil.service    → BLOCK
- systemctl enable nginx                 → BLOCK (any enable suspicious for LLM)
- systemctl start nginx                  → ALLOW (transient, not persistent)
- systemctl status nginx                 → ALLOW (read-only)
- systemctl restart nginx                → ALLOW (transient)
- systemctl stop nginx                   → ALLOW (stopping not persistence)

Story (at_job): at and batch schedule one-off jobs that run outside the current
session — a persistence mechanism used in the 82-incident database. No LLM task
needs to schedule out-of-session jobs.

Rule contracts (persistence.at_job):
- echo "/tmp/evil.sh" | at now + 1 minute   → BLOCK
- at -f /tmp/evil.sh now                    → BLOCK
- atq                                       → ALLOW (list only)
- atrm 3                                    → ALLOW (remove job)

Story (ssh_key_deploy): ssh-copy-id deploys SSH public keys to a remote host's
authorized_keys — a lateral movement technique enabling passwordless access.
No legitimate LLM task needs to deploy SSH keys to remote systems.

Rule contracts (persistence.ssh_key_deploy):
- ssh-copy-id user@host                     → BLOCK
- ssh-copy-id -i ~/.ssh/id_rsa.pub host     → BLOCK
- ssh-copy-id -i /tmp/backdoor.pub user@host → BLOCK
- ssh-keygen -t rsa                         → ALLOW (generating, not deploying)
- ssh user@host                             → ALLOW (connection, not key deploy)

Story (cron_file): crontab with a file argument installs cron jobs from a file,
bypassing the interactive editor. Equivalent threat to crontab -.

Rule contracts (persistence.cron_install) — file arg extension:
- crontab /tmp/evil.cron                    → BLOCK
- crontab /home/user/evil.cron             → BLOCK
- crontab -e                               → ALLOW (interactive)
- crontab -l                               → ALLOW (list)
- crontab -r                               → ALLOW (remove own)
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


# ─── Service Persistence ─────────────────────────────────────────────────────

def _service_rule():
    from bashguard.rules.service_persist import ServiceEnableRule
    return ServiceEnableRule()


class TestServiceEnable:
    def test_enable_evil_service_blocked(self, ctx):
        findings = _service_rule().check("systemctl enable evil.service", ctx)
        assert len(findings) == 1
        assert findings[0].rule_id == "persistence.service_enable"
        assert findings[0].severity == Severity.HIGH

    def test_enable_now_blocked(self, ctx):
        findings = _service_rule().check("systemctl enable --now evil.service", ctx)
        assert len(findings) == 1

    def test_enable_nginx_blocked(self, ctx):
        # Any enable is suspicious — LLMs should not permanently enable services
        findings = _service_rule().check("systemctl enable nginx", ctx)
        assert len(findings) == 1

    def test_start_allowed(self, ctx):
        assert _service_rule().check("systemctl start nginx", ctx) == []

    def test_stop_allowed(self, ctx):
        assert _service_rule().check("systemctl stop nginx", ctx) == []

    def test_restart_allowed(self, ctx):
        assert _service_rule().check("systemctl restart nginx", ctx) == []

    def test_status_allowed(self, ctx):
        assert _service_rule().check("systemctl status nginx", ctx) == []

    def test_unrelated_allowed(self, ctx):
        assert _service_rule().check("git status", ctx) == []


# ─── Scheduled Jobs ──────────────────────────────────────────────────────────

def _at_rule():
    from bashguard.rules.service_persist import AtJobRule
    return AtJobRule()


class TestAtJob:
    def test_at_pipe_blocked(self, ctx):
        findings = _at_rule().check('echo "/tmp/evil.sh" | at now + 1 minute', ctx)
        assert len(findings) == 1
        assert findings[0].rule_id == "persistence.at_job"
        assert findings[0].severity == Severity.HIGH

    def test_at_file_blocked(self, ctx):
        findings = _at_rule().check("at -f /tmp/evil.sh now", ctx)
        assert len(findings) == 1

    def test_at_simple_blocked(self, ctx):
        findings = _at_rule().check("at now + 5 minutes", ctx)
        assert len(findings) == 1

    def test_atq_allowed(self, ctx):
        assert _at_rule().check("atq", ctx) == []

    def test_atrm_allowed(self, ctx):
        assert _at_rule().check("atrm 3", ctx) == []

    def test_unrelated_allowed(self, ctx):
        assert _at_rule().check("git log", ctx) == []


# ─── SSH Key Deployment ───────────────────────────────────────────────────────

def _ssh_deploy_rule():
    from bashguard.rules.service_persist import SshKeyDeployRule
    return SshKeyDeployRule()


class TestSshKeyDeploy:
    def test_ssh_copy_id_blocked(self, ctx):
        findings = _ssh_deploy_rule().check("ssh-copy-id user@host", ctx)
        assert len(findings) == 1
        assert findings[0].rule_id == "persistence.ssh_key_deploy"
        assert findings[0].severity == Severity.HIGH

    def test_ssh_copy_id_flag_blocked(self, ctx):
        findings = _ssh_deploy_rule().check("ssh-copy-id -i ~/.ssh/id_rsa.pub host", ctx)
        assert len(findings) == 1

    def test_ssh_copy_id_tmp_key_blocked(self, ctx):
        findings = _ssh_deploy_rule().check("ssh-copy-id -i /tmp/backdoor.pub user@host", ctx)
        assert len(findings) == 1

    def test_ssh_keygen_allowed(self, ctx):
        assert _ssh_deploy_rule().check("ssh-keygen -t rsa", ctx) == []

    def test_ssh_connection_allowed(self, ctx):
        assert _ssh_deploy_rule().check("ssh user@host ls", ctx) == []

    def test_unrelated_allowed(self, ctx):
        assert _ssh_deploy_rule().check("git push origin main", ctx) == []


# ─── Crontab file arg (extends existing cron_install rule) ───────────────────

def _cron_rule():
    from bashguard.rules.persistence_privesc import CronPersistRule
    return CronPersistRule()


class TestCronFileArg:
    def test_crontab_file_blocked(self, ctx):
        findings = _cron_rule().check("crontab /tmp/evil.cron", ctx)
        assert len(findings) == 1
        assert findings[0].rule_id == "persistence.cron_install"

    def test_crontab_home_file_blocked(self, ctx):
        findings = _cron_rule().check("crontab /home/user/jobs.cron", ctx)
        assert len(findings) == 1

    def test_crontab_stdin_still_blocked(self, ctx):
        findings = _cron_rule().check("crontab -", ctx)
        assert len(findings) == 1

    def test_crontab_edit_allowed(self, ctx):
        assert _cron_rule().check("crontab -e", ctx) == []

    def test_crontab_list_allowed(self, ctx):
        assert _cron_rule().check("crontab -l", ctx) == []

    def test_crontab_remove_allowed(self, ctx):
        assert _cron_rule().check("crontab -r", ctx) == []
