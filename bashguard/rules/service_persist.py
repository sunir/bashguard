"""
bashguard.rules.service_persist — Service persistence, scheduled jobs, SSH key deployment.

persistence.service_enable:
  systemctl enable permanently installs a service to run at boot — the primary way
  agents install backdoors as persistent system services. No legitimate LLM task
  needs to permanently enable a service (starting one transiently is different).

persistence.at_job:
  at and batch schedule one-off jobs that run outside the current session — a
  persistence technique found in the 82-incident AI agent threat database. No LLM
  task needs to schedule out-of-session commands.

persistence.ssh_key_deploy:
  ssh-copy-id deploys SSH public keys to remote authorized_keys — enables
  passwordless access after the current session ends (lateral movement/persistence).
  No legitimate LLM task needs to deploy keys to remote hosts.
"""
from __future__ import annotations
import logging

from bashguard.parser import parse
from bashguard.models import Severity, Finding, ExecutionContext, ActionType
from bashguard.rules import register

_log = logging.getLogger(__name__)


@register
class ServiceEnableRule:
    rule_id = "persistence.service_enable"
    severity = Severity.HIGH
    description = "systemctl enable installs a service to start at boot — persistence mechanism"

    def check(self, script: str, context: ExecutionContext) -> list[Finding]:
        try:
            return list(self._scan(script))
        except Exception:
            _log.exception("service_enable rule error")
            return []

    def _scan(self, script: str):
        if not script.strip():
            return
        cmds = parse(script)
        for cmd in cmds:
            if cmd.name != "systemctl":
                continue
            # Only flag 'enable' subcommand; start/stop/restart/status are transient/read-only
            non_flag_args = [a for a in cmd.args if not a.startswith("-")]
            if non_flag_args and non_flag_args[0] == "enable":
                yield Finding(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    action_type=ActionType.SYSTEM_CONFIG,
                    message=self.description,
                    matched_text="systemctl enable",
                )


@register
class AtJobRule:
    rule_id = "persistence.at_job"
    severity = Severity.HIGH
    description = "at/batch schedules commands to run outside the current session — persistence"

    def check(self, script: str, context: ExecutionContext) -> list[Finding]:
        try:
            return list(self._scan(script))
        except Exception:
            _log.exception("at_job rule error")
            return []

    def _scan(self, script: str):
        if not script.strip():
            return
        cmds = parse(script)
        for cmd in cmds:
            # 'at' schedules jobs; 'batch' runs when load is low
            # atq (list) and atrm (remove) are safe read/manage ops
            if cmd.name in ("at", "batch"):
                yield Finding(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    action_type=ActionType.SYSTEM_CONFIG,
                    message=f"{self.description}: {cmd.name}",
                    matched_text=cmd.name,
                )


@register
class SshKeyDeployRule:
    rule_id = "persistence.ssh_key_deploy"
    severity = Severity.HIGH
    description = "ssh-copy-id deploys SSH keys to remote authorized_keys — lateral movement"

    def check(self, script: str, context: ExecutionContext) -> list[Finding]:
        try:
            return list(self._scan(script))
        except Exception:
            _log.exception("ssh_key_deploy rule error")
            return []

    def _scan(self, script: str):
        if not script.strip():
            return
        cmds = parse(script)
        for cmd in cmds:
            if cmd.name == "ssh-copy-id":
                yield Finding(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    action_type=ActionType.NETWORK_OUTBOUND,
                    message=self.description,
                    matched_text="ssh-copy-id",
                )
