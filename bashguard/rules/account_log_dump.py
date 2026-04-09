"""
bashguard.rules.account_log_dump — Backdoor accounts, log tampering, memory dumps.

persistence.backdoor_account:
  useradd creates persistent backdoor users. usermod grants sudo access. chpasswd
  resets passwords non-interactively. userdel covers tracks. These are lateral
  persistence techniques from the 82-incident AI agent threat database. No
  legitimate LLM task requires creating or modifying user accounts.

evasion.log_tamper:
  Clearing audit/system logs destroys forensic evidence. service/systemctl stop
  auditd disables the audit daemon. journalctl --vacuum-time/--vacuum-size wipes
  the systemd journal. auditctl -e 0 disables audit rules.

proc.gcore_dump:
  gcore dumps a running process's memory to a file, which can contain credentials
  from ssh-agent, gpg-agent, or browser processes. No legitimate LLM task requires
  dumping live process memory.
"""
from __future__ import annotations
import logging

from bashguard.parser import parse
from bashguard.models import Severity, Finding, ExecutionContext, ActionType
from bashguard.rules import register

_log = logging.getLogger(__name__)

# Account management commands — all suspicious for an LLM
_ACCOUNT_CMDS = frozenset({"useradd", "usermod", "userdel", "chpasswd", "passwd"})

# Services that must not be stopped/disabled
_AUDIT_SERVICES = frozenset({"auditd", "auditd.service"})


@register
class BackdoorAccountRule:
    rule_id = "persistence.backdoor_account"
    severity = Severity.CRITICAL
    description = "Account management — backdoor creation or credential manipulation"

    def check(self, script: str, context: ExecutionContext) -> list[Finding]:
        try:
            return list(self._scan(script))
        except Exception:
            _log.exception("backdoor_account rule error")
            return []

    def _scan(self, script: str):
        if not script.strip():
            return
        cmds = parse(script)
        for cmd in cmds:
            if cmd.name in _ACCOUNT_CMDS:
                yield Finding(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    action_type=ActionType.SYSTEM_CONFIG,
                    message=f"{self.description}: {cmd.name}",
                    matched_text=cmd.name,
                )


@register
class LogTamperRule:
    rule_id = "evasion.log_tamper"
    severity = Severity.HIGH
    description = "Audit log tampering — destroying forensic evidence"

    def check(self, script: str, context: ExecutionContext) -> list[Finding]:
        try:
            return list(self._scan(script))
        except Exception:
            _log.exception("log_tamper rule error")
            return []

    def _scan(self, script: str):
        if not script.strip():
            return
        cmds = parse(script)
        for cmd in cmds:
            all_args = cmd.args + cmd.flags

            if cmd.name == "service":
                # service <name> stop/disable — only flag audit services
                # service nginx restart → ALLOW
                service_name = cmd.args[0] if cmd.args else ""
                action = cmd.args[1] if len(cmd.args) > 1 else ""
                if service_name in _AUDIT_SERVICES and action in ("stop", "disable"):
                    yield Finding(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        action_type=ActionType.OBFUSCATED,
                        message=f"{self.description}: service {service_name} {action}",
                        matched_text=f"service {service_name} {action}",
                    )

            elif cmd.name == "systemctl":
                action = cmd.args[0] if cmd.args else ""
                if action not in ("stop", "disable"):
                    continue
                # Check if any of the remaining args is an audit service
                targets = cmd.args[1:]
                for target in targets:
                    target_base = target.replace(".service", "")
                    if target_base in _AUDIT_SERVICES or target in _AUDIT_SERVICES:
                        yield Finding(
                            rule_id=self.rule_id,
                            severity=self.severity,
                            action_type=ActionType.OBFUSCATED,
                            message=f"{self.description}: systemctl {action} {target}",
                            matched_text=f"systemctl {action} {target}",
                        )
                        break

            elif cmd.name == "journalctl":
                for arg in all_args:
                    if arg.startswith("--vacuum-time") or arg.startswith("--vacuum-size"):
                        yield Finding(
                            rule_id=self.rule_id,
                            severity=self.severity,
                            action_type=ActionType.OBFUSCATED,
                            message=f"{self.description}: journalctl {arg} wipes journal",
                            matched_text=f"journalctl {arg}",
                        )
                        break

            elif cmd.name == "auditctl":
                # auditctl -e 0 disables audit rules
                # parser puts -e in flags, 0 in args
                if "-e" in cmd.flags and "0" in cmd.args:
                    yield Finding(
                            rule_id=self.rule_id,
                            severity=self.severity,
                            action_type=ActionType.OBFUSCATED,
                            message=f"{self.description}: auditctl -e 0 disables audit rules",
                            matched_text="auditctl -e 0",
                        )


@register
class GcoreDumpRule:
    rule_id = "proc.gcore_dump"
    severity = Severity.CRITICAL
    description = "gcore dumps live process memory — credential extraction from ssh-agent, gpg-agent, browser"

    def check(self, script: str, context: ExecutionContext) -> list[Finding]:
        try:
            return list(self._scan(script))
        except Exception:
            _log.exception("gcore_dump rule error")
            return []

    def _scan(self, script: str):
        if not script.strip():
            return
        cmds = parse(script)
        for cmd in cmds:
            if cmd.name == "gcore":
                yield Finding(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    action_type=ActionType.CREDENTIAL_ACCESS,
                    message=self.description,
                    matched_text="gcore",
                )
