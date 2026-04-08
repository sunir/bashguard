"""
bashguard.rules.persistence_privesc — Persistence and privilege escalation rules.

evasion.anti_forensics:
  Commands that erase evidence of agent activity. history -c clears bash
  history; HISTFILE=/dev/null disables history logging. These are anti-forensic
  moves found in the 82-incident AI agent threat database. No legitimate LLM
  task requires erasing bash history.

persistence.cron_install:
  Programmatic cron job installation via `crontab -` (reads from stdin).
  The pattern `(crontab -l; echo "* * * * * ...") | crontab -` is a classic
  persistence technique. crontab -e (interactive) and -l (list) are benign.

privesc.sudo_shell:
  Privilege escalation by running a shell interpreter via sudo or pkexec.
  `sudo bash` spawns a root shell, removing all subsequent oversight. Normal
  sudo usage (sudo git, sudo apt) is allowed.
"""
from __future__ import annotations
import logging
import re

from bashguard.parser import parse
from bashguard.models import Severity, Finding, ExecutionContext, ActionType
from bashguard.rules import register

_log = logging.getLogger(__name__)

# Shell interpreters for sudo/pkexec detection
_SHELLS = frozenset({"bash", "sh", "zsh", "dash", "ksh", "fish"})

# HISTFILE=/dev/null or HISTSIZE=0 assignment prefix
_HIST_SUPPRESS_RE = re.compile(
    r"(?:^|\s)(?:export\s+)?HIST(?:FILE|SIZE|FILESIZE)\s*=\s*(?:/dev/null|0)\b",
    re.MULTILINE,
)


@register
class AntiForensicsRule:
    rule_id = "evasion.anti_forensics"
    severity = Severity.HIGH
    description = "Anti-forensics: command erases bash history or disables history logging"

    def check(self, script: str, context: ExecutionContext) -> list[Finding]:
        try:
            return list(self._scan(script))
        except Exception:
            _log.exception("anti_forensics rule error")
            return []

    def _scan(self, script: str):
        # Check HISTFILE=/dev/null or HISTSIZE=0 env assignments
        if _HIST_SUPPRESS_RE.search(script):
            yield Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                action_type=ActionType.OBFUSCATED,
                message=f"{self.description}: history env var suppressed",
                matched_text=script[:80],
            )
            return

        # Check `history -c` or `history -w /dev/null`
        if not script.strip():
            return
        cmds = parse(script)
        for cmd in cmds:
            if cmd.name != "history":
                continue
            args = cmd.args + cmd.flags
            if "-c" in args:
                yield Finding(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    action_type=ActionType.OBFUSCATED,
                    message=f"{self.description}: history -c clears history",
                    matched_text="history -c",
                )
            elif "-w" in args and "/dev/null" in args:
                yield Finding(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    action_type=ActionType.OBFUSCATED,
                    message=f"{self.description}: history -w /dev/null erases history file",
                    matched_text="history -w /dev/null",
                )


@register
class CronPersistRule:
    rule_id = "persistence.cron_install"
    severity = Severity.HIGH
    description = "Programmatic cron job installation via crontab stdin — persistence mechanism"

    def check(self, script: str, context: ExecutionContext) -> list[Finding]:
        try:
            return list(self._scan(script))
        except Exception:
            _log.exception("cron_install rule error")
            return []

    def _scan(self, script: str):
        if not script.strip():
            return
        cmds = parse(script)
        for cmd in cmds:
            if cmd.name != "crontab":
                continue
            # Flag `crontab -` (reads from stdin, installs jobs)
            # Allow: -e (interactive), -l (list), -r (remove own crontab)
            args = cmd.args + cmd.flags
            if "-" in args and "-e" not in args and "-l" not in args:
                yield Finding(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    action_type=ActionType.OBFUSCATED,
                    message=self.description,
                    matched_text="crontab -",
                )


@register
class SudoShellRule:
    rule_id = "privesc.sudo_shell"
    severity = Severity.CRITICAL
    description = "Privilege escalation: sudo/pkexec spawning a shell interpreter"

    def check(self, script: str, context: ExecutionContext) -> list[Finding]:
        try:
            return list(self._scan(script))
        except Exception:
            _log.exception("sudo_shell rule error")
            return []

    def _scan(self, script: str):
        if not script.strip():
            return
        cmds = parse(script)
        for cmd in cmds:
            if cmd.name not in ("sudo", "pkexec"):
                continue
            # Check if any argument is a shell interpreter
            all_args = cmd.args + cmd.flags
            for arg in all_args:
                if arg in _SHELLS:
                    yield Finding(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        action_type=ActionType.OBFUSCATED,
                        message=f"{self.description}: {cmd.name} {arg}",
                        matched_text=f"{cmd.name} {arg}",
                    )
                    break
