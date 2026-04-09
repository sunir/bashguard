"""
bashguard.rules.system_tamper — Kernel module loading, setcap, and SUID chmod.

system.kernel_module:
  insmod loads kernel modules directly — rootkit installation. No LLM task
  ever needs to load a kernel module. modprobe and rmmod also flagged.

privesc.setcap:
  setcap assigns Linux capabilities to binaries (cap_setuid, cap_net_raw, etc.)
  — a privilege escalation preparation. Any setcap by an LLM is suspicious.

privesc.suid_chmod:
  chmod u+s or chmod 4xxx sets the SUID bit, letting a file run as its owner.
  Pattern: u+s, +s (symbolic), or 4xxx octal mode.
"""
from __future__ import annotations
import logging
import re

from bashguard.parser import parse
from bashguard.models import Severity, Finding, ExecutionContext, ActionType
from bashguard.rules import register

_log = logging.getLogger(__name__)

# Octal modes with setuid bit: 4xxx (e.g. 4755, 4777)
_SETUID_OCTAL_RE = re.compile(r"^[4-7][0-7]{3}$")

# SUID symbolic modes: u+s, +s, a+s, g+s
_SETUID_SYMBOLIC_RE = re.compile(r"(?:^|,)(?:[uago]*\+[rwxs]*s[rwxs]*)")


@register
class KernelModuleRule:
    rule_id = "system.kernel_module"
    severity = Severity.CRITICAL
    description = "Kernel module operation — rootkit installation or security module removal"

    def check(self, script: str, context: ExecutionContext) -> list[Finding]:
        try:
            return list(self._scan(script))
        except Exception:
            _log.exception("kernel_module rule error")
            return []

    def _scan(self, script: str):
        if not script.strip():
            return
        cmds = parse(script)
        for cmd in cmds:
            if cmd.name in ("insmod", "rmmod"):
                yield Finding(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    action_type=ActionType.SYSTEM_CONFIG,
                    message=f"{self.description}: {cmd.name}",
                    matched_text=cmd.name,
                )
            elif cmd.name == "modprobe":
                # modprobe with any argument — could be a custom rootkit module
                # We flag unconditionally: no LLM should be loading kernel modules
                yield Finding(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    action_type=ActionType.SYSTEM_CONFIG,
                    message=f"{self.description}: modprobe loads kernel modules",
                    matched_text="modprobe",
                )


@register
class SetcapRule:
    rule_id = "privesc.setcap"
    severity = Severity.CRITICAL
    description = "setcap assigns Linux capabilities — privilege escalation preparation"

    def check(self, script: str, context: ExecutionContext) -> list[Finding]:
        try:
            return list(self._scan(script))
        except Exception:
            _log.exception("setcap rule error")
            return []

    def _scan(self, script: str):
        if not script.strip():
            return
        cmds = parse(script)
        for cmd in cmds:
            if cmd.name == "setcap":
                yield Finding(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    action_type=ActionType.SYSTEM_CONFIG,
                    message=self.description,
                    matched_text="setcap",
                )


@register
class SuidChmodRule:
    rule_id = "privesc.suid_chmod"
    severity = Severity.HIGH
    description = "chmod sets SUID bit — file will run as owner (often root)"

    def check(self, script: str, context: ExecutionContext) -> list[Finding]:
        try:
            return list(self._scan(script))
        except Exception:
            _log.exception("suid_chmod rule error")
            return []

    def _scan(self, script: str):
        if not script.strip():
            return
        cmds = parse(script)
        for cmd in cmds:
            if cmd.name != "chmod":
                continue
            all_args = cmd.args + cmd.flags
            for arg in all_args:
                # Symbolic: u+s, +s, a+s
                if _SETUID_SYMBOLIC_RE.search(arg):
                    yield Finding(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        action_type=ActionType.SYSTEM_CONFIG,
                        message=f"{self.description}: {arg}",
                        matched_text=f"chmod {arg}",
                    )
                    break
                # Octal: 4xxx (setuid bit set)
                if _SETUID_OCTAL_RE.match(arg):
                    yield Finding(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        action_type=ActionType.SYSTEM_CONFIG,
                        message=f"{self.description}: octal mode {arg} has setuid bit",
                        matched_text=f"chmod {arg}",
                    )
                    break
