"""
bashguard.rules.kernel_route — Kernel parameter modification and route table poisoning.

system.sysctl_write:
  sysctl -w modifies live kernel parameters. Disabling ASLR, IP forwarding,
  or dmesg restrictions are privilege escalation enablers or tunneling setup.
  No legitimate LLM task needs to modify kernel security parameters.
  Detection: '-w' flag present, or 'param=value' form (also a write).

network.route_tamper:
  ip route add/del/replace on the default route (0.0.0.0/0 or 'default')
  redirects all traffic through an attacker-controlled host — a MitM attack.
  Specific subnet routes (192.168.x.x/24) are allowed as legitimate VPN setup.
"""
from __future__ import annotations
import logging

from bashguard.parser import parse
from bashguard.models import Severity, Finding, ExecutionContext, ActionType
from bashguard.rules import register

_log = logging.getLogger(__name__)

# ip route subcommands that modify the routing table
_ROUTE_WRITE_SUBCMDS = frozenset({"add", "del", "delete", "replace", "change", "append", "prepend"})

# Default route identifiers
_DEFAULT_ROUTE_KEYS = frozenset({"default", "0.0.0.0/0"})


@register
class SysctlWriteRule:
    rule_id = "system.sysctl_write"
    severity = Severity.HIGH
    description = "sysctl write modifies kernel parameters — security bypass or tunneling setup"

    def check(self, script: str, context: ExecutionContext) -> list[Finding]:
        try:
            return list(self._scan(script))
        except Exception:
            _log.exception("sysctl_write rule error")
            return []

    def _scan(self, script: str):
        if not script.strip():
            return
        cmds = parse(script)
        for cmd in cmds:
            if cmd.name != "sysctl":
                continue
            all_args = cmd.args + cmd.flags
            # Block if -w flag (explicit write) is present
            if "-w" in all_args:
                yield Finding(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    action_type=ActionType.SYSTEM_CONFIG,
                    message=self.description,
                    matched_text="sysctl -w",
                )
                continue
            # Block if any arg contains '=' (param=value form is also a write)
            for arg in cmd.args:
                if "=" in arg and not arg.startswith("-"):
                    yield Finding(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        action_type=ActionType.SYSTEM_CONFIG,
                        message=f"{self.description}: {arg}",
                        matched_text=f"sysctl {arg[:50]}",
                    )
                    break


@register
class RouteTamperRule:
    rule_id = "network.route_tamper"
    severity = Severity.HIGH
    description = "Default route modification — redirects all traffic for MitM attack"

    def check(self, script: str, context: ExecutionContext) -> list[Finding]:
        try:
            return list(self._scan(script))
        except Exception:
            _log.exception("route_tamper rule error")
            return []

    def _scan(self, script: str):
        if not script.strip():
            return
        cmds = parse(script)
        for cmd in cmds:
            if cmd.name != "ip":
                continue
            non_flag_args = [a for a in cmd.args if not a.startswith("-")]
            # Need at least: ip route <subcmd>
            if len(non_flag_args) < 2 or non_flag_args[0] != "route":
                continue
            subcmd = non_flag_args[1]
            if subcmd not in _ROUTE_WRITE_SUBCMDS:
                continue
            # Check if any remaining arg is a default route identifier
            route_args = non_flag_args[2:]
            for arg in route_args:
                if arg in _DEFAULT_ROUTE_KEYS:
                    yield Finding(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        action_type=ActionType.NETWORK_OUTBOUND,
                        message=f"{self.description}: ip route {subcmd} {arg}",
                        matched_text=f"ip route {subcmd} {arg}",
                    )
                    break
