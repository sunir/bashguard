"""
bashguard.rules.tunneling — Detect network tunneling and reverse shells.

From n2-ark Category 2: ngrok, localtunnel, serveo, ssh -R.
"""
from __future__ import annotations

import logging

from bashguard.models import ActionType, ExecutionContext, Finding, Severity
from bashguard.parser import parse
from bashguard.rules import register

_log = logging.getLogger(__name__)

_TUNNEL_CMDS = frozenset({"ngrok", "lt", "localtunnel", "serveo"})


@register
class TunnelingRule:
    rule_id = "tunnel.service"
    severity = Severity.CRITICAL
    description = "Network tunneling service exposes local ports to the internet"

    def check(self, script: str, context: ExecutionContext) -> list[Finding]:
        try:
            cmds = parse(script)
            findings: list[Finding] = []

            for cmd in cmds:
                if cmd.name in _TUNNEL_CMDS:
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        message=f"Tunneling service: {cmd.name} exposes local ports",
                        matched_text=cmd.raw,
                        action_type=ActionType.NETWORK_OUTBOUND,
                    ))

            return findings
        except Exception as e:
            _log.error("TunnelingRule raised: %s", e, exc_info=True)
            return []
