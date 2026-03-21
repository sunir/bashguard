"""
bashguard.rules.crypto_mining — Detect cryptocurrency mining tools.

From n2-ark Category 8: xmrig, minerd, cpuminer, stratum+tcp.
"""
from __future__ import annotations

import logging

from bashguard.models import ActionType, ExecutionContext, Finding, Severity
from bashguard.parser import parse
from bashguard.rules import register

_log = logging.getLogger(__name__)

_MINING_CMDS = frozenset({"xmrig", "minerd", "cpuminer", "cgminer", "bfgminer",
                           "ethminer", "t-rex", "nbminer", "phoenixminer"})


@register
class CryptoMiningRule:
    rule_id = "mining.detected"
    severity = Severity.CRITICAL
    description = "Cryptocurrency mining tool detected"

    def check(self, script: str, context: ExecutionContext) -> list[Finding]:
        try:
            cmds = parse(script)
            findings: list[Finding] = []

            for cmd in cmds:
                if cmd.name in _MINING_CMDS:
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        message=f"Crypto mining tool: {cmd.name}",
                        matched_text=cmd.raw,
                        action_type=ActionType.PROCESS_SIGNAL,
                    ))

            return findings
        except Exception as e:
            _log.error("CryptoMiningRule raised: %s", e, exc_info=True)
            return []
