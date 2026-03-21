"""
bashguard.rules.external_comms — Block unauthorized external communications.

Inspired by n2-ark's external communication blocking.

Detects:
  comms.email   — sendmail, mail, mutt, SMTP via curl
  comms.sms     — Twilio API, AWS SNS phone-number messages
  comms.webhook — Slack/Discord/Teams incoming webhooks

An AI agent should not autonomously send messages to external parties.
"""
from __future__ import annotations

import logging
import re

from bashguard.models import ActionType, ExecutionContext, Finding, Severity
from bashguard.parser import parse
from bashguard.rules import register

_log = logging.getLogger(__name__)

# ─── Email commands ────────────────────────────────────────────────────────────

_EMAIL_CMDS = frozenset({"sendmail", "mail", "mutt", "msmtp", "ssmtp", "mailx"})
_SMTP_PATTERN = re.compile(r'smtp://', re.IGNORECASE)

# ─── SMS patterns ─────────────────────────────────────────────────────────────

_TWILIO_PATTERN = re.compile(r'api\.twilio\.com', re.IGNORECASE)
_SNS_PHONE = re.compile(r'--phone-number')

# ─── Webhook patterns ─────────────────────────────────────────────────────────

_WEBHOOK_PATTERNS = [
    re.compile(r'hooks\.slack\.com/services/', re.IGNORECASE),
    re.compile(r'discord\.com/api/webhooks/', re.IGNORECASE),
    re.compile(r'outlook\.office\.com/webhook/', re.IGNORECASE),
    re.compile(r'chat\.googleapis\.com/.*/messages', re.IGNORECASE),
]


def _finding(rule_id: str, message: str, raw: str) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=Severity.CRITICAL,
        message=message,
        matched_text=raw,
        action_type=ActionType.NETWORK_OUTBOUND,
    )


@register
class ExternalCommsRule:
    rule_id = "comms"
    severity = Severity.CRITICAL
    description = "Block unauthorized external communications (email, SMS, webhooks)"

    def check(self, script: str, context: ExecutionContext) -> list[Finding]:
        try:
            cmds = parse(script)
            findings: list[Finding] = []

            for cmd in cmds:
                # Email commands
                if cmd.name in _EMAIL_CMDS:
                    findings.append(_finding(
                        "comms.email",
                        f"External email via {cmd.name}",
                        cmd.raw,
                    ))
                    continue

                # SMTP via curl
                if cmd.name == "curl":
                    all_text = " ".join([cmd.name] + cmd.args + cmd.flags)

                    if _SMTP_PATTERN.search(all_text):
                        findings.append(_finding(
                            "comms.email",
                            "SMTP email via curl",
                            cmd.raw,
                        ))
                        continue

                    # Twilio SMS
                    if _TWILIO_PATTERN.search(all_text):
                        findings.append(_finding(
                            "comms.sms",
                            "SMS via Twilio API",
                            cmd.raw,
                        ))
                        continue

                    # Webhooks
                    for pattern in _WEBHOOK_PATTERNS:
                        if pattern.search(all_text):
                            findings.append(_finding(
                                "comms.webhook",
                                f"Webhook post detected: {pattern.pattern}",
                                cmd.raw,
                            ))
                            break

                # AWS SNS SMS
                if cmd.name == "aws" and "sns" in cmd.args:
                    all_text = " ".join(cmd.args + cmd.flags)
                    if _SNS_PHONE.search(all_text):
                        findings.append(_finding(
                            "comms.sms",
                            "SMS via AWS SNS",
                            cmd.raw,
                        ))

            return findings
        except Exception as e:
            _log.error("ExternalCommsRule raised: %s", e, exc_info=True)
            return []
