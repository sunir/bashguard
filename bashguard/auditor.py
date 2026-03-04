"""
bashguard.auditor — Apply security rules to a bash script.

Takes a script string and ExecutionContext. Returns all Findings from all
registered rules, sorted by severity (highest first).

A crashing rule is logged and skipped — it never terminates the audit.
Silent bypass is worse than noisy crash.
"""

from __future__ import annotations
import logging
from bashguard.models import Finding, ExecutionContext, Severity
from bashguard.rules import all_rules, Rule

_log = logging.getLogger(__name__)

_SEVERITY_ORDER: dict[Severity, int] = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.INFO: 1,
}


def audit(
    script: str,
    context: ExecutionContext,
    rules: list[Rule] | None = None,
) -> list[Finding]:
    """Apply rules to script. Returns findings sorted by severity descending."""
    if not script.strip():
        return []

    active_rules = rules if rules is not None else all_rules()
    findings: list[Finding] = []

    for rule in active_rules:
        try:
            rule_findings = rule.check(script, context)
            findings.extend(rule_findings)
        except Exception as e:
            _log.error(
                "Rule %s raised unexpectedly: %s", rule.rule_id, e, exc_info=True
            )

    findings.sort(key=lambda f: _SEVERITY_ORDER.get(f.severity, 0), reverse=True)
    return findings
