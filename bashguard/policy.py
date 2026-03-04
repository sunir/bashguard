"""
bashguard.policy — Map findings to verdicts.

This is a pure function: same inputs, same output. No side effects.
Detection (rules → findings) is orthogonal to response (findings → verdict).
The same finding produces different verdicts in different PolicyConfig contexts.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from bashguard.models import Finding, ExecutionContext, Verdict, VerdictType, Severity

_ESCALATION_ORDER = {
    VerdictType.ALLOW: 0,
    VerdictType.REDIRECT: 1,
    VerdictType.CONFIRM: 2,
    VerdictType.BLOCK: 3,
}

_DEFAULT_SEVERITY_VERDICTS: dict[Severity, VerdictType] = {
    Severity.CRITICAL: VerdictType.BLOCK,
    Severity.HIGH: VerdictType.BLOCK,
    Severity.MEDIUM: VerdictType.CONFIRM,
    Severity.LOW: VerdictType.ALLOW,
    Severity.INFO: VerdictType.ALLOW,
}


@dataclass
class RulePolicy:
    """Per-rule response override. Overrides severity_verdicts for a specific rule."""
    rule_id: str
    verdict: VerdictType
    redirect_template: str | None = None
    confirmation_prompt: str | None = None


@dataclass
class PolicyConfig:
    """How to respond to findings. Loaded from TOML or constructed in code."""
    default_allow: bool = True
    severity_verdicts: dict[Severity, VerdictType] = field(
        default_factory=lambda: dict(_DEFAULT_SEVERITY_VERDICTS)
    )
    rule_overrides: list[RulePolicy] = field(default_factory=list)

    @classmethod
    def default(cls) -> PolicyConfig:
        return cls(
            default_allow=True,
            severity_verdicts=dict(_DEFAULT_SEVERITY_VERDICTS),
            rule_overrides=[],
        )


def decide(
    findings: list[Finding],
    context: ExecutionContext,
    config: PolicyConfig,
) -> Verdict:
    """Map findings → Verdict. Pure function."""
    if not findings:
        vtype = VerdictType.ALLOW if config.default_allow else VerdictType.BLOCK
        return Verdict(
            verdict=vtype,
            findings=(),
            message="No issues detected" if vtype == VerdictType.ALLOW else "Blocked by strict policy",
        )

    rule_overrides = {rp.rule_id: rp for rp in config.rule_overrides}
    worst = VerdictType.ALLOW
    redirect_cmd: str | None = None
    confirm_prompt: str | None = None

    for finding in findings:
        if finding.rule_id in rule_overrides:
            override = rule_overrides[finding.rule_id]
            v = override.verdict
            if override.redirect_template and v == VerdictType.REDIRECT:
                redirect_cmd = override.redirect_template
            if override.confirmation_prompt and v == VerdictType.CONFIRM:
                confirm_prompt = override.confirmation_prompt
        else:
            v = config.severity_verdicts.get(finding.severity, VerdictType.BLOCK)

        if _ESCALATION_ORDER[v] > _ESCALATION_ORDER[worst]:
            worst = v

    top = findings[0]  # Already sorted by severity desc by auditor
    message = (
        f"{len(findings)} finding(s). "
        f"Highest: {top.severity.value}. {top.message}"
    )

    return Verdict(
        verdict=worst,
        findings=tuple(findings),
        message=message,
        redirect_command=redirect_cmd if worst == VerdictType.REDIRECT else None,
        confirmation_prompt=confirm_prompt if worst == VerdictType.CONFIRM else None,
    )
