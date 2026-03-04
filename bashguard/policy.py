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
    # Structured redirect payload — resolved against Finding.metadata at decide() time.
    # Template syntax: {"path": "{path}"} → resolved from finding.metadata["path"].
    # Literal values (int, non-template str) are kept as-is and count as resolved.
    redirect_tool: str | None = None
    redirect_args_template: dict | None = None


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


import re as _re

_TEMPLATE_VAR = _re.compile(r'^\{(\w+)\}$')


def _resolve_args(template: dict, metadata: dict) -> tuple[dict, bool]:
    """Resolve template variables from finding metadata.

    String values matching {key} are substituted from metadata.
    Literal values (int, float, or non-template str) are kept as-is.
    Returns (resolved_args, fully_resolved).
    """
    resolved: dict = {}
    all_resolved = True
    for k, v in template.items():
        if isinstance(v, str):
            m = _TEMPLATE_VAR.match(v)
            if m:
                value = metadata.get(m.group(1))
                resolved[k] = value
                if value is None:
                    all_resolved = False
            else:
                resolved[k] = v  # literal string
        else:
            resolved[k] = v  # literal int, float, etc.
    return resolved, all_resolved


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
    redirect_tool: str | None = None
    redirect_args: dict | None = None
    redirect_resolved: bool = False
    confirm_prompt: str | None = None

    for finding in findings:
        if finding.rule_id in rule_overrides:
            override = rule_overrides[finding.rule_id]
            v = override.verdict
            if v == VerdictType.REDIRECT:
                if override.redirect_template:
                    redirect_cmd = override.redirect_template
                # Structured payload — first REDIRECT finding wins (highest severity)
                if override.redirect_tool and redirect_tool is None:
                    redirect_tool = override.redirect_tool
                    if override.redirect_args_template is not None:
                        redirect_args, redirect_resolved = _resolve_args(
                            override.redirect_args_template, finding.metadata
                        )
                    else:
                        redirect_resolved = True
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
        redirect_tool=redirect_tool if worst == VerdictType.REDIRECT else None,
        redirect_args=redirect_args if worst == VerdictType.REDIRECT else None,
        redirect_resolved=redirect_resolved if worst == VerdictType.REDIRECT else False,
        confirmation_prompt=confirm_prompt if worst == VerdictType.CONFIRM else None,
    )
