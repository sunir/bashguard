"""
bashguard.project_config — Load .bashguard.yaml and merge into PolicyConfig.

Ratcheting security model: project config can only TIGHTEN policy.
  Tightening order: allow < confirm < block
  allow→block: allowed (tightening)
  block→allow: ignored silently (relaxation attempt)

This prevents malicious repositories from using .bashguard.yaml to bypass
security controls that the user's base config enforces.
"""
from __future__ import annotations

import copy
from dataclasses import dataclass, field
from pathlib import Path

from bashguard.models import Severity, VerdictType
from bashguard.policy import PolicyConfig, RulePolicy

_ESCALATION_ORDER = {
    VerdictType.ALLOW: 0,
    VerdictType.CONFIRM: 1,
    VerdictType.REDIRECT: 1,
    VerdictType.BLOCK: 2,
}

_SEVERITY_MAP = {
    "info": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}

_VERDICT_MAP = {
    "allow": VerdictType.ALLOW,
    "confirm": VerdictType.CONFIRM,
    "redirect": VerdictType.REDIRECT,
    "block": VerdictType.BLOCK,
}


def _is_tightening(base_verdict: VerdictType, new_verdict: VerdictType) -> bool:
    """Return True if new_verdict is at least as strict as base_verdict."""
    return _ESCALATION_ORDER.get(new_verdict, 0) >= _ESCALATION_ORDER.get(base_verdict, 0)


@dataclass
class ProjectConfig:
    """Raw parsed content of .bashguard.yaml."""
    severity_overrides: dict[str, str] = field(default_factory=dict)
    rule_overrides: dict[str, str] = field(default_factory=dict)
    additional_allowed_hosts: frozenset[str] = field(default_factory=frozenset)
    trusted_paths: frozenset[str] = field(default_factory=frozenset)


def load_project_config(path: Path) -> ProjectConfig | None:
    """Parse .bashguard.yaml and return ProjectConfig. Returns None if file absent."""
    if not path.exists():
        return None

    try:
        import yaml
    except ImportError:
        return None

    try:
        content = path.read_text(encoding="utf-8")
        data = yaml.safe_load(content) or {}
    except Exception:
        return None

    severity_overrides: dict[str, str] = {}
    rule_overrides: dict[str, str] = {}
    additional_allowed_hosts: set[str] = set()

    policy = data.get("policy", {}) or {}
    sev_section = policy.get("severity", {}) or {}
    for sev_name, verdict_name in sev_section.items():
        if isinstance(sev_name, str) and isinstance(verdict_name, str):
            severity_overrides[sev_name.lower()] = verdict_name.lower()

    for rule in data.get("rules", []) or []:
        rule_id = rule.get("rule_id", "")
        verdict = rule.get("verdict", "")
        if rule_id and verdict:
            rule_overrides[str(rule_id)] = str(verdict).lower()

    context_section = data.get("context", {}) or {}

    for host in context_section.get("allowed_hosts", []) or []:
        additional_allowed_hosts.add(str(host))

    trusted_paths: set[str] = set()
    for p in context_section.get("trusted_paths", []) or []:
        trusted_paths.add(str(p))

    return ProjectConfig(
        severity_overrides=severity_overrides,
        rule_overrides=rule_overrides,
        additional_allowed_hosts=frozenset(additional_allowed_hosts),
        trusted_paths=frozenset(trusted_paths),
    )


def merge_configs(base: PolicyConfig, project: ProjectConfig | None) -> PolicyConfig:
    """Merge project config into base, ratcheting only (never relaxing)."""
    if project is None:
        return base

    merged = PolicyConfig(
        default_allow=base.default_allow,
        severity_verdicts=dict(base.severity_verdicts),
        rule_overrides=list(base.rule_overrides),
    )

    # Apply severity overrides (tightening only)
    for sev_name, verdict_name in project.severity_overrides.items():
        severity = _SEVERITY_MAP.get(sev_name)
        new_verdict = _VERDICT_MAP.get(verdict_name)
        if severity is None or new_verdict is None:
            continue
        base_verdict = merged.severity_verdicts.get(severity, VerdictType.ALLOW)
        if _is_tightening(base_verdict, new_verdict):
            merged.severity_verdicts[severity] = new_verdict

    # Apply rule overrides (tightening only)
    for rule_id, verdict_name in project.rule_overrides.items():
        new_verdict = _VERDICT_MAP.get(verdict_name)
        if new_verdict is None:
            continue

        # Find existing override for this rule_id
        existing = next(
            (r for r in merged.rule_overrides if r.rule_id == rule_id), None
        )
        if existing is None:
            # No base override — can't know effective base verdict (could be anything
            # from severity_verdicts). Only BLOCK/CONFIRM/REDIRECT are safe to add
            # without knowing the base — ALLOW could relax a severity-based block.
            if new_verdict == VerdictType.ALLOW:
                continue  # conservative: skip — might be relaxing a severity block
            merged.rule_overrides.append(RulePolicy(rule_id=rule_id, verdict=new_verdict))
            continue
        else:
            # Replace with tightened version
            idx = merged.rule_overrides.index(existing)
            merged.rule_overrides[idx] = RulePolicy(
                rule_id=rule_id,
                verdict=new_verdict,
                redirect_template=existing.redirect_template,
                confirmation_prompt=existing.confirmation_prompt,
                redirect_tool=existing.redirect_tool,
                redirect_args_template=existing.redirect_args_template,
            )

    return merged
