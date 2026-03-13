"""
bashguard.rules — Rule Protocol and registry.

A Rule is any object satisfying the Rule protocol:
  - rule_id: str
  - severity: Severity
  - description: str
  - check(script: str, context: ExecutionContext) -> list[Finding]

Rules self-register via the @register decorator. Import this module
to populate the registry; import individual rule modules to register them.
"""

from __future__ import annotations
from typing import Protocol, runtime_checkable
from bashguard.models import Severity, Finding, ExecutionContext


@runtime_checkable
class Rule(Protocol):
    rule_id: str
    severity: Severity
    description: str

    def check(self, script: str, context: ExecutionContext) -> list[Finding]:
        """Inspect the script and return zero or more findings.
        Must NEVER raise. Return [] on any internal error."""
        ...


_REGISTRY: dict[str, Rule] = {}


def register(rule_class):
    """Class decorator. Instantiates and registers the rule."""
    instance = rule_class()
    _REGISTRY[instance.rule_id] = instance
    return rule_class


def all_rules() -> list[Rule]:
    return list(_REGISTRY.values())


def get_rule(rule_id: str) -> Rule | None:
    return _REGISTRY.get(rule_id)


def _load_builtin_rules() -> None:
    """Import all built-in rule modules so they self-register."""
    from bashguard.rules import error_nodes       # noqa: F401
    from bashguard.rules import credentials       # noqa: F401
    from bashguard.rules import network           # noqa: F401
    from bashguard.rules import destructive       # noqa: F401
    from bashguard.rules import package_install   # noqa: F401
    from bashguard.rules import git_scope         # noqa: F401
    from bashguard.rules import protected_paths   # noqa: F401
    from bashguard.rules import evasion             # noqa: F401
    from bashguard.rules import content_inspection  # noqa: F401


_load_builtin_rules()
