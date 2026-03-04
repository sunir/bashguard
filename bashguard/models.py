"""
bashguard.models — All data models for the security audit pipeline.

All models are frozen dataclasses: immutable values, not mutable objects.
No rule can modify a Finding after creation. Audit correctness is enforced
at the language level.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum


class Severity(Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class VerdictType(Enum):
    ALLOW = "allow"
    BLOCK = "block"
    CONFIRM = "confirm"
    REDIRECT = "redirect"


@dataclass(frozen=True)
class Finding:
    """One detected issue produced by one rule.

    Rules return 0..N Findings. A Finding is evidence, not a verdict.
    The policy layer decides what to do with the evidence.
    """
    rule_id: str                      # dotted id: "parse.error_node"
    severity: Severity
    message: str
    matched_text: str                 # exact text that triggered this
    span: tuple[int, int] = (0, 0)    # (start_byte, end_byte) in source
    metadata: dict = field(default_factory=dict)

    def __post_init__(self):
        if not self.rule_id:
            raise ValueError("rule_id must not be empty")


@dataclass(frozen=True)
class ExecutionContext:
    """Runtime context provided by the caller alongside every audit.

    Callers must be explicit — no hidden globals. Context drives
    context-sensitive rules (e.g. "is this path inside the worktree?").
    """
    cwd: str
    worktree_root: str | None = None
    allowed_hosts: frozenset = field(default_factory=frozenset)
    allowed_paths: frozenset = field(default_factory=frozenset)
    env_vars: dict = field(default_factory=dict)


@dataclass(frozen=True)
class Verdict:
    """Final output of the policy layer. This is what callers act on."""
    verdict: VerdictType
    findings: tuple                    # tuple[Finding, ...]
    message: str
    redirect_command: str | None = None
    confirmation_prompt: str | None = None
    # Structured redirect payload (Prolog unification model):
    #   resolved=True  → all args bound, call tool directly (no LLM round-trip)
    #   resolved=False → free variables present, surface to LLM to fill in
    redirect_tool: str | None = None
    redirect_args: dict | None = None
    redirect_resolved: bool = False
