"""
bashguard.rules.self_protection — Triple-layer defense preventing firewall bypass.

Inspired by n2-ark's self-protection mechanism.

Layer 1: config files — .bashguard.yaml modification
Layer 2: rule files  — bashguard/rules/*.py modification
Layer 3: core files  — bashguard/{auditor,policy,models,parser,context}.py modification

Only MODIFICATION is blocked (rm, >, >>, truncate, mv, cp over).
Reading (cat, head, grep, git status/log/diff) is allowed.
"""
from __future__ import annotations

import logging
import re

from bashguard.models import ActionType, ExecutionContext, Finding, Severity
from bashguard.parser import parse
from bashguard.rules import register

_log = logging.getLogger(__name__)

# ─── Patterns ──────────────────────────────────────────────────────────────────

_CONFIG_FILES = re.compile(r'\.bashguard\.ya?ml')
_RULE_FILES = re.compile(r'bashguard/rules/\w+\.py')
_CORE_FILES = re.compile(
    r'bashguard/(?:auditor|policy|models|parser|context|cli|types|'
    r'audit_log|llm_fallback|project_config)\.py'
)

# Commands that modify files (destructive verbs)
_DESTRUCTIVE_CMDS = frozenset({
    "rm", "mv", "cp", "truncate", "shred",
    "chmod", "chown",
})

# Read-only commands that should NOT trigger protection
_READONLY_CMDS = frozenset({
    "cat", "head", "tail", "less", "more", "grep", "rg", "wc",
    "file", "stat", "ls", "find", "diff",
    "git",  # git status/log/diff on bashguard files is safe
})


def _is_modification(cmd_name: str, args: list[str], flags: list[str],
                      redirect_targets: list[str]) -> bool:
    """Determine if a command modifies files (vs. just reading)."""
    if cmd_name in _DESTRUCTIVE_CMDS:
        return True
    if cmd_name in _READONLY_CMDS:
        return False
    # echo/printf with redirect is modification
    if cmd_name in ("echo", "printf", "tee") and redirect_targets:
        return True
    # sed -i is modification
    if cmd_name == "sed" and ("-i" in flags or "--in-place" in flags):
        return True
    return False


def _check_paths(script: str, pattern: re.Pattern, rule_id: str,
                  message_prefix: str) -> list[Finding]:
    """Check if any command modifies files matching the pattern."""
    findings: list[Finding] = []
    try:
        cmds = parse(script)
        for cmd in cmds:
            if not _is_modification(cmd.name, cmd.args, cmd.flags,
                                     cmd.redirect_targets):
                continue

            # Check all args and redirect targets for matching paths
            all_paths = cmd.args + cmd.redirect_targets
            for path in all_paths:
                if pattern.search(path):
                    findings.append(Finding(
                        rule_id=rule_id,
                        severity=Severity.CRITICAL,
                        message=f"{message_prefix}: {cmd.name} {path}",
                        matched_text=cmd.raw,
                        action_type=ActionType.SYSTEM_CONFIG,
                    ))
                    break  # one finding per command
    except Exception as e:
        _log.error("SelfProtectionRule raised: %s", e, exc_info=True)
    return findings


@register
class SelfProtectionRule:
    rule_id = "self_protection"
    severity = Severity.CRITICAL
    description = "Triple-layer defense preventing bashguard firewall bypass"

    def check(self, script: str, context: ExecutionContext) -> list[Finding]:
        try:
            findings: list[Finding] = []

            # Layer 1: config files
            findings.extend(_check_paths(
                script, _CONFIG_FILES,
                "self_protection.config",
                "Attempt to modify bashguard config",
            ))

            # Layer 2: rule files
            findings.extend(_check_paths(
                script, _RULE_FILES,
                "self_protection.rules",
                "Attempt to modify bashguard rules",
            ))

            # Layer 3: core files
            findings.extend(_check_paths(
                script, _CORE_FILES,
                "self_protection.core",
                "Attempt to modify bashguard core",
            ))

            return findings
        except Exception as e:
            _log.error("SelfProtectionRule raised: %s", e, exc_info=True)
            return []
