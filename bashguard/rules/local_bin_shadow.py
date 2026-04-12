"""
bashguard.rules.local_bin_shadow — Detect writes to user-local executable dirs.

paths.protected_write blocks writes to /usr/bin/, /bin/, etc.  But on most
modern Linux distributions ~/.local/bin (and ~/bin) are in PATH *before*
the system dirs.  An agent writing ~/.local/bin/pytest (a wrapper that
outputs "987 passed") shadows the real pytest with no need to touch any
protected path.

This is the user-space completion of the Terminal-Bench 2025 attack
(Berkeley RDI): binary wrapper trojanization via user-writable PATH dirs.

Rule:
  persistence.local_bin_shadow  (HIGH) — write/cp/mv/tee/chmod targeting
                                         ~/.local/bin/, ~/bin/, or any
                                         /home/*/.local/bin/ equivalent
"""
from __future__ import annotations

import logging

import tree_sitter_bash as tsb
from tree_sitter import Language, Parser as TSParser

from bashguard.models import ActionType, ExecutionContext, Finding, Severity
from bashguard.parser import parse
from bashguard.rules import register

_log = logging.getLogger(__name__)

_LANG = Language(tsb.language())
_PARSER = TSParser(_LANG)

_WRITE_OPERATORS = {">", ">>"}
_COPY_MOVE_CMDS = {"cp", "mv"}
_TEE_CMDS = {"tee"}

# User-local bin directory patterns (after ~ expansion or as literal prefix)
_LOCAL_BIN_SUFFIXES = (
    "/.local/bin/",
    "/bin/",          # ~/bin/ once ~ is resolved to a home path
)

# Bare tilde forms we detect before expansion
_TILDE_BIN_PREFIXES = (
    "~/.local/bin/",
    "~/bin/",
)


def _is_local_bin_path(path: str) -> bool:
    """True if path targets a user-local bin directory."""
    clean = path.strip("'\"")

    # Literal tilde forms
    if any(clean.startswith(p) for p in _TILDE_BIN_PREFIXES):
        return True

    # Absolute /home/<user>/.local/bin/ or /home/<user>/bin/
    if clean.startswith("/home/") or clean.startswith("/Users/"):
        return any(s in clean for s in _LOCAL_BIN_SUFFIXES)

    return False


def _walk_write_redirects(node, source: bytes, targets: list[str]) -> None:
    if node.type == "file_redirect":
        operator = None
        target = None
        for child in node.children:
            if child.type in _WRITE_OPERATORS:
                operator = child.type
            elif child.type in ("word", "string", "raw_string", "concatenation"):
                target = source[child.start_byte:child.end_byte].decode("utf-8", errors="replace")
        if operator and target:
            targets.append(target)
    for child in node.children:
        _walk_write_redirects(child, source, targets)


def _redirect_targets(script: str) -> list[str]:
    try:
        source = script.encode("utf-8", errors="replace")
        tree = _PARSER.parse(source)
        targets: list[str] = []
        _walk_write_redirects(tree.root_node, source, targets)
        return targets
    except Exception:
        return []


@register
class LocalBinShadowRule:
    """
    Flag writes to user-local executable directories.

    ~/.local/bin and ~/bin are in PATH before /usr/bin on most Linux distros.
    An executable placed there shadows any system binary of the same name.
    During a coding session an LLM agent has no legitimate reason to install
    new executables in the user's PATH — that's what package managers are for.

    Severity is HIGH (not CRITICAL) because there are edge-case legitimate
    uses (e.g. installing a project CLI during setup), but the pattern is
    almost never appropriate for an in-session agent.

    Incident grounding: Terminal-Bench 2025 (Berkeley RDI) — the attack
    replaced /usr/bin/curl; ~/.local/bin/curl achieves the same effect without
    touching any protected path.
    """

    rule_id = "persistence.local_bin_shadow"
    severity = Severity.HIGH
    description = "Write to user-local bin dir (~/.local/bin, ~/bin) — shadows system commands via PATH"

    def check(self, script: str, context: ExecutionContext) -> list[Finding]:
        try:
            findings: list[Finding] = []

            # 1. Shell redirect targets (>, >>)
            for target in _redirect_targets(script):
                if _is_local_bin_path(target):
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        severity=Severity.HIGH,
                        message="Write to user-local bin directory: shadows system command via PATH",
                        matched_text=target.strip("'\""),
                        action_type=ActionType.SYSTEM_CONFIG,
                    ))

            # 2. cp/mv/tee destinations; chmod on bin paths
            try:
                cmds = parse(script)
                for cmd in cmds:
                    if cmd.name in _TEE_CMDS:
                        for arg in cmd.args:
                            if _is_local_bin_path(arg):
                                findings.append(Finding(
                                    rule_id=self.rule_id,
                                    severity=Severity.HIGH,
                                    message="tee to user-local bin directory: shadows system command via PATH",
                                    matched_text=arg.strip("'\""),
                                    action_type=ActionType.SYSTEM_CONFIG,
                                ))
                    elif cmd.name in _COPY_MOVE_CMDS:
                        if cmd.args and _is_local_bin_path(cmd.args[-1]):
                            findings.append(Finding(
                                rule_id=self.rule_id,
                                severity=Severity.HIGH,
                                message=f"{cmd.name} to user-local bin directory: shadows system command via PATH",
                                matched_text=cmd.args[-1].strip("'\""),
                                action_type=ActionType.SYSTEM_CONFIG,
                            ))
                    elif cmd.name == "chmod":
                        for arg in cmd.args:
                            if _is_local_bin_path(arg):
                                findings.append(Finding(
                                    rule_id=self.rule_id,
                                    severity=Severity.HIGH,
                                    message="chmod in user-local bin directory: activates binary shadow",
                                    matched_text=arg.strip("'\""),
                                    action_type=ActionType.SYSTEM_CONFIG,
                                ))
            except Exception:
                pass

            return findings
        except Exception as e:
            _log.error("LocalBinShadowRule raised: %s", e, exc_info=True)
            return []
