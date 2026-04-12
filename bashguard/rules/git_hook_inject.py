"""
bashguard.rules.git_hook_inject — Detect writes to .git/hooks/.

Git hooks run automatically on git operations (commit, push, merge).
Writing a malicious script to .git/hooks/pre-commit installs a persistent
backdoor that executes every time the developer runs `git commit` — the
agent doesn't need to be running for the payload to fire.

This is the repository-layer equivalent of the binary wrapper trojanization
described in Berkeley RDI "Trustworthy Benchmarks" (2025): the attack
intercepts a trusted tool chain by injecting code at a trusted execution point.

Hook files also cover chmod +x on hook paths: an executable hook that already
exists is as dangerous as writing a new one.

Rule:
  git.hook_inject  (CRITICAL) — write/chmod targeting .git/hooks/* paths
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


def _is_hook_path(path: str) -> bool:
    """True if path is inside a .git/hooks/ directory."""
    clean = path.strip("'\"")
    return "/.git/hooks/" in clean or clean.startswith(".git/hooks/")


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
class GitHookInjectRule:
    """
    Flag any write or chmod targeting a .git/hooks/ path.

    git hooks execute automatically on git operations — pre-commit, post-receive,
    pre-push, commit-msg, post-merge, post-checkout.  A hook script installed
    here runs every time the developer uses git, with the developer's credentials
    and filesystem access.  No continued agent presence needed.

    Also flags chmod +x on hook paths: making an existing hook executable
    activates it as reliably as writing a new one.

    Incident grounding: Terminal-Bench 2025 (Berkeley RDI) — binary wrapper
    injection at trusted execution points; git hook injection is the VCS-layer
    equivalent.
    """

    rule_id = "git.hook_inject"
    severity = Severity.CRITICAL
    description = "Write or chmod to .git/hooks/ — installs persistent backdoor on git operations"

    def check(self, script: str, context: ExecutionContext) -> list[Finding]:
        try:
            findings: list[Finding] = []

            # 1. Shell redirect targets (>, >>)
            for target in _redirect_targets(script):
                if _is_hook_path(target):
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        severity=Severity.CRITICAL,
                        message=f"Write to git hook path: persistent backdoor on git operations",
                        matched_text=target.strip("'\""),
                        action_type=ActionType.SYSTEM_CONFIG,
                    ))

            # 2. cp/mv/tee destinations; chmod on hook paths
            try:
                cmds = parse(script)
                for cmd in cmds:
                    if cmd.name in _TEE_CMDS:
                        for arg in cmd.args:
                            if _is_hook_path(arg):
                                findings.append(Finding(
                                    rule_id=self.rule_id,
                                    severity=Severity.CRITICAL,
                                    message=f"tee to git hook path: persistent backdoor on git operations",
                                    matched_text=arg.strip("'\""),
                                    action_type=ActionType.SYSTEM_CONFIG,
                                ))
                    elif cmd.name in _COPY_MOVE_CMDS:
                        if cmd.args and _is_hook_path(cmd.args[-1]):
                            findings.append(Finding(
                                rule_id=self.rule_id,
                                severity=Severity.CRITICAL,
                                message=f"{cmd.name} to git hook path: persistent backdoor on git operations",
                                matched_text=cmd.args[-1].strip("'\""),
                                action_type=ActionType.SYSTEM_CONFIG,
                            ))
                    elif cmd.name == "chmod":
                        # chmod +x .git/hooks/pre-commit (or any chmod on hook path)
                        for arg in cmd.args:
                            if _is_hook_path(arg):
                                findings.append(Finding(
                                    rule_id=self.rule_id,
                                    severity=Severity.CRITICAL,
                                    message=f"chmod on git hook path: activates hook as executable backdoor",
                                    matched_text=arg.strip("'\""),
                                    action_type=ActionType.SYSTEM_CONFIG,
                                ))
            except Exception:
                pass

            return findings
        except Exception as e:
            _log.error("GitHookInjectRule raised: %s", e, exc_info=True)
            return []
