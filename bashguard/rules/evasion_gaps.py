"""
bashguard.rules.evasion_gaps — Evasion patterns from spec 04-evasions.md
not covered by the main evasion.py module.

evasion.function_shadow (pattern 4.4):
  Redefining a trusted shell command as a function with a different body.
  cd() { rm -rf "$1"; } redefines cd as destructive. The alias rule catches
  `alias ls='...'` but function_definition nodes are a separate AST construct.
  We flag any function definition whose name matches a known shell builtin
  or commonly trusted command.

evasion.path_traversal (pattern 2.4):
  Using `..` or `.` components in the command name path to reach a binary via
  a non-canonical path that bypasses string-based allowlists/denylists.
  /usr/bin/../bin/rm doesn't match "/usr/bin/rm" in a simple string check.
  We detect `..` in the command name token (first token of a command).
"""
from __future__ import annotations
import logging
import re

from bashguard.parser import parse
from bashguard.models import Severity, Finding, ExecutionContext, ActionType
from bashguard.rules import register

_log = logging.getLogger(__name__)

# Shell builtins and commonly trusted commands that agents might shadow
_TRUSTED_COMMANDS = frozenset({
    # Shell builtins
    "cd", "echo", "export", "source", "eval", "exec", "exit", "return",
    "set", "unset", "read", "printf", "test", "trap", "wait", "kill",
    "jobs", "bg", "fg", "type", "which", "hash", "alias", "unalias",
    "declare", "local", "readonly", "shift", "getopts", "umask", "ulimit",
    # Trusted system commands
    "ls", "cat", "cp", "mv", "rm", "mkdir", "rmdir", "chmod", "chown",
    "find", "grep", "sed", "awk", "sort", "uniq", "head", "tail", "wc",
    "curl", "wget", "ssh", "scp", "rsync", "tar", "zip", "unzip",
    "git", "python", "python3", "node", "npm", "pip", "sudo", "su",
    "systemctl", "service", "apt", "brew", "yum", "make", "gcc",
    "docker", "kubectl", "terraform",
})

# Match function definition syntax: name() { ... } or function name { ... }
# We look for the function name in the parser output
_FUNC_DEF_RE = re.compile(
    r"^\s*(?:function\s+)?(\w+)\s*\(\s*\)\s*\{",
    re.MULTILINE,
)
_FUNC_KW_RE = re.compile(
    r"^\s*function\s+(\w+)\s*\{",
    re.MULTILINE,
)

# .. or /. component in a path (command name position)
_TRAVERSAL_RE = re.compile(r"(?:^|/)\.\.(?:/|$)|(?:^|/)\.(?:/|$)")


def _extract_function_names(script: str) -> list[str]:
    """Return all function names defined in the script."""
    names = []
    for m in _FUNC_DEF_RE.finditer(script):
        names.append(m.group(1))
    for m in _FUNC_KW_RE.finditer(script):
        n = m.group(1)
        if n not in names:
            names.append(n)
    return names


def _command_name_has_traversal(name: str) -> bool:
    """Return True if the command name contains .. or /. path components."""
    # Must start with / or ../ to be a path (not a flag or argument)
    if not (name.startswith("/") or name.startswith("../") or name.startswith("./")):
        return False
    return bool(_TRAVERSAL_RE.search(name))


@register
class FunctionShadowRule:
    rule_id = "evasion.function_shadow"
    severity = Severity.HIGH
    description = "Function definition shadows a trusted command — may redirect execution"

    def check(self, script: str, context: ExecutionContext) -> list[Finding]:
        try:
            shadowed = [
                n for n in _extract_function_names(script)
                if n in _TRUSTED_COMMANDS
            ]
            return [
                Finding(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    action_type=ActionType.OBFUSCATED,
                    message=f"{self.description}: {name!r}",
                    matched_text=name,
                )
                for name in shadowed
            ]
        except Exception:
            _log.exception("function_shadow rule error")
            return []


@register
class PathTraversalRule:
    rule_id = "evasion.path_traversal"
    severity = Severity.HIGH
    description = "Path traversal (.. or .) in command name — bypasses path-based allowlists"

    def check(self, script: str, context: ExecutionContext) -> list[Finding]:
        try:
            return list(self._scan(script))
        except Exception:
            _log.exception("path_traversal rule error")
            return []

    def _scan(self, script: str):
        if not script.strip():
            return
        cmds = parse(script)
        for cmd in cmds:
            if _command_name_has_traversal(cmd.name):
                yield Finding(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    action_type=ActionType.OBFUSCATED,
                    message=self.description,
                    matched_text=cmd.name,
                )


# ─── xargs shell (spec 04-evasions.md pattern 4.6) ───────────────────────────

_SHELLS = frozenset({"bash", "sh", "zsh", "dash", "ksh"})


@register
class XargsShellRule:
    rule_id = "evasion.xargs_shell"
    severity = Severity.CRITICAL
    description = "xargs delivers stdin to a shell interpreter — indirect pipe_to_shell"

    def check(self, script: str, context: ExecutionContext) -> list[Finding]:
        try:
            return list(self._scan(script))
        except Exception:
            _log.exception("xargs_shell rule error")
            return []

    def _scan(self, script: str):
        if not script.strip():
            return
        cmds = parse(script)
        for cmd in cmds:
            if cmd.name != "xargs":
                continue
            # Check if any arg is a shell interpreter
            for arg in cmd.args:
                if arg in _SHELLS:
                    yield Finding(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        action_type=ActionType.OBFUSCATED,
                        message=self.description,
                        matched_text=f"xargs ... {arg} -c",
                    )
                    break


# ─── ANSI-C escape obfuscation (spec 04-evasions.md pattern 3.4) ─────────────

import re as _re

# $'\x..' or $'\0..' — hex and octal encoded strings
# Allow common whitespace: \n \t \r \a \b \f \v (single letter after \)
# Flag: \x followed by hex digits, \0 followed by octal digits, \NNN (octal)
_ANSI_C_HEX_RE = _re.compile(r"\$'[^']*\\x[0-9a-fA-F]{2}[^']*'")
_ANSI_C_OCT_RE = _re.compile(r"\$'[^']*\\[0-7]{3}[^']*'")


@register
class AnsiCEscapeRule:
    rule_id = "evasion.ansi_c_escape"
    severity = Severity.HIGH
    description = "ANSI-C $'\\x..' escape hides actual string value from static analysis"

    def check(self, script: str, context: ExecutionContext) -> list[Finding]:
        try:
            return list(self._scan(script))
        except Exception:
            _log.exception("ansi_c_escape rule error")
            return []

    def _scan(self, script: str):
        for line in script.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if _ANSI_C_HEX_RE.search(stripped) or _ANSI_C_OCT_RE.search(stripped):
                yield Finding(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    action_type=ActionType.OBFUSCATED,
                    message=self.description,
                    matched_text=stripped,
                )
