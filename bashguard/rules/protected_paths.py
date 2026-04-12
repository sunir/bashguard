"""
bashguard.rules.protected_paths — Flag writes to protected system directories.

Detects shell redirects (>, >>) that target OS-owned paths that an LLM
has no business writing to: system binaries, kernel interfaces, device nodes,
bootloader config, etc. Also detects cp/mv/install commands that place files
into protected system paths — a common binary trojanization vector.

This is distinct from credentials.py (which catches reads of secret files).
This rule catches WRITES to system integrity paths regardless of command.

Protected prefixes mirror bashguard.policies.FileWritePolicy:
    /etc /usr /sys /proc /boot /bin /sbin /lib /lib64 /dev /opt
"""

from __future__ import annotations
import logging

import tree_sitter_bash as tsb
from tree_sitter import Language, Parser as TSParser

from bashguard.parser import parse
from bashguard.models import Severity, Finding, ExecutionContext, ActionType
from bashguard.rules import register

_log = logging.getLogger(__name__)

_LANG = Language(tsb.language())
_PARSER = TSParser(_LANG)

_PROTECTED_WRITE_PREFIXES = (
    "/etc/", "/usr/", "/sys/", "/proc/",
    "/boot/", "/bin/", "/sbin/",
    "/lib/", "/lib64/", "/dev/", "/opt/",
)

_PROTECTED_WRITE_ROOTS = {"/etc", "/usr", "/sys", "/proc",
                           "/boot", "/bin", "/sbin", "/lib", "/lib64", "/dev", "/opt"}

# Commands that write a file to a destination path
# For cp/mv: last positional arg is destination
# For install: last positional arg is destination (or dir with -d)
_FILE_WRITE_CMDS = frozenset({"cp", "mv", "install"})

# /dev pseudo-devices used for I/O plumbing — not actual device writes
_SAFE_DEV_PATHS = {"/dev/null", "/dev/stdin", "/dev/stdout", "/dev/stderr"}

# tree-sitter node types that represent write operators
_WRITE_OPERATORS = {">", ">>"}


def _is_protected_write(path: str) -> bool:
    clean = path.strip("'\"")
    if clean in _SAFE_DEV_PATHS:
        return False
    if clean in _PROTECTED_WRITE_ROOTS:
        return True
    return any(clean.startswith(p) for p in _PROTECTED_WRITE_PREFIXES)


def _find_write_redirects(node, source: bytes, findings: list, script: str) -> None:
    """Walk the CST looking for file_redirect nodes with > or >> operators."""
    if node.type == "file_redirect":
        # Children: [operator, target_word]
        operator = None
        target = None
        for child in node.children:
            if child.type in _WRITE_OPERATORS:
                operator = child.type
            elif child.type in ("word", "string", "raw_string", "concatenation"):
                target = source[child.start_byte:child.end_byte].decode("utf-8", errors="replace")
        if operator and target and _is_protected_write(target):
            findings.append(Finding(
                rule_id="paths.protected_write",
                severity=Severity.HIGH,
                message=f"Write ({operator}) to protected system path: {target.strip(chr(39) + chr(34))}",
                matched_text=script,
                metadata={"target": target, "operator": operator},
                action_type=ActionType.SYSTEM_CONFIG,
            ))
    for child in node.children:
        _find_write_redirects(child, source, findings, script)


@register
class ProtectedPathsRule:
    rule_id = "paths.protected_write"
    severity = Severity.HIGH
    description = "Write to a protected system path via redirect or cp/mv/install"

    def check(self, script: str, context: ExecutionContext) -> list[Finding]:
        try:
            source = script.encode("utf-8", errors="replace")
            tree = _PARSER.parse(source)
            findings: list[Finding] = []
            _find_write_redirects(tree.root_node, source, findings, script)
            if findings:
                return findings
            # Also catch cp/mv/install with a protected destination
            for cmd in parse(script):
                if cmd.name not in _FILE_WRITE_CMDS:
                    continue
                pos_args = [a for a in cmd.args if not a.startswith("-")]
                if not pos_args:
                    continue
                dest = pos_args[-1]
                if _is_protected_write(dest):
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        message=f"{cmd.name} writes to protected system path: {dest}",
                        matched_text=script,
                        metadata={"target": dest, "cmd": cmd.name},
                        action_type=ActionType.SYSTEM_CONFIG,
                    ))
                    break
            return findings
        except Exception as e:
            _log.error("ProtectedPathsRule raised: %s", e, exc_info=True)
            return []
