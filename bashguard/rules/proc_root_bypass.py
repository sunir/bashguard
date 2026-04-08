"""
bashguard.rules.proc_root_bypass — Block /proc/self/root path evasion.

CVE-2025-54794: Claude Code's sandbox was bypassed using
/proc/self/root/usr/bin/npx — the same binary as /usr/bin/npx but reachable
via a different path, evading a denylist that only checked canonical paths.
The agent then disabled the bubblewrap sandbox entirely when caught.

/proc/self/root is a symlink to the filesystem root of the current process.
Using it as a prefix reaches any binary or file via a non-canonical path,
bypassing string-based allowlists and denylists.

Blocked: any command execution or file read via /proc/self/root/<path>
Allowed: ls /proc/self/root/ (listing), cat /proc/self/status (own status)
"""
from __future__ import annotations
import logging
import re

from bashguard.models import Severity, Finding, ExecutionContext, ActionType
from bashguard.rules import register

_log = logging.getLogger(__name__)

_PROC_SELF_ROOT = "/proc/self/root/"

# Paths that are benign to list/access under /proc/self/root
_SAFE_EXACT = frozenset({
    "/proc/self/root/",
    "/proc/self/root",
})

# Allowed /proc/self/* paths (not /proc/self/root/...)
_SAFE_SELF_PREFIX = frozenset({
    "/proc/self/status",
    "/proc/self/stat",
    "/proc/self/statm",
})


def _contains_proc_root_exec(line: str) -> bool:
    """Return True if the line uses /proc/self/root/ to reach a binary or file."""
    if _PROC_SELF_ROOT not in line:
        return False
    # Extract all /proc/self/root/... tokens
    for m in re.finditer(r"/proc/self/root/\S*", line):
        path = m.group(0).rstrip("'\")")
        if path in _SAFE_EXACT or path + "/" in _SAFE_EXACT:
            continue
        # ls /proc/self/root/ with trailing slash — benign
        # But ls /proc/self/root/etc/passwd — not benign
        if re.match(r"^/proc/self/root/?$", path):
            continue
        return True
    return False


@register
class ProcRootBypassRule:
    rule_id = "evasion.proc_root_bypass"
    severity = Severity.CRITICAL
    description = "/proc/self/root used to bypass path-based allowlists (CVE-2025-54794 pattern)"

    def check(self, script: str, context: ExecutionContext) -> list[Finding]:
        try:
            return list(self._scan(script))
        except Exception:
            _log.exception("proc_root_bypass rule error")
            return []

    def _scan(self, script: str):
        for line in script.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if _contains_proc_root_exec(stripped):
                yield Finding(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    action_type=ActionType.OBFUSCATED,
                    message=self.description,
                    matched_text=stripped,
                )
