"""
bashguard.rules.proc_scrape — Block /proc filesystem credential scraping.

The Mythos model used low-level /proc/ access to find credentials for
messaging services, source control, and the Anthropic API by inspecting
process memory — without any user request to do so.

/proc/<pid>/environ, /proc/<pid>/mem, /proc/<pid>/cmdline, and
/proc/<pid>/fd expose secrets from other running processes. Reading them
is a credential extraction technique, not normal agent work.

Blocked: reads of /proc/<pid|self|*>/{environ,mem,cmdline,fd,...}
Allowed: /proc/cpuinfo, /proc/meminfo, /proc/version, /proc/self/status
         (hardware/OS info — no credentials)
"""

from __future__ import annotations
import logging
import re

from bashguard.models import Severity, Finding, ExecutionContext, ActionType
from bashguard.rules import register

_log = logging.getLogger(__name__)

# /proc entries that are safe — hardware or kernel info, never credentials
_SAFE_PROC_ENTRIES = frozenset({
    "/proc/cpuinfo",
    "/proc/meminfo",
    "/proc/version",
    "/proc/uptime",
    "/proc/loadavg",
    "/proc/stat",
    "/proc/mounts",
    "/proc/self/status",
    "/proc/self/stat",
    "/proc/self/statm",
})

# Sensitive per-process entries that leak credentials or memory
_SENSITIVE_SUFFIXES = frozenset({
    "environ",
    "mem",
    "cmdline",
})

# Regex: /proc/<pid|self|*>/<something>
_PROC_PID_RE = re.compile(r"/proc/(\d+|\*|self|\{\})/(.+)")


def _is_sensitive_proc_path(path: str) -> bool:
    """Return True if this /proc path exposes credentials or memory."""
    clean = path.strip("'\"")

    if clean in _SAFE_PROC_ENTRIES:
        return False

    m = _PROC_PID_RE.match(clean)
    if not m:
        return False

    pid_part, entry = m.group(1), m.group(2)
    # Any per-pid path except the safe /proc/self/* ones
    entry_root = entry.split("/")[0]
    if entry_root in _SENSITIVE_SUFFIXES:
        return True
    # fd/N — open file descriptors of another process
    if entry_root == "fd":
        return True
    # Anything under a numeric PID is suspicious
    if pid_part != "self":
        return True
    return False


@register
class ProcScrapeRule:
    rule_id = "proc.credential_scrape"
    severity = Severity.CRITICAL
    description = "/proc filesystem access that exposes process credentials or memory"

    def check(self, script: str, context: ExecutionContext) -> list[Finding]:
        try:
            return list(self._scan(script))
        except Exception:
            _log.exception("proc_scrape rule error")
            return []

    def _scan(self, script: str):
        for line in script.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if self._line_is_sensitive(stripped):
                yield Finding(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    action_type=ActionType.CREDENTIAL_ACCESS,
                    message=self.description,
                    matched_text=stripped,
                )

    def _line_is_sensitive(self, line: str) -> bool:
        # Find any /proc/... token in the line
        for token in re.split(r"\s+|'[^']*'|\"[^\"]*\"", line):
            token = token.strip("'\"")
            if token.startswith("/proc/") and _is_sensitive_proc_path(token):
                return True
        # Also catch tokens inside quotes
        for m in re.finditer(r"['\"]?(/proc/[^\s'\"]+)['\"]?", line):
            if _is_sensitive_proc_path(m.group(1)):
                return True
        return False
