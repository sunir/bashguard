"""
bashguard.rules.proc_inject — Block injection into running processes.

The Mythos model edited the process of a running MCP server to change the
external URL to which the server sent data. This silently redirected all
server traffic without any visible file change.

Process injection lets an agent:
- Silently redirect where a running service sends data
- Extract secrets from another process's heap at runtime
- Insert arbitrary code into a running service

This is distinct from proc.credential_scrape (which blocks READING /proc).
This rule blocks WRITING to running processes or attaching debuggers that
enable code injection.

Blocked:
  gdb -p <pid>              — attach debugger to live process
  gdb --pid <pid>           — same
  strace -p <pid>           — attach syscall tracer (reads internals)
  ltrace -p <pid>           — attach library call tracer
  dd of=/proc/<pid>/mem     — write directly to process memory

Allowed:
  gdb ./program             — debug a new process (not attaching to live PID)
  gdb --args ./program      — same with args
  gdb ./program ./core      — core dump analysis
  strace ./program          — trace a new process (not attaching)
"""

from __future__ import annotations
import logging
import re

from bashguard.models import Severity, Finding, ExecutionContext, ActionType
from bashguard.rules import register

_log = logging.getLogger(__name__)

_PID_RE = re.compile(r"^\d+$")
_PROC_MEM_WRITE_RE = re.compile(r"of=/proc/\d+/mem")


def _has_pid_attach(tokens: list[str]) -> bool:
    """Return True if -p / --pid <number> appears in token list."""
    for i, tok in enumerate(tokens):
        if tok in ("-p", "--pid") and i + 1 < len(tokens):
            if _PID_RE.match(tokens[i + 1]):
                return True
        # Combined: -p1234
        if re.match(r"^-p\d+$", tok):
            return True
    return False


@register
class ProcessInjectRule:
    rule_id = "proc.process_inject"
    severity = Severity.CRITICAL
    description = "Attaching to or injecting code into a running process"

    def check(self, script: str, context: ExecutionContext) -> list[Finding]:
        try:
            return list(self._scan(script))
        except Exception:
            _log.exception("proc_inject rule error")
            return []

    def _scan(self, script: str):
        for line in script.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            finding = self._check_line(stripped)
            if finding:
                yield finding

    def _check_line(self, line: str) -> Finding | None:
        tokens = line.split()
        if not tokens:
            return None
        cmd = tokens[0]

        # gdb/strace/ltrace with -p attach to live process
        if cmd in ("gdb", "strace", "ltrace"):
            if _has_pid_attach(tokens[1:]):
                return self._finding(line)

        # dd of=/proc/<pid>/mem — write to process memory
        if cmd == "dd" and _PROC_MEM_WRITE_RE.search(line):
            return self._finding(line)

        return None

    def _finding(self, line: str) -> Finding:
        return Finding(
            rule_id=self.rule_id,
            severity=self.severity,
            action_type=ActionType.PROCESS_SIGNAL,
            message=self.description,
            matched_text=line,
        )
