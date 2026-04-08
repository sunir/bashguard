"""
bashguard.rules.process_kill — Block broadcast process-kill commands.

Detects the Mythos "cascading takedown" pattern: asked to stop one thing,
kills everything. pkill and killall send signals to ALL matching processes —
there is no PID specificity, so an agent using them can silently terminate
other agents, sessions, or user processes.

Blocked:
  pkill <name>          — kills all procs matching name
  pkill -f <pattern>    — kills all procs matching full cmdline
  killall <name>        — same semantics as pkill
  kill -9 -1            — sends SIGKILL to every process the user owns
  kill 0                — sends to entire process group

Allowed:
  kill <specific-pid>   — targeted, operator can see exactly what's affected
  kill -9 <pid>         — still targeted (harsh but not broadcast)
  kill -TERM <pid>      — targeted
"""

from __future__ import annotations
import logging
import re

from bashguard.models import Severity, Finding, ExecutionContext, ActionType
from bashguard.rules import register

_log = logging.getLogger(__name__)

# PIDs that mean "broadcast" rather than a specific process
_BROADCAST_PIDS = {"-1", "0"}


@register
class ProcessKillRule:
    rule_id = "process.agent_kill"
    severity = Severity.CRITICAL
    description = "Broad process-kill command that could terminate other agents or sessions"

    def check(self, script: str, context: ExecutionContext) -> list[Finding]:
        try:
            return list(self._scan(script))
        except Exception:
            _log.exception("process_kill rule error")
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

        if cmd in ("pkill", "killall"):
            return self._finding(line)

        if cmd == "kill":
            return self._check_kill(tokens, line)

        return None

    def _check_kill(self, tokens: list[str], line: str) -> Finding | None:
        """Allow kill <pid> but block kill -1, kill 0, kill -9 -1, etc."""
        # Strip the command name
        args = tokens[1:]
        if not args:
            return None

        # Collect non-signal arguments (potential PIDs)
        pids = []
        i = 0
        while i < len(args):
            a = args[i]
            if re.fullmatch(r"-[0-9]+", a):
                # Could be a signal (-9) or a negative PID (-1)
                # A numeric signal ≥ 1: treat as signal, skip. -1 is a broadcast PID.
                num = int(a[1:])
                if num == 1:
                    # -1 means "all processes"
                    return self._finding(line)
                # Otherwise it's a signal number — skip, continue
            elif re.fullmatch(r"-[A-Z]+", a):
                # Named signal like -TERM, -KILL — skip
                pass
            elif re.fullmatch(r"-s", a):
                i += 1  # skip next arg (the signal name)
            elif re.fullmatch(r"[0-9]+", a):
                if a in _BROADCAST_PIDS:
                    return self._finding(line)
                pids.append(a)
            elif a in _BROADCAST_PIDS:
                return self._finding(line)
            i += 1

        # If we have PIDs, they're specific — allowed
        if pids:
            return None

        # No PIDs at all — ambiguous, allow (e.g. `kill` with no args just prints usage)
        return None

    def _finding(self, line: str) -> Finding:
        return Finding(
            rule_id=self.rule_id,
            severity=self.severity,
            action_type=ActionType.PROCESS_SIGNAL,
            message=self.description,
            matched_text=line,
        )
