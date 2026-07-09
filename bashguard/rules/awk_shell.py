"""
bashguard.rules.awk_shell — awk/gawk/mawk system() and pipe-getline detection.

GTFOBins documents awk as a shell-escape vector:
  awk 'BEGIN{system("/bin/sh")}'        # system() runs a shell
  awk 'BEGIN{cmd="id"; cmd | getline}'  # pipe-getline runs a command
  awk '{print | "/bin/sh"}'             # print-pipe runs a command

All three patterns execute arbitrary code with no legitimate use in an
automated coding context. The inline program is extracted from the first
positional argument (or -f argument if present) and scanned for these idioms.

Story: BG-AWK-SYSTEM
"""
from __future__ import annotations

import logging
import re

from bashguard.models import ActionType, ExecutionContext, Finding, Severity
from bashguard.parser import parse
from bashguard.rules import register

_log = logging.getLogger(__name__)

_AWK_VARIANTS = frozenset({"awk", "gawk", "mawk", "nawk"})

# system("...") or system($var) — any system() call is code execution
_RE_SYSTEM = re.compile(r'\bsystem\s*\(')
# cmd | getline or "str" | getline — command output piped into variable
_RE_PIPE_GETLINE = re.compile(r'\|\s*getline\b')
# print something | "cmd" — output piped to a command
_RE_PRINT_PIPE = re.compile(r'\bprint\b.*\|')


def _extract_program(cmd) -> str | None:
    """Return the awk program string with quotes stripped, or None if unavailable."""
    # Skip -f (reads from file — we don't scan file contents)
    if "-f" in cmd.flags:
        return None
    # Find first positional arg that isn't a plain filename (heuristic: contains { or ;)
    for arg in cmd.args:
        stripped = arg.strip("'\"")
        if "{" in stripped or ";" in stripped:
            return stripped
    # Fallback: just use the first arg
    return cmd.args[0].strip("'\"") if cmd.args else None


def _is_dangerous(program: str) -> str | None:
    """Return a description of the dangerous pattern found, or None if safe."""
    if _RE_SYSTEM.search(program):
        return "system() executes arbitrary shell commands"
    if _RE_PIPE_GETLINE.search(program):
        return "pipe-to-getline pattern executes commands and captures output"
    if _RE_PRINT_PIPE.search(program):
        return "print-to-pipe pattern executes commands"
    return None


@register
class AwkShellRule:
    # Story: BG-AWK-SYSTEM
    rule_id = "evasion.awk_shell"
    severity = Severity.CRITICAL
    description = "awk system()/pipe-getline executes arbitrary shell commands"

    def check(self, script: str, context: ExecutionContext) -> list[Finding]:
        try:
            findings: list[Finding] = []
            for cmd in parse(script):
                if cmd.name not in _AWK_VARIANTS:
                    continue
                program = _extract_program(cmd)
                if program is None:
                    continue
                reason = _is_dangerous(program)
                if reason:
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        message=f"{cmd.name}: {reason}",
                        matched_text=cmd.raw,
                        action_type=ActionType.LANG_EXEC,
                    ))
            return findings
        except Exception:
            _log.exception("AwkShellRule error")
            return []
