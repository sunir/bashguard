"""
bashguard.rules.vim_shell — vim/vi/ex shell escape via ex commands.

GTFOBins documents vim/vi/view/ex as shell-escape vectors:
  vim -c ":!id"           # -c executes ex command; :! runs shell
  vim -c ":shell"         # drops to interactive shell
  vim "+:!id" file.txt    # + prefix is ex command shorthand
  ex "+:!id" file.txt     # ex = vim line editor mode

Plain editor use (vim file.txt, vi README.md) is legitimate. The rule
triggers only when a -c/--cmd argument or +cmd prefix contains a shell-
escape pattern (:!, :shell, or bare shell/!).

Story: VIM-SHELL-ESCAPE
"""
from __future__ import annotations

import logging
import re

from bashguard.models import ActionType, ExecutionContext, Finding, Severity
from bashguard.parser import parse
from bashguard.rules import register

_log = logging.getLogger(__name__)

_VIM_VARIANTS = frozenset({"vim", "vi", "view", "ex", "nvim", "rvim", "rview", "gvim", "evim"})

# ex commands that escape to shell: :!cmd or :shell
_RE_SHELL_EX = re.compile(r"^:?(!|shell\b)", re.IGNORECASE)

# +cmd or +N prefix — strip leading colon if present
# +42 (line number) is allowed; +shell or +!cmd is not
_RE_PLUS_CMD = re.compile(r"^\+(.+)$")
_RE_LINE_NUMBER = re.compile(r"^\d+$")


def _is_shell_ex(arg: str) -> bool:
    """Return True if arg is an ex command containing a shell escape."""
    stripped = arg.strip("'\"")
    # -c ":!cmd" or -c "!cmd" or -c ":shell"
    return bool(_RE_SHELL_EX.match(stripped))


def _check_cmd(cmd) -> str | None:
    """Return a description of the shell escape found, or None if safe."""
    flags = cmd.flags
    args = cmd.args

    # -c or --cmd in flags: parser puts the ex-command as args[0]
    if ("-c" in flags or "--cmd" in flags) and args:
        ex_cmd = args[0].strip("'\"")
        if _is_shell_ex(ex_cmd):
            flag = "-c" if "-c" in flags else "--cmd"
            return f"shell escape via {flag} '{ex_cmd}'"

    # Walk args for +cmd prefixes (e.g. "+:!id", "+shell", "+!/bin/sh")
    for arg in args:
        stripped = arg.strip("'\"")
        m = _RE_PLUS_CMD.match(stripped)
        if not m:
            continue
        ex_cmd = m.group(1)
        # +N (line number) — legitimate
        if _RE_LINE_NUMBER.match(ex_cmd):
            continue
        # Strip optional leading colon
        ex_body = ex_cmd.lstrip(":")
        if ex_body.startswith("!") or ex_body.lower().startswith("shell"):
            return f"shell escape via +{ex_cmd}"

    return None


@register
class VimShellRule:
    # Story: VIM-SHELL-ESCAPE
    rule_id = "evasion.vim_shell"
    severity = Severity.HIGH
    description = "vim/vi ex command shell escape (:! or :shell)"

    def check(self, script: str, context: ExecutionContext) -> list[Finding]:
        try:
            findings: list[Finding] = []
            for cmd in parse(script):
                if cmd.name not in _VIM_VARIANTS:
                    continue
                reason = _check_cmd(cmd)
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
            _log.exception("VimShellRule error")
            return []
