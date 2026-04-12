"""
bashguard.rules.network_recon_shell — Port scanning, socat shells, block device copy.

network.port_scan:
  nmap and masscan perform host/port discovery — standard reconnaissance for
  lateral movement. The 82-incident AI agent threat database includes agents
  running nmap to map the network before attacking other hosts. No legitimate
  LLM task needs to scan networks or hosts.

network.socat_shell:
  socat with EXEC: creates a bind or reverse shell — a network-accessible command
  interpreter. socat TCP-LISTEN:4444,fork EXEC:/bin/bash exposes a root shell on
  the network. Legitimate socat use (port forwarding, relay) does not use EXEC:.

destructive.disk_copy:
  dd reading from block devices (/dev/sda, /dev/mem) copies raw disk or memory
  content — used for offline credential extraction or evidence destruction.
  Safe pseudo-devices (/dev/urandom, /dev/zero) are allowed. All others are not.
"""
from __future__ import annotations
import logging
import re

from bashguard.parser import parse
from bashguard.models import Severity, Finding, ExecutionContext, ActionType
from bashguard.rules import register

_log = logging.getLogger(__name__)

# Safe /dev sources — not block devices
_SAFE_DEV_SOURCES = frozenset({
    "/dev/urandom", "/dev/random", "/dev/zero",
    "/dev/null", "/dev/stdin", "/dev/stdout", "/dev/stderr",
    "/dev/fd/0", "/dev/fd/1", "/dev/fd/2",
})

# Pattern for socat EXEC: address
_SOCAT_EXEC_RE = re.compile(r"\bEXEC:", re.IGNORECASE)


@register
class PortScanRule:
    rule_id = "network.port_scan"
    severity = Severity.HIGH
    description = "Network port scan — reconnaissance for lateral movement"

    def check(self, script: str, context: ExecutionContext) -> list[Finding]:
        try:
            return list(self._scan(script))
        except Exception:
            _log.exception("port_scan rule error")
            return []

    def _scan(self, script: str):
        if not script.strip():
            return
        cmds = parse(script)
        for cmd in cmds:
            if cmd.name in ("nmap", "masscan", "zmap"):
                yield Finding(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    action_type=ActionType.NETWORK_OUTBOUND,
                    message=f"{self.description}: {cmd.name}",
                    matched_text=cmd.name,
                )


@register
class SocatShellRule:
    rule_id = "network.socat_shell"
    severity = Severity.CRITICAL
    description = "socat EXEC: creates a network-accessible shell — bind/reverse shell"

    def check(self, script: str, context: ExecutionContext) -> list[Finding]:
        try:
            return list(self._scan(script))
        except Exception:
            _log.exception("socat_shell rule error")
            return []

    def _scan(self, script: str):
        if not script.strip():
            return
        cmds = parse(script)
        for cmd in cmds:
            if cmd.name != "socat":
                continue
            all_args = cmd.args + cmd.flags
            for arg in all_args:
                if _SOCAT_EXEC_RE.match(arg):
                    yield Finding(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        action_type=ActionType.NETWORK_OUTBOUND,
                        message=self.description,
                        matched_text=f"socat ... {arg[:40]}",
                    )
                    break


@register
class DiskCopyRule:
    rule_id = "destructive.disk_copy"
    severity = Severity.CRITICAL
    description = "dd reads block device — raw disk/memory imaging for data extraction"

    def check(self, script: str, context: ExecutionContext) -> list[Finding]:
        try:
            return list(self._scan(script))
        except Exception:
            _log.exception("disk_copy rule error")
            return []

    # Commands that read file content (besides dd) that can exfil raw disk
    _RAW_READ_CMDS = frozenset({"cat", "strings", "hexdump", "xxd", "od", "head", "tail"})

    def _scan(self, script: str):
        if not script.strip():
            return
        cmds = parse(script)
        for cmd in cmds:
            if cmd.name == "dd":
                yield from self._check_dd(cmd)
            elif cmd.name in self._RAW_READ_CMDS:
                yield from self._check_raw_read(cmd)

    def _check_dd(self, cmd):
        all_args = cmd.args + cmd.flags
        for arg in all_args:
            if not arg.startswith("if="):
                continue
            src = arg[3:]  # strip 'if='
            # Block block devices (/dev/sda, /dev/mem) and kernel memory (/proc/kcore)
            blocked = (
                (src.startswith("/dev/") and src not in _SAFE_DEV_SOURCES)
                or src in ("/proc/kcore", "/proc/kallsyms")
            )
            if blocked:
                yield Finding(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    action_type=ActionType.CREDENTIAL_ACCESS,
                    message=f"{self.description}: {arg}",
                    matched_text=f"dd {arg}",
                )
                break

    def _check_raw_read(self, cmd):
        """Catch cat/strings/hexdump etc. reading raw block devices."""
        for arg in cmd.args:
            if not arg.startswith("-") and arg.startswith("/dev/"):
                if arg not in _SAFE_DEV_SOURCES:
                    yield Finding(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        action_type=ActionType.CREDENTIAL_ACCESS,
                        message=f"{cmd.name} reads raw block device: {arg}",
                        matched_text=f"{cmd.name} {arg}",
                    )
                    break
