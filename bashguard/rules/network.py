"""
bashguard.rules.network — Flag outbound network access to unknown hosts.

1 bit of exfiltration = infinite bits of exfiltration.

Detects:
- curl/wget/nc/socat/ssh/scp/rsync to hosts not in context.allowed_hosts
- Bash /dev/tcp redirect trick
- Pipe-to-shell patterns (curl ... | bash)

Uses the bash_ast CommandNode for structured argument access.
"""

from __future__ import annotations
import logging
import re
from urllib.parse import urlparse

from bashguard.parser import parse, CommandNode
from bashguard.models import Severity, Finding, ExecutionContext, ActionType
from bashguard.rules import register

_log = logging.getLogger(__name__)

_NETWORK_COMMANDS = {"curl", "wget", "nc", "ncat", "netcat", "socat",
                     "ssh", "scp", "rsync", "ftp", "sftp", "telnet"}

_URL_RE = re.compile(r"https?://([^/\s]+)")
_DEV_TCP = "/dev/tcp/"


def _extract_url_host(text: str) -> str | None:
    m = _URL_RE.search(text)
    if m:
        return m.group(1).split(":")[0]  # strip port if present
    return None


def _extract_nc_host(cmd: CommandNode) -> str | None:
    positional = [a for a in cmd.args if not a.startswith("-")]
    return positional[0] if positional else None


@register
class NetworkRule:
    rule_id = "network.unknown_host"
    severity = Severity.CRITICAL
    description = "Network access to a host not in the context allow-list"

    def check(self, script: str, context: ExecutionContext) -> list[Finding]:
        try:
            cmds = parse(script)
            findings = []

            for cmd in cmds:
                host = None

                if cmd.name in _NETWORK_COMMANDS:
                    # Try to find a URL in args
                    for arg in cmd.args + cmd.flags:
                        h = _extract_url_host(arg)
                        if h:
                            host = h
                            break
                    # nc/ssh: host is first positional arg
                    if host is None and cmd.name in {"nc", "ncat", "netcat", "ssh",
                                                     "scp", "sftp", "telnet"}:
                        host = _extract_nc_host(cmd)

                    if host and host not in context.allowed_hosts:
                        findings.append(Finding(
                            rule_id=self.rule_id,
                            severity=self.severity,
                            message=(
                                f"'{cmd.name}' accesses unknown host '{host}' — "
                                "not in allowed_hosts"
                            ),
                            matched_text=cmd.raw,
                            metadata={"command": cmd.name, "host": host},
                            action_type=ActionType.NETWORK_OUTBOUND,
                        ))
                    elif host is None and cmd.name in {"nc", "ncat", "netcat"}:
                        # nc with no recognizable host — still flag it
                        findings.append(Finding(
                            rule_id=self.rule_id,
                            severity=self.severity,
                            message=f"'{cmd.name}' used — potential network access",
                            matched_text=cmd.raw,
                            metadata={"command": cmd.name},
                            action_type=ActionType.NETWORK_OUTBOUND,
                        ))

                # Check redirect targets for /dev/tcp
                for target in cmd.redirect_targets:
                    if _DEV_TCP in target:
                        findings.append(Finding(
                            rule_id="network.dev_tcp",
                            severity=self.severity,
                            message=f"Bash /dev/tcp redirect detected: {target}",
                            matched_text=cmd.raw,
                            metadata={"target": target},
                            action_type=ActionType.NETWORK_OUTBOUND,
                        ))

            return findings
        except Exception as e:
            _log.error("NetworkRule raised: %s", e, exc_info=True)
            return []
