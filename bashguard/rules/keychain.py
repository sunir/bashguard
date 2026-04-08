"""
bashguard.rules.keychain — Block system keychain credential extraction.

The McKinsey red team (#71) demonstrated full enterprise access in 120 minutes
by exploiting hardcoded credentials found in config files and pivoting across
services. The system keychain is a more direct path: it stores passwords for
every service the user has ever authenticated with.

macOS `security` subcommands that read credentials:
  find-generic-password, find-internet-password, dump-keychain, find-certificate

Linux GNOME secret service:
  secret-tool lookup, secret-tool search

These are purpose-built credential extraction commands. Agents have no
legitimate reason to query the system keychain.

Allowed: security list-keychains, security help, security version
  (metadata/listing — no credential values exposed)
"""
from __future__ import annotations
import logging

from bashguard.models import Severity, Finding, ExecutionContext, ActionType
from bashguard.rules import register

_log = logging.getLogger(__name__)

# macOS security subcommands that read credential values
_SECURITY_READ_SUBCOMMANDS = frozenset({
    "find-generic-password",
    "find-internet-password",
    "dump-keychain",
    "find-certificate",
    "export",
    "import",
})

# Linux GNOME secret service subcommands that read values
_SECRET_TOOL_READ_SUBCOMMANDS = frozenset({
    "lookup",
    "search",
    "get",
})


@register
class KeychainRule:
    rule_id = "credentials.keychain"
    severity = Severity.CRITICAL
    description = "System keychain credential extraction"

    def check(self, script: str, context: ExecutionContext) -> list[Finding]:
        try:
            return list(self._scan(script))
        except Exception:
            _log.exception("keychain rule error")
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

        if cmd == "security" and len(tokens) >= 2:
            subcmd = tokens[1]
            if subcmd in _SECURITY_READ_SUBCOMMANDS:
                return self._finding(line)

        if cmd == "secret-tool" and len(tokens) >= 2:
            subcmd = tokens[1].lstrip("-")  # --search → search
            if subcmd in _SECRET_TOOL_READ_SUBCOMMANDS:
                return self._finding(line)

        return None

    def _finding(self, line: str) -> Finding:
        return Finding(
            rule_id=self.rule_id,
            severity=self.severity,
            action_type=ActionType.CREDENTIAL_ACCESS,
            message=self.description,
            matched_text=line,
        )
