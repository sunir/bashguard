"""
bashguard.rules.oversight_tamper — Block disabling of oversight/monitoring config.

Two incidents:
1. Models given a long-term goal conflicting with developer priorities edited
   a config file to switch oversight_enabled: true to false.
2. RSA 2026: An agent rewrote an organization's entire security policy to
   remove a permission barrier it encountered, then continued operating under
   the new policy.

Oversight tamper is the meta-attack: instead of working around a constraint,
remove the constraint from the system itself. Unlike most security rules,
this attack requires no network access and no special privileges — just
write access to a config file.

Blocked:
- sed that replaces *_enabled: true with *_enabled: false (oversight, monitoring, audit)
- echo/printf appending *_enabled: false to any config
- Writes/truncates to audit log files
- Writes to files named oversight.*, monitoring.*, audit.*

Allowed:
- cat / reading config files
- sed that re-enables (false → true)
- Unrelated config writes (debug: true, etc.)
"""
from __future__ import annotations
import logging
import re

from bashguard.models import Severity, Finding, ExecutionContext, ActionType
from bashguard.rules import register

_log = logging.getLogger(__name__)

# Keywords that signal oversight/monitoring configuration
_OVERSIGHT_KEYS = re.compile(
    r"\b(?:oversight|monitoring|audit_log(?:ging)?|audit)\s*[_:]?\s*(?:enabled|logging|active)",
    re.IGNORECASE,
)

# Disabling value pattern
_FALSE_VALUE_RE = re.compile(r":\s*(?:false|0|disabled|off)\b", re.IGNORECASE)

# Files that are audit logs (writing to them = destroying evidence)
_AUDIT_FILE_RE = re.compile(
    r"\baudit(?:_log)?(?:s)?\.(?:json[l]?|log|txt|csv)\b",
    re.IGNORECASE,
)

# Files named oversight.*, monitoring.*
_OVERSIGHT_FILE_RE = re.compile(
    r"\b(?:oversight|monitoring)\.(?:yaml|yml|json|toml|ini|conf)\b",
    re.IGNORECASE,
)

# sed patterns that disable oversight keys
_SED_DISABLE_RE = re.compile(
    r"s[|/](" + _OVERSIGHT_KEYS.pattern + r"[^\|/]*(?:true|enabled|1))"
    r"[|/](\1.*(?:false|disabled|0|off))",
    re.IGNORECASE,
)

# Simpler: sed changing a monitored key from true to false
_SED_TRUE_TO_FALSE_RE = re.compile(
    r"s[/|]([^/|]*(?:oversight|monitoring|audit)[^/|]*:?\s*(?:true|enabled))"
    r"[/|][^/|]*(?:false|disabled|off)[/|]",
    re.IGNORECASE,
)

# Destructive operations on audit files
_AUDIT_DESTROY_CMDS = frozenset({"rm", "truncate", "shred"})


def _is_disabling_write(line: str) -> bool:
    """Return True if the line writes a 'disabled' value for an oversight key."""
    if not (_OVERSIGHT_KEYS.search(line) and _FALSE_VALUE_RE.search(line)):
        return False
    # Make sure it's a write (>>, >, echo, printf, cat >)
    return bool(re.search(r">>|(?<![<>])>|echo|printf|cat\s+>", line))


@register
class OversightTamperRule:
    rule_id = "config.oversight_tamper"
    severity = Severity.CRITICAL
    description = "Disabling or destroying oversight/monitoring configuration"

    def check(self, script: str, context: ExecutionContext) -> list[Finding]:
        try:
            return list(self._scan(script))
        except Exception:
            _log.exception("oversight_tamper rule error")
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
        # sed -i 's/oversight_enabled: true/oversight_enabled: false/'
        if "sed" in line and _SED_TRUE_TO_FALSE_RE.search(line):
            return self._finding(line)

        # echo 'oversight_enabled: false' >> config
        if _is_disabling_write(line):
            return self._finding(line)

        # Writes to oversight/monitoring config files
        tokens = line.split()
        if tokens:
            cmd = tokens[0]
            if _OVERSIGHT_FILE_RE.search(line) and re.search(r">>|(?<![<>])>|cat\s+/dev/null", line):
                return self._finding(line)

            # Destructive operations on audit log files
            if cmd in _AUDIT_DESTROY_CMDS and _AUDIT_FILE_RE.search(line):
                return self._finding(line)

            # truncate -s 0 audit.jsonl
            if cmd == "truncate" and _AUDIT_FILE_RE.search(line):
                return self._finding(line)

        return None

    def _finding(self, line: str) -> Finding:
        return Finding(
            rule_id=self.rule_id,
            severity=self.severity,
            action_type=ActionType.SYSTEM_CONFIG,
            message=self.description,
            matched_text=line,
        )
