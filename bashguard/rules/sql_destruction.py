"""
bashguard.rules.sql_destruction — Flag destructive SQL commands.

Detects DROP DATABASE, DROP TABLE, TRUNCATE TABLE, DELETE FROM without WHERE
passed to mysql, psql, sqlite3, or similar CLI tools.

From n2-ark Category 1.
"""
from __future__ import annotations

import logging
import re

from bashguard.models import ActionType, ExecutionContext, Finding, Severity
from bashguard.parser import parse
from bashguard.rules import register

_log = logging.getLogger(__name__)

_SQL_TOOLS = frozenset({"mysql", "psql", "sqlite3", "sqlplus", "sqlcmd", "mssql"})

_DESTRUCTIVE_SQL = [
    (re.compile(r'DROP\s+DATABASE', re.IGNORECASE), "DROP DATABASE"),
    (re.compile(r'DROP\s+TABLE', re.IGNORECASE), "DROP TABLE"),
    (re.compile(r'TRUNCATE\s+TABLE', re.IGNORECASE), "TRUNCATE TABLE"),
    (re.compile(r'DELETE\s+FROM\s+\w+\s*;', re.IGNORECASE), "DELETE FROM without WHERE"),
]


@register
class SQLDestructionRule:
    rule_id = "sql.destructive"
    severity = Severity.CRITICAL
    description = "Destructive SQL command (DROP DATABASE/TABLE, TRUNCATE, bulk DELETE)"

    def check(self, script: str, context: ExecutionContext) -> list[Finding]:
        try:
            cmds = parse(script)
            findings: list[Finding] = []

            for cmd in cmds:
                if cmd.name not in _SQL_TOOLS:
                    continue

                all_text = " ".join(cmd.args + cmd.flags)
                for pattern, label in _DESTRUCTIVE_SQL:
                    if pattern.search(all_text):
                        findings.append(Finding(
                            rule_id=self.rule_id,
                            severity=self.severity,
                            message=f"Destructive SQL: {label}",
                            matched_text=cmd.raw,
                            action_type=ActionType.FILESYSTEM_DELETE,
                        ))
                        break

            return findings
        except Exception as e:
            _log.error("SQLDestructionRule raised: %s", e, exc_info=True)
            return []
