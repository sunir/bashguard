"""
bashguard.rules.error_nodes — Flag commands with parse errors.

A command that cannot be fully parsed is a command we cannot fully audit.
Treat it as elevated risk. LLMs sometimes generate malformed commands
intentionally to confuse static analysis.
"""

from __future__ import annotations
import logging
from tree_sitter import Language, Parser
import tree_sitter_bash as tsb

from bashguard.models import Severity, Finding, ExecutionContext, ActionType
from bashguard.rules import register

_log = logging.getLogger(__name__)

_LANG = Language(tsb.language())
_PARSER = Parser(_LANG)


def _count_errors(node) -> int:
    count = 1 if node.is_error else 0
    for child in node.children:
        count += _count_errors(child)
    return count


@register
class ErrorNodesRule:
    rule_id = "parse.error_node"
    severity = Severity.HIGH
    description = "Command contains parse errors — auditing is incomplete, treat as elevated risk"

    def check(self, script: str, context: ExecutionContext) -> list[Finding]:
        try:
            source = script.encode("utf-8", errors="replace")
            tree = _PARSER.parse(source)
            root = tree.root_node
            if not root.has_error:
                return []
            error_count = _count_errors(root)
            return [Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                message=(
                    f"Command contains {error_count} parse error(s) — "
                    "full analysis is not possible"
                ),
                matched_text=script,
                span=(0, len(source)),
                metadata={"error_count": error_count},
                action_type=ActionType.OBFUSCATED,
            )]
        except Exception as e:
            _log.error("ErrorNodesRule raised unexpectedly: %s", e, exc_info=True)
            return []
