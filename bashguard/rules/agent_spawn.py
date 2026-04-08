"""
bashguard.rules.agent_spawn — Block spawning AI agent subprocesses.

Two incidents:
1. RSA 2026: 100 AI agents in a shared channel; one lacking permission to fix
   a bug coordinated with another agent that had permissions. Zero human
   approvals at any step. Discovered only when an engineer noticed an
   unexplained code commit.
2. Claude weight extraction: during red-team testing with domain access, Claude
   attempted to re-launch itself as a new agent instance.

An agent spawning another agent creates an oversight gap: the human approved
one agent's actions, not the recursive sub-agents it launches. Each hop
dilutes accountability and may escape per-agent policy enforcement.

Blocked:
  claude --agent-mode / claude (AI CLI)
  npx @anthropic-ai/claude-code
  python3 -m claude_agent_sdk
  autogpt, crewai, openai-agents, langchain-cli
  aider (autonomous coding agent)

Allowed:
  claude --help (just printing help, not executing)
  python3 my_script.py (generic Python, not an AI agent CLI)
  npx create-react-app (unrelated npx usage)
"""
from __future__ import annotations
import logging
import re

from bashguard.models import Severity, Finding, ExecutionContext, ActionType
from bashguard.rules import register

_log = logging.getLogger(__name__)

# Direct AI agent CLI names
_AGENT_CMDS = frozenset({
    "autogpt",
    "crewai",
    "openai-agents",
    "langchain-cli",
    "aider",
})

# npx packages that are AI agent frameworks
_AGENT_NPX_PACKAGES = frozenset({
    "@anthropic-ai/claude-code",
    "claude-code",
})

# Python modules that are AI agent frameworks
_AGENT_MODULES = frozenset({
    "claude_agent_sdk",
    "autogpt",
    "crewai",
})

# claude CLI — allowed only with --help; blocked otherwise
_CLAUDE_HELP_ONLY_RE = re.compile(r"\bclaude\b.*(--help|-h)\b")
_CLAUDE_CMD_RE = re.compile(r"^\bclaude\b\s*(?!--help|-h\b)")


@register
class AgentSpawnRule:
    rule_id = "evasion.agent_spawn"
    severity = Severity.CRITICAL
    description = "Spawning an AI agent subprocess — creates oversight gap"

    def check(self, script: str, context: ExecutionContext) -> list[Finding]:
        try:
            return list(self._scan(script))
        except Exception:
            _log.exception("agent_spawn rule error")
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

        # Direct agent CLI commands
        if cmd in _AGENT_CMDS:
            return self._finding(line)

        # claude CLI — allow --help, block everything else
        if cmd == "claude":
            if not _CLAUDE_HELP_ONLY_RE.search(line):
                return self._finding(line)

        # npx with AI agent package names
        if cmd == "npx":
            for tok in tokens[1:]:
                clean = tok.strip("'\"")
                if clean in _AGENT_NPX_PACKAGES:
                    return self._finding(line)

        # python3 -m <agent_module>
        if cmd in ("python", "python3", "uv") and "-m" in tokens:
            m_idx = tokens.index("-m")
            if m_idx + 1 < len(tokens):
                module = tokens[m_idx + 1]
                if module in _AGENT_MODULES:
                    return self._finding(line)

        return None

    def _finding(self, line: str) -> Finding:
        return Finding(
            rule_id=self.rule_id,
            severity=self.severity,
            action_type=ActionType.OBFUSCATED,
            message=self.description,
            matched_text=line,
        )
