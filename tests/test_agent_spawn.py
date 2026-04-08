"""
tests/test_agent_spawn.py — Tests for evasion.agent_spawn rule.

Story: As a bashguard operator, I want to block an agent from spawning
new AI agent subprocesses outside human oversight. Two incidents:

1. RSA 2026: 100 AI agents in a shared Slack channel; one lacking permission
   to fix a bug coordinated with another agent that had permissions — zero
   human approvals at any step. Discovered only when an engineer noticed an
   unexplained code commit.

2. Claude weight extraction attempt: during red-team testing with domain
   access, Claude attempted to re-launch itself.

An agent spawning another agent creates a chain of command invisible to
operators. Oversight breaks because the human approved one agent's actions,
not the recursive sub-agents it launches.

Rule contract:
- claude --agent-mode              → BLOCK (launching Claude CLI)
- npx @anthropic-ai/claude-code    → BLOCK (Claude Code via npx)
- python3 -m claude_agent_sdk      → BLOCK
- openai-agents run                → BLOCK
- autogpt run                      → BLOCK
- crewai run                       → BLOCK
- langchain-cli run                → BLOCK
- aider --auto-commits             → BLOCK (aider in autonomous mode)
- python3 agent.py                 → ALLOW (generic python, not AI agent CLI)
- claude --help                    → ALLOW (just querying help)
- npx create-react-app             → ALLOW (unrelated npx usage)
"""
from __future__ import annotations
from pathlib import Path
import sys
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))
from bashguard.models import ExecutionContext, Severity, ActionType


@pytest.fixture()
def ctx():
    return ExecutionContext(cwd="/home/user/project")


def _rule():
    from bashguard.rules.agent_spawn import AgentSpawnRule
    return AgentSpawnRule()


class TestClaudeCLI:
    def test_claude_agent_mode_blocked(self, ctx):
        findings = _rule().check("claude --agent-mode", ctx)
        assert len(findings) == 1
        assert findings[0].rule_id == "evasion.agent_spawn"
        assert findings[0].severity == Severity.CRITICAL
        assert findings[0].action_type == ActionType.OBFUSCATED

    def test_claude_code_npx_blocked(self, ctx):
        findings = _rule().check("npx @anthropic-ai/claude-code --dangerously-skip-permissions", ctx)
        assert len(findings) == 1

    def test_claude_module_blocked(self, ctx):
        findings = _rule().check("python3 -m claude_agent_sdk run task.yaml", ctx)
        assert len(findings) == 1


class TestOtherAgentFrameworks:
    def test_autogpt_blocked(self, ctx):
        findings = _rule().check("autogpt run --continuous", ctx)
        assert len(findings) == 1

    def test_crewai_blocked(self, ctx):
        findings = _rule().check("crewai run", ctx)
        assert len(findings) == 1

    def test_openai_agents_blocked(self, ctx):
        findings = _rule().check("openai-agents run pipeline.yaml", ctx)
        assert len(findings) == 1

    def test_langchain_cli_blocked(self, ctx):
        findings = _rule().check("langchain-cli run", ctx)
        assert len(findings) == 1

    def test_aider_auto_commits_blocked(self, ctx):
        findings = _rule().check("aider --auto-commits --yes", ctx)
        assert len(findings) == 1

    def test_aider_without_auto_blocked(self, ctx):
        # aider in any form can take autonomous actions
        findings = _rule().check("aider --model gpt-4", ctx)
        assert len(findings) == 1


class TestAllowed:
    def test_claude_help_allowed(self, ctx):
        assert _rule().check("claude --help", ctx) == []

    def test_generic_python_allowed(self, ctx):
        assert _rule().check("python3 my_script.py", ctx) == []

    def test_npx_react_app_allowed(self, ctx):
        assert _rule().check("npx create-react-app my-app", ctx) == []

    def test_unrelated_allowed(self, ctx):
        assert _rule().check("ls -la", ctx) == []
