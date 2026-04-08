"""
tests/test_credentials_ide.py — IDE and AI agent config paths in credentials rule.

Story: As a bashguard operator, I want to block agents from reading IDE settings
and AI agent memory stores. The LiteLLM supply chain attack (#65) specifically
harvested: .env files, shell profiles, terminal history, IDE settings
(.vscode/settings.json), cached tokens, and AI agent memory stores (~/.claude/).

Developers routinely paste API keys into IDE settings (for environment variable
overrides, REST client configs, etc.). AI agent memory stores contain
conversation history, cached approvals, and session tokens.

Rule contract (extends credentials.privileged_path):
- cat .vscode/settings.json          → BLOCK (IDE settings — API keys)
- cat ~/.vscode/settings.json        → BLOCK
- ls .idea/                          → BLOCK (JetBrains — often has tokens)
- cat "~/Library/Application Support/Code/User/settings.json" → BLOCK (VS Code macOS)
- cat ~/.config/Code/User/settings.json → BLOCK (VS Code Linux)
- cat ~/.claude/settings.json        → BLOCK (AI agent config)
- ls ~/.claude/projects/             → BLOCK (AI agent project memory)
- cat ~/.bash_profile                → BLOCK (shell profile — credentials in env)
- cat .env.local                     → BLOCK (already covered, verify)
- ls .vscode/                        → BLOCK (directory listing reveals structure)
- cat README.md                      → ALLOW
- cat src/main.py                    → ALLOW
"""
from __future__ import annotations
from pathlib import Path
import sys
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))
from bashguard.models import ExecutionContext


@pytest.fixture()
def ctx():
    return ExecutionContext(cwd="/home/user/project")


def _findings(script: str, ctx):
    from bashguard.rules.credentials import CredentialsRule
    return CredentialsRule().check(script, ctx)


class TestIDESettings:
    def test_vscode_settings_blocked(self, ctx):
        findings = _findings("cat .vscode/settings.json", ctx)
        assert len(findings) == 1
        assert findings[0].rule_id == "credentials.privileged_path"

    def test_vscode_home_blocked(self, ctx):
        findings = _findings("cat ~/.vscode/settings.json", ctx)
        assert len(findings) == 1

    def test_vscode_dir_listing_blocked(self, ctx):
        findings = _findings("ls .vscode/", ctx)
        assert len(findings) == 1

    def test_idea_dir_blocked(self, ctx):
        findings = _findings("ls .idea/", ctx)
        assert len(findings) == 1

    def test_idea_workspace_blocked(self, ctx):
        findings = _findings("cat .idea/workspace.xml", ctx)
        assert len(findings) == 1

    def test_vscode_macos_blocked(self, ctx):
        findings = _findings(
            'cat "~/Library/Application Support/Code/User/settings.json"', ctx
        )
        assert len(findings) == 1

    def test_vscode_linux_blocked(self, ctx):
        findings = _findings("cat ~/.config/Code/User/settings.json", ctx)
        assert len(findings) == 1


class TestAgentMemory:
    def test_claude_settings_blocked(self, ctx):
        findings = _findings("cat ~/.claude/settings.json", ctx)
        assert len(findings) == 1

    def test_claude_projects_blocked(self, ctx):
        findings = _findings("ls ~/.claude/projects/", ctx)
        assert len(findings) == 1

    def test_claude_memory_blocked(self, ctx):
        findings = _findings("cat ~/.claude/projects/my-repo/memory/user.md", ctx)
        assert len(findings) == 1


class TestShellProfiles:
    def test_bash_profile_blocked(self, ctx):
        findings = _findings("cat ~/.bash_profile", ctx)
        assert len(findings) == 1

    def test_zprofile_blocked(self, ctx):
        findings = _findings("cat ~/.zprofile", ctx)
        assert len(findings) == 1

    def test_bash_history_still_blocked(self, ctx):
        # Regression: already covered, must stay covered
        findings = _findings("cat ~/.bash_history", ctx)
        assert len(findings) == 1


class TestAllowed:
    def test_readme_allowed(self, ctx):
        assert _findings("cat README.md", ctx) == []

    def test_src_file_allowed(self, ctx):
        assert _findings("cat src/main.py", ctx) == []

    def test_git_log_allowed(self, ctx):
        assert _findings("git log --oneline", ctx) == []
