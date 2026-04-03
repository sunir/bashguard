"""
Tests for bashguard.credentials — credential injection via PreToolUse hook rewrite.

Story: As a user, I want to use placeholders like {{OPENAI_API_KEY}} in bash
commands that Claude writes, and have the real credential substituted at
execution time via the PreToolUse hook's updatedInput rewrite — so the real
secret never appears in Claude's context window or transcript.

Success criteria:
- Credential store loaded from ~/.bashguard/credentials.yaml
- {{SECRET_NAME}} placeholders substituted in commands before execution
- $SECRET_NAME env-var style placeholders also substituted
- If no credentials file, command passes through unchanged
- Credentials never appear in hook stdout (they're in updatedInput.command only)
- Hook integration: ALLOW command with placeholders → rewritten command in updatedInput
- Unknown placeholders left as-is (don't break commands with unrelated $ vars)
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from bashguard.credentials import CredentialStore, substitute


PYTHON = sys.executable
CLI = [PYTHON, "-m", "bashguard.cli"]
REPO_ROOT = Path(__file__).parent.parent


class TestCredentialStore:

    def test_empty_file_returns_empty_store(self, tmp_path):
        creds_file = tmp_path / "credentials.yaml"
        creds_file.write_text("")
        store = CredentialStore.load(creds_file)
        assert store.is_empty()

    def test_missing_file_returns_empty_store(self, tmp_path):
        store = CredentialStore.load(tmp_path / "nonexistent.yaml")
        assert store.is_empty()

    def test_loads_key_value_pairs(self, tmp_path):
        creds_file = tmp_path / "credentials.yaml"
        creds_file.write_text("OPENAI_API_KEY: sk-test-123\nGITHUB_TOKEN: ghp-abc\n")
        store = CredentialStore.load(creds_file)
        assert store.get("OPENAI_API_KEY") == "sk-test-123"
        assert store.get("GITHUB_TOKEN") == "ghp-abc"

    def test_get_unknown_key_returns_none(self, tmp_path):
        creds_file = tmp_path / "credentials.yaml"
        creds_file.write_text("FOO: bar\n")
        store = CredentialStore.load(creds_file)
        assert store.get("UNKNOWN") is None

    def test_store_repr_redacts_values(self, tmp_path):
        creds_file = tmp_path / "credentials.yaml"
        creds_file.write_text("OPENAI_API_KEY: sk-super-secret\n")
        store = CredentialStore.load(creds_file)
        assert "sk-super-secret" not in repr(store)
        assert "OPENAI_API_KEY" in repr(store)


class TestSubstitute:

    def test_double_brace_placeholder_substituted(self):
        store = CredentialStore({"OPENAI_API_KEY": "sk-real"})
        result = substitute("curl -H 'Authorization: Bearer {{OPENAI_API_KEY}}'", store)
        assert result == "curl -H 'Authorization: Bearer sk-real'"

    def test_dollar_placeholder_substituted(self):
        store = CredentialStore({"GITHUB_TOKEN": "ghp-real"})
        result = substitute("git clone https://x:$GITHUB_TOKEN@github.com/repo", store)
        assert result == "git clone https://x:ghp-real@github.com/repo"

    def test_unknown_placeholder_left_alone(self):
        store = CredentialStore({"FOO": "bar"})
        result = substitute("echo $HOME and $USER", store)
        assert result == "echo $HOME and $USER"

    def test_multiple_placeholders_substituted(self):
        store = CredentialStore({"KEY_A": "val-a", "KEY_B": "val-b"})
        result = substitute("{{KEY_A}} {{KEY_B}}", store)
        assert result == "val-a val-b"

    def test_no_credentials_returns_command_unchanged(self):
        store = CredentialStore({})
        cmd = "curl https://api.example.com"
        assert substitute(cmd, store) == cmd

    def test_mixed_styles_both_substituted(self):
        store = CredentialStore({"KEY": "secret"})
        result = substitute("echo {{KEY}} $KEY", store)
        assert result == "echo secret secret"

    def test_partial_word_dollar_not_substituted(self):
        """$FOO_BAR should not substitute $FOO if only FOO is in store."""
        store = CredentialStore({"FOO": "bar"})
        result = substitute("echo $FOO_BAR", store)
        assert result == "echo $FOO_BAR"

    def test_braced_dollar_substituted(self):
        store = CredentialStore({"KEY": "val"})
        result = substitute("echo ${KEY}", store)
        assert result == "echo val"


class TestHookIntegration:
    """End-to-end: credential substitution in the PreToolUse hook pipeline."""

    def _hook(self, command: str, creds_file: Path | None = None,
               cwd: str | None = None) -> tuple[int, str]:
        payload = json.dumps({
            "tool_name": "Bash",
            "tool_input": {"command": command},
        })
        env = {**os.environ, "BASHGUARD_SEATBELT": "0"}  # isolate credential test
        if creds_file:
            env["BASHGUARD_CREDENTIALS"] = str(creds_file)
        result = subprocess.run(
            CLI + ["hook"],
            input=payload,
            capture_output=True,
            text=True,
            env=env,
            cwd=cwd or str(REPO_ROOT),
        )
        return result.returncode, result.stdout.strip()

    def test_no_placeholders_allows_silently(self, tmp_path):
        code, out = self._hook("echo hello")
        assert code == 0
        assert out == ""

    def test_placeholder_in_allowed_command_substituted(self, tmp_path):
        creds = tmp_path / "creds.yaml"
        creds.write_text("MY_TOKEN: secret-value\n")
        code, out = self._hook("echo {{MY_TOKEN}}", creds_file=creds)
        assert code == 0
        data = json.loads(out)
        cmd = data["hookSpecificOutput"]["updatedInput"]["command"]
        assert "secret-value" in cmd
        assert "{{MY_TOKEN}}" not in cmd

    def test_real_key_not_in_hook_stdout_as_json_value(self, tmp_path):
        """The real credential must not appear in the top-level hook JSON as a readable field."""
        creds = tmp_path / "creds.yaml"
        creds.write_text("API_KEY: super-secret-key\n")
        code, out = self._hook("curl -H 'Auth: {{API_KEY}}'", creds_file=creds)
        # The key IS in updatedInput.command — that's expected and intentional.
        # But it should not appear as a separate JSON field where Claude could
        # read it from a subsequent hook result inspection.
        data = json.loads(out)
        hso = data["hookSpecificOutput"]
        assert "super-secret-key" not in json.dumps(hso.get("permissionDecision", ""))
        assert "super-secret-key" not in json.dumps(hso.get("additionalContext", ""))

    def test_blocked_command_with_placeholder_still_blocked(self, tmp_path):
        creds = tmp_path / "creds.yaml"
        creds.write_text("TOKEN: secret\n")
        # rm -rf / is still blocked regardless of credential placeholders
        code, out = self._hook("rm -rf / {{TOKEN}}", creds_file=creds)
        data = json.loads(out)
        assert data["permissionDecision"] == "deny"
