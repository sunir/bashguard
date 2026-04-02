"""
Tests for seatbelt integration into the PreToolUse hook pipeline.

Story: When bashguard audits a bash command and returns ALLOW, the command
should be automatically wrapped with sandbox-exec so that execution is
kernel-enforced even if the audit missed something.

Success criteria:
- ALLOW verdict + seatbelt available → hookSpecificOutput with updatedInput
- ALLOW verdict + seatbelt disabled (BASHGUARD_SEATBELT=0) → empty (current behavior)
- ALLOW verdict + sandbox-exec absent → empty (graceful degradation)
- BLOCK/CONFIRM verdicts → unchanged (existing permissionDecision format)
- Rewritten command uses sandbox-exec -f <profile_path> /bin/bash -c <quoted_cmd>
- Profile path is stable (keyed to SESSION_ID or CWD-based fallback)
- Profile file content is valid SBPL (deny default, allow project writes)
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

PYTHON = sys.executable
CLI = [PYTHON, "-m", "bashguard.cli"]
REPO_ROOT = Path(__file__).parent.parent


def _hook(command: str, env: dict | None = None, cwd: str | None = None) -> tuple[int, str]:
    """Run bashguard hook with a command. Returns (exit_code, stdout)."""
    payload = json.dumps({
        "session_id": "test-seatbelt-session",
        "tool_name": "Bash",
        "tool_input": {"command": command},
    })
    merged_env = {**os.environ, **(env or {})}
    result = subprocess.run(
        CLI + ["hook"],
        input=payload,
        capture_output=True,
        text=True,
        env=merged_env,
        cwd=cwd or str(REPO_ROOT),
    )
    return result.returncode, result.stdout.strip()


pytestmark = pytest.mark.skipif(
    sys.platform != "darwin",
    reason="seatbelt integration is macOS-only",
)


class TestSeatbeltHookDisabled:
    """When seatbelt is disabled, existing behavior is preserved."""

    def test_allow_is_empty_when_disabled(self):
        code, out = _hook("echo hello", env={"BASHGUARD_SEATBELT": "0"})
        assert code == 0
        assert out == ""

    def test_block_unchanged_when_disabled(self):
        code, out = _hook("rm -rf /", env={"BASHGUARD_SEATBELT": "0"})
        data = json.loads(out)
        assert data["permissionDecision"] == "deny"


class TestSeatbeltHookEnabled:
    """When seatbelt is available and enabled, ALLOW commands are wrapped."""

    def test_allow_returns_hook_specific_output(self, tmp_path):
        code, out = _hook("echo hello", cwd=str(tmp_path))
        assert code == 0
        assert out != ""
        data = json.loads(out)
        assert "hookSpecificOutput" in data

    def test_allow_has_permission_decision_allow(self, tmp_path):
        code, out = _hook("echo hello", cwd=str(tmp_path))
        data = json.loads(out)
        hso = data["hookSpecificOutput"]
        assert hso["permissionDecision"] == "allow"

    def test_allow_has_updated_input_command(self, tmp_path):
        code, out = _hook("echo hello", cwd=str(tmp_path))
        data = json.loads(out)
        hso = data["hookSpecificOutput"]
        assert "updatedInput" in hso
        assert "command" in hso["updatedInput"]

    def test_updated_command_contains_sandbox_exec(self, tmp_path):
        code, out = _hook("echo hello", cwd=str(tmp_path))
        data = json.loads(out)
        cmd = data["hookSpecificOutput"]["updatedInput"]["command"]
        assert "sandbox-exec" in cmd

    def test_updated_command_contains_original_script(self, tmp_path):
        code, out = _hook("echo hello world", cwd=str(tmp_path))
        data = json.loads(out)
        cmd = data["hookSpecificOutput"]["updatedInput"]["command"]
        assert "echo hello world" in cmd

    def test_updated_command_uses_profile_file(self, tmp_path):
        code, out = _hook("echo hello", cwd=str(tmp_path))
        data = json.loads(out)
        cmd = data["hookSpecificOutput"]["updatedInput"]["command"]
        # sandbox-exec -f <profile_file> ...
        assert "-f" in cmd

    def test_profile_file_exists_and_is_valid_sbpl(self, tmp_path):
        code, out = _hook("ls", cwd=str(tmp_path))
        data = json.loads(out)
        cmd = data["hookSpecificOutput"]["updatedInput"]["command"]
        # Extract profile path from "sandbox-exec -f <path> ..."
        parts = cmd.split()
        f_idx = parts.index("-f")
        profile_path = Path(parts[f_idx + 1])
        assert profile_path.exists(), f"Profile file not found: {profile_path}"
        content = profile_path.read_text()
        assert "(deny default)" in content
        assert "(allow file-write*" in content

    def test_profile_allows_project_writes(self, tmp_path):
        code, out = _hook("ls", cwd=str(tmp_path))
        data = json.loads(out)
        cmd = data["hookSpecificOutput"]["updatedInput"]["command"]
        parts = cmd.split()
        f_idx = parts.index("-f")
        profile_path = Path(parts[f_idx + 1])
        content = profile_path.read_text()
        real_cwd = str(tmp_path.resolve())
        assert real_cwd in content

    def test_block_is_unchanged_when_seatbelt_enabled(self, tmp_path):
        """BLOCK verdicts use existing format regardless of seatbelt."""
        code, out = _hook("rm -rf /", cwd=str(tmp_path))
        data = json.loads(out)
        assert data["permissionDecision"] == "deny"

    def test_hook_event_name_is_set(self, tmp_path):
        code, out = _hook("echo hello", cwd=str(tmp_path))
        data = json.loads(out)
        hso = data["hookSpecificOutput"]
        assert hso.get("hookEventName") == "PreToolUse"

    def test_sandboxed_command_actually_runs(self, tmp_path):
        """End-to-end: the rewritten command should execute successfully."""
        target = tmp_path / "seatbelt-out.txt"
        code, out = _hook(f"echo sandboxed > {target}", cwd=str(tmp_path))
        data = json.loads(out)
        rewritten = data["hookSpecificOutput"]["updatedInput"]["command"]
        # Execute the rewritten command
        result = subprocess.run(rewritten, shell=True, capture_output=True, text=True)
        assert result.returncode == 0, f"Rewritten command failed: {result.stderr}"
        assert target.read_text().strip() == "sandboxed"
