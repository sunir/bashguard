"""
Story: As a Claude Code hook author, I need bash-ast to:

1. Read Claude PreToolUse JSON via stdin (hook mode) and emit gates-compatible
   permissionDecision JSON so Claude Code's gates system can block commands
   before they execute.

2. Analyze a bash command in debug mode and output structured JSON showing
   all violations and the recommended action.

Success criteria (hook mode):
- `echo HOOK_JSON | bash-ast hook` → silent (empty) for safe commands
- `echo HOOK_JSON | bash-ast hook` → {"permissionDecision": "deny", ...} for blocked
- All hook mode outputs exit 0 (gates reads stdout JSON, not exit code)

Success criteria (analyze mode):
- `bash-ast analyze --command 'echo hello'` → JSON with empty violations
- `bash-ast analyze --command 'rm -rf /'` → JSON with violations
- Output has required fields: commands, violations, response
"""

import json
import subprocess
import sys
import os

PYTHON = sys.executable
CLI = [PYTHON, "-m", "bashguard.cli"]


def _hook_json(command: str) -> str:
    """Build a Claude PreToolUse hook JSON payload."""
    return json.dumps({
        "session_id": "test-session",
        "transcript_path": "/tmp/transcript.jsonl",
        "cwd": os.getcwd(),
        "tool_name": "Bash",
        "tool_input": {"command": command},
    })


def hook(command: str) -> tuple[int, str]:
    """Run bash-ast hook with a command, return (exit_code, stdout)."""
    result = subprocess.run(
        CLI + ["hook"],
        input=_hook_json(command),
        capture_output=True,
        text=True,
    )
    return result.returncode, result.stdout.strip()


def analyze(command: str) -> tuple[int, dict | str]:
    """Run bash-ast analyze --command, return (exit_code, parsed_json_or_output)."""
    result = subprocess.run(
        CLI + ["analyze", "--command", command],
        capture_output=True,
        text=True,
    )
    try:
        return result.returncode, json.loads(result.stdout)
    except json.JSONDecodeError:
        return result.returncode, result.stdout + result.stderr


class TestHookMode:
    def test_safe_command_is_silent(self):
        code, out = hook("echo hello")
        assert code == 0
        assert out == ""

    def test_blocked_command_exits_0(self):
        # hook mode always exits 0 — gates reads stdout JSON
        code, out = hook("rm -rf /")
        assert code == 0

    def test_blocked_command_outputs_deny(self):
        code, out = hook("rm -rf /")
        data = json.loads(out)
        assert data["permissionDecision"] == "deny"

    def test_deny_has_reason(self):
        code, out = hook("rm -rf /")
        data = json.loads(out)
        assert "reason" in data
        assert data["reason"]

    def test_evasion_blocked(self):
        code, out = hook("eval $(cat /etc/passwd)")
        data = json.loads(out)
        assert data["permissionDecision"] == "deny"

    def test_credential_read_blocked(self):
        code, out = hook("cat ~/.ssh/id_rsa")
        data = json.loads(out)
        assert data["permissionDecision"] == "deny"

    def test_git_push_feature_branch_allowed(self):
        code, out = hook("git push origin feature/my-branch")
        assert code == 0
        assert out == ""  # silent = allow


class TestAnalyzeMode:
    def test_safe_command_has_empty_violations(self):
        code, data = analyze("echo hello")
        assert isinstance(data, dict)
        assert data["violations"] == []

    def test_blocked_command_has_violations(self):
        code, data = analyze("rm -rf /")
        assert isinstance(data, dict)
        assert len(data["violations"]) > 0

    def test_output_has_required_fields(self):
        code, data = analyze("echo hello")
        assert "commands" in data
        assert "violations" in data
        assert "response" in data

    def test_response_has_action(self):
        code, data = analyze("echo hello")
        assert "action" in data["response"]
        assert data["response"]["action"] == "allow"

    def test_blocked_response_is_block(self):
        code, data = analyze("rm -rf /")
        assert data["response"]["action"] == "block"

    def test_violation_has_rule_id(self):
        code, data = analyze("rm -rf /")
        assert len(data["violations"]) > 0
        v = data["violations"][0]
        assert "rule_id" in v
        assert "severity" in v
        assert "message" in v

    def test_commands_field_contains_script(self):
        code, data = analyze("echo hello")
        assert "echo hello" in data["commands"]

    def test_analyze_exits_0(self):
        code, data = analyze("rm -rf /")
        assert code == 0
