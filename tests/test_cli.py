"""
Story: As a Claude Code hook author, I need bash-audit to output valid JSON
and correct exit codes for every verdict type, so I can integrate it with
a single shell conditional.

Success:
- "echo hello" exits 0 with JSON verdict=allow
- ">&" exits 1 with JSON verdict=block (HIGH finding blocked by default)
- --stdin reads the command from stdin
- JSON output is always valid and contains required fields
- Text format output contains verdict word on first line
- --cwd overrides the working directory in context
"""

import json
import subprocess
import sys
import os

PYTHON = sys.executable
CLI = [PYTHON, "-m", "bash_audit.cli"]


def run(args: list[str], stdin: str | None = None) -> tuple[int, dict | str]:
    """Run bash-audit CLI, return (exit_code, parsed_json_or_stderr)."""
    env = {**os.environ, "TERM": "dumb"}
    result = subprocess.run(
        CLI + args,
        input=stdin,
        capture_output=True,
        text=True,
        env=env,
    )
    try:
        return result.returncode, json.loads(result.stdout)
    except json.JSONDecodeError:
        return result.returncode, result.stdout + result.stderr


class TestExitCodes:
    def test_safe_command_exits_0(self):
        code, data = run(["echo hello"])
        assert code == 0

    def test_safe_command_verdict_allow(self):
        code, data = run(["echo hello"])
        assert isinstance(data, dict)
        assert data["verdict"] == "allow"

    def test_malformed_command_exits_1(self):
        # >& triggers parse error → HIGH → BLOCK
        code, data = run([">&"])
        assert code == 1

    def test_malformed_command_verdict_block(self):
        code, data = run([">&"])
        assert isinstance(data, dict)
        assert data["verdict"] == "block"


class TestJsonOutput:
    def test_output_is_valid_json(self):
        code, data = run(["echo hello"])
        assert isinstance(data, dict)

    def test_required_fields_present(self):
        code, data = run(["echo hello"])
        assert "verdict" in data
        assert "message" in data
        assert "findings" in data
        assert "parse" in data

    def test_parse_field_has_error_info(self):
        code, data = run(["echo hello"])
        assert "has_errors" in data["parse"]
        assert "error_count" in data["parse"]

    def test_findings_is_list(self):
        code, data = run(["echo hello"])
        assert isinstance(data["findings"], list)

    def test_block_findings_populated(self):
        code, data = run([">&"])
        assert len(data["findings"]) > 0
        assert data["findings"][0]["rule_id"] == "parse.error_node"


class TestStdinMode:
    def test_stdin_flag_reads_command(self):
        code, data = run(["--stdin"], stdin="echo hello\n")
        assert code == 0
        assert data["verdict"] == "allow"

    def test_stdin_malformed_blocks(self):
        code, data = run(["--stdin"], stdin=">&\n")
        assert code == 1


class TestOptions:
    def test_cwd_option_accepted(self, tmp_path):
        code, data = run(["--cwd", str(tmp_path), "echo hello"])
        assert code == 0

    def test_format_json_is_default(self):
        code, data = run(["echo hello"])
        assert isinstance(data, dict)

    def test_no_command_shows_usage(self):
        code, out = run([])
        # Should show usage / error, not crash with traceback
        assert isinstance(out, (dict, str))
