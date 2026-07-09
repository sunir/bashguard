"""Tests for bashguard launch mode: session-level deny-default sandbox.

Story: SANDBOX-EXEC-LAUNCH

bashguard launch -c 'CMD' wraps CMD in sandbox-exec (macOS) with a deny-default
profile, providing session-level sandboxing for the entire process tree.

Contracts:
- Profile is deny-default with allow-reads everywhere and allow-writes to project dir
- ~/.claude and /var/db/ai/claude are always in the allow-write set
- --project DIR overrides the project path; CWD is used when omitted
- Profile is written to a stable path keyed by project root hash (cached)
- sandbox-exec absent → fail-open (exec the command directly)
- Exit code from the wrapped command propagates
"""
from __future__ import annotations

import hashlib
import os
import subprocess
import sys
from pathlib import Path

import pytest

PYTHON = sys.executable
BASHGUARD = [PYTHON, "-m", "bashguard.cli"]
REPO_ROOT = Path(__file__).parent.parent
PROFILE_DIR = Path("/tmp/bashguard-launch-profiles")


def _launch(args: list[str], env: dict | None = None, cwd: str | None = None) -> tuple[int, str, str]:
    """Run bashguard launch ... Return (exit_code, stdout, stderr)."""
    merged = {**os.environ, **(env or {})}
    result = subprocess.run(
        BASHGUARD + ["launch"] + args,
        capture_output=True,
        text=True,
        env=merged,
        cwd=cwd or str(REPO_ROOT),
    )
    return result.returncode, result.stdout, result.stderr


def _profile_path(project: Path) -> Path:
    key = hashlib.sha256(str(project.resolve()).encode()).hexdigest()[:12]
    return PROFILE_DIR / f"{key}.sb"


class TestLaunchProfileContent:
    # Story: SANDBOX-EXEC-LAUNCH

    def test_profile_deny_default(self, tmp_path):
        """Profile must start with (deny default)."""
        project = tmp_path / "myproject"
        project.mkdir()
        _launch(["--project", str(project), "-c", "true"])
        profile_path = _profile_path(project)
        assert profile_path.exists(), f"Profile not found at {profile_path}"
        content = profile_path.read_text()
        assert "(deny default)" in content

    def test_profile_allows_reads_everywhere(self, tmp_path):
        """Profile must allow reads to /, so agent can read system libs."""
        project = tmp_path / "myproject"
        project.mkdir()
        _launch(["--project", str(project), "-c", "true"])
        content = _profile_path(project).read_text()
        assert '(allow file-read* (subpath "/"))' in content

    def test_profile_allows_project_writes(self, tmp_path):
        """Profile must allow writes to the project directory."""
        project = tmp_path / "myproject"
        project.mkdir()
        _launch(["--project", str(project), "-c", "true"])
        content = _profile_path(project).read_text()
        real = str(project.resolve())
        assert f'(allow file-write* (subpath "{real}"))' in content

    def test_profile_allows_claude_config_writes(self, tmp_path):
        """Profile must allow writes to ~/.claude for config and history."""
        project = tmp_path / "myproject"
        project.mkdir()
        _launch(["--project", str(project), "-c", "true"])
        content = _profile_path(project).read_text()
        # Use resolved path — macOS may symlink /var/db → /private/var/db
        claude_dir = str((Path.home() / ".claude").resolve())
        assert f'(allow file-write* (subpath "{claude_dir}"))' in content

    def test_profile_allows_var_db_ai(self, tmp_path):
        """Profile must allow writes to /var/db/ai/claude (prod deployments)."""
        project = tmp_path / "myproject"
        project.mkdir()
        _launch(["--project", str(project), "-c", "true"])
        content = _profile_path(project).read_text()
        # Use resolved path — macOS /var/db is a symlink to /private/var/db
        var_db = str(Path("/var/db/ai/claude").resolve())
        assert f'(allow file-write* (subpath "{var_db}"))' in content

    def test_profile_allows_tmp(self, tmp_path):
        """Profile must allow writes to /private/tmp."""
        project = tmp_path / "myproject"
        project.mkdir()
        _launch(["--project", str(project), "-c", "true"])
        content = _profile_path(project).read_text()
        assert '(allow file-write* (subpath "/private/tmp"))' in content

    def test_project_override_changes_allowed_path(self, tmp_path):
        """--project DIR must be reflected in the allow-write rule, not CWD."""
        project_a = tmp_path / "projA"
        project_b = tmp_path / "projB"
        project_a.mkdir()
        project_b.mkdir()
        _launch(["--project", str(project_a), "-c", "true"])
        _launch(["--project", str(project_b), "-c", "true"])
        content_a = _profile_path(project_a).read_text()
        content_b = _profile_path(project_b).read_text()
        real_a = str(project_a.resolve())
        real_b = str(project_b.resolve())
        assert f'(allow file-write* (subpath "{real_a}"))' in content_a
        assert f'(allow file-write* (subpath "{real_b}"))' in content_b
        assert f'(allow file-write* (subpath "{real_b}"))' not in content_a


class TestLaunchProfileCaching:
    # Story: SANDBOX-EXEC-LAUNCH

    def test_profile_stable_path(self, tmp_path):
        """Same project produces the same profile file path."""
        project = tmp_path / "myproject"
        project.mkdir()
        _launch(["--project", str(project), "-c", "true"])
        p1 = _profile_path(project)
        mtime1 = p1.stat().st_mtime
        _launch(["--project", str(project), "-c", "true"])
        mtime2 = p1.stat().st_mtime
        assert mtime1 == mtime2, "Profile was regenerated on second call (should be cached)"


class TestLaunchExecution:
    # Story: SANDBOX-EXEC-LAUNCH

    def test_exit_code_passthrough(self, tmp_path):
        """Exit code from the wrapped command must propagate."""
        project = tmp_path / "myproject"
        project.mkdir()
        code, _, _ = _launch(["--project", str(project), "-c", "exit 42"])
        # With sandbox-exec: exit code from the shell propagates
        # Without sandbox-exec (fail-open): also propagates
        assert code == 42

    def test_stdout_passthrough(self, tmp_path, capsys):
        """stdout from the wrapped command must be visible."""
        project = tmp_path / "myproject"
        project.mkdir()
        _, stdout, stderr = _launch(["--project", str(project), "-c", "echo hello"])
        assert "hello" in stdout or "hello" in stderr  # sandbox-exec may redirect

    def test_fail_open_without_sandbox_exec(self, tmp_path):
        """When sandbox-exec is absent, command runs directly (no crash, exit 0)."""
        project = tmp_path / "myproject"
        project.mkdir()
        env = {"BASHGUARD_SEATBELT": "0"}  # disable seatbelt → triggers fail-open
        code, _, _ = _launch(["--project", str(project), "-c", "exit 0"], env=env)
        assert code == 0
