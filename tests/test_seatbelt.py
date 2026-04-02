"""
Tests for bashguard.seatbelt — macOS sandbox-exec profile generation and execution.

Story: As a bashguard session, I want to wrap bash command execution in a
seatbelt (sandbox-exec) profile so that writes outside the project dir are
blocked at the OS kernel level, providing defense-in-depth beneath FUSE.

Success criteria:
- SBPL profile generated correctly for a given project path
- Writes to project dir allowed; writes outside blocked (EPERM)
- Reads anywhere allowed (agent needs to read system libs, tools)
- Network outbound blocked by default
- Real paths used (symlinks resolved — /tmp → /private/tmp on macOS)
- Graceful degradation: if sandbox-exec missing, runs command unsandboxed
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from bashguard.seatbelt import (
    SeatbeltProfile,
    build_profile,
    run_sandboxed,
    sandbox_exec_available,
)


pytestmark = pytest.mark.skipif(
    sys.platform != "darwin",
    reason="seatbelt is macOS-only",
)


class TestSeatbeltProfile:
    """Unit tests for SBPL profile generation."""

    def test_profile_denies_default(self, tmp_path):
        profile = build_profile(project_path=tmp_path)
        assert "(deny default)" in profile.sbpl

    def test_profile_allows_reads_everywhere(self, tmp_path):
        profile = build_profile(project_path=tmp_path)
        assert '(allow file-read* (subpath "/"))' in profile.sbpl

    def test_profile_allows_writes_to_project(self, tmp_path):
        real = str(tmp_path.resolve())
        profile = build_profile(project_path=tmp_path)
        assert f'(allow file-write* (subpath "{real}"))' in profile.sbpl

    def test_profile_allows_writes_to_tmp(self, tmp_path):
        profile = build_profile(project_path=tmp_path)
        # /tmp writes allowed (agents use temp files)
        assert '(allow file-write* (subpath "/private/tmp"))' in profile.sbpl

    def test_profile_blocks_writes_outside_project(self, tmp_path):
        real = str(tmp_path.resolve())
        profile = build_profile(project_path=tmp_path)
        # profile should NOT contain a blanket allow for parent
        parent = str(tmp_path.parent.resolve())
        assert f'(allow file-write* (subpath "{parent}"))' not in profile.sbpl

    def test_profile_denies_network_by_default(self, tmp_path):
        profile = build_profile(project_path=tmp_path)
        assert "(allow network-outbound" not in profile.sbpl

    def test_profile_allows_network_for_known_hosts(self, tmp_path):
        profile = build_profile(
            project_path=tmp_path,
            allowed_hosts=["api.openai.com", "pypi.org"],
        )
        assert "api.openai.com" in profile.sbpl
        assert "pypi.org" in profile.sbpl

    def test_profile_allows_process_exec(self, tmp_path):
        profile = build_profile(project_path=tmp_path)
        assert "(allow process-exec*)" in profile.sbpl

    def test_profile_resolves_symlinks(self, tmp_path):
        # /tmp on macOS is a symlink to /private/tmp — seatbelt needs real paths
        via_symlink = Path("/tmp") / "seatbelt-symlink-test"
        profile = build_profile(project_path=via_symlink)
        # Profile must use the real path, not the symlink form
        assert "/private/tmp/seatbelt-symlink-test" in profile.sbpl
        assert '(subpath "/tmp/' not in profile.sbpl

    def test_profile_str_is_sbpl(self, tmp_path):
        profile = build_profile(project_path=tmp_path)
        assert str(profile) == profile.sbpl

    def test_profile_allows_extra_write_paths(self, tmp_path):
        extra = tmp_path.parent / "shared-output"
        profile = build_profile(project_path=tmp_path, extra_write_paths=[extra])
        assert str(extra.resolve()) in profile.sbpl


class TestSandboxExecAvailable:
    """sandbox-exec availability detection."""

    def test_available_on_macos(self):
        assert sandbox_exec_available() is True


class TestRunSandboxed:
    """Integration tests — actually runs sandbox-exec."""

    def test_write_to_project_allowed(self, tmp_path):
        target = tmp_path / "output.txt"
        result = run_sandboxed(
            ["bash", "-c", f"echo hello > {target}"],
            project_path=tmp_path,
        )
        assert result.returncode == 0
        assert target.read_text().strip() == "hello"

    def test_write_outside_project_blocked(self, tmp_path):
        # Use home dir — definitely outside both project and /private/tmp
        outside = Path.home() / ".bashguard-seatbelt-test-forbidden.txt"
        outside.unlink(missing_ok=True)
        result = run_sandboxed(
            ["bash", "-c", f"echo evil > {outside}"],
            project_path=tmp_path,
        )
        assert result.returncode != 0
        assert not outside.exists()

    def test_read_anywhere_allowed(self, tmp_path):
        result = run_sandboxed(
            ["bash", "-c", "cat /etc/hosts"],
            project_path=tmp_path,
        )
        assert result.returncode == 0
        assert "localhost" in result.stdout

    def test_network_blocked_by_default(self, tmp_path):
        result = run_sandboxed(
            ["bash", "-c", "curl -s --max-time 2 http://example.com"],
            project_path=tmp_path,
        )
        assert result.returncode != 0

    def test_tmp_writes_allowed(self, tmp_path):
        result = run_sandboxed(
            ["bash", "-c", "echo ok > /tmp/seatbelt-test-allowed.txt"],
            project_path=tmp_path,
        )
        assert result.returncode == 0
        Path("/tmp/seatbelt-test-allowed.txt").unlink(missing_ok=True)

    def test_returns_stdout_stderr(self, tmp_path):
        result = run_sandboxed(
            ["bash", "-c", "echo out && echo err >&2"],
            project_path=tmp_path,
        )
        assert result.returncode == 0
        assert "out" in result.stdout
        assert "err" in result.stderr

    def test_graceful_degradation_without_sandbox_exec(self, tmp_path, monkeypatch):
        """If sandbox-exec not found, command runs unsandboxed."""
        monkeypatch.setattr("bashguard.seatbelt.sandbox_exec_available", lambda: False)
        result = run_sandboxed(
            ["echo", "hello"],
            project_path=tmp_path,
        )
        assert result.returncode == 0
        assert "hello" in result.stdout
