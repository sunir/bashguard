"""
Tests for bashguard claude setup command.

Verifies that `bashguard claude setup` installs the PreToolUse hook
into ~/.claude/hooks/PreToolUse.d/local/70-bashguard as a symlink
pointing to the bundled hook script.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest


HOOKS_DIR = Path.home() / ".claude" / "hooks" / "PreToolUse.d" / "system"
HOOK_LINK = HOOKS_DIR / "70-bashguard"
REPO_ROOT = Path(__file__).parent.parent
HOOK_SOURCE = REPO_ROOT / "hooks" / "70-bashguard"


class TestClaudeSetup:
    """Tests for `bashguard claude setup`."""

    def test_hook_source_exists(self):
        """The bundled hook script must exist before setup can install it."""
        assert HOOK_SOURCE.exists(), f"Hook source missing: {HOOK_SOURCE}"
        assert os.access(HOOK_SOURCE, os.X_OK), f"Hook source not executable: {HOOK_SOURCE}"

    def test_setup_creates_symlink(self, tmp_path, monkeypatch):
        """claude setup creates a symlink in the target directory."""
        target_dir = tmp_path / "PreToolUse.d" / "local"
        target_link = target_dir / "70-bashguard"

        from bashguard.setup import install_hook
        install_hook(target_dir=target_dir)

        assert target_link.is_symlink(), "Expected a symlink at target path"
        assert target_link.resolve() == HOOK_SOURCE.resolve(), "Symlink should point to bundled hook"

    def test_setup_creates_parent_dirs(self, tmp_path):
        """claude setup creates the target directory if it doesn't exist."""
        target_dir = tmp_path / "deep" / "nested" / "local"
        assert not target_dir.exists()

        from bashguard.setup import install_hook
        install_hook(target_dir=target_dir)

        assert target_dir.exists()
        assert (target_dir / "70-bashguard").is_symlink()

    def test_setup_idempotent(self, tmp_path):
        """Running claude setup twice does not raise or duplicate the link."""
        target_dir = tmp_path / "local"

        from bashguard.setup import install_hook
        install_hook(target_dir=target_dir)
        install_hook(target_dir=target_dir)  # second call — should be a no-op

        assert (target_dir / "70-bashguard").is_symlink()

    def test_setup_replaces_stale_symlink(self, tmp_path):
        """If a stale symlink exists, setup replaces it with the correct one."""
        target_dir = tmp_path / "local"
        target_dir.mkdir(parents=True)
        link = target_dir / "70-bashguard"
        link.symlink_to("/nonexistent/path")
        assert not link.exists()  # dangling

        from bashguard.setup import install_hook
        install_hook(target_dir=target_dir)

        assert link.is_symlink()
        assert link.resolve() == HOOK_SOURCE.resolve()

    def test_cli_claude_setup(self, tmp_path, monkeypatch):
        """`bashguard claude setup` via CLI returns exit 0."""
        target_dir = tmp_path / "PreToolUse.d" / "local"
        env = {**os.environ, "BASHGUARD_HOOKS_DIR": str(target_dir)}
        result = subprocess.run(
            [sys.executable, "-m", "bashguard.cli", "claude", "setup"],
            capture_output=True, text=True, env=env,
            cwd=str(REPO_ROOT),
        )
        assert result.returncode == 0, f"CLI failed: {result.stderr}"
        assert (target_dir / "70-bashguard").is_symlink()
