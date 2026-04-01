"""
tests/test_colony_hooks.py — Tests for colony SessionStart/End hook support.

The SessionStart hook uses SESSION_ID (from colony common.sh) as the agent
token, registers it in a file-based registry, and mounts the FUSE sandbox.
The SessionEnd hook unmounts, generates an overlay diff, and files an issue
if there are pending changes.

Story: As a colony agent, when my session starts, bashguard automatically
mounts a FUSE sandbox over my CWD so writes are captured in an overlay.
When my session ends, any overlay changes are written as a patch file and
flagged for human review via the colony issues system.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, call, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "spike"))

from colony_hooks import (  # noqa: E402
    FileRegistry,
    session_start,
    session_end,
    overlay_diff,
)


@pytest.fixture()
def registry_path(tmp_path: Path) -> Path:
    return tmp_path / "sessions.json"


@pytest.fixture()
def registry(registry_path: Path) -> FileRegistry:
    return FileRegistry(registry_path)


# ---------------------------------------------------------------------------
# FileRegistry — file-based session registry
# ---------------------------------------------------------------------------

class TestFileRegistry:
    def test_register_creates_file(self, registry: FileRegistry, registry_path: Path):
        registry.register("sess-abc", "/alice", "/tmp/mount-abc")
        assert registry_path.exists()

    def test_register_and_lookup(self, registry: FileRegistry):
        registry.register("sess-abc", "/alice", "/tmp/mount-abc")
        entry = registry.lookup("sess-abc")
        assert entry is not None
        assert entry["granted_root"] == "/alice"
        assert entry["mount_point"] == "/tmp/mount-abc"

    def test_lookup_missing_returns_none(self, registry: FileRegistry):
        assert registry.lookup("ghost") is None

    def test_unregister_removes_entry(self, registry: FileRegistry):
        registry.register("sess-abc", "/alice", "/tmp/mount-abc")
        registry.unregister("sess-abc")
        assert registry.lookup("sess-abc") is None

    def test_multiple_sessions(self, registry: FileRegistry):
        registry.register("sess-1", "/alice", "/tmp/mnt-1")
        registry.register("sess-2", "/bob", "/tmp/mnt-2")
        assert registry.lookup("sess-1")["granted_root"] == "/alice"
        assert registry.lookup("sess-2")["granted_root"] == "/bob"

    def test_persists_across_instances(self, registry: FileRegistry, registry_path: Path):
        registry.register("sess-abc", "/alice", "/tmp/mount-abc")
        # New instance reads same file
        r2 = FileRegistry(registry_path)
        assert r2.lookup("sess-abc")["granted_root"] == "/alice"


# ---------------------------------------------------------------------------
# session_start
# ---------------------------------------------------------------------------

class TestSessionStart:
    def test_writes_token_file(self, tmp_path: Path, registry_path: Path):
        project = tmp_path / "my-project"
        project.mkdir()
        registry = FileRegistry(registry_path)

        with patch("colony_hooks.subprocess.Popen") as mock_popen:
            mock_popen.return_value = MagicMock(pid=1234)
            session_start(
                session_id="sess-abc",
                project_path=project,
                registry=registry,
                mounts_dir=tmp_path / "mounts",
            )

        assert (project / ".bashguard-token").read_text().strip() == "sess-abc"

    def test_registers_session(self, tmp_path: Path, registry_path: Path):
        project = tmp_path / "my-project"
        project.mkdir()
        registry = FileRegistry(registry_path)

        with patch("colony_hooks.subprocess.Popen") as mock_popen:
            mock_popen.return_value = MagicMock(pid=1234)
            session_start(
                session_id="sess-abc",
                project_path=project,
                registry=registry,
                mounts_dir=tmp_path / "mounts",
            )

        entry = registry.lookup("sess-abc")
        assert entry is not None
        assert entry["granted_root"] == f"/{project.name}"

    def test_starts_fuse_daemon(self, tmp_path: Path, registry_path: Path):
        project = tmp_path / "my-project"
        project.mkdir()
        registry = FileRegistry(registry_path)

        with patch("colony_hooks.subprocess.Popen") as mock_popen:
            mock_popen.return_value = MagicMock(pid=1234)
            session_start(
                session_id="sess-abc",
                project_path=project,
                registry=registry,
                mounts_dir=tmp_path / "mounts",
            )

        mock_popen.assert_called_once()
        args = mock_popen.call_args[0][0]
        assert any("token_auth_fs" in str(a) for a in args)


# ---------------------------------------------------------------------------
# session_end
# ---------------------------------------------------------------------------

class TestSessionEnd:
    def _start(self, project: Path, registry: FileRegistry, mounts_dir: Path):
        with patch("colony_hooks.subprocess.Popen") as mock_popen:
            mock_popen.return_value = MagicMock(pid=1234)
            session_start(
                session_id="sess-abc",
                project_path=project,
                registry=registry,
                mounts_dir=mounts_dir,
            )

    def test_removes_token_file(self, tmp_path: Path, registry_path: Path):
        project = tmp_path / "my-project"
        project.mkdir()
        registry = FileRegistry(registry_path)
        self._start(project, registry, tmp_path / "mounts")

        with patch("colony_hooks.subprocess.run"):
            session_end(session_id="sess-abc", registry=registry)

        assert not (project / ".bashguard-token").exists()

    def test_unregisters_session(self, tmp_path: Path, registry_path: Path):
        project = tmp_path / "my-project"
        project.mkdir()
        registry = FileRegistry(registry_path)
        self._start(project, registry, tmp_path / "mounts")

        with patch("colony_hooks.subprocess.run"):
            session_end(session_id="sess-abc", registry=registry)

        assert registry.lookup("sess-abc") is None

    def test_calls_unmount(self, tmp_path: Path, registry_path: Path):
        project = tmp_path / "my-project"
        project.mkdir()
        registry = FileRegistry(registry_path)
        self._start(project, registry, tmp_path / "mounts")
        entry = registry.lookup("sess-abc")
        mount_point = entry["mount_point"]

        with patch("colony_hooks.subprocess.run") as mock_run:
            session_end(session_id="sess-abc", registry=registry)

        assert any(mount_point in str(c) for c in mock_run.call_args_list)

    def test_unknown_session_is_noop(self, registry_path: Path):
        registry = FileRegistry(registry_path)
        # Should not raise — idempotent
        session_end(session_id="ghost", registry=registry)


# ---------------------------------------------------------------------------
# overlay_diff
# ---------------------------------------------------------------------------

class TestOverlayDiff:
    def test_empty_overlay_returns_empty(self, tmp_path: Path):
        from shadow_fs import ShadowFS
        real = tmp_path / "real"
        real.mkdir()
        (real / "file.txt").write_bytes(b"original\n")
        fs = ShadowFS(str(real))
        diff = overlay_diff(fs)
        assert diff == ""

    def test_write_shows_in_diff(self, tmp_path: Path):
        from shadow_fs import ShadowFS
        real = tmp_path / "real"
        real.mkdir()
        (real / "file.txt").write_bytes(b"original\n")
        fs = ShadowFS(str(real))
        fh = fs.open("/file.txt", os.O_WRONLY | os.O_TRUNC)
        fs.write("/file.txt", b"modified\n", 0, fh)
        diff = overlay_diff(fs)
        assert "file.txt" in diff
        assert "modified" in diff

    def test_new_file_shows_in_diff(self, tmp_path: Path):
        from shadow_fs import ShadowFS
        real = tmp_path / "real"
        real.mkdir()
        fs = ShadowFS(str(real))
        fs.create("/new.txt", 0o644)
        fs.write("/new.txt", b"new content\n", 0, fh=1)
        diff = overlay_diff(fs)
        assert "new.txt" in diff

    def test_delete_shows_in_diff(self, tmp_path: Path):
        from shadow_fs import ShadowFS
        real = tmp_path / "real"
        real.mkdir()
        (real / "gone.txt").write_bytes(b"will be deleted\n")
        fs = ShadowFS(str(real))
        fs.unlink("/gone.txt")
        diff = overlay_diff(fs)
        assert "gone.txt" in diff
        assert "DELETE" in diff or "delete" in diff.lower()
