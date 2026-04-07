"""
tests/test_session.py — Unit tests for bashguard session CLI (W5).

The session CLI wires together token generation, .bashguard-token placement,
FUSE daemon startup, and state persistence. Tests mock the FUSE daemon
subprocess to avoid requiring a live mount.

Story: As a bashguard user, I run `bashguard-session start --project ~/source/my-repo`
and get a mounted sandbox path. The real project is untouched. When I'm done,
`bashguard-session stop` unmounts and discards all writes.

Session start contract:
- Generates a unique token
- Writes .bashguard-token to the project dir
- Records session state to ~/.bashguard/sessions/<id>.json
- Starts FUSE daemon (token_auth_fs.py) in background
- Returns the mount path where the agent should work

Session stop contract:
- Reads session state
- Unmounts FUSE mount (diskutil unmount / umount)
- Removes .bashguard-token from project dir
- Removes session state file
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "spike"))

from session import SessionManager, SessionState  # noqa: E402


@pytest.fixture()
def project_dir(tmp_path: Path) -> Path:
    d = tmp_path / "my-project"
    d.mkdir()
    (d / "main.py").write_text("x = 1\n")
    return d


@pytest.fixture()
def sessions_dir(tmp_path: Path) -> Path:
    d = tmp_path / "sessions"
    d.mkdir()
    return d


@pytest.fixture()
def manager(sessions_dir: Path, tmp_path: Path) -> SessionManager:
    return SessionManager(
        sessions_dir=sessions_dir,
        mounts_dir=tmp_path / "mounts",
    )


# ---------------------------------------------------------------------------
# Session state
# ---------------------------------------------------------------------------

class TestSessionState:
    def test_serialises_to_json(self, tmp_path: Path):
        state = SessionState(
            session_id="abc-123",
            token="tok-xyz",
            project_path=str(tmp_path / "proj"),
            real_root=str(tmp_path),
            granted_root="/proj",
            mount_point=str(tmp_path / "mnt"),
            pid=9999,
        )
        path = tmp_path / "state.json"
        state.save(path)
        data = json.loads(path.read_text())
        assert data["session_id"] == "abc-123"
        assert data["token"] == "tok-xyz"
        assert data["pid"] == 9999

    def test_roundtrip_load(self, tmp_path: Path):
        state = SessionState(
            session_id="abc-123",
            token="tok-xyz",
            project_path=str(tmp_path / "proj"),
            real_root=str(tmp_path),
            granted_root="/proj",
            mount_point=str(tmp_path / "mnt"),
            pid=9999,
        )
        path = tmp_path / "state.json"
        state.save(path)
        loaded = SessionState.load(path)
        assert loaded.session_id == state.session_id
        assert loaded.token == state.token
        assert loaded.granted_root == state.granted_root
        assert loaded.pid == state.pid


# ---------------------------------------------------------------------------
# Session start
# ---------------------------------------------------------------------------

class TestSessionStart:
    def test_start_writes_token_file(self, manager: SessionManager, project_dir: Path):
        with patch("session.subprocess.Popen") as mock_popen:
            mock_popen.return_value = MagicMock(pid=1234)
            session = manager.start(project_dir)

        token_file = project_dir / ".bashguard-token"
        assert token_file.exists()
        token = token_file.read_text().strip()
        assert len(token) > 8  # non-trivial token

    def test_start_saves_state(self, manager: SessionManager, project_dir: Path):
        with patch("session.subprocess.Popen") as mock_popen:
            mock_popen.return_value = MagicMock(pid=1234)
            session = manager.start(project_dir)

        state_file = manager.sessions_dir / f"{session.session_id}.json"
        assert state_file.exists()
        data = json.loads(state_file.read_text())
        assert data["project_path"] == str(project_dir)
        assert data["pid"] == 1234

    def test_start_creates_mount_dir(self, manager: SessionManager, project_dir: Path):
        with patch("session.subprocess.Popen") as mock_popen:
            mock_popen.return_value = MagicMock(pid=1234)
            session = manager.start(project_dir)

        assert Path(session.mount_point).exists()

    def test_start_real_root_is_parent(self, manager: SessionManager, project_dir: Path):
        with patch("session.subprocess.Popen") as mock_popen:
            mock_popen.return_value = MagicMock(pid=1234)
            session = manager.start(project_dir)

        assert session.real_root == str(project_dir.parent)
        assert session.granted_root == f"/{project_dir.name}"

    def test_start_launches_fuse_daemon(self, manager: SessionManager, project_dir: Path):
        with patch("session.subprocess.Popen") as mock_popen:
            mock_popen.return_value = MagicMock(pid=1234)
            manager.start(project_dir)

        mock_popen.assert_called_once()
        args = mock_popen.call_args[0][0]
        # Should invoke token_auth_fs.py
        assert any("token_auth_fs" in str(a) for a in args)

    def test_each_start_generates_unique_token(
        self, manager: SessionManager, project_dir: Path, tmp_path: Path
    ):
        project2 = tmp_path / "other-project"
        project2.mkdir()

        with patch("session.subprocess.Popen") as mock_popen:
            mock_popen.return_value = MagicMock(pid=1234)
            s1 = manager.start(project_dir)
            s2 = manager.start(project2)

        assert s1.token != s2.token
        assert s1.session_id != s2.session_id


# ---------------------------------------------------------------------------
# Session stop
# ---------------------------------------------------------------------------

class TestSessionStop:
    def test_stop_removes_token_file(self, manager: SessionManager, project_dir: Path):
        with patch("session.subprocess.Popen") as mock_popen:
            mock_popen.return_value = MagicMock(pid=1234)
            session = manager.start(project_dir)

        with patch("session.subprocess.run"):
            manager.stop(session.session_id)

        assert not (project_dir / ".bashguard-token").exists()

    def test_stop_removes_state_file(self, manager: SessionManager, project_dir: Path):
        with patch("session.subprocess.Popen") as mock_popen:
            mock_popen.return_value = MagicMock(pid=1234)
            session = manager.start(project_dir)

        with patch("session.subprocess.run"):
            manager.stop(session.session_id)

        state_file = manager.sessions_dir / f"{session.session_id}.json"
        assert not state_file.exists()

    def test_stop_calls_unmount(self, manager: SessionManager, project_dir: Path):
        with patch("session.subprocess.Popen") as mock_popen:
            mock_popen.return_value = MagicMock(pid=1234)
            session = manager.start(project_dir)

        with patch("session.subprocess.run") as mock_run:
            manager.stop(session.session_id)

        mock_run.assert_called_once()
        args = mock_run.call_args[0][0]
        assert session.mount_point in args

    def test_stop_unknown_session_raises(self, manager: SessionManager):
        with pytest.raises(KeyError, match="no session"):
            manager.stop("nonexistent-id")


# ---------------------------------------------------------------------------
# Session list
# ---------------------------------------------------------------------------

class TestSessionList:
    def test_list_empty(self, manager: SessionManager):
        assert manager.list_sessions() == []

    def test_list_shows_active_sessions(self, manager: SessionManager, project_dir: Path):
        with patch("session.subprocess.Popen") as mock_popen:
            mock_popen.return_value = MagicMock(pid=1234)
            session = manager.start(project_dir)

        sessions = manager.list_sessions()
        assert len(sessions) == 1
        assert sessions[0].session_id == session.session_id

    def test_list_excludes_stopped_sessions(
        self, manager: SessionManager, project_dir: Path
    ):
        with patch("session.subprocess.Popen") as mock_popen:
            mock_popen.return_value = MagicMock(pid=1234)
            session = manager.start(project_dir)

        with patch("session.subprocess.run"):
            manager.stop(session.session_id)

        assert manager.list_sessions() == []


# ---------------------------------------------------------------------------
# Fork (checkpoint before risky operation)
# ---------------------------------------------------------------------------

class TestSessionFork:
    def test_fork_records_checkpoint(self, manager: SessionManager, project_dir: Path):
        with patch("session.subprocess.Popen") as mock_popen:
            mock_popen.return_value = MagicMock(pid=1234)
            session = manager.start(project_dir)

        manager.fork(session.session_id, label="before big refactor")

        reloaded = manager.get(session.session_id)
        assert len(reloaded.checkpoints) == 1
        assert reloaded.checkpoints[0]["label"] == "before big refactor"
        assert "time" in reloaded.checkpoints[0]

    def test_fork_without_label(self, manager: SessionManager, project_dir: Path):
        with patch("session.subprocess.Popen") as mock_popen:
            mock_popen.return_value = MagicMock(pid=1234)
            session = manager.start(project_dir)

        manager.fork(session.session_id)

        reloaded = manager.get(session.session_id)
        assert len(reloaded.checkpoints) == 1
        assert reloaded.checkpoints[0]["label"] == "checkpoint-1"

    def test_fork_multiple_checkpoints(self, manager: SessionManager, project_dir: Path):
        with patch("session.subprocess.Popen") as mock_popen:
            mock_popen.return_value = MagicMock(pid=1234)
            session = manager.start(project_dir)

        manager.fork(session.session_id, label="step-1")
        manager.fork(session.session_id, label="step-2")

        reloaded = manager.get(session.session_id)
        assert len(reloaded.checkpoints) == 2
        assert reloaded.checkpoints[1]["label"] == "step-2"

    def test_fork_unknown_session_raises(self, manager: SessionManager):
        with pytest.raises(KeyError):
            manager.fork("nonexistent")


# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------

class TestSessionStatus:
    def test_status_returns_dict(self, manager: SessionManager, project_dir: Path):
        with patch("session.subprocess.Popen") as mock_popen:
            mock_popen.return_value = MagicMock(pid=1234)
            session = manager.start(project_dir)

        status = manager.status(session.session_id)
        assert status["session_id"] == session.session_id
        assert status["project_path"] == str(project_dir)
        assert status["state"] == "active"
        assert "checkpoints" in status

    def test_status_with_checkpoints(self, manager: SessionManager, project_dir: Path):
        with patch("session.subprocess.Popen") as mock_popen:
            mock_popen.return_value = MagicMock(pid=1234)
            session = manager.start(project_dir)

        manager.fork(session.session_id, label="before-migration")
        status = manager.status(session.session_id)
        assert len(status["checkpoints"]) == 1

    def test_status_unknown_session_raises(self, manager: SessionManager):
        with pytest.raises(KeyError):
            manager.status("nonexistent")


# ---------------------------------------------------------------------------
# Sync (overlay diff)
# ---------------------------------------------------------------------------

class TestSessionSync:
    def test_sync_returns_diff_path(self, manager: SessionManager, project_dir: Path):
        with patch("session.subprocess.Popen") as mock_popen:
            mock_popen.return_value = MagicMock(pid=1234)
            session = manager.start(project_dir)

        result = manager.sync_plan(session.session_id)
        assert result["session_id"] == session.session_id
        assert result["real_root"] == str(project_dir)
        assert result["mount_point"] == session.mount_point

    def test_sync_unknown_session_raises(self, manager: SessionManager):
        with pytest.raises(KeyError):
            manager.sync_plan("nonexistent")
