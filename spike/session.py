#!/usr/bin/env python3
"""
spike/session.py — bashguard session CLI (W5).

Wires token generation + .bashguard-token placement + FUSE daemon startup
into a single `bashguard-session start` command.

Usage:
    python3 spike/session.py start --project ~/source/my-repo
    python3 spike/session.py stop <session-id>
    python3 spike/session.py list

start:
    1. Generate UUID token
    2. Write .bashguard-token to project dir
    3. Derive real_root (project parent) and granted_root (/project-name)
    4. Create mount point at <mounts_dir>/<session-id>/
    5. Start token_auth_fs.py daemon in background
    6. Save session state to <sessions_dir>/<session-id>.json
    7. Print: session id + mount path

stop <id>:
    1. Load session state
    2. Unmount: diskutil unmount <mount_point> (macOS)
    3. Remove .bashguard-token from project dir
    4. Remove session state file

list:
    Print all active sessions.

Environment:
    BASHGUARD_SESSIONS_DIR  — override state dir (default ~/.bashguard/sessions)
    BASHGUARD_MOUNTS_DIR    — override mounts dir (default ~/.bashguard/mounts)
"""
from __future__ import annotations

import json
import os
import secrets
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

_SPIKE_DIR = Path(__file__).parent
_TOKEN_AUTH_FS = _SPIKE_DIR / "token_auth_fs.py"
_DEFAULT_SESSIONS_DIR = Path.home() / ".bashguard" / "sessions"
_DEFAULT_MOUNTS_DIR = Path.home() / ".bashguard" / "mounts"


@dataclass
class SessionState:
    session_id: str
    token: str
    project_path: str
    real_root: str
    granted_root: str
    mount_point: str
    pid: int

    def save(self, path: Path) -> None:
        path.write_text(json.dumps(asdict(self), indent=2))

    @classmethod
    def load(cls, path: Path) -> "SessionState":
        data = json.loads(path.read_text())
        return cls(**data)

    @property
    def work_dir(self) -> str:
        """The path inside the mount where the agent should cd."""
        return str(Path(self.mount_point) / self.granted_root.lstrip("/"))


class SessionManager:
    """Manages bashguard sandbox sessions."""

    def __init__(
        self,
        sessions_dir: Path | None = None,
        mounts_dir: Path | None = None,
    ):
        self.sessions_dir = sessions_dir or Path(
            os.environ.get("BASHGUARD_SESSIONS_DIR", str(_DEFAULT_SESSIONS_DIR))
        )
        self.mounts_dir = mounts_dir or Path(
            os.environ.get("BASHGUARD_MOUNTS_DIR", str(_DEFAULT_MOUNTS_DIR))
        )
        self.sessions_dir.mkdir(parents=True, exist_ok=True)
        self.mounts_dir.mkdir(parents=True, exist_ok=True)

    def start(self, project_path: Path) -> SessionState:
        """Start a sandbox session for project_path."""
        project_path = project_path.resolve()
        session_id = secrets.token_hex(8)
        token = f"bashguard-{secrets.token_urlsafe(16)}"

        # Derive real_root and granted_root
        real_root = str(project_path.parent)
        granted_root = f"/{project_path.name}"

        # Create mount point
        mount_point = self.mounts_dir / session_id
        mount_point.mkdir(parents=True, exist_ok=True)

        # Write token to project dir
        token_file = project_path / ".bashguard-token"
        token_file.write_text(f"{token}\n")

        # Build registry env var: "token:granted_root"
        registry_env = f"{token}:{granted_root}"

        # Start FUSE daemon
        env = {
            **os.environ,
            "BASHGUARD_TOKEN_REGISTRY": registry_env,
        }
        proc = subprocess.Popen(
            [sys.executable, str(_TOKEN_AUTH_FS),
             real_root, str(mount_point), str(project_path)],
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        state = SessionState(
            session_id=session_id,
            token=token,
            project_path=str(project_path),
            real_root=real_root,
            granted_root=granted_root,
            mount_point=str(mount_point),
            pid=proc.pid,
        )
        state.save(self.sessions_dir / f"{session_id}.json")
        return state

    def stop(self, session_id: str) -> None:
        """Stop a session: unmount, clean up token file and state."""
        state_file = self.sessions_dir / f"{session_id}.json"
        if not state_file.exists():
            raise KeyError(f"no session with id {session_id!r}")

        state = SessionState.load(state_file)

        # Unmount
        subprocess.run(
            ["diskutil", "unmount", state.mount_point],
            capture_output=True,
        )

        # Remove token file
        token_file = Path(state.project_path) / ".bashguard-token"
        token_file.unlink(missing_ok=True)

        # Remove state
        state_file.unlink()

    def list_sessions(self) -> list[SessionState]:
        """Return all active sessions."""
        sessions = []
        for f in self.sessions_dir.glob("*.json"):
            try:
                sessions.append(SessionState.load(f))
            except Exception:
                pass
        return sessions


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main():
    import argparse

    parser = argparse.ArgumentParser(
        prog="bashguard-session",
        description="Manage bashguard sandbox sessions",
    )
    sub = parser.add_subparsers(dest="cmd")

    p_start = sub.add_parser("start", help="Start a sandbox session")
    p_start.add_argument("--project", required=True, help="Project directory to sandbox")

    p_stop = sub.add_parser("stop", help="Stop a session")
    p_stop.add_argument("session_id", help="Session ID to stop")

    sub.add_parser("list", help="List active sessions")

    args = parser.parse_args()
    manager = SessionManager()

    if args.cmd == "start":
        project = Path(args.project).expanduser().resolve()
        if not project.is_dir():
            print(f"Error: {project!r} is not a directory", file=sys.stderr)
            sys.exit(1)
        state = manager.start(project)
        print(f"Session started: {state.session_id}")
        print(f"Work dir: {state.work_dir}")
        print(f"  cd {state.work_dir}")

    elif args.cmd == "stop":
        try:
            manager.stop(args.session_id)
            print(f"Session {args.session_id} stopped.")
        except KeyError as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)

    elif args.cmd == "list":
        sessions = manager.list_sessions()
        if not sessions:
            print("No active sessions.")
        for s in sessions:
            print(f"  {s.session_id}  {s.project_path}  →  {s.work_dir}")

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
