"""
spike/colony_hooks.py — Colony SessionStart/End hook support for FUSE sandbox.

Called by the shell hooks in hooks/SessionStart.d/system/75-bashguard-mount
and hooks/SessionEnd.d/system/75-bashguard-unmount.

FileRegistry: file-based {session_id → {granted_root, mount_point, project_path}}
session_start(): writes token, registers, mounts FUSE daemon
session_end(): unmounts, removes token, unregisters
overlay_diff(): human-readable summary of overlay changes
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

_SPIKE_DIR = Path(__file__).parent
_TOKEN_AUTH_FS = _SPIKE_DIR / "token_auth_fs.py"
_DEFAULT_REGISTRY = Path.home() / ".bashguard" / "sessions.json"
_DEFAULT_MOUNTS = Path.home() / ".bashguard" / "mounts"


class FileRegistry:
    """File-backed {session_id → session_entry} registry."""

    def __init__(self, path: Path | None = None):
        self.path = path or _DEFAULT_REGISTRY
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def _read(self) -> dict:
        if not self.path.exists():
            return {}
        return json.loads(self.path.read_text())

    def _write(self, data: dict) -> None:
        self.path.write_text(json.dumps(data, indent=2))

    def register(self, session_id: str, granted_root: str, mount_point: str,
                 project_path: str = "", pid: int = 0) -> None:
        data = self._read()
        data[session_id] = {
            "granted_root": granted_root,
            "mount_point": mount_point,
            "project_path": project_path,
            "pid": pid,
        }
        self._write(data)

    def lookup(self, session_id: str) -> dict | None:
        return self._read().get(session_id)

    def unregister(self, session_id: str) -> None:
        data = self._read()
        data.pop(session_id, None)
        self._write(data)


def session_start(
    session_id: str,
    project_path: Path,
    registry: FileRegistry,
    mounts_dir: Path | None = None,
) -> str:
    """
    Start a FUSE sandbox session for project_path using session_id as the token.

    Returns the mount path where the agent's granted subtree is accessible.
    """
    project_path = project_path.resolve()
    mounts_dir = mounts_dir or _DEFAULT_MOUNTS
    mounts_dir = Path(mounts_dir)
    mounts_dir.mkdir(parents=True, exist_ok=True)

    real_root = str(project_path.parent)
    granted_root = f"/{project_path.name}"
    mount_point = str(mounts_dir / session_id)
    Path(mount_point).mkdir(parents=True, exist_ok=True)

    # Write token (= SESSION_ID) to project dir
    token_file = project_path / ".bashguard-token"
    token_file.write_text(f"{session_id}\n")

    # Start FUSE daemon
    registry_env = f"{session_id}:{granted_root}"
    env = {**os.environ, "BASHGUARD_TOKEN_REGISTRY": registry_env}
    proc = subprocess.Popen(
        [sys.executable, str(_TOKEN_AUTH_FS),
         real_root, mount_point, str(project_path)],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    registry.register(
        session_id,
        granted_root=granted_root,
        mount_point=mount_point,
        project_path=str(project_path),
        pid=proc.pid,
    )

    return str(Path(mount_point) / granted_root.lstrip("/"))


def session_end(session_id: str, registry: FileRegistry) -> None:
    """
    End a FUSE sandbox session: unmount, remove token file, unregister.
    Idempotent — safe to call even if session is already gone.
    """
    entry = registry.lookup(session_id)
    if entry is None:
        return  # Already cleaned up

    # Unmount
    subprocess.run(
        ["diskutil", "unmount", entry["mount_point"]],
        capture_output=True,
    )

    # Remove token file
    token_file = Path(entry["project_path"]) / ".bashguard-token"
    token_file.unlink(missing_ok=True)

    registry.unregister(session_id)


def overlay_diff(fs) -> str:
    """
    Return a human-readable diff summary of an ShadowFS overlay.

    Returns empty string if overlay is empty (no changes).
    """
    lines = []

    for path, content in sorted(fs._overlay.items()):
        real_path = Path(fs.real_root) / path.lstrip("/")
        if real_path.exists():
            original = real_path.read_bytes()
            if content != original:
                lines.append(f"MODIFY {path}")
                # Show first few differing lines
                orig_lines = original.decode(errors="replace").splitlines()
                new_lines = content.decode(errors="replace").splitlines()
                for i, (o, n) in enumerate(zip(orig_lines, new_lines)):
                    if o != n:
                        lines.append(f"  - {o}")
                        lines.append(f"  + {n}")
                if len(new_lines) > len(orig_lines):
                    for n in new_lines[len(orig_lines):]:
                        lines.append(f"  + {n}")
        else:
            lines.append(f"CREATE {path}")
            preview = content.decode(errors="replace")[:200]
            for l in preview.splitlines()[:5]:
                lines.append(f"  + {l}")

    for path in sorted(fs._tombstones):
        lines.append(f"DELETE {path}")

    return "\n".join(lines)
