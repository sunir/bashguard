"""
tests/test_shadow_fs_integration.py — Integration tests for ShadowFS over a
real project directory (S3 waypoint).

These tests mount the shadow FS over a real git repo copy and verify that
dev workflows (git status, pytest, file edits) work correctly through FUSE,
and that the real directory remains untouched after all writes.

Story: As a bashguard agent sandbox, I need to mount the shadow FS over a
developer's actual project directory so Claude's tools route through FUSE.
After the session, the real project is unchanged — only the overlay captured
the writes.

Prerequisites: FUSE-T installed (brew install --cask fuse-t).
Skip if FUSE not available (CI environments).
"""
from __future__ import annotations

import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest

FUSE_AVAILABLE = Path("/usr/local/lib/libfuse.dylib").exists()
pytestmark = pytest.mark.skipif(
    not FUSE_AVAILABLE, reason="FUSE-T not installed (libfuse.dylib missing)"
)

SHADOW_FS = Path(__file__).parent.parent / "spike" / "shadow_fs.py"
PYTHON = sys.executable


@pytest.fixture(scope="module")
def real_project(tmp_path_factory) -> Path:
    """A small fake 'project' directory with files, a git repo, and a test."""
    d = tmp_path_factory.mktemp("real_project")
    (d / "README.md").write_text("# Test Project\n")
    (d / "main.py").write_text("def add(a, b): return a + b\n")
    (d / "test_main.py").write_text(
        "from main import add\ndef test_add(): assert add(1, 2) == 3\n"
    )
    subprocess.run(["git", "init"], cwd=d, check=True, capture_output=True)
    subprocess.run(["git", "add", "."], cwd=d, check=True, capture_output=True)
    subprocess.run(
        ["git", "commit", "-m", "initial"],
        cwd=d, check=True, capture_output=True,
        env={**os.environ, "GIT_AUTHOR_NAME": "test", "GIT_AUTHOR_EMAIL": "t@t.com",
             "GIT_COMMITTER_NAME": "test", "GIT_COMMITTER_EMAIL": "t@t.com"},
    )
    return d


@pytest.fixture()
def mounted(real_project: Path, tmp_path: Path):
    """Mount shadow FS over real_project at a temp mount point. Yield mount path."""
    mount = tmp_path / "mount"
    mount.mkdir()

    proc = subprocess.Popen(
        [PYTHON, str(SHADOW_FS), str(real_project), str(mount)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    # Wait for mount to be ready
    deadline = time.time() + 5
    while time.time() < deadline:
        if list(mount.iterdir()):  # mount has content = ready
            break
        time.sleep(0.1)
    else:
        proc.terminate()
        pytest.fail("Shadow FS did not mount within 5 seconds")

    yield mount

    # Teardown: unmount
    subprocess.run(["diskutil", "unmount", str(mount)], capture_output=True)
    proc.wait(timeout=3)


# ---------------------------------------------------------------------------
# S3: real dev workflow tests
# ---------------------------------------------------------------------------

class TestS3DevWorkflow:

    def test_ls_through_fuse_shows_project_files(self, mounted: Path, real_project: Path):
        fuse_names = {p.name for p in mounted.iterdir()}
        real_names = {p.name for p in real_project.iterdir() if p.name != ".git"}
        assert "README.md" in fuse_names
        assert "main.py" in fuse_names
        assert "test_main.py" in fuse_names

    def test_read_file_through_fuse(self, mounted: Path):
        content = (mounted / "README.md").read_text()
        assert "Test Project" in content

    def test_write_through_fuse_does_not_touch_real_dir(
        self, mounted: Path, real_project: Path
    ):
        original = (real_project / "main.py").read_text()
        (mounted / "main.py").write_text("def add(a, b): return a + b + 1\n")
        assert (mounted / "main.py").read_text() == "def add(a, b): return a + b + 1\n"
        assert (real_project / "main.py").read_text() == original

    def test_create_new_file_through_fuse_not_in_real(
        self, mounted: Path, real_project: Path
    ):
        (mounted / "new_module.py").write_text("x = 42\n")
        assert (mounted / "new_module.py").read_text() == "x = 42\n"
        assert not (real_project / "new_module.py").exists()

    def test_delete_through_fuse_does_not_delete_real(
        self, mounted: Path, real_project: Path
    ):
        (mounted / "README.md").unlink()
        assert not (mounted / "README.md").exists()
        assert (real_project / "README.md").exists()

    def test_git_status_works_through_fuse(self, mounted: Path):
        result = subprocess.run(
            ["git", "status"],
            cwd=mounted,
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        assert "nothing to commit" in result.stdout or "working tree clean" in result.stdout

    def test_git_does_not_see_fuse_writes_as_committed(
        self, mounted: Path, real_project: Path
    ):
        (mounted / "main.py").write_text("# modified\n")
        result = subprocess.run(
            ["git", "status"],
            cwd=mounted,
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        # git sees the modification (overlay visible)
        assert "main.py" in result.stdout or "modified" in result.stdout

    def test_real_project_untouched_after_all_writes(
        self, mounted: Path, real_project: Path
    ):
        """After a session of writes/deletes, the real project is bit-for-bit unchanged."""
        # Do a bunch of writes
        (mounted / "main.py").write_text("# clobbered\n")
        (mounted / "new1.py").write_text("pass\n")
        (mounted / "new2.py").write_text("pass\n")
        (mounted / "README.md").unlink()

        # Real project must be pristine
        assert (real_project / "README.md").exists()
        assert (real_project / "main.py").read_text() == "def add(a, b): return a + b\n"
        assert not (real_project / "new1.py").exists()
        assert not (real_project / "new2.py").exists()
