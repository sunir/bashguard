"""
tests/test_acl_shadow_fs.py — Unit tests for ACLShadowFS subtree enforcement (W3).

The ACL layer sits on top of the shadow FS. When an agent is granted access
to `/project/my-repo`, it can read/write/delete anything inside that tree.
Access to paths outside the granted tree is blocked with EPERM.

Story: As a bashguard agent sandbox, I need each agent to be locked to its
granted directory subtree. An agent working in /project/alice cannot read or
write /project/bob, /etc, ~/.ssh, or any other path outside its grant.
Reads outside the grant: EPERM. Writes outside the grant: EPERM.
"""
from __future__ import annotations

import errno
import os
import stat
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "spike"))

from acl_shadow_fs import ACLShadowFS  # noqa: E402
from fuse import FuseOSError  # noqa: E402


@pytest.fixture()
def real_dir(tmp_path: Path) -> Path:
    (tmp_path / "allowed").mkdir()
    (tmp_path / "allowed" / "file.txt").write_bytes(b"inside grant\n")
    (tmp_path / "outside").mkdir()
    (tmp_path / "outside" / "secret.txt").write_bytes(b"outside grant\n")
    (tmp_path / "root.txt").write_bytes(b"at root\n")
    return tmp_path


@pytest.fixture()
def fs(real_dir: Path) -> ACLShadowFS:
    """Agent granted access to /allowed only."""
    return ACLShadowFS(str(real_dir), granted_root="/allowed")


# ---------------------------------------------------------------------------
# Inside-grant: all operations allowed
# ---------------------------------------------------------------------------

class TestInsideGrant:
    def test_read_inside_grant(self, fs: ACLShadowFS):
        data = fs.read("/allowed/file.txt", 1024, 0, fh=1)
        assert data == b"inside grant\n"

    def test_write_inside_grant(self, fs: ACLShadowFS, real_dir: Path):
        fh = fs.open("/allowed/file.txt", os.O_WRONLY | os.O_TRUNC)
        fs.write("/allowed/file.txt", b"modified\n", 0, fh)
        assert fs.read("/allowed/file.txt", 1024, 0, fh) == b"modified\n"
        # Real file untouched
        assert (real_dir / "allowed" / "file.txt").read_bytes() == b"inside grant\n"

    def test_create_inside_grant(self, fs: ACLShadowFS, real_dir: Path):
        fs.create("/allowed/new.txt", 0o644)
        fs.write("/allowed/new.txt", b"new\n", 0, fh=1)
        assert fs.read("/allowed/new.txt", 1024, 0, fh=1) == b"new\n"
        assert not (real_dir / "allowed" / "new.txt").exists()

    def test_delete_inside_grant(self, fs: ACLShadowFS, real_dir: Path):
        fs.unlink("/allowed/file.txt")
        assert fs._is_tombstoned("/allowed/file.txt")
        assert (real_dir / "allowed" / "file.txt").exists()

    def test_readdir_inside_grant(self, fs: ACLShadowFS):
        names = {e for e in fs.readdir("/allowed", fh=0) if e not in (".", "..")}
        assert "file.txt" in names

    def test_getattr_inside_grant(self, fs: ACLShadowFS):
        st = fs.getattr("/allowed/file.txt")
        assert stat.S_ISREG(st["st_mode"])


# ---------------------------------------------------------------------------
# Outside-grant: all operations blocked with EPERM
# ---------------------------------------------------------------------------

class TestOutsideGrant:
    def test_read_outside_grant_blocked(self, fs: ACLShadowFS):
        with pytest.raises(FuseOSError) as exc:
            fs.read("/outside/secret.txt", 1024, 0, fh=1)
        assert exc.value.errno == errno.EPERM

    def test_write_outside_grant_blocked(self, fs: ACLShadowFS):
        with pytest.raises(FuseOSError) as exc:
            fs.open("/outside/secret.txt", os.O_WRONLY | os.O_TRUNC)
        assert exc.value.errno == errno.EPERM

    def test_create_outside_grant_blocked(self, fs: ACLShadowFS):
        with pytest.raises(FuseOSError) as exc:
            fs.create("/outside/new.txt", 0o644)
        assert exc.value.errno == errno.EPERM

    def test_delete_outside_grant_blocked(self, fs: ACLShadowFS):
        with pytest.raises(FuseOSError) as exc:
            fs.unlink("/outside/secret.txt")
        assert exc.value.errno == errno.EPERM

    def test_getattr_outside_grant_blocked(self, fs: ACLShadowFS):
        with pytest.raises(FuseOSError) as exc:
            fs.getattr("/outside/secret.txt")
        assert exc.value.errno == errno.EPERM

    def test_readdir_outside_grant_blocked(self, fs: ACLShadowFS):
        with pytest.raises(FuseOSError) as exc:
            list(fs.readdir("/outside", fh=0))
        assert exc.value.errno == errno.EPERM

    def test_root_file_outside_grant_blocked(self, fs: ACLShadowFS):
        with pytest.raises(FuseOSError) as exc:
            fs.read("/root.txt", 1024, 0, fh=1)
        assert exc.value.errno == errno.EPERM

    def test_root_dir_readdir_blocked(self, fs: ACLShadowFS):
        """Agent cannot enumerate the root to discover other agents' dirs."""
        with pytest.raises(FuseOSError) as exc:
            list(fs.readdir("/", fh=0))
        assert exc.value.errno == errno.EPERM

    def test_path_traversal_blocked(self, fs: ACLShadowFS):
        """Path like /allowed/../outside must not escape the grant."""
        with pytest.raises(FuseOSError) as exc:
            fs.read("/allowed/../outside/secret.txt", 1024, 0, fh=1)
        assert exc.value.errno == errno.EPERM


# ---------------------------------------------------------------------------
# Grant root itself is accessible
# ---------------------------------------------------------------------------

class TestGrantRoot:
    def test_getattr_grant_root(self, fs: ACLShadowFS):
        st = fs.getattr("/allowed")
        assert stat.S_ISDIR(st["st_mode"])

    def test_readdir_grant_root(self, fs: ACLShadowFS):
        names = {e for e in fs.readdir("/allowed", fh=0) if e not in (".", "..")}
        assert "file.txt" in names
