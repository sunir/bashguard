"""
tests/test_shadow_fs.py — Unit tests for ShadowFS overlay logic.

Tests exercise the ShadowFS class directly without mounting (no FUSE daemon
required). We test the internal overlay state machine: read passthrough,
write-to-overlay, tombstone-on-delete, rename, readdir merge.

Story: As a bashguard agent sandbox, I need a shadow filesystem where
all reads pass through to the real directory but all writes, creates,
and deletes are captured in an in-memory overlay so the real directory
is never modified.
"""
from __future__ import annotations

import errno
import os
import stat
import tempfile
from pathlib import Path

import pytest

# ShadowFS is a spike — lives in spike/, not a package. Adjust path.
import sys
sys.path.insert(0, str(Path(__file__).parent.parent / "spike"))

from shadow_fs import ShadowFS  # noqa: E402
from fuse import FuseOSError  # noqa: E402


@pytest.fixture()
def real_dir(tmp_path: Path) -> Path:
    """A real directory with known content for the shadow FS to sit over."""
    (tmp_path / "existing.txt").write_bytes(b"original content\n")
    (tmp_path / "other.txt").write_bytes(b"other file\n")
    (tmp_path / "subdir").mkdir()
    (tmp_path / "subdir" / "nested.txt").write_bytes(b"nested\n")
    return tmp_path


@pytest.fixture()
def fs(real_dir: Path) -> ShadowFS:
    return ShadowFS(str(real_dir))


# ---------------------------------------------------------------------------
# read passthrough
# ---------------------------------------------------------------------------

class TestReadPassthrough:
    def test_reads_real_file_content(self, fs: ShadowFS, real_dir: Path):
        data = fs.read("/existing.txt", 1024, 0, fh=1)
        assert data == b"original content\n"

    def test_reads_with_offset(self, fs: ShadowFS):
        # "original content\n": o=0 r=1 i=2 g=3 i=4 n=5 a=6 l=7
        data = fs.read("/existing.txt", 4, 0, fh=1)
        assert data == b"orig"
        data = fs.read("/existing.txt", 4, 4, fh=1)
        assert data == b"inal"

    def test_missing_real_file_raises_enoent(self, fs: ShadowFS):
        with pytest.raises(FuseOSError) as exc:
            fs.read("/nonexistent.txt", 1024, 0, fh=1)
        assert exc.value.errno == errno.ENOENT

    def test_real_dir_never_modified_after_read(self, fs: ShadowFS, real_dir: Path):
        fs.read("/existing.txt", 1024, 0, fh=1)
        assert (real_dir / "existing.txt").read_bytes() == b"original content\n"


# ---------------------------------------------------------------------------
# write to overlay
# ---------------------------------------------------------------------------

class TestWriteOverlay:
    def test_write_existing_file_goes_to_overlay(self, fs: ShadowFS, real_dir: Path):
        fh = fs.open("/existing.txt", os.O_WRONLY | os.O_TRUNC)
        fs.write("/existing.txt", b"MODIFIED\n", 0, fh)
        assert fs.read("/existing.txt", 1024, 0, fh) == b"MODIFIED\n"
        # Real file untouched
        assert (real_dir / "existing.txt").read_bytes() == b"original content\n"

    def test_create_new_file_overlay_only(self, fs: ShadowFS, real_dir: Path):
        fs.create("/new.txt", 0o644)
        fs.write("/new.txt", b"brand new\n", 0, fh=1)
        assert fs.read("/new.txt", 1024, 0, fh=1) == b"brand new\n"
        assert not (real_dir / "new.txt").exists()

    def test_write_append_semantics(self, fs: ShadowFS):
        fs.create("/append.txt", 0o644)
        fs.write("/append.txt", b"hello", 0, fh=1)
        fs.write("/append.txt", b" world", 5, fh=1)
        assert fs.read("/append.txt", 1024, 0, fh=1) == b"hello world"

    def test_truncate_in_overlay(self, fs: ShadowFS, real_dir: Path):
        fh = fs.open("/existing.txt", os.O_RDWR)
        fs.write("/existing.txt", b"original content\n", 0, fh)
        fs.truncate("/existing.txt", 4)
        assert fs.read("/existing.txt", 1024, 0, fh) == b"orig"
        assert (real_dir / "existing.txt").read_bytes() == b"original content\n"

    def test_write_does_not_affect_other_files(self, fs: ShadowFS, real_dir: Path):
        fs.create("/new.txt", 0o644)
        fs.write("/new.txt", b"new content", 0, fh=1)
        assert fs.read("/other.txt", 1024, 0, fh=1) == b"other file\n"
        assert (real_dir / "other.txt").read_bytes() == b"other file\n"


# ---------------------------------------------------------------------------
# delete / tombstone
# ---------------------------------------------------------------------------

class TestDeleteTombstone:
    def test_unlink_real_file_creates_tombstone(self, fs: ShadowFS, real_dir: Path):
        fs.unlink("/existing.txt")
        assert fs._is_tombstoned("/existing.txt")
        # Real file still there
        assert (real_dir / "existing.txt").exists()

    def test_tombstoned_file_raises_enoent_on_read(self, fs: ShadowFS):
        fs.unlink("/existing.txt")
        with pytest.raises(FuseOSError) as exc:
            fs.read("/existing.txt", 1024, 0, fh=1)
        assert exc.value.errno == errno.ENOENT

    def test_tombstoned_file_raises_enoent_on_getattr(self, fs: ShadowFS):
        fs.unlink("/existing.txt")
        with pytest.raises(FuseOSError) as exc:
            fs.getattr("/existing.txt")
        assert exc.value.errno == errno.ENOENT

    def test_unlink_overlay_file_removes_from_overlay(self, fs: ShadowFS, real_dir: Path):
        fs.create("/newfile.txt", 0o644)
        fs.write("/newfile.txt", b"temp", 0, fh=1)
        fs.unlink("/newfile.txt")
        assert "/newfile.txt" not in fs._overlay
        # Nothing added to tombstones for a pure overlay file (real doesn't have it)
        assert not (real_dir / "newfile.txt").exists()

    def test_double_unlink_raises_enoent(self, fs: ShadowFS):
        fs.unlink("/existing.txt")
        with pytest.raises(FuseOSError) as exc:
            fs.unlink("/existing.txt")
        assert exc.value.errno == errno.ENOENT


# ---------------------------------------------------------------------------
# readdir merges real + overlay, hides tombstones
# ---------------------------------------------------------------------------

class TestReaddir:
    def _names(self, fs: ShadowFS, path: str) -> set[str]:
        return {e for e in fs.readdir(path, fh=0) if e not in (".", "..")}

    def test_initial_readdir_shows_real_files(self, fs: ShadowFS):
        names = self._names(fs, "/")
        assert "existing.txt" in names
        assert "other.txt" in names
        assert "subdir" in names

    def test_readdir_hides_tombstoned_files(self, fs: ShadowFS):
        fs.unlink("/existing.txt")
        names = self._names(fs, "/")
        assert "existing.txt" not in names
        assert "other.txt" in names

    def test_readdir_shows_overlay_only_files(self, fs: ShadowFS):
        fs.create("/overlay_only.txt", 0o644)
        names = self._names(fs, "/")
        assert "overlay_only.txt" in names

    def test_readdir_no_duplicates_when_overlay_shadows_real(self, fs: ShadowFS):
        fh = fs.open("/existing.txt", os.O_RDWR)
        fs.write("/existing.txt", b"changed", 0, fh)
        names = list(e for e in fs.readdir("/", fh=0) if e not in (".", ".."))
        assert names.count("existing.txt") == 1


# ---------------------------------------------------------------------------
# rename
# ---------------------------------------------------------------------------

class TestRename:
    def test_rename_overlay_file(self, fs: ShadowFS):
        fs.create("/a.txt", 0o644)
        fs.write("/a.txt", b"content", 0, fh=1)
        fs.rename("/a.txt", "/b.txt")
        assert fs.read("/b.txt", 1024, 0, fh=1) == b"content"
        assert "/a.txt" not in fs._overlay

    def test_rename_real_file_tombstones_original(self, fs: ShadowFS, real_dir: Path):
        fs.rename("/existing.txt", "/renamed.txt")
        assert fs._is_tombstoned("/existing.txt")
        assert fs.read("/renamed.txt", 1024, 0, fh=1) == b"original content\n"
        assert (real_dir / "existing.txt").exists()

    def test_rename_nonexistent_raises_enoent(self, fs: ShadowFS):
        with pytest.raises(FuseOSError) as exc:
            fs.rename("/ghost.txt", "/target.txt")
        assert exc.value.errno == errno.ENOENT


# ---------------------------------------------------------------------------
# getattr
# ---------------------------------------------------------------------------

class TestGetattr:
    def test_getattr_real_file(self, fs: ShadowFS):
        st = fs.getattr("/existing.txt")
        assert stat.S_ISREG(st["st_mode"])
        assert st["st_size"] == len(b"original content\n")

    def test_getattr_overlay_file(self, fs: ShadowFS):
        fs.create("/new.txt", 0o644)
        fs.write("/new.txt", b"hello", 0, fh=1)
        st = fs.getattr("/new.txt")
        assert stat.S_ISREG(st["st_mode"])
        assert st["st_size"] == 5

    def test_getattr_tombstoned_raises_enoent(self, fs: ShadowFS):
        fs.unlink("/existing.txt")
        with pytest.raises(FuseOSError) as exc:
            fs.getattr("/existing.txt")
        assert exc.value.errno == errno.ENOENT

    def test_getattr_overlay_dir(self, fs: ShadowFS):
        fs.mkdir("/newdir", 0o755)
        st = fs.getattr("/newdir")
        assert stat.S_ISDIR(st["st_mode"])
