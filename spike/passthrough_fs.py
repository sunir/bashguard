#!/usr/bin/env python3
"""
spike/passthrough_fs.py — macFUSE passthrough filesystem.

Mounts a real directory read-through at a FUSE mount point.
All ops delegate to the underlying real filesystem.

Usage:
    python3 spike/passthrough_fs.py <real_root> <mount_point>

Example:
    mkdir /tmp/fuse-passthrough
    python3 spike/passthrough_fs.py ~/source/bashguard /tmp/fuse-passthrough
    ls /tmp/fuse-passthrough   # should mirror ~/source/bashguard

Unmount:
    diskutil unmount /tmp/fuse-passthrough

Exit with Ctrl-C (foreground mode).
"""
from __future__ import annotations

import errno
import os
import sys

from fuse import FUSE, FuseOSError, Operations


class PassthroughFS(Operations):
    """Transparent passthrough: every call maps to the real filesystem."""

    def __init__(self, real_root: str):
        self.real_root = os.path.realpath(real_root)

    def _real(self, path: str) -> str:
        """Map FUSE path to real path under root."""
        return os.path.join(self.real_root, path.lstrip("/"))

    # --- helpers ---

    def _full_path(self, partial: str) -> str:
        return self._real(partial)

    # --- stat ---

    def getattr(self, path, fh=None):
        st = os.lstat(self._real(path))
        return {
            key: getattr(st, key)
            for key in (
                "st_atime", "st_ctime", "st_gid", "st_mode",
                "st_mtime", "st_nlink", "st_size", "st_uid",
            )
        }

    def readlink(self, path):
        return os.readlink(self._real(path))

    # --- directory ---

    def readdir(self, path, fh):
        yield "."
        yield ".."
        for name in os.listdir(self._real(path)):
            yield name

    def mkdir(self, path, mode):
        os.mkdir(self._real(path), mode)

    def rmdir(self, path):
        os.rmdir(self._real(path))

    # --- file lifecycle ---

    def open(self, path, flags):
        return os.open(self._real(path), flags)

    def create(self, path, mode, fi=None):
        return os.open(self._real(path), os.O_WRONLY | os.O_CREAT, mode)

    def release(self, path, fh):
        return os.close(fh)

    # --- I/O ---

    def read(self, path, length, offset, fh):
        os.lseek(fh, offset, os.SEEK_SET)
        return os.read(fh, length)

    def write(self, path, buf, offset, fh):
        os.lseek(fh, offset, os.SEEK_SET)
        return os.write(fh, buf)

    def truncate(self, path, length, fh=None):
        with open(self._real(path), "r+b") as f:
            f.truncate(length)

    def flush(self, path, fh):
        return os.fsync(fh)

    def fsync(self, path, fdatasync, fh):
        return self.flush(path, fh)

    # --- mutations ---

    def unlink(self, path):
        os.unlink(self._real(path))

    def rename(self, old, new):
        os.rename(self._real(old), self._real(new))

    def link(self, target, name):
        os.link(self._real(target), self._real(name))

    def symlink(self, name, target):
        os.symlink(target, self._real(name))

    def chmod(self, path, mode):
        os.chmod(self._real(path), mode)

    def chown(self, path, uid, gid):
        os.chown(self._real(path), uid, gid)

    def utimens(self, path, times=None):
        os.utime(self._real(path), times)

    # --- filesystem info ---

    def statfs(self, path):
        stv = os.statvfs(self._real(path))
        return {
            key: getattr(stv, key)
            for key in (
                "f_bavail", "f_bfree", "f_blocks", "f_bsize",
                "f_favail", "f_ffree", "f_files", "f_flag",
                "f_frsize", "f_namemax",
            )
        }


def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <real_root> <mount_point>", file=sys.stderr)
        sys.exit(1)

    real_root = sys.argv[1]
    mount_point = sys.argv[2]

    if not os.path.isdir(real_root):
        print(f"Error: real_root {real_root!r} is not a directory", file=sys.stderr)
        sys.exit(1)

    if not os.path.isdir(mount_point):
        print(f"Error: mount_point {mount_point!r} is not a directory", file=sys.stderr)
        sys.exit(1)

    real_root = os.path.expanduser(real_root)
    print(f"Mounting {real_root!r} → {mount_point!r} (foreground, Ctrl-C to stop)")
    FUSE(PassthroughFS(real_root), mount_point, nothreads=True, foreground=True)


if __name__ == "__main__":
    main()
