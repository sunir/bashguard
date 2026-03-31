#!/usr/bin/env python3
"""
spike/acl_shadow_fs.py — Shadow FS with subtree ACL enforcement (W3).

Extends ShadowFS with a granted_root: all paths outside the granted subtree
are blocked with EPERM. The agent can only read/write/delete within its
granted directory tree.

Usage:
    mkdir /tmp/fuse-acl
    python3 spike/acl_shadow_fs.py <real_root> <mount_point> <granted_root>

    # granted_root is relative to mount_point, e.g. /my-project
    # Access to /other-project, /etc, etc. → EPERM

Example:
    python3 spike/acl_shadow_fs.py ~/source /tmp/fuse-acl /bashguard
    # Agent can only touch /tmp/fuse-acl/bashguard/ and below

Design:
    _granted_root: str  — normalized FUSE path prefix (e.g. "/bashguard")

    _check_access(path):
        Normalize path (resolve ..) then check it starts with granted_root.
        Raise FuseOSError(EPERM) if outside.

    All Operations methods call _check_access before doing anything.
    Inherits all overlay/tombstone logic from ShadowFS.
"""
from __future__ import annotations

import errno
import os
import posixpath
import sys

from fuse import FUSE, FuseOSError

from shadow_fs import ShadowFS


class ACLShadowFS(ShadowFS):
    """Shadow FS with subtree ACL: paths outside granted_root → EPERM."""

    def __init__(self, real_root: str, granted_root: str):
        super().__init__(real_root)
        # Normalize: ensure leading slash, no trailing slash
        self._granted_root = "/" + granted_root.strip("/")

    def _check_access(self, path: str) -> None:
        """Raise EPERM if path is outside the granted subtree."""
        # Normalize away any .. traversal
        normalized = posixpath.normpath("/" + path.lstrip("/"))
        # Allow exact match (the granted root dir itself) or subtree
        if normalized != self._granted_root and not normalized.startswith(
            self._granted_root.rstrip("/") + "/"
        ):
            raise FuseOSError(errno.EPERM)

    # --- stat ---

    def getattr(self, path, fh=None):
        self._check_access(path)
        return super().getattr(path, fh)

    def readlink(self, path):
        self._check_access(path)
        return super().readlink(path)

    # --- directory ---

    def readdir(self, path, fh):
        self._check_access(path)
        return super().readdir(path, fh)

    def mkdir(self, path, mode):
        self._check_access(path)
        return super().mkdir(path, mode)

    def rmdir(self, path):
        self._check_access(path)
        return super().rmdir(path)

    # --- file lifecycle ---

    def open(self, path, flags):
        # Block writes outside grant; allow reads only inside grant
        self._check_access(path)
        return super().open(path, flags)

    def create(self, path, mode, fi=None):
        self._check_access(path)
        return super().create(path, mode, fi)

    # --- I/O ---

    def read(self, path, length, offset, fh):
        self._check_access(path)
        return super().read(path, length, offset, fh)

    def write(self, path, buf, offset, fh):
        self._check_access(path)
        return super().write(path, buf, offset, fh)

    def truncate(self, path, length, fh=None):
        self._check_access(path)
        return super().truncate(path, length, fh)

    # --- mutations ---

    def unlink(self, path):
        self._check_access(path)
        return super().unlink(path)

    def rename(self, old, new):
        self._check_access(old)
        self._check_access(new)
        return super().rename(old, new)

    def chmod(self, path, mode):
        self._check_access(path)
        return super().chmod(path, mode)

    def chown(self, path, uid, gid):
        self._check_access(path)
        return super().chown(path, uid, gid)

    def symlink(self, name, target):
        self._check_access(name)
        return super().symlink(name, target)

    def link(self, target, name):
        self._check_access(target)
        self._check_access(name)
        return super().link(target, name)


def main():
    if len(sys.argv) < 4:
        print(
            f"Usage: {sys.argv[0]} <real_root> <mount_point> <granted_root>",
            file=sys.stderr,
        )
        sys.exit(1)

    real_root = os.path.expanduser(sys.argv[1])
    mount_point = sys.argv[2]
    granted_root = sys.argv[3]

    if not os.path.isdir(real_root):
        print(f"Error: {real_root!r} is not a directory", file=sys.stderr)
        sys.exit(1)
    if not os.path.isdir(mount_point):
        print(f"Error: {mount_point!r} is not a directory", file=sys.stderr)
        sys.exit(1)

    print(f"ACL Shadow FS: {real_root!r} → {mount_point!r}")
    print(f"Granted subtree: {granted_root!r}")
    print("Access outside grant → EPERM. Ctrl-C or unmount to stop.")
    FUSE(ACLShadowFS(real_root, granted_root), mount_point, nothreads=True, foreground=True)


if __name__ == "__main__":
    main()
