#!/usr/bin/env python3
"""
spike/shadow_fs.py — macFUSE/FUSE-T shadow filesystem with copy-on-write overlay.

Reads pass through to real FS. Writes go to in-memory overlay. Deletes are
tombstoned. The real directory is never modified.

This is the core containment primitive for the agent sandbox.

Usage:
    mkdir /tmp/fuse-shadow
    python3 spike/shadow_fs.py <real_root> <mount_point>

    # Everything you write goes to overlay — real_root is untouched.
    # Ctrl-C or unmount to discard all writes.

Unmount:
    diskutil unmount <mount_point>

Design:
    _overlay: dict[str, bytes]   — written file contents (keyed by FUSE path)
    _overlay_dirs: set[str]      — created directories (not in real FS)
    _tombstones: set[str]        — deleted paths (real FS has them, overlay hides them)

    read(path):
        if tombstoned → ENOENT
        if in overlay → return overlay bytes
        else → read from real FS

    write(path, buf):
        put in overlay (create if new)

    unlink(path):
        if in overlay → remove from overlay
        if in real FS → add to tombstones

    getattr(path):
        if tombstoned → ENOENT
        if in overlay → synthesize stat from overlay content
        else → real FS stat

    readdir(path):
        start with real FS entries (if path exists there)
        remove tombstoned names
        add overlay-only names
"""
from __future__ import annotations

import errno
import os
import stat
import sys
import time
from typing import Iterator

from fuse import FUSE, FuseOSError, Operations


class ShadowFS(Operations):
    """Shadow FS: reads pass through, writes go to overlay, real dir never touched."""

    def __init__(self, real_root: str):
        self.real_root = os.path.realpath(real_root)
        # overlay[fuse_path] = bytes content
        self._overlay: dict[str, bytes] = {}
        # overlay_dirs: dirs created only in overlay (not in real FS)
        self._overlay_dirs: set[str] = set()
        # tombstones: paths deleted from FUSE view (may exist in real FS)
        self._tombstones: set[str] = set()
        # open file handles: fh -> (path, writable)
        self._fh_counter = 0
        self._open_files: dict[int, tuple[str, bool]] = {}

    # --- path mapping ---

    def _real(self, path: str) -> str:
        return os.path.join(self.real_root, path.lstrip("/"))

    def _real_exists(self, path: str) -> bool:
        return os.path.exists(self._real(path))

    def _in_overlay(self, path: str) -> bool:
        return path in self._overlay or path in self._overlay_dirs

    def _is_tombstoned(self, path: str) -> bool:
        return path in self._tombstones

    # --- stat ---

    def getattr(self, path, fh=None):
        if self._is_tombstoned(path):
            raise FuseOSError(errno.ENOENT)

        if path in self._overlay:
            # Synthesize a file stat from overlay content
            now = time.time()
            return {
                "st_mode": stat.S_IFREG | 0o644,
                "st_nlink": 1,
                "st_size": len(self._overlay[path]),
                "st_uid": os.getuid(),
                "st_gid": os.getgid(),
                "st_atime": now,
                "st_mtime": now,
                "st_ctime": now,
            }

        if path in self._overlay_dirs:
            now = time.time()
            return {
                "st_mode": stat.S_IFDIR | 0o755,
                "st_nlink": 2,
                "st_size": 0,
                "st_uid": os.getuid(),
                "st_gid": os.getgid(),
                "st_atime": now,
                "st_mtime": now,
                "st_ctime": now,
            }

        try:
            st = os.lstat(self._real(path))
        except OSError:
            raise FuseOSError(errno.ENOENT)

        return {
            key: getattr(st, key)
            for key in (
                "st_atime", "st_ctime", "st_gid", "st_mode",
                "st_mtime", "st_nlink", "st_size", "st_uid",
            )
        }

    def readlink(self, path):
        if self._is_tombstoned(path) or path in self._overlay:
            raise FuseOSError(errno.EINVAL)
        return os.readlink(self._real(path))

    # --- directory ---

    def readdir(self, path, fh) -> Iterator[str]:
        yield "."
        yield ".."

        seen: set[str] = set()

        # Real FS entries (minus tombstones)
        real_path = self._real(path)
        if os.path.isdir(real_path):
            for name in os.listdir(real_path):
                child = os.path.join(path, name) if path != "/" else f"/{name}"
                if not self._is_tombstoned(child):
                    seen.add(name)
                    yield name

        # Overlay-only entries for this directory
        prefix = path.rstrip("/") + "/"
        for p in list(self._overlay) + list(self._overlay_dirs):
            if p.startswith(prefix):
                rest = p[len(prefix):]
                if "/" not in rest and rest and rest not in seen:
                    seen.add(rest)
                    yield rest

    def mkdir(self, path, mode):
        if self._is_tombstoned(path):
            self._tombstones.discard(path)
        self._overlay_dirs.add(path)

    def rmdir(self, path):
        # Check empty
        prefix = path.rstrip("/") + "/"
        for p in self._overlay:
            if p.startswith(prefix):
                raise FuseOSError(errno.ENOTEMPTY)
        if os.path.isdir(self._real(path)):
            for name in os.listdir(self._real(path)):
                child = prefix + name
                if not self._is_tombstoned(child):
                    raise FuseOSError(errno.ENOTEMPTY)
        self._overlay_dirs.discard(path)
        self._tombstones.add(path)

    # --- file lifecycle ---

    def _next_fh(self) -> int:
        self._fh_counter += 1
        return self._fh_counter

    def open(self, path, flags):
        if self._is_tombstoned(path):
            raise FuseOSError(errno.ENOENT)
        writable = bool(flags & (os.O_WRONLY | os.O_RDWR))
        # If opening for write and not in overlay yet, copy real content in
        if writable and path not in self._overlay:
            real = self._real(path)
            if os.path.isfile(real):
                with open(real, "rb") as f:
                    self._overlay[path] = f.read()
            else:
                self._overlay[path] = b""
        if flags & os.O_TRUNC and path in self._overlay:
            self._overlay[path] = b""
        fh = self._next_fh()
        self._open_files[fh] = (path, writable)
        return fh

    def create(self, path, mode, fi=None):
        self._tombstones.discard(path)
        self._overlay[path] = b""
        fh = self._next_fh()
        self._open_files[fh] = (path, True)
        return fh

    def release(self, path, fh):
        self._open_files.pop(fh, None)
        return 0

    # --- I/O ---

    def read(self, path, length, offset, fh):
        if self._is_tombstoned(path):
            raise FuseOSError(errno.ENOENT)

        if path in self._overlay:
            data = self._overlay[path]
            return data[offset: offset + length]

        # Pass through to real FS
        real = self._real(path)
        try:
            with open(real, "rb") as f:
                f.seek(offset)
                return f.read(length)
        except OSError as e:
            raise FuseOSError(e.errno)

    def write(self, path, buf, offset, fh):
        # Ensure path is in overlay (open() should have done this, but be safe)
        if path not in self._overlay:
            real = self._real(path)
            if os.path.isfile(real):
                with open(real, "rb") as f:
                    self._overlay[path] = f.read()
            else:
                self._overlay[path] = b""

        data = self._overlay[path]
        # Extend if needed
        if offset > len(data):
            data = data + b"\x00" * (offset - len(data))
        data = data[:offset] + buf + data[offset + len(buf):]
        self._overlay[path] = data
        return len(buf)

    def truncate(self, path, length, fh=None):
        if path not in self._overlay:
            real = self._real(path)
            if os.path.isfile(real):
                with open(real, "rb") as f:
                    self._overlay[path] = f.read()
            else:
                self._overlay[path] = b""
        self._overlay[path] = self._overlay[path][:length]

    def flush(self, path, fh):
        return 0  # Overlay is in-memory; nothing to flush

    def fsync(self, path, fdatasync, fh):
        return 0

    # --- mutations ---

    def unlink(self, path):
        if self._is_tombstoned(path):
            raise FuseOSError(errno.ENOENT)
        self._overlay.pop(path, None)
        if self._real_exists(path):
            self._tombstones.add(path)

    def rename(self, old, new):
        if self._is_tombstoned(old):
            raise FuseOSError(errno.ENOENT)

        # Get content: overlay first, then real
        if old in self._overlay:
            content = self._overlay.pop(old)
        elif self._real_exists(old):
            with open(self._real(old), "rb") as f:
                content = f.read()
            self._tombstones.add(old)
        else:
            raise FuseOSError(errno.ENOENT)

        self._tombstones.discard(new)
        self._overlay[new] = content

    def chmod(self, path, mode):
        return 0  # Overlay doesn't track permissions in this spike

    def chown(self, path, uid, gid):
        return 0

    def utimens(self, path, times=None):
        return 0

    # --- filesystem info ---

    def statfs(self, path):
        stv = os.statvfs(self.real_root)
        return {
            key: getattr(stv, key)
            for key in (
                "f_bavail", "f_bfree", "f_blocks", "f_bsize",
                "f_favail", "f_ffree", "f_files", "f_flag",
                "f_frsize", "f_namemax",
            )
        }

    # --- debug helper ---

    def overlay_summary(self) -> str:
        lines = [f"Overlay ({len(self._overlay)} files, {len(self._tombstones)} tombstones):"]
        for path, content in sorted(self._overlay.items()):
            lines.append(f"  WRITE  {path!r}  ({len(content)} bytes)")
        for path in sorted(self._tombstones):
            lines.append(f"  DELETE {path!r}")
        return "\n".join(lines)


def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <real_root> <mount_point>", file=sys.stderr)
        sys.exit(1)

    real_root = os.path.expanduser(sys.argv[1])
    mount_point = sys.argv[2]

    if not os.path.isdir(real_root):
        print(f"Error: {real_root!r} is not a directory", file=sys.stderr)
        sys.exit(1)
    if not os.path.isdir(mount_point):
        print(f"Error: {mount_point!r} is not a directory", file=sys.stderr)
        sys.exit(1)

    print(f"Shadow FS: {real_root!r} → {mount_point!r}")
    print("Writes go to overlay. Real dir untouched. Ctrl-C or unmount to discard.")
    FUSE(ShadowFS(real_root), mount_point, nothreads=True, foreground=True)


if __name__ == "__main__":
    main()
