"""
bashguard.context — ExecutionContext builder.

Provides make_context() for constructing a context from the current
environment. Callers can override any field.
"""

from __future__ import annotations
import os
import subprocess
from .models import ExecutionContext


def _git_worktree_root(cwd: str) -> str | None:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True, text=True, cwd=cwd, timeout=5
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except Exception:
        pass
    return None


def make_context(
    cwd: str | None = None,
    worktree_root: str | None = None,
    allowed_hosts: frozenset | None = None,
    allowed_paths: frozenset | None = None,
) -> ExecutionContext:
    """Build an ExecutionContext from the current environment."""
    resolved_cwd = cwd or os.getcwd()
    resolved_worktree = (
        worktree_root
        if worktree_root is not None
        else _git_worktree_root(resolved_cwd)
    )
    return ExecutionContext(
        cwd=resolved_cwd,
        worktree_root=resolved_worktree,
        allowed_hosts=allowed_hosts or frozenset(),
        allowed_paths=allowed_paths or frozenset(),
        env_vars={k: v for k, v in os.environ.items()
                  if k in ("HOME", "USER", "PATH", "SHELL")},
    )
