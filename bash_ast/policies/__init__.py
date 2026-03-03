"""
bash_ast.policies — built-in security policies + composition.

A policy is any object with a .check(cmd: CommandNode) -> Violation | None method.
"""

from __future__ import annotations
from dataclasses import dataclass
from bash_ast.parser import CommandNode


@dataclass
class Violation:
    policy_name: str
    message: str
    command: CommandNode


class FileWritePolicy:
    """Block shell redirects that write to protected filesystem paths."""

    name = "file_write"

    _PROTECTED_PREFIXES = ("/etc", "/usr", "/sys", "/proc", "/boot",
                           "/bin", "/sbin", "/lib", "/lib64", "/dev")

    def check(self, cmd: CommandNode) -> Violation | None:
        for target in cmd.redirect_targets:
            # Normalise: strip quotes
            path = target.strip("'\"")
            if path == "/" or any(path.startswith(p) for p in self._PROTECTED_PREFIXES):
                return Violation(
                    policy_name=self.name,
                    message=f"Write to protected path blocked: {path}",
                    command=cmd,
                )
        return None


class GitPolicy:
    """Block destructive git operations."""

    name = "git"

    _PROTECTED_BRANCHES = {"main", "master", "production"}
    _DESTRUCTIVE_SUBCOMMANDS = {"reset", "rebase", "force-push", "push --force"}

    def check(self, cmd: CommandNode) -> Violation | None:
        if cmd.name != "git":
            return None

        subcommand = cmd.args[0] if cmd.args else ""

        # Block push to protected branches
        if subcommand == "push":
            # Last positional arg after remote is branch name
            positional = [a for a in cmd.args[1:] if not a.startswith("-")]
            branch = positional[-1] if positional else ""
            if branch in self._PROTECTED_BRANCHES:
                return Violation(
                    policy_name=self.name,
                    message=f"git push to protected branch blocked: {branch}",
                    command=cmd,
                )
            # Block --force / -f
            if "--force" in cmd.flags or "-f" in cmd.flags:
                return Violation(
                    policy_name=self.name,
                    message="git push --force blocked",
                    command=cmd,
                )

        # Block git reset --hard
        if subcommand == "reset" and "--hard" in cmd.flags:
            return Violation(
                policy_name=self.name,
                message="git reset --hard blocked",
                command=cmd,
            )

        return None


class DangerousCommandPolicy:
    """Block rm -rf on non-/tmp paths."""

    name = "dangerous_command"

    _SAFE_PREFIXES = ("/tmp",)

    def check(self, cmd: CommandNode) -> Violation | None:
        if cmd.name != "rm":
            return None

        is_recursive = any(
            "-r" in f or "-R" in f or "r" in f.lstrip("-")
            for f in cmd.flags
        )
        is_force = any("f" in f.lstrip("-") for f in cmd.flags)

        if not (is_recursive and is_force):
            return None

        # Check each target path
        targets = [a for a in cmd.args if not a.startswith("-")]
        for target in targets:
            path = target.strip("'\"")
            if not any(path.startswith(p) for p in self._SAFE_PREFIXES):
                return Violation(
                    policy_name=self.name,
                    message=f"rm -rf on non-/tmp path blocked: {path}",
                    command=cmd,
                )

        return None


class _ComposedPolicy:
    """Run multiple policies; return first violation found."""

    def __init__(self, *policies):
        self._policies = policies

    def check(self, cmd: CommandNode) -> Violation | None:
        for policy in self._policies:
            v = policy.check(cmd)
            if v is not None:
                return v
        return None


def compose(*policies) -> _ComposedPolicy:
    """Compose multiple policies; first violation wins."""
    return _ComposedPolicy(*policies)


__all__ = [
    "Violation",
    "FileWritePolicy",
    "GitPolicy",
    "DangerousCommandPolicy",
    "compose",
]
