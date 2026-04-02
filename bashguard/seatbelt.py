"""
bashguard.seatbelt — macOS sandbox-exec profile generation and sandboxed execution.

Provides defense-in-depth beneath the FUSE shadow FS layer:
- FUSE captures writes (CoW overlay, real dir untouched)
- seatbelt enforces the same policy at the OS kernel level

The combination means: even if FUSE daemon crashes or is bypassed, the kernel
still blocks writes outside the project dir. Two independent enforcement points
with different failure modes.

Profile policy:
- (deny default)                  — deny everything not explicitly allowed
- (allow file-read* /)            — reads anywhere (agent needs system libs, tools)
- (allow file-write* <project>)   — writes to project dir only
- (allow file-write* /private/tmp) — temp files always allowed
- (allow process-exec*)           — subprocesses allowed (bash, git, uv, etc.)
- (allow signal)                  — process signalling (Ctrl-C, etc.)
- network: denied by default; allowed per-host if specified
"""
from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class SeatbeltProfile:
    """An SBPL (Sandbox Profile Language) policy document."""

    sbpl: str

    def __str__(self) -> str:
        return self.sbpl


def build_profile(
    project_path: Path,
    allowed_hosts: list[str] | None = None,
    extra_write_paths: list[Path] | None = None,
) -> SeatbeltProfile:
    """Build a deny-default SBPL profile that allows writes only to project_path.

    Args:
        project_path: The agent's working directory. Writes outside this are denied.
        allowed_hosts: Optional list of hostnames to allow outbound TCP connections.
        extra_write_paths: Additional paths the agent may write to (e.g. shared output dirs).

    Returns:
        SeatbeltProfile with the generated SBPL.
    """
    real = str(Path(project_path).resolve())

    lines = [
        "(version 1)",
        "(deny default)",
        # Reads anywhere — agent needs /usr/bin, /System, /opt/homebrew, etc.
        '(allow file-read* (subpath "/"))',
        # Writes: project dir only + /private/tmp
        f'(allow file-write* (subpath "{real}"))',
        '(allow file-write* (subpath "/private/tmp"))',
    ]

    if extra_write_paths:
        for p in extra_write_paths:
            lines.append(f'(allow file-write* (subpath "{p.resolve()!s}"))')

    if allowed_hosts:
        for host in allowed_hosts:
            lines.append(f'(allow network-outbound (remote tcp "{host}:*"))')

    lines += [
        "(allow process-exec*)",
        "(allow signal)",
    ]

    return SeatbeltProfile(sbpl="\n".join(lines))


def sandbox_exec_available() -> bool:
    """Return True if sandbox-exec is present on this system."""
    return shutil.which("sandbox-exec") is not None


@dataclass
class SandboxResult:
    returncode: int
    stdout: str
    stderr: str


def run_sandboxed(
    cmd: list[str],
    project_path: Path,
    allowed_hosts: list[str] | None = None,
    extra_write_paths: list[Path] | None = None,
    timeout: int | None = None,
) -> SandboxResult:
    """Run cmd under a seatbelt policy derived from project_path.

    Fail-open: if sandbox-exec is not available, the command runs without sandboxing.
    This preserves the agent's ability to work on systems without sandbox-exec
    (non-macOS, or unusual macOS installs) while providing enforcement where it's
    available.

    Args:
        cmd: Command and arguments to run.
        project_path: The agent's working directory (write boundary).
        allowed_hosts: Optional hostnames to allow outbound connections to.
        extra_write_paths: Additional paths the agent may write to.
        timeout: Optional timeout in seconds.

    Returns:
        SandboxResult with returncode, stdout, stderr.
    """
    if not sandbox_exec_available():
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return SandboxResult(result.returncode, result.stdout, result.stderr)

    profile = build_profile(
        project_path=project_path,
        allowed_hosts=allowed_hosts,
        extra_write_paths=extra_write_paths,
    )

    result = subprocess.run(
        ["sandbox-exec", "-p", profile.sbpl] + cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    return SandboxResult(result.returncode, result.stdout, result.stderr)
