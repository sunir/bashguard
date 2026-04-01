"""
bashguard.setup — Install bashguard as Claude hook plugins.

`bashguard claude setup` symlinks bundled hook scripts into the
~/.claude/hooks/<HookType>.d/system/ directories so the colony hook
dispatcher picks them up automatically. system/ is the policy layer.

Hooks installed:
  PreToolUse.d/system/70-bashguard        — bash command auditing
  SessionStart.d/system/75-bashguard-mount  — FUSE sandbox mount on session start
  SessionEnd.d/system/75-bashguard-unmount  — unmount + overlay diff on session end

Target directories can be overridden via BASHGUARD_HOOKS_DIR for testing.
"""
from __future__ import annotations

import os
from pathlib import Path

_PACKAGE_ROOT = Path(__file__).parent.parent
_HOOKS_DIR = _PACKAGE_ROOT / "hooks"

_HOOK_SPECS: list[tuple[str, str]] = [
    # (hook_filename, target_hook_type_dir)
    ("70-bashguard",         "PreToolUse.d"),
    ("75-bashguard-mount",   "SessionStart.d"),
    ("75-bashguard-unmount", "SessionEnd.d"),
]

_SYSTEM_SUBDIR = "system"


def _claude_hooks_root() -> Path:
    override = os.environ.get("BASHGUARD_HOOKS_DIR")
    if override:
        return Path(override)
    return Path.home() / ".claude" / "hooks"


def _symlink(source: Path, target: Path) -> Path:
    """Symlink source → target. Idempotent, replaces stale links."""
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.is_symlink() and target.resolve() == source.resolve():
        return target  # Already correct.
    if target.is_symlink() or target.exists():
        target.unlink()
    target.symlink_to(source)
    return target


def install_hook(target_dir: Path | None = None) -> Path:
    """Symlink the PreToolUse hook (backwards-compatible entry point)."""
    if target_dir is None:
        target_dir = _claude_hooks_root() / "PreToolUse.d" / _SYSTEM_SUBDIR
    source = _HOOKS_DIR / "70-bashguard"
    return _symlink(source, target_dir / "70-bashguard")


def install_all_hooks() -> list[Path]:
    """Symlink all bundled hooks into their system/ dirs. Returns installed paths."""
    root = _claude_hooks_root()
    installed = []
    for hook_name, hook_type_dir in _HOOK_SPECS:
        source = _HOOKS_DIR / hook_name
        target = root / hook_type_dir / _SYSTEM_SUBDIR / hook_name
        installed.append(_symlink(source, target))
    return installed
