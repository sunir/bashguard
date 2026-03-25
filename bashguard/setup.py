"""
bashguard.setup — Install bashguard as a Claude PreToolUse hook plugin.

`bashguard claude setup` symlinks the bundled hook script into
~/.claude/hooks/PreToolUse.d/system/70-bashguard so the colony hook
dispatcher picks it up automatically. system/ is the policy layer (runs
first, managed by setup.d, not in user git).

The target directory can be overridden via BASHGUARD_HOOKS_DIR for testing.
"""
from __future__ import annotations

import os
from pathlib import Path

HOOK_NAME = "70-bashguard"
_PACKAGE_ROOT = Path(__file__).parent.parent
HOOK_SOURCE = _PACKAGE_ROOT / "hooks" / HOOK_NAME

_DEFAULT_TARGET_DIR = (
    Path.home() / ".claude" / "hooks" / "PreToolUse.d" / "system"
)


def _resolve_target_dir() -> Path:
    override = os.environ.get("BASHGUARD_HOOKS_DIR")
    return Path(override) if override else _DEFAULT_TARGET_DIR


def install_hook(target_dir: Path | None = None) -> Path:
    """Symlink the bundled hook into target_dir.

    Creates parent directories if needed. Replaces stale symlinks.
    Returns the installed symlink path.
    """
    if target_dir is None:
        target_dir = _resolve_target_dir()

    target_dir.mkdir(parents=True, exist_ok=True)
    link = target_dir / HOOK_NAME

    if link.is_symlink() and link.resolve() == HOOK_SOURCE.resolve():
        return link  # Already correct — idempotent.

    if link.is_symlink() or link.exists():
        link.unlink()

    link.symlink_to(HOOK_SOURCE)
    return link
