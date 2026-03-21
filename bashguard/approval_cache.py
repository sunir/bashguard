"""
bashguard.approval_cache — Remember human approvals per-session.

When a CONFIRM verdict is approved by the human, cache the approval
so subsequent checks for the same rule_id ALLOW without re-asking.

File-backed (JSON) for hook mode where each invocation is a separate process.
TTL-based expiry prevents stale approvals from persisting forever.

Inspired by n2-ark's _approvals Set with approve/revoke/reset.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

DEFAULT_PATH = Path.home() / ".bashguard" / "approvals.json"
DEFAULT_TTL = 30 * 60  # 30 minutes


class ApprovalCache:
    """File-backed approval cache with TTL expiry."""

    def __init__(self, path: Path = DEFAULT_PATH, ttl_seconds: int = DEFAULT_TTL):
        self._path = path
        self._ttl = ttl_seconds

    def _load(self) -> dict[str, float]:
        """Load {rule_id: timestamp} from file."""
        if not self._path.exists():
            return {}
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                return data
        except (json.JSONDecodeError, OSError):
            pass
        return {}

    def _save(self, data: dict[str, float]) -> None:
        """Write {rule_id: timestamp} to file."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(json.dumps(data), encoding="utf-8")

    def approve(self, rule_id: str) -> None:
        """Grant approval for a rule_id."""
        data = self._load()
        data[rule_id] = time.time()
        self._save(data)

    def is_approved(self, rule_id: str) -> bool:
        """Check if rule_id has a non-expired approval."""
        data = self._load()
        ts = data.get(rule_id)
        if ts is None:
            return False
        if time.time() - ts > self._ttl:
            # Expired — clean up
            del data[rule_id]
            self._save(data)
            return False
        return True

    def revoke(self, rule_id: str) -> None:
        """Remove approval for a rule_id."""
        data = self._load()
        data.pop(rule_id, None)
        self._save(data)

    def reset(self) -> None:
        """Clear all approvals."""
        self._save({})
