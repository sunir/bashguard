"""Contract path-ownership check — layer 1 of CONTRACT-ENFORCEMENT-HOOK.

Story: CONTRACT-ENFORCEMENT-HOOK

Deterministic: reads the compiled contract directory and checks whether a
file path falls inside another agent's repo root. Fail-open always.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

_log = logging.getLogger(__name__)


@dataclass(frozen=True)
class ContractEntry:
    repo: str
    role: str
    owns: list[dict] = field(default_factory=list)
    boundaries: list[dict] = field(default_factory=list)
    collaborates: list[dict] = field(default_factory=list)


@dataclass(frozen=True)
class ContractDirectory:
    contracts: list[ContractEntry]
    generated_at: Optional[datetime]  # None = old flat-array schema (treat as stale)

    def is_stale(self, max_age_hours: int = 24) -> bool:
        if self.generated_at is None:
            return True
        age = datetime.now(tz=timezone.utc) - self.generated_at
        return age.total_seconds() > max_age_hours * 3600


@dataclass(frozen=True)
class PathOwnershipResult:
    violation: bool
    foreign_repo: Optional[str] = None
    message: str = ""


def load_directory(path: Path) -> Optional[ContractDirectory]:
    """Load directory.json. Returns None on any error (fail-open)."""
    if not path.exists():
        return None
    try:
        raw = json.loads(path.read_text())
    except Exception as e:
        _log.warning("contract_path_check: unparseable directory.json: %s", e)
        return None

    try:
        # Wrapped schema: {generated_at, contracts: [...]}
        if isinstance(raw, dict) and "contracts" in raw:
            entries = [_parse_entry(c) for c in raw.get("contracts", [])]
            generated_at = _parse_ts(raw.get("generated_at"))
        # Flat array schema (old compiler, no generated_at)
        elif isinstance(raw, list):
            entries = [_parse_entry(c) for c in raw]
            generated_at = None
        else:
            _log.warning("contract_path_check: unrecognised directory.json shape")
            return None
        return ContractDirectory(contracts=entries, generated_at=generated_at)
    except Exception as e:
        _log.warning("contract_path_check: failed to parse directory: %s", e)
        return None


def check_path_ownership(
    path: Path,
    current_repo: str,
    directory: Optional[ContractDirectory],
    colony_root: Path,
) -> PathOwnershipResult:
    """Check if `path` falls under another agent's repo root.

    Fail-open: returns no-violation on any missing data.
    """
    if directory is None:
        return PathOwnershipResult(violation=False)

    repo_names = {e.repo for e in directory.contracts}
    if current_repo not in repo_names:
        return PathOwnershipResult(violation=False)

    try:
        resolved = path.resolve()
    except Exception:
        return PathOwnershipResult(violation=False)

    for entry in directory.contracts:
        if entry.repo == current_repo:
            continue
        repo_root = (colony_root / entry.repo).resolve()
        try:
            resolved.relative_to(repo_root)
        except ValueError:
            continue
        # Path is inside another agent's repo
        return PathOwnershipResult(
            violation=True,
            foreign_repo=entry.repo,
            message=(
                f"Path-ownership violation: {current_repo} is touching "
                f"{entry.repo}'s repo at {path}"
            ),
        )

    return PathOwnershipResult(violation=False)


def _parse_entry(raw: dict) -> ContractEntry:
    return ContractEntry(
        repo=raw["repo"],
        role=raw.get("role", ""),
        owns=raw.get("owns", []),
        boundaries=raw.get("boundaries", []),
        collaborates=raw.get("collaborates", []),
    )


def _parse_ts(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception:
        return None
