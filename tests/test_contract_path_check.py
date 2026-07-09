"""Tests for contract path-ownership check (layer 1 of contract enforcement).

Story: CONTRACT-ENFORCEMENT-HOOK

Layer 1 is deterministic: given a tool call's file path and the compiled
contract directory, is the path inside another agent's repo root?

Design: fail-open always. Never block. Only warn + alert.
"""
from __future__ import annotations

import json
import textwrap
from pathlib import Path

import pytest

import sys
from pathlib import Path as _Path
# Standalone module in hooks/lib/ — no bashguard package dependency
_hooks_lib = _Path(__file__).parent.parent / "hooks" / "lib"
if str(_hooks_lib) not in sys.path:
    sys.path.insert(0, str(_hooks_lib))

from contract_path_check import (  # noqa: E402
    ContractDirectory,
    PathOwnershipResult,
    check_path_ownership,
    load_directory,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

COLONY_ROOT = Path("/colony")

DIRECTORY_FRESH = {
    "generated_at": "2026-07-09T00:00:00Z",
    "contracts": [
        {
            "repo": "bashguard",
            "role": "Security sandbox",
            "owns": [{"item": "Rule engine", "detail": "bashguard/rules/"}],
            "boundaries": [],
            "collaborates": [],
        },
        {
            "repo": "deploy",
            "role": "Deploy agent",
            "owns": [{"item": "Deploy pipeline", "detail": "deploy/"}],
            "boundaries": [],
            "collaborates": [],
        },
        {
            "repo": "qa",
            "role": "QA agent",
            "owns": [{"item": "Test suite", "detail": "qa/"}],
            "boundaries": [],
            "collaborates": [],
        },
    ],
}


@pytest.fixture
def directory_file(tmp_path: Path) -> Path:
    p = tmp_path / "directory.json"
    p.write_text(json.dumps(DIRECTORY_FRESH))
    return p


@pytest.fixture
def stale_directory_file(tmp_path: Path) -> Path:
    stale = dict(DIRECTORY_FRESH, generated_at="2020-01-01T00:00:00Z")
    p = tmp_path / "directory.json"
    p.write_text(json.dumps(stale))
    return p


# ---------------------------------------------------------------------------
# load_directory
# ---------------------------------------------------------------------------


class TestLoadDirectory:
    # Story: CONTRACT-ENFORCEMENT-HOOK

    def test_loads_valid_file(self, directory_file: Path) -> None:
        d = load_directory(directory_file)
        assert d is not None
        assert len(d.contracts) == 3

    def test_missing_file_returns_none(self, tmp_path: Path) -> None:
        d = load_directory(tmp_path / "nonexistent.json")
        assert d is None

    def test_unparseable_returns_none(self, tmp_path: Path) -> None:
        p = tmp_path / "bad.json"
        p.write_text("not json {{{")
        d = load_directory(p)
        assert d is None

    def test_flat_array_schema_no_generated_at(self, tmp_path: Path) -> None:
        """Old compiler output: flat array without generated_at wrapper."""
        flat = DIRECTORY_FRESH["contracts"]
        p = tmp_path / "directory.json"
        p.write_text(json.dumps(flat))
        d = load_directory(p)
        assert d is not None
        assert d.generated_at is None  # treated as infinitely stale
        assert len(d.contracts) == 3

    def test_stale_directory_flagged(self, stale_directory_file: Path) -> None:
        d = load_directory(stale_directory_file)
        assert d is not None
        assert d.is_stale(max_age_hours=24)

    def test_fresh_directory_not_stale(self, directory_file: Path) -> None:
        d = load_directory(directory_file)
        assert d is not None
        assert not d.is_stale(max_age_hours=24)


# ---------------------------------------------------------------------------
# check_path_ownership
# ---------------------------------------------------------------------------


class TestPathOwnershipOwnRepo:
    # Story: CONTRACT-ENFORCEMENT-HOOK

    def test_own_repo_path_allowed(self, directory_file: Path) -> None:
        d = load_directory(directory_file)
        result = check_path_ownership(
            path=COLONY_ROOT / "bashguard" / "bashguard" / "rules" / "network.py",
            current_repo="bashguard",
            directory=d,
            colony_root=COLONY_ROOT,
        )
        assert result.violation is False

    def test_path_outside_all_repos_allowed(self, directory_file: Path) -> None:
        d = load_directory(directory_file)
        result = check_path_ownership(
            path=Path("/tmp/scratch.txt"),
            current_repo="bashguard",
            directory=d,
            colony_root=COLONY_ROOT,
        )
        assert result.violation is False


class TestPathOwnershipViolation:
    # Story: CONTRACT-ENFORCEMENT-HOOK

    def test_touching_other_repo_is_violation(self, directory_file: Path) -> None:
        d = load_directory(directory_file)
        result = check_path_ownership(
            path=COLONY_ROOT / "qa" / "tests" / "test_deploy.py",
            current_repo="deploy",
            directory=d,
            colony_root=COLONY_ROOT,
        )
        assert result.violation is True
        assert result.foreign_repo == "qa"
        assert "deploy" in result.message
        assert "qa" in result.message

    def test_deploy_touching_bashguard_is_violation(self, directory_file: Path) -> None:
        d = load_directory(directory_file)
        result = check_path_ownership(
            path=COLONY_ROOT / "bashguard" / "hooks" / "70-bashguard",
            current_repo="deploy",
            directory=d,
            colony_root=COLONY_ROOT,
        )
        assert result.violation is True
        assert result.foreign_repo == "bashguard"


class TestPathOwnershipEdgeCases:
    # Story: CONTRACT-ENFORCEMENT-HOOK

    def test_none_directory_always_allows(self) -> None:
        result = check_path_ownership(
            path=COLONY_ROOT / "qa" / "tests" / "foo.py",
            current_repo="deploy",
            directory=None,
            colony_root=COLONY_ROOT,
        )
        assert result.violation is False

    def test_repo_not_in_directory_allows(self, directory_file: Path) -> None:
        d = load_directory(directory_file)
        result = check_path_ownership(
            path=COLONY_ROOT / "qa" / "tests" / "foo.py",
            current_repo="unknown_agent",
            directory=d,
            colony_root=COLONY_ROOT,
        )
        assert result.violation is False

    def test_stale_directory_still_checks_paths(self, stale_directory_file: Path) -> None:
        """Staleness triggers a warning but does NOT disable path checking."""
        d = load_directory(stale_directory_file)
        result = check_path_ownership(
            path=COLONY_ROOT / "qa" / "tests" / "foo.py",
            current_repo="deploy",
            directory=d,
            colony_root=COLONY_ROOT,
        )
        assert result.violation is True
