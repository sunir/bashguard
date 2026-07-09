"""Integration tests for the 11-contract-enforcement hook.

Story: CONTRACT-ENFORCEMENT-HOOK

Tests the bash hook end-to-end: stdin JSON → stdout/stderr/exit code.
The hook is advisory only — always exits 0.
"""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path

import pytest

HOOK = Path(__file__).parent.parent / "hooks" / "11-contract-enforcement"

DIRECTORY_FRESH = {
    "generated_at": "2099-01-01T00:00:00Z",  # far future = never stale in tests
    "contracts": [
        {"repo": "bashguard", "role": "Security sandbox", "owns": [], "boundaries": [], "collaborates": []},
        {"repo": "qa", "role": "QA agent", "owns": [], "boundaries": [], "collaborates": []},
        {"repo": "deploy", "role": "Deploy agent", "owns": [], "boundaries": [], "collaborates": []},
    ],
}

DIRECTORY_STALE = dict(DIRECTORY_FRESH, generated_at="2020-01-01T00:00:00Z")


def _run(tool_name: str, tool_input: dict, cwd: str, directory_json: str | None = None,
         colony_root: str | None = None) -> tuple[int, str, str]:
    stdin = json.dumps({"tool_name": tool_name, "tool_input": tool_input, "cwd": cwd})
    env = {**os.environ}
    if colony_root:
        env["COLONY_ROOT"] = colony_root
    result = subprocess.run(
        [str(HOOK)],
        input=stdin, text=True, capture_output=True, env=env,
    )
    return result.returncode, result.stdout, result.stderr


class TestFailOpen:
    # Story: CONTRACT-ENFORCEMENT-HOOK

    def test_missing_directory_silent_allow(self, tmp_path: Path) -> None:
        code, out, err = _run("Bash", {"command": "ls"}, str(tmp_path))
        assert code == 0
        assert err == ""

    def test_non_bash_tool_silent_allow(self, tmp_path: Path) -> None:
        code, out, err = _run("TaskCreate", {}, str(tmp_path))
        assert code == 0
        assert err == ""

    def test_always_exits_0(self, tmp_path: Path) -> None:
        """Even with a violation, exit 0 — advisory only."""
        colony_root = tmp_path / "colony"
        colony_root.mkdir()
        qa_repo = colony_root / "qa"
        qa_repo.mkdir()
        bashguard_repo = colony_root / "bashguard"
        bashguard_repo.mkdir()
        # Make it a real git repo so git rev-parse works
        subprocess.run(["git", "init", str(bashguard_repo)], capture_output=True)

        dir_path = colony_root / "the_management" / "contracts"
        dir_path.mkdir(parents=True)
        (dir_path / "directory.json").write_text(json.dumps(DIRECTORY_FRESH))

        code, out, err = _run(
            "Write",
            {"file_path": str(qa_repo / "tests" / "foo.py")},
            str(bashguard_repo),
            colony_root=str(colony_root),
        )
        assert code == 0


class TestStaleDirectory:
    # Story: CONTRACT-ENFORCEMENT-HOOK

    def test_stale_warns_stderr(self, tmp_path: Path) -> None:
        colony_root = tmp_path / "colony"
        colony_root.mkdir()
        bashguard_repo = colony_root / "bashguard"
        bashguard_repo.mkdir()
        subprocess.run(["git", "init", str(bashguard_repo)], capture_output=True)

        dir_path = colony_root / "the_management" / "contracts"
        dir_path.mkdir(parents=True)
        (dir_path / "directory.json").write_text(json.dumps(DIRECTORY_STALE))

        code, out, err = _run("Bash", {"command": "ls"}, str(bashguard_repo),
                              colony_root=str(colony_root))
        assert code == 0
        assert "stale" in err.lower()


class TestPathOwnershipViolation:
    # Story: CONTRACT-ENFORCEMENT-HOOK

    def test_write_to_other_repo_warns(self, tmp_path: Path) -> None:
        colony_root = tmp_path / "colony"
        colony_root.mkdir()
        qa_repo = colony_root / "qa"
        qa_repo.mkdir()
        deploy_repo = colony_root / "deploy"
        deploy_repo.mkdir()
        subprocess.run(["git", "init", str(deploy_repo)], capture_output=True)

        dir_path = colony_root / "the_management" / "contracts"
        dir_path.mkdir(parents=True)
        (dir_path / "directory.json").write_text(json.dumps(DIRECTORY_FRESH))

        code, out, err = _run(
            "Write",
            {"file_path": str(qa_repo / "tests" / "test_deploy.py")},
            str(deploy_repo),
            colony_root=str(colony_root),
        )
        assert code == 0
        assert "qa" in err

    def test_own_repo_write_silent(self, tmp_path: Path) -> None:
        colony_root = tmp_path / "colony"
        colony_root.mkdir()
        bashguard_repo = colony_root / "bashguard"
        bashguard_repo.mkdir()
        subprocess.run(["git", "init", str(bashguard_repo)], capture_output=True)

        dir_path = colony_root / "the_management" / "contracts"
        dir_path.mkdir(parents=True)
        (dir_path / "directory.json").write_text(json.dumps(DIRECTORY_FRESH))

        code, out, err = _run(
            "Write",
            {"file_path": str(bashguard_repo / "bashguard" / "rules" / "new_rule.py")},
            str(bashguard_repo),
            colony_root=str(colony_root),
        )
        assert code == 0
        assert err == ""

    def test_path_outside_all_repos_silent(self, tmp_path: Path) -> None:
        colony_root = tmp_path / "colony"
        colony_root.mkdir()
        bashguard_repo = colony_root / "bashguard"
        bashguard_repo.mkdir()
        subprocess.run(["git", "init", str(bashguard_repo)], capture_output=True)

        dir_path = colony_root / "the_management" / "contracts"
        dir_path.mkdir(parents=True)
        (dir_path / "directory.json").write_text(json.dumps(DIRECTORY_FRESH))

        code, out, err = _run(
            "Write",
            {"file_path": "/tmp/scratch.txt"},
            str(bashguard_repo),
            colony_root=str(colony_root),
        )
        assert code == 0
        assert err == ""
