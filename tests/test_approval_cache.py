"""Tests for approval cache — remember human approvals per-session.

When a CONFIRM verdict is issued and the human approves, subsequent
checks for the same rule_id should ALLOW without re-asking.

File-backed for hook mode (separate process per invocation).
TTL-based expiry to prevent stale approvals.
"""
import json
import time

import pytest

from bashguard.approval_cache import ApprovalCache


class TestApprovalCache:
    def test_not_approved_by_default(self, tmp_path):
        cache = ApprovalCache(path=tmp_path / "approvals.json")
        assert not cache.is_approved("git.destructive")

    def test_approve_then_check(self, tmp_path):
        cache = ApprovalCache(path=tmp_path / "approvals.json")
        cache.approve("git.destructive")
        assert cache.is_approved("git.destructive")

    def test_approve_persists_to_file(self, tmp_path):
        path = tmp_path / "approvals.json"
        cache1 = ApprovalCache(path=path)
        cache1.approve("git.destructive")

        # New instance reads from file
        cache2 = ApprovalCache(path=path)
        assert cache2.is_approved("git.destructive")

    def test_revoke(self, tmp_path):
        cache = ApprovalCache(path=tmp_path / "approvals.json")
        cache.approve("git.destructive")
        cache.revoke("git.destructive")
        assert not cache.is_approved("git.destructive")

    def test_reset_clears_all(self, tmp_path):
        cache = ApprovalCache(path=tmp_path / "approvals.json")
        cache.approve("git.destructive")
        cache.approve("network.unknown_host")
        cache.reset()
        assert not cache.is_approved("git.destructive")
        assert not cache.is_approved("network.unknown_host")

    def test_ttl_expiry(self, tmp_path):
        cache = ApprovalCache(path=tmp_path / "approvals.json", ttl_seconds=1)
        cache.approve("git.destructive")
        assert cache.is_approved("git.destructive")
        time.sleep(1.1)
        assert not cache.is_approved("git.destructive")

    def test_multiple_rules_independent(self, tmp_path):
        cache = ApprovalCache(path=tmp_path / "approvals.json")
        cache.approve("git.destructive")
        assert cache.is_approved("git.destructive")
        assert not cache.is_approved("network.unknown_host")

    def test_missing_file_returns_not_approved(self, tmp_path):
        cache = ApprovalCache(path=tmp_path / "nonexistent.json")
        assert not cache.is_approved("anything")

    def test_corrupt_file_treated_as_empty(self, tmp_path):
        path = tmp_path / "approvals.json"
        path.write_text("not valid json {{{{")
        cache = ApprovalCache(path=path)
        assert not cache.is_approved("anything")
