"""
tests/test_token_auth_fs.py — Unit tests for token-based agent auth (W4).

The FUSE daemon reads a `.bashguard-token` file from the agent's CWD to
identify which agent is making filesystem calls. The token maps to a
granted subtree. Agents without a valid token, or whose token maps to a
different subtree, are blocked.

Auth model:
    TokenRegistry holds: {token_value → granted_root}
    TokenAuthFS(real_root, token_registry, agent_cwd):
        - On init, reads .bashguard-token from agent_cwd
        - Maps token → granted_root via registry
        - Passes granted_root to ACLShadowFS

Story: As a bashguard agent sandbox, I need each agent to be authenticated
by a token file in its CWD. The FUSE daemon verifies the token before
granting access to any path. An agent whose token is missing, expired, or
invalid gets EACCES on all operations. An agent with a valid token gets
the same ACL behavior as W3 (subtree enforcement).
"""
from __future__ import annotations

import errno
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "spike"))

from token_auth_fs import TokenRegistry, TokenAuthFS, InvalidTokenError  # noqa: E402
from fuse import FuseOSError  # noqa: E402


@pytest.fixture()
def real_dir(tmp_path: Path) -> Path:
    (tmp_path / "alice").mkdir()
    (tmp_path / "alice" / "work.txt").write_bytes(b"alice's work\n")
    (tmp_path / "bob").mkdir()
    (tmp_path / "bob" / "secret.txt").write_bytes(b"bob's secret\n")
    return tmp_path


@pytest.fixture()
def registry() -> TokenRegistry:
    r = TokenRegistry()
    r.register("token-alice-abc123", "/alice")
    r.register("token-bob-xyz789", "/bob")
    return r


@pytest.fixture()
def alice_cwd(tmp_path: Path) -> Path:
    cwd = tmp_path / "alice_cwd"
    cwd.mkdir()
    (cwd / ".bashguard-token").write_text("token-alice-abc123\n")
    return cwd


@pytest.fixture()
def bob_cwd(tmp_path: Path) -> Path:
    cwd = tmp_path / "bob_cwd"
    cwd.mkdir()
    (cwd / ".bashguard-token").write_text("token-bob-xyz789\n")
    return cwd


@pytest.fixture()
def alice_fs(real_dir: Path, registry: TokenRegistry, alice_cwd: Path) -> TokenAuthFS:
    return TokenAuthFS(str(real_dir), registry, str(alice_cwd))


@pytest.fixture()
def bob_fs(real_dir: Path, registry: TokenRegistry, bob_cwd: Path) -> TokenAuthFS:
    return TokenAuthFS(str(real_dir), registry, str(bob_cwd))


# ---------------------------------------------------------------------------
# Token loading
# ---------------------------------------------------------------------------

class TestTokenLoading:
    def test_loads_token_from_cwd(self, alice_fs: TokenAuthFS):
        assert alice_fs.granted_root == "/alice"

    def test_missing_token_file_raises(self, real_dir: Path, registry: TokenRegistry, tmp_path: Path):
        empty_cwd = tmp_path / "no_token"
        empty_cwd.mkdir()
        with pytest.raises(InvalidTokenError, match="no .bashguard-token"):
            TokenAuthFS(str(real_dir), registry, str(empty_cwd))

    def test_unknown_token_raises(self, real_dir: Path, registry: TokenRegistry, tmp_path: Path):
        bad_cwd = tmp_path / "bad_token"
        bad_cwd.mkdir()
        (bad_cwd / ".bashguard-token").write_text("not-a-real-token\n")
        with pytest.raises(InvalidTokenError, match="unrecognized token"):
            TokenAuthFS(str(real_dir), registry, str(bad_cwd))

    def test_token_whitespace_stripped(self, real_dir: Path, registry: TokenRegistry, tmp_path: Path):
        """Token file may have trailing newline — must be stripped."""
        cwd = tmp_path / "ws_cwd"
        cwd.mkdir()
        (cwd / ".bashguard-token").write_text("  token-alice-abc123  \n")
        fs = TokenAuthFS(str(real_dir), registry, str(cwd))
        assert fs.granted_root == "/alice"


# ---------------------------------------------------------------------------
# Alice can access /alice, blocked from /bob
# ---------------------------------------------------------------------------

class TestAliceAccess:
    def test_alice_reads_own_file(self, alice_fs: TokenAuthFS):
        data = alice_fs.read("/alice/work.txt", 1024, 0, fh=1)
        assert data == b"alice's work\n"

    def test_alice_blocked_from_bob(self, alice_fs: TokenAuthFS):
        with pytest.raises(FuseOSError) as exc:
            alice_fs.read("/bob/secret.txt", 1024, 0, fh=1)
        assert exc.value.errno == errno.EPERM

    def test_alice_cannot_list_bob(self, alice_fs: TokenAuthFS):
        with pytest.raises(FuseOSError) as exc:
            list(alice_fs.readdir("/bob", fh=0))
        assert exc.value.errno == errno.EPERM

    def test_alice_write_stays_in_overlay(self, alice_fs: TokenAuthFS, real_dir: Path):
        fh = alice_fs.open("/alice/work.txt", os.O_WRONLY | os.O_TRUNC)
        alice_fs.write("/alice/work.txt", b"modified\n", 0, fh)
        assert alice_fs.read("/alice/work.txt", 1024, 0, fh) == b"modified\n"
        assert (real_dir / "alice" / "work.txt").read_bytes() == b"alice's work\n"


# ---------------------------------------------------------------------------
# Bob can access /bob, blocked from /alice
# ---------------------------------------------------------------------------

class TestBobAccess:
    def test_bob_reads_own_file(self, bob_fs: TokenAuthFS):
        data = bob_fs.read("/bob/secret.txt", 1024, 0, fh=1)
        assert data == b"bob's secret\n"

    def test_bob_blocked_from_alice(self, bob_fs: TokenAuthFS):
        with pytest.raises(FuseOSError) as exc:
            bob_fs.read("/alice/work.txt", 1024, 0, fh=1)
        assert exc.value.errno == errno.EPERM


# ---------------------------------------------------------------------------
# TokenRegistry management
# ---------------------------------------------------------------------------

class TestTokenRegistry:
    def test_register_and_lookup(self):
        r = TokenRegistry()
        r.register("tok1", "/project-a")
        assert r.lookup("tok1") == "/project-a"

    def test_lookup_unknown_returns_none(self):
        r = TokenRegistry()
        assert r.lookup("ghost") is None

    def test_revoke_removes_token(self):
        r = TokenRegistry()
        r.register("tok1", "/project-a")
        r.revoke("tok1")
        assert r.lookup("tok1") is None

    def test_tokens_are_independent(self):
        r = TokenRegistry()
        r.register("tok-a", "/a")
        r.register("tok-b", "/b")
        assert r.lookup("tok-a") == "/a"
        assert r.lookup("tok-b") == "/b"
        r.revoke("tok-a")
        assert r.lookup("tok-b") == "/b"
