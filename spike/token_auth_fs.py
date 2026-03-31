#!/usr/bin/env python3
"""
spike/token_auth_fs.py — Shadow FS with capability-based token authentication (W4).

Each agent has a `.bashguard-token` file in its CWD. The FUSE daemon reads
this token on startup and maps it to a granted subtree via a TokenRegistry.
Access outside the granted subtree is blocked (EPERM), as in W3.

Token model:
    - TokenRegistry: in-memory map of {token → granted_root}
    - TokenAuthFS: reads .bashguard-token from agent_cwd, resolves grant,
      delegates to ACLShadowFS for enforcement

Usage:
    python3 spike/token_auth_fs.py <real_root> <mount_point> <agent_cwd>

    The daemon reads <agent_cwd>/.bashguard-token to determine which
    subtree of <real_root> the agent is allowed to access.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

from fuse import FUSE

from acl_shadow_fs import ACLShadowFS


class InvalidTokenError(Exception):
    """Raised when the token file is missing or unrecognized."""


class TokenRegistry:
    """In-memory map of token values to granted subtree paths."""

    def __init__(self):
        self._map: dict[str, str] = {}

    def register(self, token: str, granted_root: str) -> None:
        """Associate token with a granted subtree (e.g. '/alice')."""
        self._map[token.strip()] = granted_root

    def revoke(self, token: str) -> None:
        """Remove a token from the registry."""
        self._map.pop(token.strip(), None)

    def lookup(self, token: str) -> str | None:
        """Return granted_root for token, or None if not found."""
        return self._map.get(token.strip())


class TokenAuthFS(ACLShadowFS):
    """
    Shadow FS authenticated by .bashguard-token in agent's CWD.

    Reads the token file, resolves the grant via TokenRegistry,
    then enforces subtree ACL via ACLShadowFS.
    """

    def __init__(self, real_root: str, registry: TokenRegistry, agent_cwd: str):
        token_path = Path(agent_cwd) / ".bashguard-token"
        if not token_path.exists():
            raise InvalidTokenError(
                f"no .bashguard-token in {agent_cwd!r} — "
                "agent must be launched with a token file in its CWD"
            )

        token = token_path.read_text().strip()
        granted_root = registry.lookup(token)
        if granted_root is None:
            raise InvalidTokenError(
                f"unrecognized token in {token_path} — "
                "token not registered with the FUSE daemon"
            )

        super().__init__(real_root, granted_root)
        self.granted_root = granted_root
        self._token = token
        self._agent_cwd = agent_cwd


def main():
    if len(sys.argv) < 4:
        print(
            f"Usage: {sys.argv[0]} <real_root> <mount_point> <agent_cwd>",
            file=sys.stderr,
        )
        print("  The FUSE daemon reads <agent_cwd>/.bashguard-token to grant access.",
              file=sys.stderr)
        sys.exit(1)

    real_root = os.path.expanduser(sys.argv[1])
    mount_point = sys.argv[2]
    agent_cwd = os.path.expanduser(sys.argv[3])

    if not os.path.isdir(real_root):
        print(f"Error: {real_root!r} is not a directory", file=sys.stderr)
        sys.exit(1)
    if not os.path.isdir(mount_point):
        print(f"Error: {mount_point!r} is not a directory", file=sys.stderr)
        sys.exit(1)

    # In production, the registry would be populated by `bashguard session start`.
    # For the spike, we read a simple registry file or accept a token→root mapping
    # from environment variables.
    registry = TokenRegistry()
    registry_env = os.environ.get("BASHGUARD_TOKEN_REGISTRY", "")
    for entry in registry_env.split(","):
        entry = entry.strip()
        if ":" in entry:
            token, root = entry.split(":", 1)
            registry.register(token.strip(), root.strip())

    try:
        fs = TokenAuthFS(real_root, registry, agent_cwd)
    except InvalidTokenError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"Token Auth FS: {real_root!r} → {mount_point!r}")
    print(f"Agent CWD: {agent_cwd!r}")
    print(f"Granted subtree: {fs.granted_root!r}")
    print("Ctrl-C or unmount to stop.")
    FUSE(fs, mount_point, nothreads=True, foreground=True)


if __name__ == "__main__":
    main()
