"""
bashguard.credentials — Credential injection via PreToolUse hook rewrite.

Loads a credential store from ~/.bashguard/credentials.yaml (or
BASHGUARD_CREDENTIALS env var) and substitutes placeholders in bash
commands before execution. The real secret never appears in Claude's
context window — only the placeholder does.

Supported placeholder styles:
  {{SECRET_NAME}}   — double-brace (explicit, unambiguous)
  ${SECRET_NAME}    — bash braced variable (substituted only if in store)
  $SECRET_NAME      — bare variable (word-boundary match, only if in store)

Unknown placeholders are left unchanged so legitimate shell variables
($HOME, $USER, etc.) are not mangled.

Credential file format (YAML, user-managed, never committed):
  OPENAI_API_KEY: sk-real-key-here
  GITHUB_TOKEN: ghp-real-token-here
"""
from __future__ import annotations

import os
import re
from pathlib import Path


_DEFAULT_CREDS_PATH = Path.home() / ".bashguard" / "credentials.yaml"


class CredentialStore:
    """Immutable mapping of credential name → value."""

    def __init__(self, mapping: dict[str, str]):
        self._data = dict(mapping)

    def is_empty(self) -> bool:
        return not self._data

    def get(self, key: str) -> str | None:
        return self._data.get(key)

    def keys(self) -> list[str]:
        return list(self._data.keys())

    def __repr__(self) -> str:
        # Never expose values in repr
        keys = ", ".join(self._data.keys())
        return f"CredentialStore({{{keys}}})"

    @classmethod
    def load(cls, path: Path | None = None) -> "CredentialStore":
        """Load credential store from YAML file. Returns empty store on any error."""
        target = path or _default_creds_path()
        if not target or not target.exists():
            return cls({})
        try:
            return cls(_parse_yaml_simple(target.read_text()))
        except Exception:
            return cls({})


def _default_creds_path() -> Path | None:
    if env := os.environ.get("BASHGUARD_CREDENTIALS"):
        return Path(env)
    return _DEFAULT_CREDS_PATH if _DEFAULT_CREDS_PATH.exists() else None


def _parse_yaml_simple(text: str) -> dict[str, str]:
    """Parse simple key: value YAML (no nesting, no lists). Avoids yaml dep."""
    result: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" in line:
            key, _, value = line.partition(":")
            result[key.strip()] = value.strip()
    return result


def substitute(command: str, store: CredentialStore) -> str:
    """Substitute credential placeholders in command with real values.

    Leaves unknown placeholders untouched so shell variables like $HOME
    are not mangled.
    """
    if store.is_empty():
        return command

    result = command

    for key in store.keys():
        value = store.get(key)
        if value is None:
            continue

        # {{KEY}} — double-brace style
        result = result.replace(f"{{{{{key}}}}}", value)

        # ${KEY} — bash braced style
        result = result.replace(f"${{{key}}}", value)

        # $KEY — bare style, word-boundary so $KEY_SUFFIX is not matched
        result = re.sub(rf"\${key}(?!\w)", value, result)

    return result


def load_and_substitute(command: str) -> str:
    """Load default credential store and substitute placeholders in command."""
    store = CredentialStore.load()
    return substitute(command, store)
