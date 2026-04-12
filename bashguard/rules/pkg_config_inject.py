"""
bashguard.rules.pkg_config_inject — Package manager config file injection.

supply_chain.pkg_config_inject:
  Writing directly to package manager config files achieves the same
  registry-redirect supply chain attack as `pip config set` but bypasses
  that command-level check entirely. An agent that writes
  `registry=https://evil.com` to ~/.npmrc has turned every subsequent
  `npm install` into a malicious package fetch.

  Also detects git config --global mutations for dangerous keys
  (core.hooksPath, http.proxy, https.proxy) — global git config tampering
  that affects all repos on the machine and can redirect hook execution
  or exfiltrate credentials through an attacker-controlled proxy.

Blocked files:
  ~/.pip/pip.conf, ~/.pip/pip.ini, ~/Library/Application Support/pip/pip.conf
  ~/.npmrc, ~/.yarnrc, ~/.yarnrc.yml
  ~/.gemrc, ~/.cargo/config.toml (cargo)

Blocked git config keys (global/system scope only):
  core.hooksPath       — redirects all git hooks to attacker path
  http.proxy           — routes git HTTP through attacker proxy
  https.proxy          — routes git HTTPS through attacker proxy
  http.extraHeader     — injects arbitrary HTTP headers (exfil tokens)
  credential.helper    — custom credential handler (can steal creds)
  url.<base>.insteadOf — silently rewrites remote URLs

Allowed:
  Reads of any config file
  git config --local <any key>
  git config --global user.name/email/signingkey
"""
from __future__ import annotations
import logging

import tree_sitter_bash as tsb
from tree_sitter import Language, Parser as TSParser

from bashguard.parser import parse
from bashguard.models import Severity, Finding, ExecutionContext, ActionType
from bashguard.rules import register

_log = logging.getLogger(__name__)
_LANG = Language(tsb.language())
_PARSER = TSParser(_LANG)

# Package manager config files that, if written, redirect registry
_PKG_CONFIG_BASENAMES = frozenset({
    "pip.conf", "pip.ini",
    ".npmrc", ".yarnrc", ".yarnrc.yml",
    ".gemrc",
})

# Tilde-relative paths that are exact pkg config locations
_PKG_CONFIG_TILDE_PATHS = frozenset({
    "~/.pip/pip.conf",
    "~/.pip/pip.ini",
    "~/.npmrc",
    "~/.yarnrc",
    "~/.yarnrc.yml",
    "~/.gemrc",
    "~/.cargo/config.toml",
})

# git config keys that are dangerous at global/system scope
_GIT_DANGEROUS_KEYS = frozenset({
    "core.hookspath",       # case-insensitive in git; match lower
    "http.proxy",
    "https.proxy",
    "http.extraheader",
    "credential.helper",
})

# git config key prefixes that are dangerous
_GIT_DANGEROUS_KEY_PREFIXES = (
    "url.",                 # url.<base>.insteadOf rewrites
)

# git config keys that are safe at global scope
_GIT_SAFE_GLOBAL_KEYS = frozenset({
    "user.name", "user.email", "user.signingkey",
    "core.editor", "core.autocrlf", "core.eol",
    "init.defaultbranch",
    "pull.rebase", "push.default",
    "merge.conflictstyle",
    "color.ui", "color.diff", "color.status",
    "alias.st", "alias.co", "alias.br", "alias.lg",
})


def _text(node, source: bytes) -> str:
    return source[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def _collect(root, *node_types: str) -> list:
    results = []
    stack = [root]
    while stack:
        node = stack.pop()
        if node.type in node_types:
            results.append(node)
        stack.extend(node.children)
    return results


def _is_pkg_config_path(path: str) -> bool:
    """Return True if path refers to a package manager config file."""
    clean = path.strip("'\"")
    # Exact tilde paths
    if clean in _PKG_CONFIG_TILDE_PATHS:
        return True
    # By basename for any absolute path to known names
    basename = clean.split("/")[-1]
    return basename in _PKG_CONFIG_BASENAMES


def _is_write_redirect(redir_node) -> bool:
    """Return True for > or >> redirect operators (not < or <<)."""
    for child in redir_node.children:
        if child.type in (">", ">>", "file_descriptor"):
            return True
        if child.type in ("<", "heredoc_redirect"):
            return False
    return False


def _walk_write_redirects(root, source: bytes) -> list[str]:
    """Collect targets of write (>/>> ) redirects."""
    targets = []
    for redir in _collect(root, "file_redirect"):
        # Only > and >> are writes; skip < (input redirect)
        has_write_op = any(
            child.type in (">", ">>")
            for child in redir.children
        )
        if not has_write_op:
            continue
        for child in redir.children:
            if child.type in ("word", "string", "raw_string"):
                targets.append(_text(child, source))
    return targets


def _is_git_global_scope(cmd) -> bool:
    """Return True if git config is invoked with --global or --system."""
    return "--global" in cmd.flags or "--system" in cmd.flags


def _is_dangerous_git_key(key: str) -> bool:
    """Return True if key is a dangerous git config key."""
    lower = key.lower()
    if lower in _GIT_DANGEROUS_KEYS:
        return True
    return any(lower.startswith(p) for p in _GIT_DANGEROUS_KEY_PREFIXES)


def _finding(message: str, matched: str, **meta) -> Finding:
    return Finding(
        rule_id="supply_chain.pkg_config_inject",
        severity=Severity.CRITICAL,
        action_type=ActionType.PACKAGE_INSTALL,
        message=message,
        matched_text=matched,
        metadata=meta,
    )


@register
class PkgConfigInjectRule:
    rule_id = "supply_chain.pkg_config_inject"
    severity = Severity.CRITICAL
    description = "Write to package manager config file — supply chain registry redirect"

    def check(self, script: str, context: ExecutionContext) -> list[Finding]:
        try:
            return list(self._scan(script))
        except Exception:
            _log.exception("pkg_config_inject rule error")
            return []

    def _scan(self, script: str):
        source = script.encode("utf-8", errors="replace")
        tree = _PARSER.parse(source)
        root = tree.root_node

        # 1. Redirect writes: > ~/.npmrc, >> ~/.pip/pip.conf
        for target in _walk_write_redirects(root, source):
            clean = target.strip("'\"")
            if _is_pkg_config_path(clean):
                yield _finding(
                    f"{self.description}: write to {clean}",
                    f"... > {clean}",
                    path=clean,
                )
                return

        # 2. cp / mv / tee commands with pkg config destination
        for cmd in parse(script):
            if cmd.name in ("cp", "mv"):
                # Last positional arg is the destination
                pos_args = [a for a in cmd.args if not a.startswith("-")]
                if pos_args and _is_pkg_config_path(pos_args[-1]):
                    dest = pos_args[-1].strip("'\"")
                    yield _finding(
                        f"{self.description}: {cmd.name} to {dest}",
                        f"{cmd.name} ... {dest}",
                        path=dest,
                    )
                    return

            elif cmd.name == "tee":
                for arg in cmd.args:
                    if _is_pkg_config_path(arg):
                        dest = arg.strip("'\"")
                        yield _finding(
                            f"{self.description}: tee to {dest}",
                            f"tee {dest}",
                            path=dest,
                        )
                        return

            elif cmd.name == "git":
                yield from self._check_git_config(cmd)

    def _check_git_config(self, cmd):
        if not cmd.args or cmd.args[0] != "config":
            return
        if not _is_git_global_scope(cmd):
            return  # --local changes only affect one repo — not our concern

        # git config [--global] <key> [<value>]
        # Strip the "config" subcommand and any scope flags from positional args
        pos_args = [a for a in cmd.args[1:] if not a.startswith("-")]
        if not pos_args:
            return
        key = pos_args[0]

        if not _is_dangerous_git_key(key):
            return

        value = pos_args[1] if len(pos_args) > 1 else ""
        yield _finding(
            f"git config --global {key} is a dangerous global mutation",
            f"git config --global {key} {value}".strip(),
            key=key, value=value,
        )
