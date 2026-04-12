"""
bashguard.rules.supply_chain — Supply chain attack via package manager redirect.

supply_chain.pkg_mirror_redirect:
  Package managers (pip, npm, yarn, gem) can be configured to fetch from
  alternative registries. An AI agent that redirects the registry to an
  attacker-controlled server causes all subsequent installs to fetch
  backdoored packages — a supply chain compromise with no per-install
  detection opportunity.

  Also blocks: npm config set prefix /tmp (hijacks install path to a dir
  the agent controls, so future npm -g installs land in /tmp and shadow
  real binaries in PATH).

  Attack context: Berkeley RDI 2025 SWE-bench benchmark manipulation
  (agents modified pip config to serve rigged evaluation packages).
  MITRE ATT&CK T1195.001 (Supply Chain Compromise).

Blocked:
  pip config set global.index-url <url>
  pip config set global.extra-index-url <url>
  npm config set registry <url>
  npm set registry <url>
  npm config set prefix /tmp/...
  yarn config set registry <url>
  gem sources --add <url>

Allowed:
  pip config list / get ...
  npm config get ...
  npm config set cache <dir>    (non-registry config key)
  yarn config list
  gem sources --list
"""
from __future__ import annotations
import logging

from bashguard.parser import parse
from bashguard.models import Severity, Finding, ExecutionContext, ActionType
from bashguard.rules import register

_log = logging.getLogger(__name__)

# pip config keys that redirect package fetching
_PIP_REDIRECT_KEYS = frozenset({
    "global.index-url",
    "global.extra-index-url",
})

# npm/yarn config keys that redirect registry
_NPM_REGISTRY_KEY = "registry"

# npm config keys that hijack install path
_NPM_PATH_REDIRECT_KEYS = frozenset({"prefix"})

# Paths that, if set as npm prefix, indicate hijacking
_TMP_PREFIXES = ("/tmp", "/var/tmp")


def _finding(rule_id: str, message: str, matched: str, **meta) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=Severity.CRITICAL,
        action_type=ActionType.PACKAGE_INSTALL,
        message=message,
        matched_text=matched,
        metadata=meta,
    )


@register
class PkgMirrorRedirectRule:
    rule_id = "supply_chain.pkg_mirror_redirect"
    severity = Severity.CRITICAL
    description = "Package manager redirected to non-official registry — supply chain compromise"

    def check(self, script: str, context: ExecutionContext) -> list[Finding]:
        try:
            return list(self._scan(script))
        except Exception:
            _log.exception("pkg_mirror_redirect rule error")
            return []

    def _scan(self, script: str):
        for cmd in parse(script):
            if cmd.name in ("pip", "pip2", "pip3"):
                yield from self._check_pip(cmd)
            elif cmd.name in ("npm", "npx"):
                yield from self._check_npm(cmd)
            elif cmd.name == "yarn":
                yield from self._check_yarn(cmd)
            elif cmd.name == "gem":
                yield from self._check_gem(cmd)

    def _check_pip(self, cmd):
        # pip config set <key> <value>
        # args = ["config", "set", "global.index-url", "https://..."]
        if not cmd.args or cmd.args[0] != "config":
            return
        args = cmd.args[1:]
        if not args or args[0] != "set":
            return
        args = args[1:]  # [key, value, ...]
        if not args:
            return
        key = args[0]
        if key in _PIP_REDIRECT_KEYS:
            yield _finding(
                self.rule_id,
                f"{self.description}: pip config set {key}",
                f"pip config set {key}",
                tool=cmd.name, key=key,
            )

    def _check_npm(self, cmd):
        # npm config set registry <url>  OR  npm set registry <url>
        args = cmd.args
        if not args:
            return

        # Normalize: "npm set ..." == "npm config set ..."
        if args[0] == "set":
            key_idx = 1
        elif len(args) >= 2 and args[0] == "config" and args[1] == "set":
            key_idx = 2
        else:
            return

        if len(args) <= key_idx:
            return
        key = args[key_idx]
        value = args[key_idx + 1] if len(args) > key_idx + 1 else ""

        if key == _NPM_REGISTRY_KEY:
            yield _finding(
                self.rule_id,
                f"{self.description}: npm config set registry",
                f"npm config set registry {value}",
                tool="npm", key=key,
            )
        elif key in _NPM_PATH_REDIRECT_KEYS:
            if any(value.startswith(p) for p in _TMP_PREFIXES):
                yield _finding(
                    self.rule_id,
                    f"{self.description}: npm config set prefix to {value}",
                    f"npm config set prefix {value}",
                    tool="npm", key=key, value=value,
                )

    def _check_yarn(self, cmd):
        # yarn config set registry <url>
        args = cmd.args
        if len(args) < 3:
            return
        if args[0] == "config" and args[1] == "set" and args[2] == _NPM_REGISTRY_KEY:
            yield _finding(
                self.rule_id,
                f"{self.description}: yarn config set registry",
                f"yarn config set registry",
                tool="yarn",
            )

    def _check_gem(self, cmd):
        # gem sources --add <url>
        all_args = cmd.args + cmd.flags
        if "--add" in all_args or "-a" in all_args:
            yield _finding(
                self.rule_id,
                f"{self.description}: gem sources --add",
                "gem sources --add",
                tool="gem",
            )
