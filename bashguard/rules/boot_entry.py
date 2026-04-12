"""
bashguard.rules.boot_entry — Boot/login persistence via autostart entries.

persistence.boot_entry:
  Writing to autostart directories or loading launch agents establishes
  boot persistence — the malicious program runs automatically on every login
  without any further agent involvement.

  Linux autostart (GNOME/KDE/XFCE):
    ~/.config/autostart/*.desktop — XDG autostart spec, runs on desktop login

  macOS LaunchAgent / LaunchDaemon (MITRE T1543.001):
    ~/Library/LaunchAgents/*.plist — per-user, runs on login
    /Library/LaunchAgents/*.plist — system-level, runs on login
    /Library/LaunchDaemons/*.plist — system-level, runs as root on boot
    launchctl load / bootstrap — activates a plist immediately

  macOS login hook:
    defaults write com.apple.loginwindow LoginHook — legacy but still works

  systemd user units:
    ~/.config/systemd/user/*.service / *.timer — user-level persistent units

MITRE ATT&CK T1543.001 (Launch Agent), T1543.004 (Launch Daemon),
T1547.011 (Plist Modification), T1037 (Boot/Logon Initialization Scripts).
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

# Tilde paths that are autostart locations (writes = persistence)
_AUTOSTART_TILDE_PREFIXES = (
    "~/Library/LaunchAgents/",      # macOS user LaunchAgent
    "~/.config/autostart/",         # Linux XDG autostart
    "~/.config/systemd/user/",      # systemd user units
)

# Absolute paths that are autostart locations
_AUTOSTART_ABS_PREFIXES = (
    "/Library/LaunchAgents/",       # macOS system LaunchAgent
    "/Library/LaunchDaemons/",      # macOS system LaunchDaemon (root)
)

# launchctl subcommands that activate a plist (dangerous)
_LAUNCHCTL_LOAD_CMDS = frozenset({"load", "bootstrap", "enable"})

# defaults LoginHook key — macOS login persistence via defaults
_DEFAULTS_LOGINWINDOW = "com.apple.loginwindow"
_DEFAULTS_HOOK_KEYS = frozenset({"LoginHook", "LogoutHook"})


def _is_autostart_path(path: str) -> bool:
    """Return True if path is an autostart/launch persistence location."""
    clean = path.strip("'\"")
    for prefix in _AUTOSTART_TILDE_PREFIXES:
        if clean.startswith(prefix) or clean == prefix.rstrip("/"):
            return True
    for prefix in _AUTOSTART_ABS_PREFIXES:
        if clean.startswith(prefix) or clean == prefix.rstrip("/"):
            return True
    return False


def _collect(root, *node_types: str) -> list:
    results = []
    stack = [root]
    while stack:
        node = stack.pop()
        if node.type in node_types:
            results.append(node)
        stack.extend(node.children)
    return results


def _text(node, source: bytes) -> str:
    return source[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def _walk_write_redirects(root, source: bytes) -> list[str]:
    targets = []
    for redir in _collect(root, "file_redirect"):
        has_write_op = any(child.type in (">", ">>") for child in redir.children)
        if not has_write_op:
            continue
        for child in redir.children:
            if child.type in ("word", "string", "raw_string"):
                targets.append(_text(child, source))
    return targets


def _finding(message: str, matched: str, **meta) -> Finding:
    return Finding(
        rule_id="persistence.boot_entry",
        severity=Severity.HIGH,
        action_type=ActionType.SYSTEM_CONFIG,
        message=message,
        matched_text=matched,
        metadata=meta,
    )


@register
class BootEntryRule:
    rule_id = "persistence.boot_entry"
    severity = Severity.HIGH
    description = "Write to autostart/launch directory establishes boot persistence"

    def check(self, script: str, context: ExecutionContext) -> list[Finding]:
        try:
            return list(self._scan(script))
        except Exception:
            _log.exception("boot_entry rule error")
            return []

    def _scan(self, script: str):
        source = script.encode("utf-8", errors="replace")
        tree = _PARSER.parse(source)
        root = tree.root_node

        # 1. Redirect writes: > ~/Library/LaunchAgents/foo.plist
        for target in _walk_write_redirects(root, source):
            clean = target.strip("'\"")
            if _is_autostart_path(clean):
                yield _finding(
                    f"{self.description}: write to {clean}",
                    f"... > {clean}",
                    path=clean,
                )
                return

        # 2. cp / mv / tee with autostart destination
        for cmd in parse(script):
            if cmd.name in ("cp", "mv"):
                pos_args = [a for a in cmd.args if not a.startswith("-")]
                if pos_args and _is_autostart_path(pos_args[-1]):
                    dest = pos_args[-1].strip("'\"")
                    yield _finding(
                        f"{self.description}: {cmd.name} to {dest}",
                        f"{cmd.name} ... {dest}",
                        path=dest,
                    )
                    return

            elif cmd.name == "tee":
                for arg in cmd.args:
                    if _is_autostart_path(arg):
                        dest = arg.strip("'\"")
                        yield _finding(
                            f"{self.description}: tee to {dest}",
                            f"tee {dest}",
                            path=dest,
                        )
                        return

            elif cmd.name == "launchctl":
                if not cmd.args:
                    continue
                subcmd = cmd.args[0]
                if subcmd in _LAUNCHCTL_LOAD_CMDS:
                    yield _finding(
                        f"launchctl {subcmd} activates a launch agent/daemon",
                        f"launchctl {subcmd}",
                        subcmd=subcmd,
                    )
                    return

            elif cmd.name == "defaults":
                # defaults write com.apple.loginwindow LoginHook /path
                # args = ["write", "com.apple.loginwindow", "LoginHook", "/path"]
                args = cmd.args
                if (len(args) >= 3 and args[0] == "write"
                        and args[1] == _DEFAULTS_LOGINWINDOW
                        and args[2] in _DEFAULTS_HOOK_KEYS):
                    yield _finding(
                        f"defaults write loginwindow {args[2]} sets macOS login persistence",
                        f"defaults write {args[1]} {args[2]}",
                        domain=args[1], key=args[2],
                    )
                    return
