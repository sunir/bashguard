"""
bashguard.rules.local_pkg_keylogger — Local package install, xinput keylogger, osascript abuse.

package.local_install:
  dpkg -i and rpm -i install packages from local .deb/.rpm files — not from
  a trusted repository. In the 82-incident database, agents downloaded malicious
  packages to /tmp and installed them to run pre/post-install scripts as root.
  pip install with a path argument (not a package name) similarly installs
  arbitrary code from the filesystem. PyPI package names are allowed.

proc.xinput_keylogger:
  xinput test <id> reads raw keyboard events from X input devices — a software
  keylogger. xinput list (diagnostic) and xinput list-props (query) are safe.
  Only 'test' and 'test-xi2' subcommands capture live keystrokes.

proc.osascript_abuse:
  osascript executes AppleScript on macOS. When the script contains 'keystroke'
  (simulating user input) or 'get the clipboard' (clipboard read), it is being
  used for input capture or data theft. Legitimate osascript use (automation,
  notifications) does not need to read input events or clipboard content.
"""
from __future__ import annotations
import logging

from bashguard.parser import parse
from bashguard.models import Severity, Finding, ExecutionContext, ActionType
from bashguard.rules import register

_log = logging.getLogger(__name__)

# xinput subcommands that read live events (keylogger)
_XINPUT_KEYLOG_SUBCMDS = frozenset({"test", "test-xi2"})

# pip subcommands that install packages
_PIP_INSTALL_SUBCMDS = frozenset({"install"})


def _is_local_path(arg: str) -> bool:
    """Return True if arg looks like a filesystem path (not a package name)."""
    return (
        arg.startswith("/")
        or arg.startswith("./")
        or arg.startswith("../")
        or arg.startswith("~/")
        or (arg.endswith(".deb") or arg.endswith(".rpm") or arg.endswith(".whl"))
    )


@register
class LocalPackageInstallRule:
    rule_id = "package.local_install"
    severity = Severity.CRITICAL
    description = "Local package install bypasses trusted repository — pre/post scripts run as root"

    def check(self, script: str, context: ExecutionContext) -> list[Finding]:
        try:
            return list(self._scan(script))
        except Exception:
            _log.exception("local_install rule error")
            return []

    def _scan(self, script: str):
        if not script.strip():
            return
        cmds = parse(script)
        for cmd in cmds:
            if cmd.name == "dpkg":
                # dpkg -i <file> — install from local file
                # dpkg -l, --status, --query are safe
                all_args = cmd.args + cmd.flags
                if "-i" not in all_args and "--install" not in all_args:
                    continue
                # Check if any arg looks like a local file path
                for arg in cmd.args:
                    if _is_local_path(arg) or arg.endswith(".deb"):
                        yield Finding(
                            rule_id=self.rule_id,
                            severity=self.severity,
                            action_type=ActionType.PACKAGE_INSTALL,
                            message=f"{self.description}: dpkg -i {arg}",
                            matched_text=f"dpkg -i {arg}",
                        )
                        break

            elif cmd.name == "rpm":
                all_args = cmd.args + cmd.flags
                if "-i" not in all_args and "--install" not in all_args:
                    continue
                for arg in cmd.args:
                    if _is_local_path(arg) or arg.endswith(".rpm"):
                        yield Finding(
                            rule_id=self.rule_id,
                            severity=self.severity,
                            action_type=ActionType.PACKAGE_INSTALL,
                            message=f"{self.description}: rpm -i {arg}",
                            matched_text=f"rpm -i {arg}",
                        )
                        break

            elif cmd.name in ("pip", "pip2", "pip3"):
                # pip install <path> — local path install
                # pip install <name> or <name>==version — PyPI, allowed
                if not cmd.args or cmd.args[0] not in _PIP_INSTALL_SUBCMDS:
                    continue
                # Check args after 'install' for local paths
                install_args = cmd.args[1:]
                for arg in install_args:
                    if _is_local_path(arg):
                        yield Finding(
                            rule_id=self.rule_id,
                            severity=self.severity,
                            action_type=ActionType.PACKAGE_INSTALL,
                            message=f"{self.description}: pip install from local path {arg}",
                            matched_text=f"pip install {arg}",
                        )
                        break


@register
class XinputKeyloggerRule:
    rule_id = "proc.xinput_keylogger"
    severity = Severity.HIGH
    description = "xinput test reads raw keyboard events — software keylogger"

    def check(self, script: str, context: ExecutionContext) -> list[Finding]:
        try:
            return list(self._scan(script))
        except Exception:
            _log.exception("xinput_keylogger rule error")
            return []

    def _scan(self, script: str):
        if not script.strip():
            return
        cmds = parse(script)
        for cmd in cmds:
            if cmd.name != "xinput":
                continue
            # First non-flag arg is the subcommand
            subcmd = next((a for a in cmd.args if not a.startswith("-")), "")
            if subcmd in _XINPUT_KEYLOG_SUBCMDS:
                yield Finding(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    action_type=ActionType.CREDENTIAL_ACCESS,
                    message=f"{self.description}: xinput {subcmd}",
                    matched_text=f"xinput {subcmd}",
                )


# AppleScript keywords that indicate input capture or data theft
_OSASCRIPT_ABUSE_KEYWORDS = (
    "keystroke",          # Simulates user keyboard input
    "get the clipboard",  # Reads clipboard contents
    "key code",           # Low-level key event injection
    "login item",         # macOS login persistence (MITRE T1547.011): make/delete login item
)


@register
class OsascriptAbuseRule:
    rule_id = "proc.osascript_abuse"
    severity = Severity.HIGH
    description = "osascript executes AppleScript for input capture or clipboard theft"

    def check(self, script: str, context: ExecutionContext) -> list[Finding]:
        try:
            return list(self._scan(script))
        except Exception:
            _log.exception("osascript_abuse rule error")
            return []

    def _scan(self, script: str):
        if not script.strip():
            return
        cmds = parse(script)
        for cmd in cmds:
            if cmd.name != "osascript":
                continue
            all_args = cmd.args + cmd.flags
            joined = " ".join(all_args).lower()
            for keyword in _OSASCRIPT_ABUSE_KEYWORDS:
                if keyword in joined:
                    yield Finding(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        action_type=ActionType.CREDENTIAL_ACCESS,
                        message=f"{self.description}: '{keyword}' in script",
                        matched_text=f"osascript ... {keyword}",
                    )
                    break
