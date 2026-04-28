"""
bashguard.rules.forbidden_binary — Binaries with no legitimate use in an
automated coding assistant context.

An LLM assistant helping with software development has no reason to invoke
offensive security tools, GUI applications, or legacy system utilities.
Presence of these commands almost certainly indicates either jailbreaking,
prompt injection, or a misconfigured script that should be stopped.

Sources include GTFOBins (https://gtfobins.github.io/) for shell-escape
capability verification, plus general security tooling knowledge.
"""
from __future__ import annotations

import logging

from bashguard.models import ActionType, ExecutionContext, Finding, Severity
from bashguard.parser import parse
from bashguard.rules import register

_log = logging.getLogger(__name__)

# Offensive security / exploitation frameworks
_OFFENSIVE_TOOLS = frozenset({
    "msfconsole", "msfvenom", "msfrpc",       # Metasploit
    "sqlmap",                                  # SQL injection automation
    "volatility", "vol.py",                   # Memory forensics
    "scanmem", "gameconqueror",                # Memory scanner
    "aircrack-ng", "airodump-ng",             # WiFi cracking
    "aireplay-ng", "airmon-ng",
    "hashcat", "john", "hydra",               # Password cracking
    "crunch",                                  # Wordlist generator
    "responder",                               # LLMNR/NBT-NS poisoner
    "bloodhound",                              # AD enumeration
    "crackmapexec", "cme",                    # Network exploitation
})

# GUI applications — LLM assistants never open graphical programs
_GUI_APPS = frozenset({
    "zathura",                                 # PDF viewer
    "gimp",                                    # Image editor
    "wireshark",                               # GUI packet analyzer
    "xdotool",                                 # X11 input automation
    "xpad",                                    # Desktop sticky notes
    "xmore",                                   # X11 pager
    "scrot",                                   # Screenshot tool
    "xmodmap",                                 # X11 keymap modifier
})

# Legacy / exotic interpreters and utilities with no modern coding use
_LEGACY_EXOTIC = frozenset({
    "crash",                                   # Kernel crash dump analyzer
    "debugfs",                                 # ext2/3/4 filesystem debugger
    "jrunscript",                              # Oracle Nashorn JS (removed Java 15+)
    "jjs",                                     # Oracle Nashorn shell (removed Java 15+)
    "dvips",                                   # TeX DVI to PostScript
    "ginsh",                                   # GNU inet shell
    "enscript",                                # Text to PostScript
    "jtag",                                    # JTAG hardware debugger
    "ksu",                                     # Kerberos-aware su
    "rtorrent",                                # BitTorrent client
    "slsh",                                    # S-Lang interpreter shell
    "tdbtool",                                 # Trivial Database shell
    "byebug",                                  # Ruby debugger (shell escape)
    "pry",                                     # Ruby REPL (shell escape)
})

_ALL_FORBIDDEN = _OFFENSIVE_TOOLS | _GUI_APPS | _LEGACY_EXOTIC


@register
class ForbiddenBinaryRule:
    rule_id = "exec.forbidden_binary"
    severity = Severity.HIGH
    description = "Binary with no legitimate use in an automated coding context"

    def check(self, script: str, _context: ExecutionContext) -> list[Finding]:
        try:
            findings: list[Finding] = []
            for cmd in parse(script):
                if cmd.name in _ALL_FORBIDDEN:
                    category = (
                        "offensive tool" if cmd.name in _OFFENSIVE_TOOLS
                        else "GUI application" if cmd.name in _GUI_APPS
                        else "legacy/exotic utility"
                    )
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        message=f"'{cmd.name}' is a {category} with no legitimate automated use",
                        matched_text=cmd.raw,
                        action_type=ActionType.UNKNOWN,
                    ))
            return findings
        except Exception:
            _log.exception("ForbiddenBinaryRule error")
            return []
