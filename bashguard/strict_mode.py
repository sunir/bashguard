"""
bashguard.strict_mode — Allowlist-only mode (Layer 3).

When enabled, only commands from DEFAULT_SAFE_COMMANDS are permitted.
Everything else produces a CRITICAL finding → BLOCK.

Inspired by n2-ark's strictMode and specs/05-fail-close.md Layer 3.

NOT registered by default — enable via .bashguard.yaml or explicit rule loading.
"""
from __future__ import annotations

import logging

from bashguard.models import ActionType, ExecutionContext, Finding, Severity
from bashguard.parser import parse

_log = logging.getLogger(__name__)

# Known-safe commands for a typical dev workflow.
# Conservative: better to miss a safe command (user adds it) than
# to include a dangerous one.
DEFAULT_SAFE_COMMANDS: frozenset[str] = frozenset({
    # Shell builtins
    "echo", "printf", "test", "true", "false", "exit", "return",
    "cd", "pwd", "pushd", "popd", "dirs",
    "export", "unset", "set", "shift", "read",
    "if", "then", "else", "fi", "for", "while", "do", "done",
    "case", "esac", "select", "until",
    "break", "continue", "trap", "wait", "sleep",
    "type", "which", "command", "builtin", "hash",

    # File operations (read-only or low-risk)
    "ls", "cat", "head", "tail", "less", "more",
    "wc", "sort", "uniq", "cut", "tr", "paste",
    "grep", "egrep", "fgrep", "rg",
    "find", "xargs", "file", "stat",
    "diff", "comm", "cmp",
    "tee", "touch", "mkdir", "mktemp",
    "cp", "mv", "ln", "rm",  # Note: rm is here but destructive rule catches rm -rf
    "basename", "dirname", "realpath", "readlink",

    # Text processing
    "sed", "awk", "jq", "yq", "csvtool",

    # Version control
    "git", "gh",

    # Package managers (install rules catch dangerous flags)
    "npm", "npx", "yarn", "pnpm",
    "pip", "pip3", "uv", "pipx",
    "cargo", "rustup",
    "go", "gem", "bundle",
    "brew", "apt", "apt-get", "dnf", "yum", "pacman",
    "composer",

    # Language runtimes
    "python", "python3", "python2",
    "node", "deno", "bun",
    "ruby", "perl", "php",
    "rustc", "gcc", "g++", "clang", "clang++",
    "java", "javac", "kotlin", "kotlinc",

    # Build tools
    "make", "cmake", "ninja", "meson",
    "tsc", "esbuild", "vite", "webpack",
    "pytest", "jest", "mocha", "vitest",

    # System info (read-only)
    "date", "cal", "uptime", "uname",
    "whoami", "id", "groups",
    "env", "printenv",
    "ps", "top", "htop",
    "df", "du", "free",
    "hostname", "arch",

    # Network (basic, network rule catches dangerous hosts)
    "curl", "wget", "ping", "dig", "nslookup", "host",

    # Compression
    "tar", "gzip", "gunzip", "bzip2", "xz", "zip", "unzip",

    # Docker (common in dev)
    "docker", "docker-compose", "podman",
    "kubectl", "helm",
})


class StrictModeRule:
    """Block any command not in the safe vocabulary.

    Not registered by default — must be explicitly enabled.
    """
    rule_id = "strict.unknown_command"
    severity = Severity.CRITICAL
    description = "Command not in strict-mode allowlist"

    def __init__(self, safe_commands: frozenset[str] | None = None):
        self._safe = safe_commands or DEFAULT_SAFE_COMMANDS

    def check(self, script: str, context: ExecutionContext) -> list[Finding]:
        try:
            cmds = parse(script)
            findings: list[Finding] = []
            for cmd in cmds:
                # Relative/absolute paths are always unknown
                if cmd.name.startswith("/") or cmd.name.startswith("./") or \
                   cmd.name.startswith("../"):
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        message=f"Path-based command not in allowlist: {cmd.name}",
                        matched_text=cmd.raw,
                        action_type=ActionType.UNKNOWN,
                    ))
                elif cmd.name not in self._safe:
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        message=f"Command '{cmd.name}' not in strict-mode allowlist",
                        matched_text=cmd.raw,
                        action_type=ActionType.UNKNOWN,
                    ))
            return findings
        except Exception as e:
            _log.error("StrictModeRule raised: %s", e, exc_info=True)
            return []
