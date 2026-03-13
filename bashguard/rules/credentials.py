"""
bashguard.rules.credentials — Flag access to credential files and directories.

Detects when a command references paths known to contain secrets:
SSH keys, AWS credentials, GnuPG keys, .env files, /etc/passwd, etc.

Uses the bash_ast CommandNode for ergonomic path checking across
args, flags, and redirect targets.
"""

from __future__ import annotations
import logging
import os

from bashguard.parser import parse
from bashguard.models import Severity, Finding, ExecutionContext, ActionType
from bashguard.rules import register

_log = logging.getLogger(__name__)

_PROTECTED_DIRS = (
    "~/.ssh",
    "~/.aws",
    "~/.gnupg",
    "~/.config/gcloud",
    "~/.kube",
    "~/.netrc",
)

_PROTECTED_EXACT = (
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/hosts",
    "~/.bash_history",
    "~/.zsh_history",
    "~/.profile",
    "~/.bashrc",
    "~/.zshrc",
)

_ENV_FILE_SUFFIXES = (".env",)
_ENV_FILE_NAMES = {".env"}


def _is_protected(path: str, home: str) -> bool:
    expanded = path.replace("~", home)
    raw = path

    for protected in _PROTECTED_DIRS:
        expanded_p = protected.replace("~", home)
        if expanded.startswith(expanded_p) or raw.startswith(protected):
            return True

    for exact in _PROTECTED_EXACT:
        expanded_e = exact.replace("~", home)
        if expanded == expanded_e or raw == exact:
            return True

    # .env files: basename is .env or starts with .env.
    basename = os.path.basename(path)
    if basename in _ENV_FILE_NAMES:
        return True
    if basename.startswith(".env.") or basename.endswith(".env"):
        return True

    return False


@register
class CredentialsRule:
    rule_id = "credentials.privileged_path"
    severity = Severity.CRITICAL
    description = "Access to credential files or directories (SSH keys, AWS, .env, etc.)"

    def check(self, script: str, context: ExecutionContext) -> list[Finding]:
        try:
            home = context.env_vars.get("HOME", os.path.expanduser("~"))
            cmds = parse(script)
            findings = []

            for cmd in cmds:
                all_paths = cmd.args + cmd.flags + cmd.redirect_targets
                for path in all_paths:
                    clean = path.strip("'\"").lstrip("@")
                    if _is_protected(clean, home):
                        findings.append(Finding(
                            rule_id=self.rule_id,
                            severity=self.severity,
                            message=f"Access to protected credential path: {clean}",
                            matched_text=cmd.raw,
                            metadata={"path": clean, "command": cmd.name},
                            action_type=ActionType.CREDENTIAL_ACCESS,
                        ))
                        break  # one finding per command is enough

            return findings
        except Exception as e:
            _log.error("CredentialsRule raised: %s", e, exc_info=True)
            return []
