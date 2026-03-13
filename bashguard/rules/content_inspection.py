"""
bashguard.rules.content_inspection — Payload-level content inspection.

Three-layer inspection:
1. Secret patterns in args  (rule_id: content.secret_in_args)
   API keys, PEM headers, tokens in command arguments → CREDENTIAL_ACCESS
2. Exfiltration patterns    (rule_id: content.exfiltration_pattern)
   Sensitive files piped/posted to network endpoints → NETWORK_OUTBOUND
3. Project boundary         (rule_id: content.outside_boundary)
   File paths outside the worktree root → FILESYSTEM_READ

All findings are CRITICAL severity.
"""
from __future__ import annotations

import logging
import os
import re

from bashguard.models import ActionType, ExecutionContext, Finding, Severity
from bashguard.parser import parse
from bashguard.rules import register

_log = logging.getLogger(__name__)

# ─── Secret patterns (in command args / flags) ─────────────────────────────

_SECRET_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("AWS access key", re.compile(r'\bAKIA[0-9A-Z]{16}\b')),
    ("PEM private key header", re.compile(r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----')),
    ("GitHub PAT token", re.compile(r'\bghp_[A-Za-z0-9]{36}\b')),
    ("GitHub App token", re.compile(r'\bghs_[A-Za-z0-9]{36}\b')),
    ("OpenAI/Anthropic-style key", re.compile(r'\bsk-(?:proj-)?[A-Za-z0-9]{20,}\b')),
    ("Generic high-entropy bearer", re.compile(
        r'(?i)(?:Bearer|token|api[_-]?key|secret)[:\s]+([A-Za-z0-9+/=_-]{20,})',
    )),
]

# ─── Sensitive source paths (for exfiltration detection) ───────────────────

_SENSITIVE_PATH_PATTERNS: list[re.Pattern] = [
    re.compile(r'@~/\.ssh/'),
    re.compile(r'@~/.aws/'),
    re.compile(r'@/etc/(passwd|shadow|sudoers)'),
    re.compile(r'@~/\.netrc'),
    re.compile(r'@~/\.gnupg/'),
]

_SENSITIVE_SOURCES: frozenset[str] = frozenset({
    "~/.ssh", "~/.aws", "~/.gnupg", "~/.netrc",
    "/etc/passwd", "/etc/shadow", "/etc/sudoers",
})

# ─── Safe prefixes for boundary check ──────────────────────────────────────

_BOUNDARY_EXEMPT_PREFIXES = ("/tmp", "/var/tmp", "/dev/null", "/dev/stdin",
                              "/dev/stdout", "/dev/stderr")


def _looks_like_path(token: str) -> bool:
    clean = token.strip("'\"@")
    return clean.startswith("/") or clean.startswith("~/") or clean.startswith("~")


def _is_sensitive_source(path: str) -> bool:
    clean = path.strip("'\"@")
    for s in _SENSITIVE_SOURCES:
        if clean.startswith(s):
            return True
    return False


def _all_args(script: str) -> list[str]:
    """Collect all args and flags from parsed commands."""
    try:
        cmds = parse(script)
        parts: list[str] = []
        for cmd in cmds:
            parts.append(cmd.name)
            parts.extend(cmd.args)
            parts.extend(cmd.flags)
            parts.extend(cmd.redirect_targets)
        return parts
    except Exception:
        return []


def _check_secret_in_args(script: str) -> list[Finding]:
    """Look for secret patterns in any command argument."""
    findings: list[Finding] = []
    for token in _all_args(script):
        for label, pattern in _SECRET_PATTERNS:
            if pattern.search(token):
                findings.append(Finding(
                    rule_id="content.secret_in_args",
                    severity=Severity.CRITICAL,
                    message=f"Possible {label} in command arguments",
                    matched_text=token[:80],
                    action_type=ActionType.CREDENTIAL_ACCESS,
                ))
                break  # one finding per token
    return findings


def _check_exfiltration(script: str) -> list[Finding]:
    """Detect sensitive file contents being sent over the network."""
    findings: list[Finding] = []
    try:
        cmds = parse(script)
        # Collect all paths seen in the pipeline
        seen_sensitive: list[str] = []
        has_network_cmd = False

        network_cmds = {"curl", "wget", "nc", "ncat", "netcat", "socat"}

        for cmd in cmds:
            if cmd.name in network_cmds:
                has_network_cmd = True

            for arg in cmd.args + cmd.flags + cmd.redirect_targets:
                if _is_sensitive_source(arg):
                    seen_sensitive.append(arg)

            # @- (stdin from pipe) combined with sensitive pipe predecessor
            if cmd.name in network_cmds and "@-" in cmd.args:
                # Check if earlier commands reference sensitive files
                # (approximated by seen_sensitive from earlier cmds)
                if seen_sensitive:
                    findings.append(Finding(
                        rule_id="content.exfiltration_pattern",
                        severity=Severity.CRITICAL,
                        message=(
                            f"Sensitive data piped to {cmd.name} — "
                            f"possible exfiltration of {seen_sensitive[0]}"
                        ),
                        matched_text=cmd.raw,
                        action_type=ActionType.NETWORK_OUTBOUND,
                    ))

            # Direct @path to network command
            if cmd.name in network_cmds:
                for arg in cmd.args + cmd.flags:
                    if _is_sensitive_source(arg):
                        findings.append(Finding(
                            rule_id="content.exfiltration_pattern",
                            severity=Severity.CRITICAL,
                            message=f"Sensitive path '{arg.strip(chr(39)+chr(34))}' sent via {cmd.name}",
                            matched_text=cmd.raw,
                            action_type=ActionType.NETWORK_OUTBOUND,
                        ))

    except Exception as e:
        _log.error("ContentInspectionRule exfiltration check raised: %s", e, exc_info=True)
    return findings


def _check_boundary(script: str, context: ExecutionContext) -> list[Finding]:
    """Flag file accesses outside the worktree root."""
    if not context.worktree_root:
        return []

    home = context.env_vars.get("HOME", os.path.expanduser("~"))
    worktree = os.path.normpath(context.worktree_root)
    findings: list[Finding] = []

    for token in _all_args(script):
        clean = token.strip("'\"@")
        # Expand ~ prefix
        if clean.startswith("~/"):
            clean = home + clean[1:]
        elif clean == "~":
            clean = home

        if not clean.startswith("/"):
            continue  # relative path — can't check

        # Exempt tmp and device paths
        if any(clean.startswith(p) for p in _BOUNDARY_EXEMPT_PREFIXES):
            continue

        real = os.path.normpath(clean)
        if not real.startswith(worktree):
            findings.append(Finding(
                rule_id="content.outside_boundary",
                severity=Severity.HIGH,
                message=f"File access outside worktree boundary: {clean}",
                matched_text=token,
                action_type=ActionType.FILESYSTEM_READ,
            ))
    return findings


@register
class ContentInspectionRule:
    rule_id = "content.inspection"  # parent rule_id (sub-rules have own IDs)
    severity = Severity.CRITICAL
    description = "Content inspection: secrets in args, exfiltration, boundary violations"

    def check(self, script: str, context: ExecutionContext) -> list[Finding]:
        try:
            findings: list[Finding] = []
            findings.extend(_check_secret_in_args(script))
            findings.extend(_check_exfiltration(script))
            findings.extend(_check_boundary(script, context))
            return findings
        except Exception as e:
            _log.error("ContentInspectionRule raised: %s", e, exc_info=True)
            return []
