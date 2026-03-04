"""
bashguard.rules.destructive — Flag irreversible filesystem destruction.

Detects:
- rm -rf on non-/tmp paths
- dd writing to devices
- mkfs (format filesystems)
- shred (secure delete)
- truncate (zero out files)
- git clean -fdx (untracked file wipe)
"""

from __future__ import annotations
import logging

from bashguard.parser import parse
from bashguard.models import Severity, Finding, ExecutionContext
from bashguard.rules import register

_log = logging.getLogger(__name__)

_SAFE_PREFIXES = ("/tmp",)

_ALWAYS_DESTRUCTIVE = {"mkfs", "mkfs.ext4", "mkfs.xfs", "mkfs.btrfs",
                       "mkfs.vfat", "shred", "wipefs"}


def _flags_contain(flags: list[str], chars: str) -> bool:
    for flag in flags:
        stripped = flag.lstrip("-")
        if all(c in stripped for c in chars):
            return True
    return False


def _is_tmp_safe(target: str) -> bool:
    clean = target.strip("'\"")
    return any(clean.startswith(p) for p in _SAFE_PREFIXES)


@register
class DestructiveRule:
    rule_id = "destructive.irreversible"
    severity = Severity.HIGH
    description = "Irreversible destructive filesystem operation"

    def check(self, script: str, context: ExecutionContext) -> list[Finding]:
        try:
            cmds = parse(script)
            findings = []

            for cmd in cmds:
                finding = None

                if cmd.name == "rm":
                    recursive = _flags_contain(cmd.flags, "r")
                    force = _flags_contain(cmd.flags, "f")
                    if recursive and force:
                        targets = [a for a in cmd.args if not a.startswith("-")]
                        for target in targets:
                            if not _is_tmp_safe(target):
                                finding = Finding(
                                    rule_id=self.rule_id,
                                    severity=Severity.CRITICAL,
                                    message=f"rm -rf on non-/tmp path: {target}",
                                    matched_text=cmd.raw,
                                    metadata={"command": "rm", "target": target},
                                )
                                break

                elif cmd.name == "dd":
                    # Flag dd writing to block devices
                    output = next(
                        (a for a in cmd.args if a.startswith("of=/dev/")), None
                    )
                    if output:
                        finding = Finding(
                            rule_id=self.rule_id,
                            severity=Severity.CRITICAL,
                            message=f"dd writing to device: {output}",
                            matched_text=cmd.raw,
                            metadata={"command": "dd", "output": output},
                        )

                elif cmd.name in _ALWAYS_DESTRUCTIVE:
                    finding = Finding(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        message=f"Destructive command: {cmd.name}",
                        matched_text=cmd.raw,
                        metadata={"command": cmd.name},
                    )

                elif cmd.name == "truncate":
                    finding = Finding(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        message="truncate can zero out files irreversibly",
                        matched_text=cmd.raw,
                        metadata={"command": "truncate"},
                    )

                elif cmd.name == "git":
                    subcommand = cmd.args[0] if cmd.args else ""
                    if subcommand == "clean":
                        has_f = _flags_contain(cmd.flags, "f")
                        if has_f:
                            finding = Finding(
                                rule_id=self.rule_id,
                                severity=self.severity,
                                message="git clean -f deletes untracked files irreversibly",
                                matched_text=cmd.raw,
                                metadata={"command": "git clean"},
                            )

                if finding:
                    findings.append(finding)

            return findings
        except Exception as e:
            _log.error("DestructiveRule raised: %s", e, exc_info=True)
            return []
