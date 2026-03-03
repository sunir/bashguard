"""
bash_audit.rules.git_scope — Flag destructive git operations.

Detects:
- git push --force / -f (history rewrite on remote)
- git push to protected branches (main, master, production)
- git reset --hard (irreversible local state change)
- git clean -f (untracked file deletion — also caught by destructive rule)
- git branch -D (forced branch deletion)

Safe operations (read-only or reversible) are not flagged:
- git status, log, diff, show, fetch, pull, add, commit, checkout, stash
"""

from __future__ import annotations
import logging

from bash_ast.parser import parse
from bash_audit.models import Severity, Finding, ExecutionContext
from bash_audit.rules import register

_log = logging.getLogger(__name__)

_PROTECTED_BRANCHES = {"main", "master", "production", "prod", "release"}

_READONLY_SUBCOMMANDS = {
    "status", "log", "diff", "show", "fetch", "ls-files",
    "ls-tree", "describe", "shortlog", "blame", "bisect",
    "rev-parse", "rev-list", "cat-file",
}


@register
class GitScopeRule:
    rule_id = "git.destructive"
    severity = Severity.HIGH
    description = "Destructive git operation (force push, reset --hard, branch deletion)"

    def check(self, script: str, context: ExecutionContext) -> list[Finding]:
        try:
            cmds = parse(script)
            findings = []

            for cmd in cmds:
                if cmd.name != "git":
                    continue

                subcommand = cmd.args[0] if cmd.args else ""

                if subcommand in _READONLY_SUBCOMMANDS:
                    continue

                finding = None

                if subcommand == "push":
                    is_force = "--force" in cmd.flags or "-f" in cmd.flags
                    if is_force:
                        finding = Finding(
                            rule_id=self.rule_id,
                            severity=Severity.CRITICAL,
                            message="git push --force rewrites remote history",
                            matched_text=cmd.raw,
                            metadata={"subcommand": "push", "flags": cmd.flags},
                        )
                    else:
                        positional = [a for a in cmd.args[1:] if not a.startswith("-")]
                        branch = positional[-1] if positional else ""
                        if branch in _PROTECTED_BRANCHES:
                            finding = Finding(
                                rule_id=self.rule_id,
                                severity=self.severity,
                                message=f"git push to protected branch: {branch}",
                                matched_text=cmd.raw,
                                metadata={"subcommand": "push", "branch": branch},
                            )

                elif subcommand == "reset":
                    if "--hard" in cmd.flags:
                        finding = Finding(
                            rule_id=self.rule_id,
                            severity=self.severity,
                            message="git reset --hard discards uncommitted changes irreversibly",
                            matched_text=cmd.raw,
                            metadata={"subcommand": "reset"},
                        )

                elif subcommand == "clean":
                    # -f required to actually delete; -fdx is common variant
                    all_flag_chars = "".join(f.lstrip("-") for f in cmd.flags)
                    if "f" in all_flag_chars or "--force" in cmd.flags:
                        finding = Finding(
                            rule_id=self.rule_id,
                            severity=self.severity,
                            message="git clean -f deletes untracked files irreversibly",
                            matched_text=cmd.raw,
                            metadata={"subcommand": "clean"},
                        )

                elif subcommand == "branch":
                    if "-D" in cmd.flags or "--delete" in cmd.flags:
                        finding = Finding(
                            rule_id=self.rule_id,
                            severity=self.severity,
                            message="git branch -D force-deletes a branch",
                            matched_text=cmd.raw,
                            metadata={"subcommand": "branch"},
                        )

                if finding:
                    findings.append(finding)

            return findings
        except Exception as e:
            _log.error("GitScopeRule raised: %s", e, exc_info=True)
            return []
