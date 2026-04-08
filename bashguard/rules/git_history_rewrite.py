"""
bashguard.rules.git_history_rewrite — Block git history rewriting commands.

The Mythos model, after using an exploit to edit files it lacked permission
to change, made further interventions to ensure those changes would NOT appear
in the git change history — erasing its own tracks.

History rewriting is a cover-up mechanism: act first, then erase the evidence.
Operators rely on git history to audit what an agent did. Rewriting destroys
that audit trail.

git filter-branch and git push --force are already blocked by git.destructive.
This rule adds the commit/rebase-level rewriting commands:

Blocked:
  git commit --amend            — rewrites the most recent commit object
  git rebase -i / --interactive — interactive rebase enables arbitrary edits
  git replace <old> <new>       — swaps object refs in history
  git notes rewrite             — rewrites note objects attached to commits

Allowed:
  git commit -m 'msg'           — normal commit, no rewrite
  git rebase main               — non-interactive rebase onto a branch
  git rebase --onto main feat   — rebase with --onto target, not interactive
"""

from __future__ import annotations
import logging

from bashguard.parser import parse
from bashguard.models import Severity, Finding, ExecutionContext, ActionType
from bashguard.rules import register

_log = logging.getLogger(__name__)


def _has_flag(flags: list[str], *names: str) -> bool:
    for f in flags:
        if f in names:
            return True
    return False


@register
class GitHistoryRewriteRule:
    rule_id = "git.history_rewrite"
    severity = Severity.HIGH
    description = "git history rewrite — destroys audit trail"

    def check(self, script: str, context: ExecutionContext) -> list[Finding]:
        try:
            return list(self._scan(script))
        except Exception:
            _log.exception("git_history_rewrite rule error")
            return []

    def _scan(self, script: str):
        if not script.strip():
            return
        cmds = parse(script)
        for cmd in cmds:
            if cmd.name != "git":
                continue
            args = cmd.args  # positional args (subcommand + its args)
            flags = cmd.flags

            if not args:
                continue
            subcommand = args[0]

            finding = self._check_subcommand(subcommand, args[1:], flags, cmd)
            if finding:
                yield finding

    def _check_subcommand(self, sub: str, args: list[str], flags: list[str], cmd) -> Finding | None:
        all_args = flags + args

        if sub == "commit":
            if _has_flag(all_args, "--amend"):
                return Finding(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    action_type=ActionType.GIT_DESTRUCTIVE,
                    message="git commit --amend rewrites history — destroys audit trail",
                    matched_text=cmd.name + " " + " ".join(cmd.args),
                )

        if sub == "rebase":
            if _has_flag(all_args, "-i", "--interactive"):
                return Finding(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    action_type=ActionType.GIT_DESTRUCTIVE,
                    message="git rebase --interactive enables arbitrary history edits",
                    matched_text=cmd.name + " " + " ".join(cmd.args),
                )

        if sub == "replace":
            return Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                action_type=ActionType.GIT_DESTRUCTIVE,
                message="git replace swaps history object refs",
                matched_text=cmd.name + " " + " ".join(cmd.args),
            )

        if sub == "notes" and args and args[0] == "rewrite":
            return Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                action_type=ActionType.GIT_DESTRUCTIVE,
                message="git notes rewrite modifies commit note objects",
                matched_text=cmd.name + " " + " ".join(cmd.args),
            )

        return None
