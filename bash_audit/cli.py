"""
bash_audit.cli — bash-audit command-line interface.

Usage:
    bash-audit [COMMAND]         audit COMMAND string
    bash-audit --stdin           read command from stdin
    bash-audit --help            show this help

Options:
    --cwd PATH           working directory for context (default: $PWD)
    --worktree PATH      git worktree root (default: auto-detect)
    --allowed-host HOST  add to allowed hosts (repeatable)
    --format json|text   output format (default: json)

Exit codes:
    0   ALLOW
    1   BLOCK
    2   CONFIRM
    3   REDIRECT
    10  usage error
    11  config error
    12  internal error

JSON output is always written to stdout.
Error messages go to stderr.
"""

from __future__ import annotations
import argparse
import json
import sys
import os

from bash_audit.auditor import audit
from bash_audit.context import make_context
from bash_audit.models import VerdictType
from bash_audit.policy import PolicyConfig, decide

import tree_sitter_bash as tsb
from tree_sitter import Language, Parser as TSParser

_LANG = Language(tsb.language())
_PARSER = TSParser(_LANG)


_EXIT_CODES = {
    VerdictType.ALLOW: 0,
    VerdictType.BLOCK: 1,
    VerdictType.CONFIRM: 2,
    VerdictType.REDIRECT: 3,
}


def _parse_error_info(script: str) -> dict:
    try:
        tree = _PARSER.parse(script.encode("utf-8", errors="replace"))
        root = tree.root_node
        return {"has_errors": root.has_error, "error_count": _count_errors(root)}
    except Exception:
        return {"has_errors": False, "error_count": 0}


def _count_errors(node) -> int:
    count = 1 if node.is_error else 0
    for child in node.children:
        count += _count_errors(child)
    return count


def _verdict_to_json(verdict, parse_info: dict) -> dict:
    return {
        "verdict": verdict.verdict.value,
        "message": verdict.message,
        "findings": [
            {
                "rule_id": f.rule_id,
                "severity": f.severity.value,
                "message": f.message,
                "matched_text": f.matched_text,
                "span": list(f.span),
                "metadata": f.metadata,
            }
            for f in verdict.findings
        ],
        "redirect_command": verdict.redirect_command,
        "confirmation_prompt": verdict.confirmation_prompt,
        "parse": parse_info,
    }


def _run(script: str, args: argparse.Namespace) -> int:
    try:
        ctx = make_context(
            cwd=args.cwd or os.getcwd(),
            worktree_root=getattr(args, "worktree", None),
            allowed_hosts=frozenset(getattr(args, "allowed_host", None) or []),
        )
        config = PolicyConfig.default()
        findings = audit(script, ctx)
        verdict = decide(findings, ctx, config)
        parse_info = _parse_error_info(script)

        output = _verdict_to_json(verdict, parse_info)
        print(json.dumps(output))
        return _EXIT_CODES.get(verdict.verdict, 12)

    except Exception as e:
        print(json.dumps({"error": str(e), "verdict": "block", "findings": [],
                          "message": f"Internal error: {e}", "parse": {}}))
        return 12


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="bash-audit",
        description="Audit a bash command against security rules.",
    )
    parser.add_argument("command", nargs="?", help="Bash command to audit")
    parser.add_argument("--stdin", action="store_true", help="Read command from stdin")
    parser.add_argument("--cwd", help="Working directory for context")
    parser.add_argument("--worktree", help="Git worktree root")
    parser.add_argument("--allowed-host", action="append", metavar="HOST",
                        help="Add host to allowed list (repeatable)")
    parser.add_argument("--format", choices=["json", "text"], default="json")

    args = parser.parse_args()

    if args.stdin:
        script = sys.stdin.read().rstrip("\n")
    elif args.command is not None:
        script = args.command
    else:
        parser.print_usage(sys.stderr)
        sys.exit(10)

    sys.exit(_run(script, args))


if __name__ == "__main__":
    main()
