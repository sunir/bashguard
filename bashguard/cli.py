"""
bashguard.cli — bash-ast command-line interface (data-grammar).

Usage:
    echo "$CLAUDE_HOOK_INPUT" | bash-ast hook
    bash-ast analyze --command 'git push origin main'
    bash-ast analyze --file script.sh

Hook mode reads Claude PreToolUse JSON from stdin and emits gates-compatible
permissionDecision JSON, or exits silently for allowed commands.

Analyze mode outputs a full JSON audit report for debugging.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from data_grammar import DataGrammar, ParseError, ExecutionError, UserError

from bashguard.types import AnalyzeScript, ClaudeSetup, Entry, LaunchWrapper, LogQuery, Output, RunScript, StatsQuery

_GRAMMAR = Path(__file__).parent / "grammar.bnf"

_TYPES = {
    "Entry": Entry,
    "AnalyzeScript": AnalyzeScript,
    "RunScript": RunScript,
    "ClaudeSetup": ClaudeSetup,
    "StatsQuery": StatsQuery,
    "LogQuery": LogQuery,
    "Launch": LaunchWrapper,
    "Output": Output,
}


def main() -> int:
    import io
    import json as _json
    try:
        grammar = DataGrammar(grammar=str(_GRAMMAR), types=_TYPES)
        buf = io.StringIO()
        old_stdout = sys.stdout
        sys.stdout = buf
        try:
            grammar.interpret_argv(sys.argv[1:])
        finally:
            sys.stdout = old_stdout
        output = buf.getvalue()
        sys.stdout.write(output)

        # Colony PreToolUse dispatcher uses exit code 2 to block.
        # run mode propagates the executed command's exit code directly.
        if output.strip():
            try:
                data = _json.loads(output)
                if data.get("permissionDecision") == "deny":
                    return 2
                # run mode: propagate executed command exit code or block/confirm codes
                verdict = data.get("verdict")
                if verdict == "block":
                    return 2
                if verdict == "confirm":
                    return 1
                if verdict == "allow" and "exit_code" in data:
                    return int(data["exit_code"])
            except (_json.JSONDecodeError, AttributeError, ValueError):
                pass
        return 0

    except (ParseError, UserError) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    except ExecutionError as e:
        print(f"Execution error: {e}", file=sys.stderr)
        return 1

    except KeyboardInterrupt:
        return 130

    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        if os.environ.get("DEBUG"):
            import traceback
            traceback.print_exc(file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
