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

from bashguard.types import AnalyzeScript, Entry, Output

_GRAMMAR = Path(__file__).parent / "grammar.bnf"

_TYPES = {
    "Entry": Entry,
    "AnalyzeScript": AnalyzeScript,
    "Output": Output,
}


def main() -> int:
    try:
        grammar = DataGrammar(grammar=str(_GRAMMAR), types=_TYPES)
        grammar.interpret_argv(sys.argv[1:])
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
