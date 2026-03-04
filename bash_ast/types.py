"""
bash_ast.types — Data-grammar type implementations for the bash-ast CLI.

Forth-style pipeline (each method consumes a token and produces Output):
  hook:    "hook" → Entry.hook_mode()              → Output
  analyze: "analyze" "--command" CMD → AnalyzeScript.analyze_command(cmd) → Output
           "analyze" "--file" PATH   → AnalyzeScript.analyze_file(path)   → Output

Key design: full audit pipeline runs inside each token-consuming method because
data-grammar's main loop only iterates while tokens remain on the input stream.
Tokenless method chains would never fire.
"""

from __future__ import annotations

import json
import sys

from data_grammar import Document, Output as BaseOutput

from bash_audit.auditor import audit as _audit
from bash_audit.context import make_context
from bash_audit.models import VerdictType
from bash_audit.policy import PolicyConfig, decide


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _run_audit(script: str):
    """Run security audit and return (findings, verdict)."""
    ctx = make_context()
    findings = _audit(script, ctx)
    verdict = decide(findings, ctx, PolicyConfig.default())
    return findings, verdict


def _gates_output(script: str) -> "Output":
    """Audit script and return gates-compatible Output (deny/ask/silent)."""
    _, verdict = _run_audit(script)
    if verdict.verdict == VerdictType.ALLOW:
        return Output(text="")
    if verdict.verdict == VerdictType.BLOCK:
        payload = {"permissionDecision": "deny", "reason": verdict.message}
        return Output(text=json.dumps(payload))
    if verdict.verdict == VerdictType.CONFIRM:
        reason = verdict.confirmation_prompt or verdict.message
        payload = {"permissionDecision": "ask", "reason": reason}
        return Output(text=json.dumps(payload))
    return Output(text="")


def _report_output(script: str) -> "Output":
    """Audit script and return full JSON debug report as Output."""
    findings, verdict = _run_audit(script)
    data = {
        "commands": [script],
        "violations": [
            {
                "rule_id": f.rule_id,
                "severity": f.severity.value,
                "message": f.message,
                "matched_text": f.matched_text,
            }
            for f in findings
        ],
        "response": {
            "action": verdict.verdict.value,
            "reason": verdict.message,
        },
    }
    return Output(text=json.dumps(data, indent=2))


# ─── Grammar types ────────────────────────────────────────────────────────────

class Entry(Document):
    """Entry point — dispatches to hook or analyze mode."""

    def hook_mode(self) -> "Output":
        """Read Claude PreToolUse JSON from stdin, audit, emit gates-compatible response."""
        try:
            data = json.load(sys.stdin)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON on stdin: {e}") from e
        cmd = data.get("tool_input", {}).get("command", "")
        return _gates_output(cmd)

    def new(self) -> "AnalyzeScript":
        """Create empty AnalyzeScript for analyze mode."""
        return AnalyzeScript()

    def __str__(self) -> str:
        return ""


class AnalyzeScript(Document):
    """Analyze mode — receives source via --command or --file token."""

    def analyze_command(self, cmd: str) -> "Output":
        """Audit the given command string, return full JSON report."""
        return _report_output(cmd)

    def analyze_file(self, path: str) -> "Output":
        """Load script from file, audit it, return full JSON report."""
        with open(path, "r", encoding="utf-8") as f:
            script = f.read()
        return _report_output(script)

    def __str__(self) -> str:
        return ""


class Output(BaseOutput):
    """Terminal output — str() is written to stdout by @output."""

    def __init__(self, text: str = "", **kwargs):
        self.text = text

    def __str__(self) -> str:
        return self.text
